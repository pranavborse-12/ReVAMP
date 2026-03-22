"""
Semgrep Scanner — Local rules, zero network calls.
Per-file language detection for incremental scans.

scan()                → full repo scan (uses repo-level detected languages)
scan_files(paths)     → incremental scan — detects language per changed file,
                        loads ONLY those masters → massive rule reduction
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .config import logger, SEMGREP_TIMEOUT, SEMGREP_APP_TOKEN, LANGUAGE_EXTENSIONS
from .utils import normalize_severity, extract_vulnerability_type

RULES_DIR = Path(__file__).parent / "semgrep_rules"

# Always loaded — every scan regardless of language
UNIVERSAL_RULES = RULES_DIR / "master-universal.yaml"
DEVOPS_RULES    = RULES_DIR / "master-devops.yaml"

# Language → master file
LANGUAGE_RULES: Dict[str, Path] = {
    "python":     RULES_DIR / "master-python.yaml",
    "javascript": RULES_DIR / "master-javascript.yaml",
    "typescript": RULES_DIR / "master-javascript.yaml",
    "java":       RULES_DIR / "master-java.yaml",
    "go":         RULES_DIR / "master-golang.yaml",
    "ruby":       RULES_DIR / "master-ruby.yaml",
    "php":        RULES_DIR / "master-php.yaml",
    "rust":       RULES_DIR / "master-systems.yaml",
    "c":          RULES_DIR / "master-systems.yaml",
    "cpp":        RULES_DIR / "master-systems.yaml",
}

SKIP_DIRS = [
    "node_modules", "vendor", ".git", "test", "tests",
    "__pycache__", "venv", ".venv", "dist", "build",
    "target", "migrations", "static", "media",
]

SEMGREP_SEVERITY_MAP = {
    "ERROR":   "HIGH",
    "WARNING": "MEDIUM",
    "INFO":    "LOW",
    "NOTE":    "LOW",
}


def _detect_languages_from_paths(relative_paths: Set[str]) -> Set[str]:
    """
    Detect languages from a set of file paths using their extensions.
    Used for incremental scans to load only relevant master files.

    e.g. {"src/auth.py", "api/routes.py"} → {"python"}
         {"app.py", "index.js"}            → {"python", "javascript"}
    """
    langs: Set[str] = set()
    for path in relative_paths:
        _, ext = os.path.splitext(path.lower())
        lang = LANGUAGE_EXTENSIONS.get(ext)
        if lang and lang in LANGUAGE_RULES:
            langs.add(lang)
    return langs


class SemgrepScanner:

    def __init__(self, repo_path: str, languages: Optional[Set[str]] = None):
        self.repo_path = repo_path
        self.languages = languages or set()
        self.name = "Semgrep"
        self.token = SEMGREP_APP_TOKEN

    def is_available(self) -> bool:
        try:
            r = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True, timeout=30,
                encoding="utf-8", errors="replace",
            )
            return r.returncode == 0
        except FileNotFoundError:
            logger.error("Semgrep not found — install: pip install semgrep")
            return False
        except subprocess.TimeoutExpired:
            return True
        except Exception as e:
            logger.error(f"Semgrep check failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Config arg builders
    # ------------------------------------------------------------------

    def _get_config_args_for_languages(self, languages: Set[str]) -> List[str]:
        """
        Build --config args for a given set of languages.
        Always includes universal + devops.
        Adds per-language master files for the provided language set.
        """
        configs: List[str] = []
        loaded: List[str] = []

        # Always load universal + devops
        for master in [UNIVERSAL_RULES, DEVOPS_RULES]:
            if master.exists():
                configs += ["--config", str(master)]
                loaded.append(master.stem)
            else:
                logger.warning(
                    f"Semgrep: missing {master.name} — "
                    "run download_rules.py + build_masters.py"
                )

        # Load language-specific masters
        seen: Set[str] = set()
        for lang in languages:
            rule_file = LANGUAGE_RULES.get(lang)
            if rule_file and rule_file.exists():
                fstr = str(rule_file)
                if fstr not in seen:
                    seen.add(fstr)
                    configs += ["--config", fstr]
                    loaded.append(rule_file.stem)
            elif rule_file:
                logger.debug(f"Semgrep: no master for language '{lang}' — skipping")

        logger.info(f"Semgrep: {len(loaded)} masters loaded: {loaded}")
        return configs

    def _get_config_args(self) -> List[str]:
        """Config args for full repo scan — uses repo-level language detection."""
        return self._get_config_args_for_languages(self.languages)

    # ------------------------------------------------------------------
    # Full scan
    # ------------------------------------------------------------------

    def scan(self) -> Tuple[List[Dict], str]:
        """Full repository scan using repo-level language detection."""
        if not self.is_available():
            return [], "Semgrep CLI not installed"

        config_args = self._get_config_args()
        if not config_args:
            return [], "No rule files found — run download_rules.py + build_masters.py"

        findings_json, error = self._run_scan(config_args=config_args, targets=[self.repo_path])
        if error and not findings_json:
            return [], error

        vulns = self._parse_findings(findings_json)
        logger.info(f"Semgrep full scan: {len(vulns)} issues found")
        return vulns, error

    # ------------------------------------------------------------------
    # Incremental scan — per-file language detection
    # ------------------------------------------------------------------

    def scan_files(self, relative_paths: Set[str]) -> Tuple[List[Dict], str]:
        """
        Scan only the given changed files.

        Key optimization over full scan:
          1. Only passes changed files as targets (not the whole repo)
          2. Detects languages from the changed files' extensions
          3. Loads ONLY the master files for those languages

        Example: 2 Python files changed out of 1000 total
          Full scan:        4000+ rules × 1000 files
          Incremental:      ~2000 python rules × 2 files  ← 1000x less work
        """
        if not relative_paths:
            return [], ""

        if not self.is_available():
            return [], "Semgrep CLI not installed"

        # Detect languages from the changed files specifically
        file_languages = _detect_languages_from_paths(relative_paths)

        if not file_languages:
            # Changed files have no language-specific rules (e.g. only .md, .txt)
            # Still run universal rules (secrets detection etc.) on them
            logger.info(
                f"Semgrep incremental: no language-specific rules for changed files "
                f"— running universal rules only"
            )

        config_args = self._get_config_args_for_languages(file_languages)
        if not config_args:
            return [], "No rule files found"

        # Resolve to absolute paths; drop files that no longer exist (deletions)
        abs_targets: List[str] = []
        for rel in relative_paths:
            abs_path = os.path.join(self.repo_path, rel.replace("/", os.sep))
            if os.path.exists(abs_path):
                abs_targets.append(abs_path)
            else:
                logger.debug(f"Semgrep incremental: skipping deleted file {rel}")

        if not abs_targets:
            logger.info("Semgrep incremental: all changed files deleted — nothing to scan")
            return [], ""

        logger.info(
            f"Semgrep incremental: {len(abs_targets)} files, "
            f"languages={file_languages}, "
            f"masters={len(config_args)//2}"
        )

        findings_json, error = self._run_scan(config_args=config_args, targets=abs_targets)
        if error and not findings_json:
            return [], error

        vulns = self._parse_findings(findings_json)
        logger.info(f"Semgrep incremental: {len(vulns)} issues found in {len(abs_targets)} files")
        return vulns, error

    # ------------------------------------------------------------------
    # CLI execution
    # ------------------------------------------------------------------

    def _run_scan(
        self,
        config_args: List[str],
        targets: List[str],
    ) -> Tuple[Optional[Dict], str]:
        import multiprocessing
        jobs = min(multiprocessing.cpu_count(), 8)

        env = os.environ.copy()
        if self.token:
            env["SEMGREP_APP_TOKEN"] = self.token
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["SEMGREP_SEND_METRICS"] = "off"

        exclude_args: List[str] = []
        for d in SKIP_DIRS:
            exclude_args += ["--exclude", d]

        cmd = [
            "semgrep", "scan",
            *config_args,
            "--json",
            "--quiet",
            "--no-rewrite-rule-ids",
            "--timeout", "5",
            "--timeout-threshold", "1",
            "--max-memory", "1024",
            "--max-target-bytes", "500000",
            "--jobs", str(jobs),
            "--metrics", "off",
            "--optimizations", "all",
            *exclude_args,
            *targets,
        ]

        logger.info(
            f"Semgrep CLI: {len(config_args)//2} masters, "
            f"{len(targets)} target(s), {jobs} jobs"
        )

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=SEMGREP_TIMEOUT,
                env=env,
            )

            if result.stderr:
                logger.debug(f"Semgrep stderr: {result.stderr[:300]}")

            if result.returncode >= 2 and not result.stdout:
                return None, f"Semgrep error (exit {result.returncode}): {result.stderr[:300]}"

            if not result.stdout or not result.stdout.strip():
                return None, "Semgrep produced no output"

            try:
                output = json.loads(result.stdout)
                logger.info(f"Semgrep raw findings: {len(output.get('results', []))}")
                return output, ""
            except json.JSONDecodeError:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            return json.loads(line), ""
                        except Exception:
                            continue
                return None, f"Invalid JSON output: {result.stdout[:200]}"

        except subprocess.TimeoutExpired:
            return None, f"Semgrep timed out after {SEMGREP_TIMEOUT}s"
        except FileNotFoundError:
            return None, "Semgrep CLI not found"
        except Exception as e:
            return None, f"Semgrep error: {e}"

    # ------------------------------------------------------------------
    # Parse findings
    # ------------------------------------------------------------------

    def _parse_findings(self, output: Optional[Dict]) -> List[Dict]:
        if not output:
            return []

        vulnerabilities = []
        skipped = 0

        for finding in output.get("results", []):
            try:
                extra    = finding.get("extra", {}) or {}
                metadata = extra.get("metadata", {}) or {}
                rule_id  = finding.get("check_id", "unknown")
                message  = extra.get("message", "")

                raw_sev    = extra.get("severity", "WARNING")
                normalized = SEMGREP_SEVERITY_MAP.get(raw_sev.upper(), raw_sev)

                cwe_raw = metadata.get("cwe", [])
                if isinstance(cwe_raw, str):
                    cwe_raw = [cwe_raw]
                cwe_list = [
                    c if c.upper().startswith("CWE-") else f"CWE-{c}"
                    for c in cwe_raw
                ]

                severity = normalize_severity(normalized, rule_id, cwe_list)

                if severity == "INFO" and not cwe_list:
                    skipped += 1
                    continue

                owasp_raw = metadata.get("owasp", [])
                if isinstance(owasp_raw, str):
                    owasp_raw = [owasp_raw]

                file_path = finding.get("path", "")
                if os.path.isabs(file_path) and file_path.startswith(self.repo_path):
                    file_path = os.path.relpath(file_path, self.repo_path)
                file_path = file_path.replace("\\", "/")

                start = finding.get("start", {}) or {}
                end   = finding.get("end",   {}) or {}

                vulnerabilities.append({
                    "scanner":            "Semgrep",
                    "rule_id":            rule_id,
                    "severity":           severity,
                    "message":            message,
                    "vulnerability_type": extract_vulnerability_type(rule_id, message),
                    "location": {
                        "file":       file_path,
                        "start_line": start.get("line", 0),
                        "end_line":   end.get("line", 0),
                        "start_col":  start.get("col"),
                        "end_col":    end.get("col"),
                    },
                    "cwe":          cwe_list if cwe_list else None,
                    "owasp":        owasp_raw,
                    "confidence":   metadata.get("confidence", "MEDIUM"),
                    "code_snippet": extra.get("lines", "")[:200] or None,
                })

            except Exception as e:
                logger.warning(f"Failed to parse semgrep finding: {e}")

        if skipped:
            logger.info(f"Semgrep: skipped {skipped} pure INFO findings")

        return vulnerabilities