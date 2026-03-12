"""
Semgrep Scanner - Fixed and optimized.

Root causes of previous 0-findings bug:
  1. --severity INFO told semgrep CLI to output ONLY INFO findings
     but the parser was skipping INFO → everything filtered out
  2. --timeout 10 too aggressive — rules need 15-30s on first run
  3. These two flags contradicted each other completely

Fixes applied:
  - Removed --severity flag entirely (get all findings, filter in parser)
  - Increased --timeout to 45s per rule (safe for first-run downloads)
  - Kept --jobs 4, --no-rewrite-rule-ids for speed
  - Added debug logging to show raw finding count before filtering
  - Language-aware rulesets — only load relevant ones
"""
import os
import json
import subprocess
from typing import List, Dict, Tuple, Optional, Set
import httpx

from .config import logger, SEMGREP_TIMEOUT, SEMGREP_APP_TOKEN
from .utils import normalize_severity, extract_vulnerability_type


SEMGREP_API_BASE = "https://semgrep.dev/api/v1"

SKIP_DIRS = [
    "node_modules", "vendor", ".git", "test", "tests",
    "__pycache__", "venv", ".venv", "dist", "build", "target",
    "migrations", "static", "media",
]

# Core rulesets — always run regardless of language
CORE_RULESETS = [
    "p/owasp-top-ten",
    "p/secrets",
]

# Only added when that language is detected in the repo
LANGUAGE_RULESETS = {
    "python":     "p/python",
    "javascript": "p/javascript",
    "typescript": "p/javascript",
    "java":       "p/java",
    "go":         "p/golang",
}

# Semgrep reports these severity strings — map them to our standard
SEMGREP_SEVERITY_MAP = {
    "ERROR":   "HIGH",
    "WARNING": "MEDIUM",
    "INFO":    "LOW",
    "NOTE":    "LOW",
}


class SemgrepScanner:

    def __init__(self, repo_path: str, languages: Optional[Set[str]] = None):
        self.repo_path = repo_path
        self.languages = languages or set()
        self.name = "Semgrep"
        self.token = SEMGREP_APP_TOKEN
        self.api_headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
            )
            return result.returncode == 0
        except FileNotFoundError:
            logger.error("Semgrep CLI not found. Install outside venv: pip install semgrep")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep --version slow (Windows cold start) — proceeding")
            return True
        except Exception as e:
            logger.error(f"Semgrep availability check failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def scan(self) -> Tuple[List[Dict], str]:
        if not self.is_available():
            return [], "Semgrep CLI not installed. Run outside venv: pip install semgrep"

        if self.token:
            logger.info("Semgrep: token configured — managed rules included")
        else:
            logger.warning("Semgrep: no token — using public rulesets only")

        try:
            findings_json, error = self._run_scan()
            if error and not findings_json:
                return [], error

            vulnerabilities = self._parse_findings(findings_json)
            logger.info(f"Semgrep found {len(vulnerabilities)} issues")
            return vulnerabilities, error

        except Exception as e:
            logger.error(f"Semgrep scan error: {e}", exc_info=True)
            return [], str(e)

    # ------------------------------------------------------------------
    # Build ruleset list
    # ------------------------------------------------------------------

    def _build_rulesets(self) -> List[str]:
        rulesets = list(CORE_RULESETS)

        for lang in self.languages:
            ruleset = LANGUAGE_RULESETS.get(lang)
            if ruleset and ruleset not in rulesets:
                rulesets.append(ruleset)
                logger.info(f"Semgrep: adding {ruleset} for language: {lang}")

        logger.info(f"Semgrep: using {len(rulesets)} rulesets: {rulesets}")
        return rulesets

    # ------------------------------------------------------------------
    # Run scan
    # ------------------------------------------------------------------

    def _run_scan(self) -> Tuple[Optional[Dict], str]:
        env = os.environ.copy()
        if self.token:
            env["SEMGREP_APP_TOKEN"] = self.token

        config_args = []
        for ruleset in self._build_rulesets():
            config_args += ["--config", ruleset]

        exclude_args = []
        for d in SKIP_DIRS:
            exclude_args += ["--exclude", d]

        cmd = [
            "semgrep", "scan",
            *config_args,
            "--json",                # structured JSON output to stdout
            "--quiet",               # suppress progress bar (stderr only)
            "--no-rewrite-rule-ids", # skip ID rewriting — saves post-processing time
            "--timeout", "45",       # per-rule timeout — 45s allows first-run downloads
            "--timeout-threshold", "3",  # abort rule after 3 timeouts
            "--max-memory", "2048",
            "--jobs", "4",           # parallel rule execution
            "--metrics", "off",      # no telemetry
            # NO --severity flag here — that filters OUTPUT not input
            # We filter severity in the parser instead, with full control
            *exclude_args,
            self.repo_path,
        ]

        logger.info(f"Running: semgrep scan (jobs=4, per-rule timeout=45s)")

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

            # Log stderr for debugging (semgrep puts stats/warnings there)
            if result.stderr:
                logger.debug(f"Semgrep stderr: {result.stderr[:500]}")

            # Exit 0 = clean, 1 = findings found — both valid
            # Exit 2+ = configuration/runtime error
            if result.returncode >= 2 and not result.stdout:
                stderr_snippet = result.stderr[:400] if result.stderr else "no stderr"
                return None, f"Semgrep error (exit {result.returncode}): {stderr_snippet}"

            if not result.stdout or not result.stdout.strip():
                stderr_snippet = result.stderr[:400] if result.stderr else "no output"
                return None, f"Semgrep produced no output: {stderr_snippet}"

            try:
                output = json.loads(result.stdout)
                raw_count = len(output.get("results", []))
                logger.info(f"Semgrep raw findings before filtering: {raw_count}")
                return output, ""
            except json.JSONDecodeError:
                # Semgrep occasionally mixes a log line before the JSON
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            output = json.loads(line)
                            raw_count = len(output.get("results", []))
                            logger.info(f"Semgrep raw findings before filtering: {raw_count}")
                            return output, ""
                        except Exception:
                            continue
                return None, f"Semgrep output not valid JSON: {result.stdout[:300]}"

        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep timed out after {SEMGREP_TIMEOUT}s")
            return None, f"Semgrep timed out after {SEMGREP_TIMEOUT}s"

        except FileNotFoundError:
            return None, "Semgrep CLI not found — install outside venv: pip install semgrep"

        except Exception as e:
            return None, f"Semgrep CLI error: {e}"

    # ------------------------------------------------------------------
    # Parse findings
    # ------------------------------------------------------------------

    def _parse_findings(self, output: Dict) -> List[Dict]:
        if not output:
            return []

        vulnerabilities = []
        skipped_info = 0

        for finding in output.get("results", []):
            try:
                extra = finding.get("extra", {}) or {}
                metadata = extra.get("metadata", {}) or {}

                rule_id = finding.get("check_id", "unknown")
                message = extra.get("message", "")

                # Semgrep uses ERROR/WARNING/INFO — normalize first
                raw_severity = extra.get("severity", "WARNING")
                normalized = SEMGREP_SEVERITY_MAP.get(raw_severity.upper(), raw_severity)

                # Apply CWE-based severity upgrade
                cwe_raw = metadata.get("cwe", [])
                if isinstance(cwe_raw, str):
                    cwe_raw = [cwe_raw]
                cwe_list = [
                    c if c.upper().startswith("CWE-") else f"CWE-{c}"
                    for c in cwe_raw
                ]

                severity = normalize_severity(normalized, rule_id, cwe_list)

                # Skip only genuine INFO/LOW noise after severity upgrade
                # This means a CWE-upgraded finding won't get skipped
                if severity in ("INFO",) and not cwe_list:
                    skipped_info += 1
                    continue

                owasp_raw = metadata.get("owasp", [])
                if isinstance(owasp_raw, str):
                    owasp_raw = [owasp_raw]

                vuln_type = extract_vulnerability_type(rule_id, message)

                file_path = finding.get("path", "")
                if os.path.isabs(file_path) and file_path.startswith(self.repo_path):
                    file_path = os.path.relpath(file_path, self.repo_path)

                start = finding.get("start", {}) or {}
                end = finding.get("end", {}) or {}

                vulnerabilities.append({
                    "scanner": "Semgrep",
                    "rule_id": rule_id,
                    "severity": severity,
                    "message": message,
                    "vulnerability_type": vuln_type,
                    "location": {
                        "file": file_path,
                        "start_line": start.get("line", 0),
                        "end_line": end.get("line", 0),
                        "start_col": start.get("col"),
                        "end_col": end.get("col"),
                    },
                    "cwe": cwe_list if cwe_list else None,
                    "owasp": owasp_raw,
                    "confidence": metadata.get("confidence", "MEDIUM"),
                    "code_snippet": extra.get("lines", "")[:200] or None,
                })

            except Exception as e:
                logger.warning(f"Failed to parse semgrep finding: {e}")
                continue

        if skipped_info > 0:
            logger.info(f"Semgrep: skipped {skipped_info} pure INFO findings")

        return vulnerabilities

    # ------------------------------------------------------------------
    # Optional: Semgrep AppSec Platform API (read-only)
    # ------------------------------------------------------------------

    def fetch_api_findings(self, deployment_slug: str) -> Tuple[List[Dict], str]:
        if not self.token:
            return [], "No SEMGREP_APP_TOKEN configured"

        vulnerabilities = []
        page = 0

        try:
            while True:
                with httpx.Client(timeout=30) as client:
                    resp = client.get(
                        f"{SEMGREP_API_BASE}/deployments/{deployment_slug}/findings",
                        headers=self.api_headers,
                        params={"page": page, "page_size": 100, "dedup": "true"},
                    )

                if resp.status_code == 401:
                    return [], "Semgrep API token invalid or expired"
                if resp.status_code != 200:
                    return vulnerabilities, f"API error: HTTP {resp.status_code}"

                data = resp.json()
                findings = data.get("findings", [])
                for f in findings:
                    vuln = self._parse_api_finding(f)
                    if vuln:
                        vulnerabilities.append(vuln)

                total = data.get("total", len(findings))
                if (page + 1) * 100 >= total or not findings:
                    break
                page += 1

        except Exception as e:
            return vulnerabilities, f"API fetch error: {e}"

        return vulnerabilities, ""

    def _parse_api_finding(self, finding: Dict) -> Optional[Dict]:
        try:
            rule = finding.get("rule", {}) or {}
            location = finding.get("location", {}) or {}
            metadata = rule.get("metadata", {}) or {}
            rule_id = finding.get("rule_id") or rule.get("id") or "unknown"
            message = finding.get("message") or rule.get("name") or ""
            raw_severity = finding.get("severity") or rule.get("severity") or "MEDIUM"
            cwe_raw = metadata.get("cwe", [])
            if isinstance(cwe_raw, str):
                cwe_raw = [cwe_raw]
            cwe_list = [c if c.upper().startswith("CWE-") else f"CWE-{c}" for c in cwe_raw]
            owasp_raw = metadata.get("owasp", [])
            if isinstance(owasp_raw, str):
                owasp_raw = [owasp_raw]
            file_path = location.get("file_path") or location.get("path") or ""
            start_line = location.get("start_line") or location.get("line") or 0
            return {
                "scanner": "Semgrep",
                "rule_id": rule_id,
                "severity": normalize_severity(raw_severity, rule_id, cwe_list),
                "message": message,
                "vulnerability_type": extract_vulnerability_type(rule_id, message),
                "location": {
                    "file": file_path,
                    "start_line": start_line,
                    "end_line": location.get("end_line") or start_line,
                    "start_col": location.get("start_col") or location.get("column"),
                    "end_col": location.get("end_col"),
                },
                "cwe": cwe_list if cwe_list else None,
                "owasp": owasp_raw,
                "confidence": metadata.get("confidence", "MEDIUM"),
                "code_snippet": None,
            }
        except Exception as e:
            logger.warning(f"Failed to parse API finding: {e}")
            return None

    def get_deployment_slug(self) -> Tuple[Optional[str], str]:
        if not self.token:
            return None, "No SEMGREP_APP_TOKEN configured"
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(f"{SEMGREP_API_BASE}/deployments", headers=self.api_headers)
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
            deployments = resp.json().get("deployments", [])
            if not deployments:
                return None, "No deployments found for this token"
            return deployments[0].get("slug") or deployments[0].get("name"), ""
        except Exception as e:
            return None, f"Error fetching deployments: {e}"