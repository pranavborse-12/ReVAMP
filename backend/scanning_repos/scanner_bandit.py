"""
Bandit Scanner - Python-specific security analysis
Fast, accurate, no API limits

Added: scan_files(relative_paths) for incremental scanning.
"""
import os
import json
import subprocess
from typing import List, Dict, Tuple, Set
from .config import logger
from .utils import normalize_severity, extract_vulnerability_type


class BanditScanner:
    """
    Bandit security scanner for Python code.
    Lightweight, fast, no external API needed.
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.name = "Bandit"

    def is_available(self) -> bool:
        """Check if Bandit is installed."""
        try:
            subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                timeout=5,
                check=True,
            )
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Full scan (original behaviour)
    # ------------------------------------------------------------------

    def scan(self) -> Tuple[List[Dict], str]:
        """Run Bandit security scan on the entire repository."""
        return self._run_bandit(targets=["-r", self.repo_path])

    # ------------------------------------------------------------------
    # Incremental scan — targeted file list
    # ------------------------------------------------------------------

    def scan_files(self, relative_paths: Set[str]) -> Tuple[List[Dict], str]:
        """
        Scan only the given Python files (relative to repo_path).

        Bandit accepts individual file paths as positional arguments, so we
        pass them directly instead of using -r (recursive).  Non-existent or
        non-.py files are silently skipped.
        """
        if not relative_paths:
            return [], ""

        if not self.is_available():
            logger.warning("Bandit not installed — skipping incremental Python scan")
            return [], "Bandit not installed"

        # Filter to .py files that actually exist on disk
        abs_targets: List[str] = []
        for rel in relative_paths:
            if not rel.endswith(".py"):
                continue
            abs_path = os.path.join(self.repo_path, rel.replace("/", os.sep))
            if os.path.exists(abs_path):
                abs_targets.append(abs_path)
            else:
                logger.debug(f"Bandit incremental: skipping missing file {rel}")

        if not abs_targets:
            logger.info("Bandit incremental: no Python files to scan")
            return [], ""

        logger.info(f"Bandit incremental: scanning {len(abs_targets)} Python files")
        # Bandit takes individual files as positional args (no -r flag)
        return self._run_bandit(targets=abs_targets)

    # ------------------------------------------------------------------
    # Shared execution core
    # ------------------------------------------------------------------

    def _run_bandit(self, targets: List[str]) -> Tuple[List[Dict], str]:
        """
        Execute Bandit with the given target arguments.

        targets for full scan:  ["-r", repo_path]
        targets for incremental: ["/abs/file1.py", "/abs/file2.py", ...]
        """
        if not self.is_available():
            logger.warning("Bandit not installed — skipping Python security checks")
            logger.info("Install with: pip install bandit")
            return [], "Bandit not installed"

        vulnerabilities: List[Dict] = []

        try:
            logger.info("Running Bandit Python security scanner...")

            cmd = [
                "bandit",
                *targets,
                "-f", "json",
                "-l",    
                "-i",
                "--exclude", "*/test/*,*/tests/*,*/.venv/*,*/venv/*,*/node_modules/*",
        ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Bandit returns 1 if issues found, 0 if clean
            if result.stdout:
                try:
                    output = json.loads(result.stdout)
                    results = output.get("results", [])

                    for finding in results:
                        issue_severity   = finding.get("issue_severity", "MEDIUM")
                        issue_confidence = finding.get("issue_confidence", "MEDIUM")
                        issue_text       = finding.get("issue_text", "")
                        test_id          = finding.get("test_id", "")
                        test_name        = finding.get("test_name", "")

                        filename    = finding.get("filename", "")
                        line_number = finding.get("line_number", 0)
                        code        = finding.get("code", "")

                        severity_map = {
                            "HIGH":   "HIGH",
                            "MEDIUM": "MEDIUM",
                            "LOW":    "LOW",
                        }
                        severity = severity_map.get(issue_severity.upper(), "MEDIUM")

                        cwe_list = []
                        if "cwe" in finding:
                            cwe_data = finding["cwe"]
                            if isinstance(cwe_data, dict):
                                cwe_id = cwe_data.get("id")
                                if cwe_id:
                                    cwe_list.append(f"CWE-{cwe_id}")
                            elif isinstance(cwe_data, str):
                                cwe_list.append(f"CWE-{cwe_data}")

                        rel_path = os.path.relpath(filename, self.repo_path)
                        rel_path = rel_path.replace("\\", "/")

                        vulnerability = {
                            "scanner": "Bandit",
                            "rule_id": test_id or test_name,
                            "severity": severity,
                            "message": issue_text,
                            "vulnerability_type": extract_vulnerability_type(test_name, issue_text),
                            "location": {
                                "file": rel_path,
                                "start_line": line_number,
                                "end_line": line_number,
                                "start_col": None,
                                "end_col": None,
                            },
                            "cwe": cwe_list if cwe_list else None,
                            "owasp": [],
                            "confidence": issue_confidence,
                            "code_snippet": code.strip()[:200] if code else None,
                        }

                        vulnerabilities.append(vulnerability)

                    logger.info(f"Bandit found {len(vulnerabilities)} Python security issues")

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Bandit output: {e}")
                    return [], "Failed to parse Bandit output"

        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timeout")
            return [], "Bandit scan timeout"
        except Exception as e:
            error_msg = f"Bandit error: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [], error_msg

        return vulnerabilities, ""