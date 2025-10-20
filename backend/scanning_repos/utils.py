"""
Utility functions for scanning module
Integrates with GitHub API and scanning tools
"""
import os
import subprocess
import asyncio
from pathlib import Path
from typing import Optional, Tuple, Set, Dict, Any
import httpx
from .config import (
    logger, LANGUAGE_EXTENSIONS, SKIP_DIRS,
    SEVERITY_RULES, CWE_SEVERITY_MAP, GITHUB_API_URL
)
from .models import SeveritySummary


def run_command_with_timeout(
    cmd: list,
    timeout: int,
    cwd: str = None,
    env: dict = None
) -> Tuple[int, str, str]:
    """Run a command with timeout and proper error handling"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            cwd=cwd,
            env=env or os.environ.copy()
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd[:3])}")
        return -1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        logger.error(f"Command failed: {str(e)}")
        return -1, "", str(e)


def detect_languages(repo_path: str, max_files: int = 10000) -> Set[str]:
    """Detect programming languages in the repository"""
    languages = set()
    file_count = 0

    try:
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for file in files:
                if file_count >= max_files:
                    logger.warning(f"File limit ({max_files}) reached during language detection")
                    break

                ext = Path(file).suffix.lower()
                if ext in LANGUAGE_EXTENSIONS:
                    languages.add(LANGUAGE_EXTENSIONS[ext])
                    file_count += 1

            if file_count >= max_files:
                break

        logger.info(f"Detected languages: {languages} (scanned {file_count} files)")
    except Exception as e:
        logger.error(f"Language detection error: {str(e)}")

    return languages


def get_code_snippet(
    file_path: str,
    start_line: int,
    end_line: int,
    max_lines: int = 10
) -> Optional[str]:
    """Extract code snippet from file with safety limits"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

            context_start = max(0, start_line - 1)
            context_end = min(len(lines), end_line, context_start + max_lines)

            snippet = ''.join(lines[context_start:context_end])
            return snippet[:500]
    except Exception as e:
        logger.debug(f"Error reading code snippet from {file_path}: {e}")
        return None


def normalize_severity(severity: str, rule_id: str = "", cwe_list: list = None) -> str:
    """
    Intelligently normalize severity based on multiple factors
    """
    severity_upper = severity.upper()

    if severity_upper in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'WARNING']:

        rule_lower = rule_id.lower()
        for pattern, mapped_severity in SEVERITY_RULES.items():
            if pattern in rule_lower:
                severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                if severity_order.index(mapped_severity) > severity_order.index(severity_upper):
                    logger.info(f"Upgraded severity from {severity_upper} to {mapped_severity} based on rule pattern: {pattern}")
                    return mapped_severity

        if cwe_list:
            for cwe in cwe_list:
                cwe_num = cwe.replace('CWE-', '').strip()
                if cwe_num in CWE_SEVERITY_MAP:
                    mapped_severity = CWE_SEVERITY_MAP[cwe_num]
                    severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                    if severity_order.index(mapped_severity) > severity_order.index(severity_upper):
                        logger.info(f"Upgraded severity from {severity_upper} to {mapped_severity} based on CWE-{cwe_num}")
                        return mapped_severity

        return severity_upper

    severity_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "NOTE": "LOW"
    }

    return severity_map.get(severity_upper, "MEDIUM")


def extract_vulnerability_type(rule_id: str, message: str) -> str:
    """Extract vulnerability type from rule ID and message"""
    rule_lower = rule_id.lower()
    message_lower = message.lower()

    patterns = {
        "SQL Injection": ['sql-injection', 'sqli', 'sql injection'],
        "Command Injection": ['command-injection', 'os-command', 'shell-injection'],
        "Cross-Site Scripting (XSS)": ['xss', 'cross-site-scripting'],
        "Path Traversal": ['path-traversal', 'directory-traversal'],
        "Cross-Site Request Forgery (CSRF)": ['csrf', 'cross-site-request'],
        "Hardcoded Credentials": ['hardcoded', 'secret', 'password', 'api-key', 'credential'],
        "Cryptographic Issue": ['crypto', 'encryption', 'weak-hash'],
        "Server-Side Request Forgery (SSRF)": ['ssrf', 'server-side-request'],
        "Insecure Deserialization": ['deserialization', 'pickle', 'unsafe-load'],
        "Information Disclosure": ['information-disclosure', 'sensitive-data', 'exposure'],
    }

    for vuln_type, terms in patterns.items():
        if any(term in rule_lower or term in message_lower for term in terms):
            return vuln_type

    return "Security Issue"


def calculate_severity_summary(vulnerabilities: list) -> SeveritySummary:
    """Calculate severity summary from vulnerabilities"""
    summary = SeveritySummary()

    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'INFO').upper()
        if severity == 'CRITICAL':
            summary.critical += 1
        elif severity == 'HIGH':
            summary.high += 1
        elif severity == 'MEDIUM':
            summary.medium += 1
        elif severity == 'LOW':
            summary.low += 1
        elif severity == 'WARNING':
            summary.warning += 1
        else:
            summary.info += 1

    return summary


def get_semgrep_token(authorization: Optional[str] = None) -> Optional[str]:
    """Get Semgrep token from env or header"""
    from .config import SEMGREP_APP_TOKEN
    if authorization and authorization.startswith("Bearer "):
        return authorization.replace("Bearer ", "")
    return SEMGREP_APP_TOKEN


async def clone_github_repo(
    github_token: str,
    owner: str,
    repo: str,
    branch: str,
    target_path: str,
    timeout: int = 120
) -> Tuple[bool, str]:
    """
    Clone a GitHub repository using GitHub token for authentication
    Optimized with sparse checkout
    """
    try:
        # Use GitHub API to get clone URL with token
        clone_url = f"https://{github_token}@github.com/{owner}/{repo}.git"

        cmd = [
            'git', 'clone',
            '--filter=blob:none',
            '--sparse',
            '--branch', branch,
            clone_url,
            target_path
        ]

        logger.info(f"Cloning {owner}/{repo} from branch {branch}...")
        returncode, stdout, stderr = run_command_with_timeout(cmd, timeout)

        if returncode != 0:
            # Sanitize error message to not expose token
            error_msg = stderr.replace(github_token, '***')
            logger.error(f"Clone failed: {error_msg}")
            return False, f"Failed to clone repository: {error_msg[:200]}"

        logger.info(f"Repository cloned successfully to {target_path}")
        return True, "Repository cloned successfully"

    except Exception as e:
        logger.error(f"Clone error: {str(e)}")
        return False, f"Clone failed: {str(e)}"