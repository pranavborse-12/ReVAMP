"""
Semgrep scanner implementation with optimizations
"""
import os
import json
from typing import Tuple, List, Optional
from .config import logger, SEMGREP_TIMEOUT, SEMGREP_APP_TOKEN
from .utils import (
    run_command_with_timeout,
    get_code_snippet,
    normalize_severity,
    extract_vulnerability_type
)


def run_semgrep_scan(repo_path: str, token: Optional[str] = None) -> Tuple[List[dict], str]:
    """
    Run optimized Semgrep scan with better severity classification
    Returns: (vulnerabilities: list, error_message: str)
    """
    vulnerabilities = []
    error_msg = ""

    try:
        logger.info("Starting Semgrep scan...")

        returncode, stdout, stderr = run_command_with_timeout(['semgrep', '--version'], 10)
        if returncode != 0:
            return [], "Semgrep not installed or not in PATH"

        logger.info(f"Semgrep version: {stdout.strip()}")

        env = os.environ.copy()
        if token or SEMGREP_APP_TOKEN:
            env['SEMGREP_APP_TOKEN'] = token or SEMGREP_APP_TOKEN
            logger.info("Using Semgrep token for enhanced rules")

        cmd = [
            'semgrep',
            '--config=p/security-audit',
            '--config=p/owasp-top-ten',
            '--json',
            '--quiet',
            '--no-git-ignore',
            '--max-memory=2048',
            '--timeout=25',
            '--max-target-bytes=1000000',
            '--metrics=off',
            repo_path
        ]

        returncode, stdout, stderr = run_command_with_timeout(cmd, SEMGREP_TIMEOUT, env=env)

        if returncode not in [0, 1]:
            logger.warning(f"Semgrep exited with code {returncode}: {stderr}")

        if stdout:
            try:
                output = json.loads(stdout)
                results = output.get('results', [])
                logger.info(f"Semgrep found {len(results)} potential issues")

                for res in results:
                    extra = res.get('extra', {})
                    metadata = extra.get('metadata', {})

                    rule_id = res.get('check_id', 'unknown')
                    message = extra.get('message', res.get('check_id', ''))

                    cwe_list = []
                    if 'cwe' in metadata:
                        cwe_data = metadata.get('cwe', [])
                        if isinstance(cwe_data, list):
                            cwe_list = [f"CWE-{c.split('-')[1]}" if 'CWE-' in str(c).upper() else f"CWE-{c}" for c in cwe_data]
                        elif isinstance(cwe_data, str):
                            cwe_list = [cwe_data]

                    original_severity = extra.get('severity', 'INFO')
                    severity = normalize_severity(original_severity, rule_id, cwe_list)
                    vuln_type = extract_vulnerability_type(rule_id, message)

                    file_path = res.get('path', '')
                    start_line = res.get('start', {}).get('line', 0)
                    end_line = res.get('end', {}).get('line', 0)

                    code_snippet = None
                    if severity in ['HIGH', 'CRITICAL'] and file_path:
                        full_path = os.path.join(repo_path, file_path)
                        code_snippet = get_code_snippet(full_path, start_line, end_line)

                    vulnerability = {
                        'scanner': 'Semgrep',
                        'rule_id': rule_id,
                        'severity': severity,
                        'message': message,
                        'vulnerability_type': vuln_type,
                        'location': {
                            'file': file_path,
                            'start_line': start_line,
                            'end_line': end_line,
                            'start_col': res.get('start', {}).get('col'),
                            'end_col': res.get('end', {}).get('col')
                        },
                        'cwe': cwe_list if cwe_list else None,
                        'owasp': metadata.get('owasp', []),
                        'confidence': metadata.get('confidence', extra.get('confidence')),
                        'code_snippet': code_snippet
                    }
                    vulnerabilities.append(vulnerability)

                logger.info(f"Semgrep processed {len(vulnerabilities)} vulnerabilities")

            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse Semgrep output: {str(e)}"
                logger.error(error_msg)
        else:
            logger.info("Semgrep completed with no issues found")

    except Exception as e:
        error_msg = f"Semgrep error: {str(e)}"
        logger.error(error_msg)

    return vulnerabilities, error_msg