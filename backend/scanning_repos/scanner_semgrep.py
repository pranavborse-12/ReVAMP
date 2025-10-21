"""
Enhanced Semgrep scanner with better coverage and detection
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
    Run comprehensive Semgrep scan with multiple rulesets
    Returns: (vulnerabilities: list, error_message: str)
    """
    vulnerabilities = []
    error_msg = ""

    try:
        logger.info("Starting Semgrep scan...")

        # Check if Semgrep is installed
        returncode, stdout, stderr = run_command_with_timeout(['semgrep', '--version'], 10)
        if returncode != 0:
            error_msg = "Semgrep not installed or not in PATH"
            logger.error(error_msg)
            return [], error_msg

        version = stdout.strip()
        logger.info(f"Semgrep version: {version}")

        # Setup environment
        env = os.environ.copy()
        semgrep_token = token or SEMGREP_APP_TOKEN
        
        if semgrep_token:
            env['SEMGREP_APP_TOKEN'] = semgrep_token
            logger.info("Using Semgrep token for enhanced rules")
        else:
            logger.warning("No Semgrep token provided - using free rules only")

        # Enhanced ruleset configuration - Multiple passes for better coverage
        rulesets = [
            # Security-focused rulesets
            'p/security-audit',
            'p/owasp-top-ten',
            'p/cwe-top-25',
            
            # Language-specific security
            'p/python',
            'p/javascript',
            'p/java',
            'p/go',
            'p/ruby',
            'p/php',
            'p/typescript',
            'p/csharp',
            
            # Additional security patterns
            'p/secrets',
            'p/sql-injection',
            'p/xss',
            'p/command-injection',
        ]

        all_results = []
        successful_scans = 0

        # Run Semgrep with multiple rulesets for comprehensive coverage
        for ruleset in rulesets:
            try:
                logger.info(f"Running Semgrep with ruleset: {ruleset}")
                
                cmd = [
                    'semgrep',
                    f'--config={ruleset}',
                    '--json',
                    '--quiet',
                    '--no-git-ignore',
                    '--max-memory=2048',
                    '--timeout=30',
                    '--max-target-bytes=1000000',
                    '--metrics=off',
                    repo_path
                ]

                returncode, stdout, stderr = run_command_with_timeout(
                    cmd, 
                    SEMGREP_TIMEOUT, 
                    env=env
                )

                # Semgrep returns 0 (no findings) or 1 (findings), both are success
                if returncode not in [0, 1]:
                    logger.warning(f"Semgrep ruleset {ruleset} exited with code {returncode}")
                    continue

                if stdout:
                    try:
                        output = json.loads(stdout)
                        results = output.get('results', [])
                        
                        if results:
                            all_results.extend(results)
                            successful_scans += 1
                            logger.info(f"Ruleset {ruleset} found {len(results)} issues")
                        else:
                            logger.debug(f"Ruleset {ruleset} found no issues")
                            
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse Semgrep output for {ruleset}: {e}")
                        continue
                        
            except Exception as e:
                logger.warning(f"Error running ruleset {ruleset}: {e}")
                continue

        logger.info(f"Semgrep completed {successful_scans}/{len(rulesets)} rulesets successfully")
        logger.info(f"Total raw findings: {len(all_results)}")

        # Deduplicate results based on file + line + rule_id
        seen = set()
        unique_results = []
        
        for res in all_results:
            # Create unique key
            file_path = res.get('path', '')
            start_line = res.get('start', {}).get('line', 0)
            rule_id = res.get('check_id', '')
            
            key = (file_path, start_line, rule_id)
            
            if key not in seen:
                seen.add(key)
                unique_results.append(res)

        logger.info(f"After deduplication: {len(unique_results)} unique findings")

        # Process results
        for res in unique_results:
            try:
                extra = res.get('extra', {})
                metadata = extra.get('metadata', {})

                rule_id = res.get('check_id', 'unknown')
                message = extra.get('message', res.get('check_id', ''))

                # Extract CWE information
                cwe_list = []
                if 'cwe' in metadata:
                    cwe_data = metadata.get('cwe', [])
                    if isinstance(cwe_data, list):
                        for cwe in cwe_data:
                            if isinstance(cwe, str):
                                # Handle different CWE formats
                                if 'CWE-' in cwe.upper():
                                    cwe_num = cwe.upper().split('CWE-')[1].split('/')[0].split(':')[0]
                                    cwe_list.append(f"CWE-{cwe_num}")
                                else:
                                    cwe_list.append(f"CWE-{cwe}")
                    elif isinstance(cwe_data, str):
                        cwe_list.append(cwe_data if 'CWE-' in cwe_data else f"CWE-{cwe_data}")

                # Extract OWASP information
                owasp_list = []
                if 'owasp' in metadata:
                    owasp_data = metadata.get('owasp', [])
                    if isinstance(owasp_data, list):
                        owasp_list = [str(o) for o in owasp_data]
                    elif isinstance(owasp_data, str):
                        owasp_list = [owasp_data]

                # Get severity and normalize it
                original_severity = extra.get('severity', 'INFO')
                severity = normalize_severity(original_severity, rule_id, cwe_list)
                
                # Extract vulnerability type
                vuln_type = extract_vulnerability_type(rule_id, message)

                # Get file location
                file_path = res.get('path', '')
                start_line = res.get('start', {}).get('line', 0)
                end_line = res.get('end', {}).get('line', start_line)

                # Get code snippet for high/critical issues
                code_snippet = None
                if severity in ['HIGH', 'CRITICAL'] and file_path:
                    full_path = os.path.join(repo_path, file_path)
                    if os.path.exists(full_path):
                        code_snippet = get_code_snippet(full_path, start_line, end_line)

                # Get confidence
                confidence = metadata.get('confidence', extra.get('confidence', 'MEDIUM'))
                if isinstance(confidence, str):
                    confidence = confidence.upper()

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
                    'owasp': owasp_list if owasp_list else None,
                    'confidence': confidence,
                    'code_snippet': code_snippet
                }
                vulnerabilities.append(vulnerability)
                
            except Exception as e:
                logger.error(f"Error processing Semgrep result: {e}", exc_info=True)
                continue

        # Log summary by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        logger.info(f"Semgrep scan complete: {len(vulnerabilities)} vulnerabilities")
        for sev, count in sorted(severity_counts.items()):
            logger.info(f"  {sev}: {count}")

        if len(vulnerabilities) == 0 and successful_scans > 0:
            logger.info("✓ No security issues found by Semgrep")
        elif successful_scans == 0:
            error_msg = "All Semgrep rulesets failed to execute"

    except Exception as e:
        error_msg = f"Semgrep error: {str(e)}"
        logger.error(error_msg, exc_info=True)

    return vulnerabilities, error_msg


def run_quick_semgrep_scan(repo_path: str, token: Optional[str] = None) -> Tuple[List[dict], str]:
    """
    Run a quick Semgrep scan with essential rulesets only
    Faster alternative for time-constrained scenarios
    """
    vulnerabilities = []
    error_msg = ""

    try:
        logger.info("Starting Quick Semgrep scan...")

        returncode, stdout, stderr = run_command_with_timeout(['semgrep', '--version'], 10)
        if returncode != 0:
            return [], "Semgrep not installed"

        env = os.environ.copy()
        if token or SEMGREP_APP_TOKEN:
            env['SEMGREP_APP_TOKEN'] = token or SEMGREP_APP_TOKEN

        # Quick scan with most important rulesets
        cmd = [
            'semgrep',
            '--config=p/security-audit',
            '--config=p/owasp-top-ten',
            '--config=p/secrets',
            '--json',
            '--quiet',
            '--no-git-ignore',
            '--max-memory=2048',
            '--timeout=25',
            '--metrics=off',
            repo_path
        ]

        returncode, stdout, stderr = run_command_with_timeout(cmd, 180, env=env)

        if returncode not in [0, 1]:
            logger.warning(f"Quick Semgrep scan exited with code {returncode}")

        if stdout:
            output = json.loads(stdout)
            results = output.get('results', [])
            logger.info(f"Quick scan found {len(results)} potential issues")

            for res in results:
                extra = res.get('extra', {})
                metadata = extra.get('metadata', {})
                
                vulnerabilities.append({
                    'scanner': 'Semgrep',
                    'rule_id': res.get('check_id', 'unknown'),
                    'severity': normalize_severity(
                        extra.get('severity', 'INFO'),
                        res.get('check_id', ''),
                        metadata.get('cwe', [])
                    ),
                    'message': extra.get('message', ''),
                    'vulnerability_type': extract_vulnerability_type(
                        res.get('check_id', ''),
                        extra.get('message', '')
                    ),
                    'location': {
                        'file': res.get('path', ''),
                        'start_line': res.get('start', {}).get('line', 0),
                        'end_line': res.get('end', {}).get('line', 0),
                        'start_col': res.get('start', {}).get('col'),
                        'end_col': res.get('end', {}).get('col')
                    },
                    'cwe': metadata.get('cwe', []),
                    'owasp': metadata.get('owasp', []),
                    'confidence': metadata.get('confidence', 'MEDIUM'),
                    'code_snippet': None
                })

    except Exception as e:
        error_msg = f"Quick Semgrep error: {str(e)}"
        logger.error(error_msg)

    return vulnerabilities, error_msg