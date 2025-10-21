"""
CodeQL scanner implementation with optimizations
"""
import os
import json
import shutil
from typing import Tuple, List, Set
from .config import (
    logger,
    CODEQL_DB_TIMEOUT,
    CODEQL_ANALYZE_TIMEOUT,
    CODEQL_LANGUAGES
)
from .utils import (
    run_command_with_timeout,
    normalize_severity,
    extract_vulnerability_type
)


def run_codeql_scan(repo_path: str, languages: Set[str]) -> Tuple[List[dict], str]:
    """
    Run optimized CodeQL scan with better vulnerability classification
    Returns: (vulnerabilities: list, error_message: str)
    """
    vulnerabilities = []
    error_msg = ""

    try:
        logger.info("Starting CodeQL scan...")

        returncode, stdout, stderr = run_command_with_timeout(['codeql', '--version'], 10)
        if returncode != 0:
            return [], "CodeQL not installed"

        logger.info(f"CodeQL version: {stdout.strip().split()[0] if stdout else 'unknown'}")

        supported_langs = languages.intersection(CODEQL_LANGUAGES)

        if not supported_langs:
            return [], "No CodeQL-supported languages detected"

        if len(supported_langs) > 2:
            priority = ['java', 'cpp', 'csharp', 'python', 'javascript']
            supported_langs = set(sorted(
                supported_langs,
                key=lambda x: priority.index(x) if x in priority else 99
            )[:2])

        logger.info(f"CodeQL scanning languages: {supported_langs}")

        db_path = os.path.join(repo_path, '.codeql-db')
        os.makedirs(db_path, exist_ok=True)

        for lang in supported_langs:
            try:
                logger.info(f"Creating CodeQL database for {lang}...")
                db_lang_path = os.path.join(db_path, lang)

                create_cmd = [
                    'codeql', 'database', 'create',
                    db_lang_path,
                    f'--language={lang}',
                    f'--source-root={repo_path}',
                    '--overwrite',
                    '--threads=2'
                ]

                returncode, stdout, stderr = run_command_with_timeout(
                    create_cmd, CODEQL_DB_TIMEOUT, cwd=repo_path
                )

                if returncode != 0:
                    logger.warning(f"Failed to create database for {lang}: {stderr}")
                    continue

                logger.info(f"Analyzing {lang} with CodeQL...")

                sarif_output = os.path.join(db_path, f'{lang}_results.sarif')
                analyze_cmd = [
                    'codeql', 'database', 'analyze',
                    db_lang_path,
                    f'{lang}-security-extended',
                    '--format=sarif-latest',
                    f'--output={sarif_output}',
                    '--threads=2',
                    '--ram=2048'
                ]

                returncode, stdout, stderr = run_command_with_timeout(
                    analyze_cmd, CODEQL_ANALYZE_TIMEOUT
                )

                if returncode != 0:
                    logger.warning(f"CodeQL analysis failed for {lang}: {stderr}")
                    continue

                lang_vulns = _parse_sarif_results(sarif_output, repo_path)
                vulnerabilities.extend(lang_vulns)

                logger.info(f"CodeQL found {len(lang_vulns)} issues in {lang}")

                if os.path.exists(db_lang_path):
                    shutil.rmtree(db_lang_path, ignore_errors=True)

            except Exception as e:
                logger.error(f"CodeQL error for {lang}: {str(e)}")
                error_msg += f"Error scanning {lang}: {str(e)}; "

        if os.path.exists(db_path):
            shutil.rmtree(db_path, ignore_errors=True)

    except Exception as e:
        error_msg = f"CodeQL error: {str(e)}"
        logger.error(error_msg)

    return vulnerabilities, error_msg


def _parse_sarif_results(sarif_output: str, repo_path: str) -> List[dict]:
    """Parse SARIF results from CodeQL"""
    vulnerabilities = []

    if not os.path.exists(sarif_output):
        return vulnerabilities

    try:
        with open(sarif_output, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)

        for run in sarif_data.get('runs', []):
            rules = {}
            for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
                rule_id = rule.get('id', '')
                rules[rule_id] = {
                    'name': rule.get('name', ''),
                    'description': rule.get('shortDescription', {}).get('text', ''),
                    'help': rule.get('help', {}).get('text', ''),
                    'properties': rule.get('properties', {})
                }

            for result_item in run.get('results', []):
                rule_id = result_item.get('ruleId', 'unknown')
                message = result_item.get('message', {}).get('text', '')
                level = result_item.get('level', 'note')

                severity_map = {
                    'error': 'HIGH',
                    'warning': 'MEDIUM',
                    'note': 'LOW',
                    'none': 'INFO'
                }
                base_severity = severity_map.get(level, 'MEDIUM')

                cwe_list = []
                properties = result_item.get('properties', {})
                tags = properties.get('tags', [])

                for tag in tags:
                    if 'cwe' in tag.lower() and 'cwe-' in tag.lower():
                        cwe_num = tag.split('cwe-')[1].split('/')[0].upper()
                        cwe_list.append(f'CWE-{cwe_num}')

                if rule_id in rules:
                    rule_props = rules[rule_id].get('properties', {})
                    rule_tags = rule_props.get('tags', [])
                    for tag in rule_tags:
                        if 'cwe' in tag.lower() and 'cwe-' in tag.lower():
                            cwe_num = tag.split('cwe-')[1].split('/')[0].upper()
                            if f'CWE-{cwe_num}' not in cwe_list:
                                cwe_list.append(f'CWE-{cwe_num}')

                severity = normalize_severity(base_severity, rule_id, cwe_list)
                vuln_type = extract_vulnerability_type(rule_id, message)

                locations = result_item.get('locations', [])
                if locations:
                    physical_location = locations[0].get('physicalLocation', {})
                    artifact_location = physical_location.get('artifactLocation', {})
                    region = physical_location.get('region', {})

                    file_path = artifact_location.get('uri', '')
                    start_line = region.get('startLine', 0)
                    end_line = region.get('endLine', start_line)
                    snippet = region.get('snippet', {}).get('text', '')

                    vulnerability = {
                        'scanner': 'CodeQL',
                        'rule_id': rule_id,
                        'severity': severity,
                        'message': message,
                        'vulnerability_type': vuln_type,
                        'location': {
                            'file': file_path,
                            'start_line': start_line,
                            'end_line': end_line,
                            'start_col': region.get('startColumn'),
                            'end_col': region.get('endColumn')
                        },
                        'cwe': cwe_list if cwe_list else None,
                        'owasp': [],
                        'confidence': 'HIGH',
                        'code_snippet': snippet[:500] if snippet else None
                    }
                    vulnerabilities.append(vulnerability)

    except Exception as e:
        logger.error(f"Error parsing SARIF results: {e}")

    return vulnerabilities


def determine_scanner(languages: Set[str], scanner_choice: str) -> Tuple[bool, bool]:
    """
    Determine which scanners to use based on choice and available tools
    Returns: (use_codeql: bool, use_semgrep: bool)
    """
    if scanner_choice == "semgrep":
        return False, True
    elif scanner_choice == "codeql":
        return True, False
    elif scanner_choice == "both":
        return True, True

    try:
        returncode, _, _ = run_command_with_timeout(['codeql', '--version'], 5)
        codeql_available = returncode == 0
    except:
        codeql_available = False

    if not codeql_available:
        logger.info("CodeQL not available, using Semgrep")
        return False, True

    codeql_preferred = {'java', 'cpp', 'csharp', 'go', 'swift', 'kotlin'}

    if languages.intersection(codeql_preferred):
        logger.info("Detected compiled languages, using both scanners")
        return True, True
    else:
        logger.info("Using Semgrep for faster scanning")
        return False, True