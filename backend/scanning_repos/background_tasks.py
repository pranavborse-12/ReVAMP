"""
Background scanning task implementation with thread safety
Integrates with GitHub authentication
"""
import os
import shutil
import tempfile
import threading
from datetime import datetime
from typing import Optional, Dict, Any
from .config import logger
from .utils import detect_languages, calculate_severity_summary, clone_github_repo
from .scanner_semgrep import run_semgrep_scan
from .scanner_codeql import run_codeql_scan, determine_scanner

# Thread-safe global state
_lock = threading.Lock()
_scan_results: Dict[str, Dict[str, Any]] = {}
_active_scans = 0


async def perform_scan(
    scan_id: str,
    github_token: str,
    repo_owner: str,
    repo_name: str,
    branch: str,
    semgrep_token: Optional[str],
    scanner_choice: str,
    max_files: int
):
    """Background scan task with GitHub integration"""
    global _active_scans
    temp_dir = None
    start_time = datetime.now()

    try:
        with _lock:
            _active_scans += 1
            if scan_id not in _scan_results:
                logger.error(f"[{scan_id}] Scan not found in results!")
                return

        logger.info(f"[{scan_id}] Starting scan for {repo_owner}/{repo_name}")

        with _lock:
            _scan_results[scan_id].update({
                'status': 'cloning',
                'started_at': start_time.isoformat()
            })

        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix="scanner_")
        logger.info(f"[{scan_id}] Temp directory: {temp_dir}")

        # Clone repository using GitHub token
        success, message = await clone_github_repo(
            github_token,
            repo_owner,
            repo_name,
            branch,
            temp_dir
        )

        if not success:
            with _lock:
                _scan_results[scan_id].update({
                    'status': 'failed',
                    'error_message': message,
                    'completed_at': datetime.now().isoformat()
                })
            logger.error(f"[{scan_id}] Clone failed: {message}")
            return

        with _lock:
            _scan_results[scan_id]['status'] = 'analyzing'

        # Detect languages
        languages = detect_languages(temp_dir, max_files)
        logger.info(f"[{scan_id}] Detected languages: {languages}")

        # Determine scanners
        use_codeql, use_semgrep = determine_scanner(languages, scanner_choice)
        logger.info(f"[{scan_id}] Scanners - CodeQL: {use_codeql}, Semgrep: {use_semgrep}")

        with _lock:
            _scan_results[scan_id]['status'] = 'scanning'

        vulnerabilities = []
        scanner_used = []
        errors = []

        # Run Semgrep
        if use_semgrep:
            logger.info(f"[{scan_id}] Running Semgrep...")
            with _lock:
                _scan_results[scan_id]['status'] = 'scanning_semgrep'

            semgrep_vulns, semgrep_error = run_semgrep_scan(temp_dir, semgrep_token)
            if semgrep_vulns:
                vulnerabilities.extend(semgrep_vulns)
                scanner_used.append('Semgrep')
                logger.info(f"[{scan_id}] Semgrep found {len(semgrep_vulns)} issues")
            if semgrep_error:
                errors.append(f"Semgrep: {semgrep_error}")

        # Run CodeQL
        if use_codeql:
            logger.info(f"[{scan_id}] Running CodeQL...")
            with _lock:
                _scan_results[scan_id]['status'] = 'scanning_codeql'

            codeql_vulns, codeql_error = run_codeql_scan(temp_dir, languages)
            if codeql_vulns:
                vulnerabilities.extend(codeql_vulns)
                scanner_used.append('CodeQL')
                logger.info(f"[{scan_id}] CodeQL found {len(codeql_vulns)} issues")
            if codeql_error:
                errors.append(f"CodeQL: {codeql_error}")

        # Calculate results
        severity_summary = calculate_severity_summary(vulnerabilities)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        severity_dict = {
            'critical': severity_summary.critical,
            'high': severity_summary.high,
            'medium': severity_summary.medium,
            'low': severity_summary.low,
            'info': severity_summary.info,
            'warning': severity_summary.warning
        }

        # Final update
        with _lock:
            _scan_results[scan_id].update({
                'status': 'completed',
                'vulnerabilities': vulnerabilities,
                'scanner_used': ' + '.join(scanner_used) if scanner_used else 'None',
                'total_issues': len(vulnerabilities),
                'severity_summary': severity_dict,
                'detected_languages': list(languages),
                'error_message': '; '.join(errors) if errors else None,
                'scan_duration': round(duration, 2),
                'completed_at': end_time.isoformat()
            })

        logger.info(f"[{scan_id}] Scan completed in {duration:.2f}s with {len(vulnerabilities)} issues")

    except Exception as e:
        error_msg = f"Scan failed: {str(e)}"
        logger.error(f"[{scan_id}] {error_msg}", exc_info=True)
        with _lock:
            if scan_id in _scan_results:
                _scan_results[scan_id].update({
                    'status': 'failed',
                    'error_message': error_msg,
                    'completed_at': datetime.now().isoformat()
                })
    finally:
        with _lock:
            _active_scans -= 1

        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"[{scan_id}] Cleaned up temp directory")
            except Exception as e:
                logger.error(f"[{scan_id}] Cleanup error: {str(e)}")


def initialize_scan(scan_id: str, repo_owner: str, repo_name: str) -> None:
    """Initialize a scan in the global results dictionary"""
    with _lock:
        _scan_results[scan_id] = {
            'scan_id': scan_id,
            'repo_owner': repo_owner,
            'repo_name': repo_name,
            'repo_url': f"https://github.com/{repo_owner}/{repo_name}",
            'status': 'queued',
            'vulnerabilities': [],
            'scanner_used': '',
            'total_issues': 0,
            'severity_summary': None,
            'detected_languages': [],
            'error_message': None,
            'scan_duration': None,
            'started_at': None,
            'completed_at': None
        }


def get_scan_result(scan_id: str) -> Optional[Dict[str, Any]]:
    """Thread-safe getter for a specific scan result"""
    with _lock:
        return _scan_results.get(scan_id)


def get_all_scan_results() -> Dict[str, Dict[str, Any]]:
    """Thread-safe getter for all scan results"""
    with _lock:
        return dict(_scan_results)


def get_user_scans(email: str) -> Dict[str, Dict[str, Any]]:
    """Get all scans for a specific user (by email)"""
    with _lock:
        # This would be enhanced with user tracking in production
        return dict(_scan_results)


def get_active_scans() -> int:
    """Thread-safe getter for active scans count"""
    with _lock:
        return _active_scans


def delete_scan(scan_id: str) -> bool:
    """Thread-safe deletion of scan result"""
    with _lock:
        if scan_id in _scan_results:
            del _scan_results[scan_id]
            return True
        return False