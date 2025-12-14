"""
Production background scanning with multi-scanner engine
"""
import os
import shutil
import tempfile
import threading
from datetime import datetime
from typing import Optional, Dict, Any
from .config import logger, MAX_REPO_SIZE_MB
from .utils import detect_languages, calculate_severity_summary, clone_github_repo, get_dir_size
from .scanner_core import VulnerabilityScanner

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
    """
    Production scan with multi-scanner engine
    """
    global _active_scans
    temp_dir = None
    start_time = datetime.now()

    try:
        with _lock:
            _active_scans += 1
            if scan_id not in _scan_results:
                logger.error(f"[{scan_id}] Scan not found!")
                return

        logger.info(f"[{scan_id}] 🚀 Starting production scan for {repo_owner}/{repo_name}")

        with _lock:
            _scan_results[scan_id].update({
                'status': 'cloning',
                'started_at': start_time.isoformat()
            })

        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix="scanner_")
        logger.info(f"[{scan_id}] 📁 Temp: {temp_dir}")

        # Clone repository
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
            logger.error(f"[{scan_id}] ❌ Clone failed: {message}")
            return

        # Check size
        repo_size_mb = get_dir_size(temp_dir) / (1024 * 1024)
        if repo_size_mb > MAX_REPO_SIZE_MB:
            error_msg = f"Repository too large: {repo_size_mb:.1f} MB (max: {MAX_REPO_SIZE_MB} MB)"
            with _lock:
                _scan_results[scan_id].update({
                    'status': 'failed',
                    'error_message': error_msg,
                    'completed_at': datetime.now().isoformat()
                })
            logger.error(f"[{scan_id}] ❌ {error_msg}")
            return

        with _lock:
            _scan_results[scan_id]['status'] = 'analyzing'

        # Detect languages
        languages = detect_languages(temp_dir, max_files=2000)
        logger.info(f"[{scan_id}] 🔍 Languages: {languages}")

        with _lock:
            _scan_results[scan_id]['status'] = 'scanning'

        # Use multi-scanner engine
        scanner = VulnerabilityScanner(temp_dir, languages)
        vulnerabilities, error_msg = scanner.scan(use_cache=False)

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
                'scanner_used': 'Multi-Scanner Engine',
                'total_issues': len(vulnerabilities),
                'severity_summary': severity_dict,
                'detected_languages': list(languages),
                'error_message': error_msg if error_msg else None,
                'scan_duration': round(duration, 2),
                'completed_at': end_time.isoformat(),
                'repo_size_mb': round(repo_size_mb, 2)
            })

        logger.info(f"[{scan_id}] ✅ Complete in {duration:.2f}s: {len(vulnerabilities)} issues")
        logger.info(f"[{scan_id}] 📊 Severity: {severity_dict}")

    except Exception as e:
        error_msg = f"Scan failed: {str(e)}"
        logger.error(f"[{scan_id}] ❌ {error_msg}", exc_info=True)
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
                logger.info(f"[{scan_id}] 🧹 Cleaned up")
            except Exception as e:
                logger.error(f"[{scan_id}] ⚠️ Cleanup error: {e}")


def initialize_scan(scan_id: str, repo_owner: str, repo_name: str) -> None:
    """Initialize scan"""
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
            'repo_size_mb': None,
            'started_at': None,
            'completed_at': None
        }


def get_scan_result(scan_id: str) -> Optional[Dict[str, Any]]:
    """Get scan result"""
    with _lock:
        return _scan_results.get(scan_id)


def get_all_scan_results() -> Dict[str, Dict[str, Any]]:
    """Get all results"""
    with _lock:
        return dict(_scan_results)


def get_user_scans(email: str) -> Dict[str, Dict[str, Any]]:
    """Get user scans"""
    with _lock:
        return dict(_scan_results)


def get_active_scans() -> int:
    """Get active count"""
    with _lock:
        return _active_scans


def delete_scan(scan_id: str) -> bool:
    """Delete scan"""
    with _lock:
        if scan_id in _scan_results:
            del _scan_results[scan_id]
            return True
        return False