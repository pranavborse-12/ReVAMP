"""
Production background scanning with multi-scanner engine
FIXED: Now properly stores to database via ScanStorageManager
"""
import os
import shutil
import tempfile
import threading
from datetime import datetime
from typing import Optional, Dict, Any

from .config import logger, MAX_REPO_SIZE_MB
from .utils import (
    detect_languages,
    calculate_severity_summary,
    clone_github_repo,
    get_dir_size
)
from .scanner_core import VulnerabilityScanner
from .storage import save_scan_to_db, complete_scan_in_db, update_scan_status_in_db, mark_scan_failed_in_db

# ─────────────────────────────────────────────────────────────
# Thread-safe global state (in-memory tracking for backward compatibility)
# ─────────────────────────────────────────────────────────────
_lock = threading.Lock()
_scan_results: Dict[str, Dict[str, Any]] = {}
_active_scans = 0


# ─────────────────────────────────────────────────────────────
# Main background scan task - FIXED VERSION WITH DATABASE STORAGE
# ─────────────────────────────────────────────────────────────
async def perform_scan(
    scan_id: str,
    user_id: str,
    github_token: str,
    repo_owner: str,
    repo_name: str,
    branch: str,
    semgrep_token: Optional[str],
    scanner_choice: str,
    max_files: int
):
    """
    Production scan task with proper database persistence
    FIXED: Now uses database storage for all state updates
    """
    global _active_scans

    temp_dir = None
    start_time = datetime.now()

    try:
        logger.info(f"[{scan_id}] 🚀 Starting scan for {repo_owner}/{repo_name}")
        logger.info(f"[{scan_id}] User: {user_id}, Branch: {branch}, Scanner: {scanner_choice}")
        
        # ══════════════════════════════════════════════════════════
        # STEP 1: INITIALIZE IN DATABASE
        # ══════════════════════════════════════════════════════════
        db_saved = await save_scan_to_db(
            scan_id=scan_id,
            user_id=user_id,
            repo_owner=repo_owner,
            repo_name=repo_name,
            branch=branch,
            scanner_mode=scanner_choice
        )
        
        if db_saved:
            logger.info(f"[{scan_id}] ✅ Scan initialized in database")
        else:
            logger.warning(f"[{scan_id}] ⚠️ Database save failed, using memory only")
        
        # Also update in-memory state for backward compatibility
        with _lock:
            _active_scans += 1
            _scan_results[scan_id] = {
                'scan_id': scan_id,
                'user_id': user_id,
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
                'started_at': start_time.isoformat(),
                'completed_at': None
            }

        # ══════════════════════════════════════════════════════════
        # STEP 2: UPDATE STATUS - CLONING
        # ══════════════════════════════════════════════════════════
        await update_scan_status_in_db(scan_id, 'cloning', started_at=start_time)
        
        with _lock:
            _scan_results[scan_id]['status'] = 'cloning'
        
        logger.info(f"[{scan_id}] 📥 Cloning repository...")

        # Clone repository
        temp_dir = tempfile.mkdtemp(prefix="scanner_")
        success, message = await clone_github_repo(
            github_token,
            repo_owner,
            repo_name,
            branch,
            temp_dir
        )

        if not success:
            raise RuntimeError(f"Clone failed: {message}")

        # Size validation
        repo_size_mb = get_dir_size(temp_dir) / (1024 * 1024)
        if repo_size_mb > MAX_REPO_SIZE_MB:
            raise RuntimeError(
                f"Repository too large: {repo_size_mb:.1f} MB "
                f"(max: {MAX_REPO_SIZE_MB} MB)"
            )
        
        logger.info(f"[{scan_id}] ✅ Repository cloned ({repo_size_mb:.2f} MB)")

        # ══════════════════════════════════════════════════════════
        # STEP 3: UPDATE STATUS - ANALYZING
        # ══════════════════════════════════════════════════════════
        await update_scan_status_in_db(scan_id, 'analyzing')
        
        with _lock:
            _scan_results[scan_id]['status'] = 'analyzing'

        # Detect languages
        languages = detect_languages(temp_dir, max_files=max_files)
        logger.info(f"[{scan_id}] 🔍 Languages detected: {languages}")

        # ══════════════════════════════════════════════════════════
        # STEP 4: UPDATE STATUS - SCANNING
        # ══════════════════════════════════════════════════════════
        await update_scan_status_in_db(scan_id, 'scanning')
        
        with _lock:
            _scan_results[scan_id]['status'] = 'scanning'
        
        logger.info(f"[{scan_id}] 🔎 Running vulnerability scanner...")

        # Run vulnerability scanner
        scanner = VulnerabilityScanner(temp_dir, languages)
        vulnerabilities, error_msg = scanner.scan(use_cache=False)

        # Calculate results
        severity = calculate_severity_summary(vulnerabilities)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        severity_dict = {
            'critical': severity.critical,
            'high': severity.high,
            'medium': severity.medium,
            'low': severity.low,
            'info': severity.info,
            'warning': severity.warning
        }
        
        logger.info(f"[{scan_id}] 📊 Scan completed: {len(vulnerabilities)} vulnerabilities found")
        logger.info(f"[{scan_id}] 📊 Severity: {severity.critical}C/{severity.high}H/{severity.medium}M/{severity.low}L")

        # ══════════════════════════════════════════════════════════
        # STEP 5: SAVE TO DATABASE - CRITICAL PART
        # ══════════════════════════════════════════════════════════
        logger.info(f"[{scan_id}] 💾 Saving results to database...")
        
        db_completed = await complete_scan_in_db(
            scan_id=scan_id,
            vulnerabilities=vulnerabilities,
            scanner_used=scanner_choice,
            languages=list(languages),
            duration=round(duration, 2),
            size_mb=round(repo_size_mb, 2),
            files=max_files
        )
        
        if db_completed:
            logger.info(f"[{scan_id}] ✅ Results saved to database successfully")
        else:
            logger.warning(f"[{scan_id}] ⚠️ Database save failed, results in memory only")

        # Update in-memory state
        with _lock:
            _scan_results[scan_id].update({
                'status': 'completed',
                'vulnerabilities': vulnerabilities,
                'scanner_used': scanner_choice,
                'total_issues': len(vulnerabilities),
                'severity_summary': severity_dict,
                'detected_languages': list(languages),
                'error_message': error_msg,
                'scan_duration': round(duration, 2),
                'completed_at': end_time.isoformat(),
                'repo_size_mb': round(repo_size_mb, 2)
            })

        logger.info(f"[{scan_id}] ✅ Scan complete ({duration:.2f}s)")

    except Exception as e:
        error_msg = f"Scan failed: {str(e)}"
        logger.error(f"[{scan_id}] ❌ {error_msg}", exc_info=True)

        # Mark as failed in database
        await mark_scan_failed_in_db(
            scan_id=scan_id,
            error_message=error_msg,
            error_code="SCAN_ERROR"
        )

        # Update in-memory state
        with _lock:
            if scan_id in _scan_results:
                _scan_results[scan_id].update({
                    'status': 'failed',
                    'error_message': error_msg,
                    'completed_at': datetime.now().isoformat()
                })

    finally:
        with _lock:
            _active_scans = max(0, _active_scans - 1)

        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"[{scan_id}] 🧹 Temp directory cleaned")
            except Exception as e:
                logger.error(f"[{scan_id}] ⚠️ Cleanup error: {e}")


# ─────────────────────────────────────────────────────────────
# Public helpers (maintain backward compatibility)
# ─────────────────────────────────────────────────────────────

def initialize_scan(scan_id: str, repo_owner: str, repo_name: str, user_id: Optional[str] = None) -> None:
    """Create in-memory entry for a new scan (for backward compatibility)"""
    with _lock:
        if scan_id in _scan_results:
            logger.warning(f"[{scan_id}] initialize_scan called but scan already exists")
            return

        _scan_results[scan_id] = {
            'scan_id': scan_id,
            'user_id': user_id,
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
            'completed_at': None,
            'queued_at': datetime.utcnow().isoformat()
        }
        logger.info(f"[{scan_id}] Initialized in-memory state")


def get_scan_result(scan_id: str) -> Optional[Dict[str, Any]]:
    """Get scan from in-memory state"""
    with _lock:
        return _scan_results.get(scan_id)


def get_all_scan_results() -> Dict[str, Dict[str, Any]]:
    """Get all scans from in-memory state"""
    with _lock:
        return dict(_scan_results)


def get_user_scans(user_id: str) -> Dict[str, Dict[str, Any]]:
    """Return only scans belonging to a user"""
    with _lock:
        return {
            k: v for k, v in _scan_results.items()
            if v.get('user_id') == user_id
        }


def get_active_scans() -> int:
    """Get count of active scans"""
    with _lock:
        return _active_scans


def delete_scan(scan_id: str) -> bool:
    """Delete scan from in-memory state"""
    with _lock:
        return _scan_results.pop(scan_id, None) is not None