"""
Production background scanning with FIXED commit tracking
✅ Properly updates last_scan_commit_sha after successful scans
✅ Prevents race conditions
✅ Handles scan allowance correctly
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
from .storage import (
    save_scan_to_db, 
    complete_scan_in_db, 
    update_scan_status_in_db, 
    mark_scan_failed_in_db,
    update_repository_commit_tracking  # NEW: Dedicated function for commit updates
)

# Thread-safe global state
_lock = threading.Lock()
_scan_results: Dict[str, Dict[str, Any]] = {}
_active_scans = 0
_repo_locks: Dict[str, threading.Lock] = {}  # NEW: Per-repository locks


def get_repo_lock(repo_full_name: str) -> threading.Lock:
    """Get or create a lock for a specific repository"""
    with _lock:
        if repo_full_name not in _repo_locks:
            _repo_locks[repo_full_name] = threading.Lock()
        return _repo_locks[repo_full_name]


async def perform_scan(
    scan_id: str,
    user_id: str,
    github_token: str,
    repo_owner: str,
    repo_name: str,
    branch: str,
    semgrep_token: Optional[str],
    scanner_choice: str,
    max_files: int,
    current_commit_sha: str  # NEW: Pass the commit SHA that was checked
):
    """
    Production scan task with FIXED commit tracking
    ✅ Updates last_scan_commit_sha ONLY after successful completion
    ✅ Uses repository-level locks to prevent concurrent scans
    """
    global _active_scans

    repo_full_name = f"{repo_owner}/{repo_name}"
    temp_dir = None
    start_time = datetime.now()
    
    # ══════════════════════════════════════════════════════════
    # STEP 0: ACQUIRE REPOSITORY LOCK (Prevent concurrent scans)
    # ══════════════════════════════════════════════════════════
    repo_lock = get_repo_lock(repo_full_name)
    
    if not repo_lock.acquire(blocking=False):
        # Another scan is already running for this repo
        error_msg = f"A scan is already in progress for {repo_full_name}"
        logger.warning(f"[{scan_id}] {error_msg}")
        
        await mark_scan_failed_in_db(
            scan_id=scan_id,
            error_message=error_msg,
            error_code="SCAN_IN_PROGRESS"
        )
        
        with _lock:
            if scan_id in _scan_results:
                _scan_results[scan_id].update({
                    'status': 'failed',
                    'error_message': error_msg,
                    'completed_at': datetime.now().isoformat()
                })
        return

    try:
        logger.info(f"[{scan_id}] 🔒 Repository lock acquired for {repo_full_name}")
        
        # ══════════════════════════════════════════════════════════
        # STEP 1: INITIALIZE IN DATABASE
        # ══════════════════════════════════════════════════════════
        db_saved = await save_scan_to_db(
            scan_id=scan_id,
            user_id=user_id,
            repo_owner=repo_owner,
            repo_name=repo_name,
            branch=branch,
            scanner_mode=scanner_choice,
            commit_sha=current_commit_sha  # Store the commit SHA we're scanning
        )
        
        if db_saved:
            logger.info(f"[{scan_id}] ✅ Scan initialized in database")
        else:
            logger.warning(f"[{scan_id}] ⚠️ Database save failed, using memory only")
        
        # Update in-memory state
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
                'completed_at': None,
                'commit_sha': current_commit_sha
            }

        # ══════════════════════════════════════════════════════════
        # STEP 2: CLONE REPOSITORY
        # ══════════════════════════════════════════════════════════
        await update_scan_status_in_db(scan_id, 'cloning', started_at=start_time)
        
        with _lock:
            _scan_results[scan_id]['status'] = 'cloning'
        
        logger.info(f"[{scan_id}] 📥 Cloning repository...")

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

        repo_size_mb = get_dir_size(temp_dir) / (1024 * 1024)
        if repo_size_mb > MAX_REPO_SIZE_MB:
            raise RuntimeError(
                f"Repository too large: {repo_size_mb:.1f} MB "
                f"(max: {MAX_REPO_SIZE_MB} MB)"
            )
        
        logger.info(f"[{scan_id}] ✅ Repository cloned ({repo_size_mb:.2f} MB)")

        # ══════════════════════════════════════════════════════════
        # STEP 3: ANALYZE LANGUAGES
        # ══════════════════════════════════════════════════════════
        await update_scan_status_in_db(scan_id, 'analyzing')
        
        with _lock:
            _scan_results[scan_id]['status'] = 'analyzing'

        languages = detect_languages(temp_dir, max_files=max_files)
        logger.info(f"[{scan_id}] 🔍 Languages detected: {languages}")

        # ══════════════════════════════════════════════════════════
        # STEP 4: SCAN FOR VULNERABILITIES
        # ══════════════════════════════════════════════════════════
        await update_scan_status_in_db(scan_id, 'scanning')
        
        with _lock:
            _scan_results[scan_id]['status'] = 'scanning'
        
        logger.info(f"[{scan_id}] 🔎 Running vulnerability scanner...")

        scanner = VulnerabilityScanner(temp_dir, languages)
        vulnerabilities, error_msg = scanner.scan(use_cache=False)

        # ✅ FIX: Normalize vulnerability structure
        # Scanners return data with a nested 'location' dict.
        # The frontend expects flat top-level fields: file_path, start_line, etc.
        # Without this, file_path is empty and search by filename doesn't work.
        normalized = []
        for v in vulnerabilities:
            loc = v.get('location', {})
            normalized.append({
                **v,
                'file_path':    v.get('file_path') or loc.get('file', ''),
                'start_line':   v.get('start_line') or loc.get('start_line', 0),
                'end_line':     v.get('end_line') or loc.get('end_line', 0),
                'start_column': v.get('start_column') or loc.get('start_column', 0),
                'code_snippet': (
                    v.get('code_snippet') or
                    loc.get('code_snippet') or
                    v.get('snippet', '')
                ),
            })
        vulnerabilities = normalized
        logger.info(f"[{scan_id}] ✅ Normalized {len(vulnerabilities)} vulnerabilities (file_path mapped)")

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
        # STEP 5: SAVE TO DATABASE (ATOMIC TRANSACTION)
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
            
            # ══════════════════════════════════════════════════════════
            # STEP 6: UPDATE COMMIT TRACKING (CRITICAL FIX)
            # ══════════════════════════════════════════════════════════
            # This must happen AFTER the scan completes successfully
            try:
                commit_updated = await update_repository_commit_tracking(
                    user_id=user_id,
                    repo_owner=repo_owner,
                    repo_name=repo_name,
                    commit_sha=current_commit_sha,
                    consume_allowance=True  # Consume one scan from allowance
                )
                
                if commit_updated:
                    logger.info(
                        f"[{scan_id}] ✅ Updated last_scan_commit_sha to {current_commit_sha[:7]}"
                    )
                else:
                    logger.warning(
                        f"[{scan_id}] ⚠️ Failed to update commit tracking"
                    )
            except Exception as commit_err:
                logger.error(
                    f"[{scan_id}] ❌ Commit tracking update failed: {commit_err}",
                    exc_info=True
                )
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

        await mark_scan_failed_in_db(
            scan_id=scan_id,
            error_message=error_msg,
            error_code="SCAN_ERROR"
        )

        with _lock:
            if scan_id in _scan_results:
                _scan_results[scan_id].update({
                    'status': 'failed',
                    'error_message': error_msg,
                    'completed_at': datetime.now().isoformat()
                })

    finally:
        # ══════════════════════════════════════════════════════════
        # CLEANUP: Release lock and clean temp directory
        # ══════════════════════════════════════════════════════════
        with _lock:
            _active_scans = max(0, _active_scans - 1)
        
        # Release repository lock
        repo_lock.release()
        logger.info(f"[{scan_id}] 🔓 Repository lock released for {repo_full_name}")

        if temp_dir and os.path.exists(temp_dir):
            VulnerabilityScanner.remove_temp_dir(temp_dir)
            logger.info(f"[{scan_id}] 🧹 Temp directory cleaned")


# ─────────────────────────────────────────────────────────────
# Public helpers (maintain backward compatibility)
# ─────────────────────────────────────────────────────────────

def initialize_scan(
    scan_id: str, 
    repo_owner: str, 
    repo_name: str, 
    user_id: Optional[str] = None, 
    branch: str = "main"
) -> None:
    """Create in-memory entry for a new scan"""
    with _lock:
        if scan_id in _scan_results:
            logger.warning(f"[{scan_id}] Scan already exists")
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
            'queued_at': datetime.utcnow().isoformat(),
            'branch': branch
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