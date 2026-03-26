"""
Production background scanning with incremental scan support.

Incremental scan flow:
  1. Fetch last_scan_commit_sha from DB (the commit scanned previously)
  2. Call GitHub Compare API to get changed files between old and new SHA
  3. If diff is small enough (≤300 files):
       a. Run scanner.scan(changed_files=diff) — scanners touch only those files
       b. Load previous findings from DB
       c. Merge: keep old findings for unchanged files, replace for changed files
  4. If diff is too large OR no previous scan: fall back to full scan
  5. Always store the complete merged result set in DB

✅ Properly updates last_scan_commit_sha after successful scans
✅ Prevents race conditions via per-repository locks
✅ Handles scan allowance correctly
"""
import os
import shutil
import tempfile
import threading
from datetime import datetime
from typing import Optional, Dict, Any, Set

from .config import logger, MAX_REPO_SIZE_MB
from .utils import (
    detect_languages,
    calculate_severity_summary,
    clone_github_repo,
    get_dir_size,
)
from .scanner_core import VulnerabilityScanner
from .storage import (
    save_scan_to_db,
    complete_scan_in_db,
    update_scan_status_in_db,
    mark_scan_failed_in_db,
    update_repository_commit_tracking,
)
from .incremental_scanning import (
    IncrementalEngine,
    get_previous_scan_vulnerabilities,
)
from .config import LANGUAGE_EXTENSIONS

# Thread-safe global state
_lock = threading.Lock()
_scan_results: Dict[str, Dict[str, Any]] = {}
_active_scans = 0
_repo_locks: Dict[str, threading.Lock] = {}   # per-repository locks


def get_repo_lock(repo_full_name: str) -> threading.Lock:
    """Get or create a lock for a specific repository."""
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
    current_commit_sha: str,
    last_scan_commit_sha: Optional[str] = None,   # ← NEW: passed from routes.py
):
    """
    Production scan task with incremental scanning support.

    When last_scan_commit_sha is provided and differs from current_commit_sha:
      - GitHub Compare API fetches the changed files
      - Only changed files are scanned
      - Previous findings for unchanged files are reused from DB

    Falls back to full scan if:
      - No previous scan exists (last_scan_commit_sha is None)
      - Diff has > 300 files
      - GitHub Compare API fails for any reason
    """
    global _active_scans

    repo_full_name = f"{repo_owner}/{repo_name}"
    temp_dir = None
    start_time = datetime.now()

    # ══════════════════════════════════════════════════════════
    # STEP 0: ACQUIRE REPOSITORY LOCK
    # ══════════════════════════════════════════════════════════
    repo_lock = get_repo_lock(repo_full_name)

    if not repo_lock.acquire(blocking=False):
        error_msg = f"A scan is already in progress for {repo_full_name}"
        logger.warning(f"[{scan_id}] {error_msg}")

        await mark_scan_failed_in_db(
            scan_id=scan_id,
            error_message=error_msg,
            error_code="SCAN_IN_PROGRESS",
        )

        with _lock:
            if scan_id in _scan_results:
                _scan_results[scan_id].update({
                    "status": "failed",
                    "error_message": error_msg,
                    "completed_at": datetime.now().isoformat(),
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
            commit_sha=current_commit_sha,
        )

        if db_saved:
            logger.info(f"[{scan_id}] ✅ Scan initialized in database")
        else:
            logger.warning(f"[{scan_id}] ⚠️ Database save failed, using memory only")

        with _lock:
            _active_scans += 1
            _scan_results[scan_id] = {
                "scan_id": scan_id,
                "user_id": user_id,
                "repo_owner": repo_owner,
                "repo_name": repo_name,
                "repo_url": f"https://github.com/{repo_owner}/{repo_name}",
                "status": "queued",
                "vulnerabilities": [],
                "scanner_used": "",
                "total_issues": 0,
                "severity_summary": None,
                "detected_languages": [],
                "error_message": None,
                "scan_duration": None,
                "repo_size_mb": None,
                "started_at": start_time.isoformat(),
                "completed_at": None,
                "commit_sha": current_commit_sha,
                # Incremental metadata — populated below
                "is_incremental": False,
                "files_scanned": None,
                "files_skipped": None,
                "changed_files_count": None,
            }

        # ══════════════════════════════════════════════════════════
        # STEP 2: DETERMINE SCAN STRATEGY
        # ══════════════════════════════════════════════════════════
        incremental_engine = IncrementalEngine(github_token)

        # PATH 2 SAFETY NET:
        # routes.py should have intercepted same-commit scans before launching
        # this task. But if a force=True scan arrives with identical SHAs,
        # we still do a full scan (which is the correct behaviour for force).
        # We only skip scanning here if we ALSO have no last_scan_commit_sha
        # difference — that case is caught in routes.py already.

        diff = await incremental_engine.get_changed_files(
            owner=repo_owner,
            repo=repo_name,
            base_sha=last_scan_commit_sha or "",
            head_sha=current_commit_sha,
            branch=branch,
        )

        strategy = "incremental" if diff.is_incremental else "full"
        if not diff.is_incremental and diff.fallback_reason:
            logger.info(f"[{scan_id}] Full scan reason: {diff.fallback_reason}")

        logger.info(
            f"[{scan_id}] Scan strategy: {strategy.upper()} "
            f"({'%d files' % len(diff.changed_files) if diff.is_incremental else 'whole repo'})"
        )

        # ══════════════════════════════════════════════════════════
        # STEP 3: CLONE REPOSITORY
        # ══════════════════════════════════════════════════════════
        await update_scan_status_in_db(scan_id, "cloning", started_at=start_time)
        with _lock:
            _scan_results[scan_id]["status"] = "cloning"

        logger.info(f"[{scan_id}] 📥 Cloning repository...")

        temp_dir = tempfile.mkdtemp(prefix="scanner_")
        success, message = await clone_github_repo(
            github_token,
            repo_owner,
            repo_name,
            branch,
            temp_dir,
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
        # STEP 4: ANALYZE LANGUAGES
        # ══════════════════════════════════════════════════════════
        await update_scan_status_in_db(scan_id, "analyzing")
        with _lock:
            _scan_results[scan_id]["status"] = "analyzing"

        languages = detect_languages(temp_dir, max_files=max_files)
        logger.info(f"[{scan_id}] 🔍 Languages detected: {languages}")

        # ══════════════════════════════════════════════════════════
        # STEP 5: SCAN FOR VULNERABILITIES
        # ══════════════════════════════════════════════════════════
        await update_scan_status_in_db(scan_id, "scanning")
        with _lock:
            _scan_results[scan_id]["status"] = "scanning"

        scanner = VulnerabilityScanner(temp_dir, languages)

        if diff.is_incremental:
            # ── PATH 3: INCREMENTAL ───────────────────────────────
            logger.info(
                f"[{scan_id}] 🔎 Incremental scan: "
                f"{len(diff.changed_files)} changed files"
            )

            # Run scanners on changed files only.
            # VulnerabilityScanner.scan(changed_files=...) routes each
            # scanner to its scan_files() method.
            # SemgrepScanner.scan_files() detects languages per-file
            # and loads ONLY the relevant master files — not the full set.
            fresh_vulns, error_msg = scanner.scan(
                use_cache=False,
                changed_files=diff.changed_files,
            )

            # Load previous findings from DB for unchanged files
            previous_vulns = await get_previous_scan_vulnerabilities(
                user_id=user_id,
                repo_owner=repo_owner,
                repo_name=repo_name,
            )

            # Merge: fresh results for changed files + old results for the rest
            inc_result = incremental_engine.merge_findings(
                fresh_findings=fresh_vulns,
                previous_findings=previous_vulns,
                changed_files=diff.changed_files,
                repo_path=temp_dir,
            )

            vulnerabilities = inc_result.vulnerabilities
            is_incremental = True
            files_scanned = inc_result.files_scanned
            files_skipped = inc_result.files_skipped

            logger.info(
                f"[{scan_id}] 📊 Incremental result: "
                f"{len(fresh_vulns)} fresh + {len(previous_vulns) - files_skipped} evicted "
                f"+ {files_skipped} retained = {len(vulnerabilities)} total"
            )

        else:
            # ── PATH 1: FULL SCAN ─────────────────────────────────
            logger.info(f"[{scan_id}] 🔎 Full scan (PATH 1)...")
            vulnerabilities, error_msg = scanner.scan(use_cache=False)
            is_incremental = False
            files_scanned = None
            files_skipped = None

        """FIX: Normalize vulnerability structure
        Scanners return data with a nested 'location' dict.
        The frontend expects flat top-level fields: file_path, start_line, etc.
        Without this, file_path is empty and search by filename doesn't work."""

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
            "critical": severity.critical,
            "high": severity.high,
            "medium": severity.medium,
            "low": severity.low,
            "info": severity.info,
            "warning": severity.warning,
        }

        logger.info(
            f"[{scan_id}] 📊 Scan completed: {len(vulnerabilities)} vulnerabilities found"
        )
        logger.info(
            f"[{scan_id}] 📊 Severity: "
            f"{severity.critical}C/{severity.high}H/"
            f"{severity.medium}M/{severity.low}L"
        )

        # ══════════════════════════════════════════════════════════
        # STEP 6: SAVE TO DATABASE
        # ══════════════════════════════════════════════════════════
        logger.info(f"[{scan_id}] 💾 Saving results to database...")

        db_completed = await complete_scan_in_db(
            scan_id=scan_id,
            vulnerabilities=vulnerabilities,
            scanner_used=scanner_choice,
            languages=list(languages),
            duration=round(duration, 2),
            size_mb=round(repo_size_mb, 2),
            files=max_files,
        )

        if db_completed:
            logger.info(f"[{scan_id}] ✅ Results saved to database successfully")

            # ══════════════════════════════════════════════════════════
            # STEP 7: UPDATE COMMIT TRACKING
            # ══════════════════════════════════════════════════════════
            try:
                commit_updated = await update_repository_commit_tracking(
                    user_id=user_id,
                    repo_owner=repo_owner,
                    repo_name=repo_name,
                    commit_sha=current_commit_sha,
                    consume_allowance=True,
                )
                if commit_updated:
                    logger.info(
                        f"[{scan_id}] ✅ Updated last_scan_commit_sha "
                        f"to {current_commit_sha[:7]}"
                    )
                else:
                    logger.warning(f"[{scan_id}] ⚠️ Failed to update commit tracking")
            except Exception as commit_err:
                logger.error(
                    f"[{scan_id}] ❌ Commit tracking update failed: {commit_err}",
                    exc_info=True,
                )
        else:
            logger.warning(f"[{scan_id}] ⚠️ Database save failed, results in memory only")

        # Update in-memory state
        with _lock:
            _scan_results[scan_id].update({
                "status": "completed",
                "vulnerabilities": vulnerabilities,
                "scanner_used": scanner_choice,
                "total_issues": len(vulnerabilities),
                "severity_summary": severity_dict,
                "detected_languages": list(languages),
                "error_message": error_msg,
                "scan_duration": round(duration, 2),
                "completed_at": end_time.isoformat(),
                "repo_size_mb": round(repo_size_mb, 2),
                # Incremental metadata for frontend
                "is_incremental": is_incremental,
                "files_scanned": files_scanned,
                "files_skipped": files_skipped,
                "changed_files_count": len(diff.changed_files) if diff.is_incremental else None,
                "scan_strategy": strategy,
            })

        logger.info(f"[{scan_id}] ✅ Scan complete ({duration:.2f}s) [{strategy}]")

    except Exception as e:
        error_msg = f"Scan failed: {str(e)}"
        logger.error(f"[{scan_id}] ❌ {error_msg}", exc_info=True)

        await mark_scan_failed_in_db(
            scan_id=scan_id,
            error_message=error_msg,
            error_code="SCAN_ERROR",
        )

        with _lock:
            if scan_id in _scan_results:
                _scan_results[scan_id].update({
                    "status": "failed",
                    "error_message": error_msg,
                    "completed_at": datetime.now().isoformat(),
                })

    finally:
        with _lock:
            _active_scans = max(0, _active_scans - 1)

        repo_lock.release()
        logger.info(f"[{scan_id}] 🔓 Repository lock released for {repo_full_name}")

        if temp_dir and os.path.exists(temp_dir):
            VulnerabilityScanner.remove_temp_dir(temp_dir)
            logger.info(f"[{scan_id}] 🧹 Temp directory cleaned")


# ─────────────────────────────────────────────────────────────
# Public helpers (backward compatible)
# ─────────────────────────────────────────────────────────────

def initialize_scan(
    scan_id: str,
    repo_owner: str,
    repo_name: str,
    user_id: Optional[str] = None,
    branch: str = "main",
) -> None:
    """Create in-memory entry for a new scan."""
    with _lock:
        if scan_id in _scan_results:
            logger.warning(f"[{scan_id}] Scan already exists")
            return

        _scan_results[scan_id] = {
            "scan_id": scan_id,
            "user_id": user_id,
            "repo_owner": repo_owner,
            "repo_name": repo_name,
            "repo_url": f"https://github.com/{repo_owner}/{repo_name}",
            "status": "queued",
            "vulnerabilities": [],
            "scanner_used": "",
            "total_issues": 0,
            "severity_summary": None,
            "detected_languages": [],
            "error_message": None,
            "scan_duration": None,
            "repo_size_mb": None,
            "started_at": None,
            "completed_at": None,
            "queued_at": datetime.utcnow().isoformat(),
            "branch": branch,
            "is_incremental": False,
            "files_scanned": None,
            "files_skipped": None,
            "changed_files_count": None,
            "scan_strategy": "pending",
        }
        logger.info(f"[{scan_id}] Initialized in-memory state")


def get_scan_result(scan_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        return _scan_results.get(scan_id)


def get_all_scan_results() -> Dict[str, Dict[str, Any]]:
    with _lock:
        return dict(_scan_results)


def get_user_scans(user_id: str) -> Dict[str, Dict[str, Any]]:
    with _lock:
        return {
            k: v for k, v in _scan_results.items()
            if v.get("user_id") == user_id
        }


def get_active_scans() -> int:
    with _lock:
        return _active_scans


def delete_scan(scan_id: str) -> bool:
    with _lock:
        return _scan_results.pop(scan_id, None) is not None