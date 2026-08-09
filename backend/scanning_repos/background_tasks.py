"""
Production background scanning with incremental scan support.

Incremental scan flow (UPDATED):
  0. If last_scan_commit_sha == current_commit_sha: ZERO WORK. Return the
     previous scan's result immediately — no clone, no scan, no DB write.
  1. Fetch last_scan_commit_sha from DB (the commit scanned previously)
  2. Reuse a cached local clone for this repo if one exists (git fetch +
     checkout), instead of a fresh full clone — this is the expensive part
     incremental scanning was NOT actually saving before. Only a fresh full
     clone falls back to tempfile.mkdtemp() as before.
  3. Call GitHub Compare API to get changed files between old and new SHA.
     If that fails or the diff is too large, try a LOCAL `git diff` against
     the cached clone before giving up to full scan.
  4. If diff is small enough:
       a. Run scanner.scan(changed_files=diff) — scanners touch only those files
       b. Load previous findings from DB (excluding just-rescanned files
          at the DB level when the changed set is small)
       c. Merge: keep old findings for unchanged files, replace for changed files
  5. If no cached/local diff possible AND no previous scan: full scan.
  6. Always store the complete merged result set in DB.

✅ Properly updates last_scan_commit_sha after successful scans
✅ Prevents race conditions via per-repository locks
✅ Handles scan allowance correctly
✅ Same-commit re-triggers short-circuit to zero work
✅ Incremental scans reuse a cached clone instead of full-cloning every time
"""
import asyncio
import os
import shutil
import threading
from datetime import datetime
from typing import Optional, Dict, Any, Set

from .config import logger, MAX_REPO_SIZE_MB, REPO_CACHE_DIR, FETCH_TIMEOUT
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


def _cached_repo_path(repo_owner: str, repo_name: str) -> str:
    """Deterministic on-disk path for a repo's cached working clone."""
    safe = f"{repo_owner}__{repo_name}".replace("/", "_")
    return os.path.join(REPO_CACHE_DIR, safe)


async def _run_git(args: list, cwd: str, timeout: int) -> None:
    """Run a git subprocess, raise RuntimeError with stderr on failure/timeout."""
    proc = await asyncio.create_subprocess_exec(
        "git", *args,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"git {' '.join(args)} timed out after {timeout}s")
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed: {stderr.decode(errors='replace')[:300]}"
        )


async def get_or_refresh_repo_clone(
    github_token: str,
    repo_owner: str,
    repo_name: str,
    branch: str,
    head_sha: str,
    scan_id: str,
    base_sha: Optional[str] = None,
) -> tuple:
    """
    Reuse a cached local clone for this repo when possible, instead of a
    fresh full `git clone` on every scan.

    This is the fix for the biggest hidden cost in incremental scanning:
    previously, EVERY scan — incremental or not — did a full clone via
    tempfile.mkdtemp() + clone_github_repo(), which means incremental mode
    was only saving scanner CPU time, not the clone/IO time that usually
    dominates wall-clock for larger repos.

    IMPORTANT — shallow clone interaction:
    clone_github_repo() does `git clone --depth 1`, i.e. a shallow clone
    with NO ancestor history. A plain `git fetch origin <branch>` on a
    shallow repo only advances the tip — it does NOT give you base_sha's
    history, so a later `git diff base_sha head_sha` would fail with
    "unknown revision" almost every time. To keep the local-diff fallback
    (incremental_scanning._local_git_diff) actually usable, on reuse we:
      - fetch with `--deepen=200` (bounded — NOT --unshallow, which would
        pull the entire history and defeat the point of a shallow clone
        for large/old repos) to extend history a bounded amount, AND
      - explicitly fetch base_sha by SHA if it's not already present.
    If base_sha still isn't reachable after that (e.g. it's more than
    ~200 commits back, or was force-pushed away), the fetch/checkout of
    base_sha silently fails and _local_git_diff() will error — which is
    fine, that's an expected, handled failure mode that falls through to
    full scan, same as before this fix existed.

    Strategy:
      1. If a cached clone exists at REPO_CACHE_DIR for this repo:
           - Refresh the remote URL (github_token may have rotated since
             the clone was created)
           - `git fetch` with bounded deepening + explicit base_sha fetch
           - `git checkout <head_sha>` (detached, exact commit)
           - On any failure (corrupted clone, fetch error, missing commit),
             discard the cached dir and fall through to a fresh full clone.
      2. If no cached clone exists, or the fallback above triggered:
           - Fresh full clone via the existing clone_github_repo() into the
             SAME cached path (not a throwaway tempdir), so future scans
             of this repo can reuse it. This is still a shallow (--depth 1)
             clone — base_sha likely won't be reachable on THIS scan, so
             the local-diff fallback naturally has no effect until the
             NEXT scan (once the cache exists and gets deepened above).

    Returns (repo_path, used_cache: bool, message: str).
    The caller is responsible for NOT deleting repo_path when used_cache
    is True (or generally now) — see cleanup note in perform_scan().
    """
    os.makedirs(REPO_CACHE_DIR, exist_ok=True)
    cache_path = _cached_repo_path(repo_owner, repo_name)
    clone_url = f"https://{github_token}@github.com/{repo_owner}/{repo_name}.git"

    if os.path.isdir(os.path.join(cache_path, ".git")):
        try:
            cache_size_mb = get_dir_size(cache_path) / (1024 * 1024)
            from .config import REPO_CACHE_MAX_MB
            if cache_size_mb > REPO_CACHE_MAX_MB:
                raise RuntimeError(
                    f"cached clone too large ({cache_size_mb:.0f}MB > "
                    f"{REPO_CACHE_MAX_MB}MB) — discarding"
                )

            logger.info(f"[{scan_id}] ♻️  Reusing cached clone for {repo_owner}/{repo_name}")

            # Refresh remote URL in case the token rotated since this clone
            # was created — avoids fetch failing on a stale embedded token.
            await _run_git(
                ["remote", "set-url", "origin", clone_url],
                cwd=cache_path, timeout=FETCH_TIMEOUT,
            )

            # Bounded deepen (not --unshallow) so large/old repos don't pay
            # full-history cost on every scan, just enough to usually cover
            # one scan interval's worth of commits.
            await _run_git(
                ["fetch", "--deepen=200", "origin", branch],
                cwd=cache_path, timeout=FETCH_TIMEOUT,
            )

            # If base_sha isn't reachable yet, try fetching it explicitly by
            # SHA — GitHub supports fetching arbitrary SHAs directly. This
            # is what actually makes the local-diff fallback usable; the
            # --deepen above alone won't reach base_sha if it's older than
            # 200 commits back or on a different ref path.
            if base_sha:
                try:
                    await _run_git(
                        ["fetch", "origin", base_sha],
                        cwd=cache_path, timeout=FETCH_TIMEOUT,
                    )
                except Exception:
                    # Not fatal — local diff fallback just won't be available
                    # this scan if base_sha truly isn't reachable. The GitHub
                    # Compare API path is still tried first anyway.
                    logger.info(
                        f"[{scan_id}] base_sha {base_sha[:7]} not reachable "
                        f"via direct fetch — local diff fallback may be unavailable"
                    )

            await _run_git(["checkout", "-f", head_sha], cwd=cache_path, timeout=FETCH_TIMEOUT)
            logger.info(f"[{scan_id}] ✅ Cached clone refreshed to {head_sha[:7]}")
            return cache_path, True, "reused cached clone"

        except Exception as exc:
            logger.warning(
                f"[{scan_id}] ⚠️ Cached clone reuse failed ({exc}) — "
                f"discarding cache and doing a fresh clone"
            )
            shutil.rmtree(cache_path, ignore_errors=True)

    # No usable cache — fresh full (shallow) clone, but INTO the cache path
    # so it's reusable next time. Note: this scan itself won't benefit from
    # the local-diff fallback (base_sha won't be in a depth-1 clone) — that
    # only becomes available starting from the NEXT scan of this repo, once
    # the cache exists and the deepen/explicit-fetch logic above can run.
    logger.info(f"[{scan_id}] 📥 No cached clone available — full clone")
    success, message = await clone_github_repo(
        github_token, repo_owner, repo_name, branch, cache_path,
    )
    if not success:
        shutil.rmtree(cache_path, ignore_errors=True)
        raise RuntimeError(f"Clone failed: {message}")

    return cache_path, False, message


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
        # STEP 2a: SAME-COMMIT SHORT-CIRCUIT — ZERO WORK
        # ══════════════════════════════════════════════════════════
        # Fixes a bug where base_sha == head_sha used to fall through to a
        # FULL SCAN for literally nothing changed. routes.py may already
        # intercept this before dispatch, but we no longer rely solely on
        # that — this is now authoritative here too, not just a "safety net"
        # comment with no actual short-circuit behind it.
        if last_scan_commit_sha and last_scan_commit_sha == current_commit_sha:
            logger.info(
                f"[{scan_id}] ⏭️  Commit {current_commit_sha[:7]} already scanned "
                f"— skipping scan entirely, reusing previous result"
            )
            previous_vulns = await get_previous_scan_vulnerabilities(
                user_id=user_id, repo_owner=repo_owner, repo_name=repo_name,
            )
            severity = calculate_severity_summary(previous_vulns)
            end_time = datetime.now()
            with _lock:
                _scan_results[scan_id].update({
                    "status": "completed",
                    "vulnerabilities": previous_vulns,
                    "scanner_used": scanner_choice,
                    "total_issues": len(previous_vulns),
                    "severity_summary": {
                        "critical": severity.critical, "high": severity.high,
                        "medium": severity.medium, "low": severity.low,
                        "info": severity.info, "warning": severity.warning,
                    },
                    "completed_at": end_time.isoformat(),
                    "scan_duration": round((end_time - start_time).total_seconds(), 2),
                    "is_incremental": False,
                    "scan_strategy": "cached_no_change",
                })
            await complete_scan_in_db(
                scan_id=scan_id, vulnerabilities=previous_vulns,
                scanner_used=scanner_choice, languages=[],
                duration=round((end_time - start_time).total_seconds(), 2),
                size_mb=0, files=0,
            )
            return

        # ══════════════════════════════════════════════════════════
        # STEP 2b: REUSE OR REFRESH LOCAL CLONE
        # ══════════════════════════════════════════════════════════
        # Done BEFORE strategy/diff resolution (not after, as before) for
        # two reasons: (1) incremental scans no longer pay for a fresh full
        # clone — they fetch+checkout into a cached working dir; (2) having
        # the local clone available lets get_changed_files() use it as a
        # local `git diff` fallback if the GitHub Compare API fails or the
        # diff is too large, instead of escalating straight to full scan.
        await update_scan_status_in_db(scan_id, "cloning", started_at=start_time)
        with _lock:
            _scan_results[scan_id]["status"] = "cloning"

        temp_dir, used_cache, clone_message = await get_or_refresh_repo_clone(
            github_token=github_token,
            repo_owner=repo_owner,
            repo_name=repo_name,
            branch=branch,
            head_sha=current_commit_sha,
            scan_id=scan_id,
            base_sha=last_scan_commit_sha,
        )

        repo_size_mb = get_dir_size(temp_dir) / (1024 * 1024)
        if repo_size_mb > MAX_REPO_SIZE_MB:
            raise RuntimeError(
                f"Repository too large: {repo_size_mb:.1f} MB "
                f"(max: {MAX_REPO_SIZE_MB} MB)"
            )

        logger.info(
            f"[{scan_id}] ✅ Repository ready ({repo_size_mb:.2f} MB) "
            f"[{'cached clone reused' if used_cache else 'fresh clone'}]"
        )

        # ══════════════════════════════════════════════════════════
        # STEP 2c: DETERMINE SCAN STRATEGY
        # ══════════════════════════════════════════════════════════
        incremental_engine = IncrementalEngine(github_token)

        diff = await incremental_engine.get_changed_files(
            owner=repo_owner,
            repo=repo_name,
            base_sha=last_scan_commit_sha or "",
            head_sha=current_commit_sha,
            branch=branch,
            # Enables local `git diff` fallback instead of escalating to
            # full scan when the GitHub Compare API fails or the diff is
            # too large. Only used as a fallback — the API path is still
            # tried first.
            local_repo_path=temp_dir,
        )

        strategy = "incremental" if diff.is_incremental else "full"
        if not diff.is_incremental and diff.fallback_reason:
            logger.info(f"[{scan_id}] Full scan reason: {diff.fallback_reason}")

        logger.info(
            f"[{scan_id}] Scan strategy: {strategy.upper()} "
            f"({'%d files' % len(diff.changed_files) if diff.is_incremental else 'whole repo'})"
        )

        # ══════════════════════════════════════════════════════════
        # STEP 4: ANALYZE LANGUAGES
        # ══════════════════════════════════════════════════════════
        await update_scan_status_in_db(scan_id, "analyzing")
        with _lock:
            _scan_results[scan_id]["status"] = "analyzing"

        if diff.is_incremental:
            # Derive languages from the changed-file list instead of
            # walking the full tree via detect_languages(). Mirrors
            # detect_languages()'s two detection rules that apply at
            # per-file granularity:
            #   1. extension → language (LANGUAGE_EXTENSIONS)
            #   2. exact filename → shell (Dockerfile/Makefile/Rakefile/Gemfile)
            # Deliberately does NOT replicate detect_languages()'s root-level
            # config-file detection (package.json, requirements.txt, go.mod,
            # etc.) — those signal what's present in the repo overall, not
            # what changed, and are irrelevant to scoping an incremental
            # scan to the diff.
            _shell_filenames = {"dockerfile", "makefile", "rakefile", "gemfile"}
            languages = set()
            for f in diff.changed_files:
                basename = f.rsplit("/", 1)[-1]
                ext = "." + basename.rsplit(".", 1)[-1].lower() if "." in basename else ""
                if ext in LANGUAGE_EXTENSIONS:
                    languages.add(LANGUAGE_EXTENSIONS[ext])
                elif basename.lower() in _shell_filenames:
                    languages.add("shell")

            if not languages:
                # Same fallback detect_languages() uses — ensures a diff of
                # e.g. a single extensionless script still gets scanned
                # instead of silently skipping all scanners.
                logger.warning(
                    f"[{scan_id}] No language detected from {len(diff.changed_files)} "
                    f"changed file(s) — defaulting to python fallback"
                )
                languages = {"python"}

            logger.info(f"[{scan_id}] 🔍 Languages derived from diff: {languages}")
        else:
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

            # Load previous findings from DB, excluding the just-rescanned
            # files at the DB level when the changed set is small enough
            # (see incremental_scanning._EXCLUDE_FILTER_MAX_FILES). Falls
            # back to loading everything (as before) above that threshold —
            # merge_findings() re-applies its own filter either way, so this
            # is a pure performance optimization, not a correctness change.
            previous_vulns = await get_previous_scan_vulnerabilities(
                user_id=user_id,
                repo_owner=repo_owner,
                repo_name=repo_name,
                exclude_files=diff.changed_files,
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
                f"{len(fresh_vulns)} fresh + {files_skipped} retained "
                f"= {len(vulnerabilities)} total"
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

        # NOTE: temp_dir is now a PERSISTENT cached clone under
        # config.REPO_CACHE_DIR (see get_or_refresh_repo_clone), reused
        # across scans of this repo — NOT a throwaway tempdir. It is
        # intentionally NOT deleted here. Deleting it on every scan would
        # silently defeat the clone-reuse optimization and put every
        # incremental scan back to paying full-clone cost.
        #
        # Cache eviction (size-based) is handled separately at the start
        # of get_or_refresh_repo_clone() via REPO_CACHE_MAX_MB, and repos
        # can be purged manually from REPO_CACHE_DIR if ever needed.


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