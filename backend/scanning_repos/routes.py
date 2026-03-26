"""
API routes for repository scanning.

Three-path scanning architecture:
  PATH 1 — First scan / no previous scan → full repo scan
  PATH 2 — Same commit as last scan → return DB results instantly, no scan
  PATH 3 — New commits detected → incremental scan (changed files only)
"""
import uuid
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from ..auth.authentication import store as auth_store, JWTManager
from .config import logger, MAX_CONCURRENT_SCANS, SEMGREP_APP_TOKEN
from .models import ScanRequest, ScanStatus, ScanResult
from .utils import get_semgrep_token
from .background_tasks import (
    perform_scan,
    initialize_scan,
    get_scan_result,
    get_all_scan_results,
    get_active_scans,
    delete_scan,
    get_user_scans,
)
from .commit_tracker import CommitTracker
from sqlalchemy import select

router = APIRouter()


async def get_user_id(request: Request) -> str:
    """Extract user_id from request cookies or JWT token."""
    import uuid as uuid_module
    user_id = None

    session_token = request.cookies.get("session_token")
    if session_token:
        try:
            payload = await JWTManager.verify_token(session_token)
            if payload:
                user_id = payload.get("user_id") or payload.get("id")
        except Exception as e:
            logger.debug(f"Session decode failed: {e}")

    if not user_id:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                token = auth_header.split(" ")[1]
                payload = await JWTManager.verify_token(token)
                if payload:
                    user_id = payload.get("user_id") or payload.get("id")

                    if not user_id and "sub" in payload:
                        email = payload["sub"]
                        try:
                            from backend.database import config as db_config
                            from backend.database.service import DatabaseService
                            if db_config.is_db_available() and db_config.AsyncSessionLocal:
                                async with db_config.AsyncSessionLocal() as db:
                                    db_user = await DatabaseService.get_user_by_email(db, email)
                                    if db_user:
                                        user_id = str(db_user.id)
                        except Exception as db_error:
                            logger.warning(f"Database lookup failed: {db_error}")
            except Exception as e:
                logger.error(f"Error extracting from JWT: {e}")

    if user_id and user_id != "anonymous":
        try:
            uuid_module.UUID(user_id)
            return user_id
        except (ValueError, AttributeError):
            logger.warning(f"Invalid UUID format: {user_id}")

    return "anonymous"


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Load previous scan results from DB as in-memory format
# ─────────────────────────────────────────────────────────────────────────────

async def _load_previous_scan_as_result(
    user_id: str,
    repo_owner: str,
    repo_name: str,
) -> Optional[dict]:
    """
    Load the most recent completed scan from DB and return it in the same
    dict format as _scan_results so the frontend gets a consistent response.
    Returns None if no completed scan exists.
    """
    try:
        from backend.database import config as db_config
        from backend.database.scan_models import Repository, ScanHistory, Vulnerability
        from sqlalchemy import select, and_, desc

        if not db_config.is_db_available() or not db_config.AsyncSessionLocal:
            return None

        async with db_config.AsyncSessionLocal() as db:
            # Find repository
            repo_result = await db.execute(
                select(Repository).where(
                    and_(
                        Repository.user_id == user_id,
                        Repository.owner == repo_owner,
                        Repository.name == repo_name,
                    )
                )
            )
            repository = repo_result.scalar_one_or_none()
            if not repository:
                return None

            # Latest completed scan
            scan_result = await db.execute(
                select(ScanHistory)
                .where(
                    and_(
                        ScanHistory.repository_id == repository.id,
                        ScanHistory.status == "completed",
                    )
                )
                .order_by(desc(ScanHistory.completed_at))
                .limit(1)
            )
            scan = scan_result.scalar_one_or_none()
            if not scan:
                return None

            # Load vulnerabilities
            vuln_result = await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == scan.id)
            )
            vuln_rows = vuln_result.scalars().all()

            # Convert to scanner output format
            vulnerabilities = []
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "warning": 0}

            for v in vuln_rows:
                sev = (v.severity or "INFO").upper()
                severity_counts[sev.lower()] = severity_counts.get(sev.lower(), 0) + 1
                vulnerabilities.append({
                    "scanner": v.scanner_name,
                    "rule_id": v.rule_id,
                    "severity": v.severity,
                    "message": v.message,
                    "vulnerability_type": v.vulnerability_type,
                    "location": {
                        "file": v.file_path,
                        "start_line": v.start_line,
                        "end_line": v.end_line,
                        "start_col": v.start_column,
                        "end_col": v.end_column,
                    },
                    "cwe": v.cwe_ids,
                    "owasp": v.owasp_categories,
                    "confidence": v.confidence,
                    "code_snippet": v.code_snippet,
                })

            return {
                "scan_id": scan.scan_id,
                "user_id": user_id,
                "repo_owner": repo_owner,
                "repo_name": repo_name,
                "repo_url": f"https://github.com/{repo_owner}/{repo_name}",
                "status": "completed",
                "vulnerabilities": vulnerabilities,
                "scanner_used": scan.scanner_used or "semgrep",
                "total_issues": scan.total_vulnerabilities or 0,
                "severity_summary": severity_counts,
                "detected_languages": list(scan.detected_languages or []),
                "error_message": None,
                "scan_duration": scan.scan_duration_seconds,
                "repo_size_mb": scan.repo_size_mb,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "commit_sha": scan.last_commit_sha,
                "is_incremental": False,
                "files_scanned": None,
                "files_skipped": None,
                "changed_files_count": None,
                "scan_strategy": "cached",
                # ← tells frontend this came straight from DB
                "served_from_cache": True,
            }

    except Exception as exc:
        logger.error(f"Failed to load previous scan from DB: {exc}", exc_info=True)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# ELIGIBILITY CHECK
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/repos/{owner}/{repo}/check-eligibility")
async def check_scan_eligibility(
    owner: str,
    repo: str,
    request: Request,
    branch: Optional[str] = "main",
):
    """
    Check if repository can be scanned and hint which path will be taken.
    Does NOT modify any database state.
    """
    try:
        github_token = request.cookies.get("github_access_token")
        if not github_token:
            raise HTTPException(status_code=401, detail="GitHub token required")

        user_id = await get_user_id(request)

        latest_commit = await CommitTracker.get_latest_commit(
            github_token, owner, repo, branch
        )

        if not latest_commit:
            return {
                "eligible": True,
                "reason": "Unable to verify commits — allowing scan",
                "remaining_scans": CommitTracker.INITIAL_SCAN_ALLOWANCE,
                "latest_commit": "unknown",
                "commit_message": "Could not fetch commit info",
                "is_first_scan": True,
                "has_new_commits": False,
                "new_commits_count": 0,
                "last_scanned_commit": None,
                "scan_strategy": "full",
            }

        from backend.database import config as db_config
        from backend.database.scan_models import Repository

        if not db_config.is_db_available() or not db_config.AsyncSessionLocal:
            return {
                "eligible": True,
                "reason": "First scan (database unavailable)",
                "remaining_scans": CommitTracker.INITIAL_SCAN_ALLOWANCE,
                "latest_commit": latest_commit["sha"][:7],
                "commit_message": latest_commit["message"][:100],
                "is_first_scan": True,
                "has_new_commits": False,
                "new_commits_count": 0,
                "last_scanned_commit": None,
                "scan_strategy": "full",
            }

        async with db_config.AsyncSessionLocal() as db:
            result = await db.execute(
                select(Repository).where(
                    Repository.user_id == user_id,
                    Repository.owner == owner,
                    Repository.name == repo,
                )
            )
            repository = result.scalar_one_or_none()

            if not repository:
                return {
                    "eligible": True,
                    "reason": "First scan of this repository",
                    "remaining_scans": CommitTracker.INITIAL_SCAN_ALLOWANCE,
                    "latest_commit": latest_commit["sha"][:7],
                    "commit_message": latest_commit["message"][:100],
                    "is_first_scan": True,
                    "has_new_commits": False,
                    "new_commits_count": 0,
                    "last_scanned_commit": None,
                    "scan_strategy": "full",
                }

            is_eligible, reason, remaining, has_new_commits = await CommitTracker.check_scan_eligibility(
                db, str(repository.id), latest_commit["sha"]
            )

            new_commits_count = 0
            last_scanned = None

            if repository.last_scan_commit_sha:
                last_scanned = repository.last_scan_commit_sha[:7]
                if latest_commit["sha"] != repository.last_scan_commit_sha:
                    new_commits = await CommitTracker.get_commits_since(
                        github_token, owner, repo,
                        repository.last_scan_commit_sha, branch,
                    )
                    new_commits_count = len(new_commits)

            # Determine strategy hint
            is_first = repository.last_scan_commit_sha is None
            same_commit = (
                repository.last_scan_commit_sha is not None
                and latest_commit["sha"] == repository.last_scan_commit_sha
            )

            if is_first:
                strategy = "full"
            elif same_commit:
                # PATH 2 — will return from DB, no scan at all
                strategy = "cached"
            elif has_new_commits:
                strategy = "incremental"
            else:
                strategy = "full"

            return {
                "eligible": is_eligible,
                "reason": reason,
                "remaining_scans": remaining if not has_new_commits else CommitTracker.INITIAL_SCAN_ALLOWANCE,
                "latest_commit": latest_commit["sha"][:7],
                "commit_message": latest_commit["message"][:100],
                "is_first_scan": is_first,
                "has_new_commits": has_new_commits,
                "new_commits_count": new_commits_count,
                "last_scanned_commit": last_scanned,
                "scan_strategy": strategy,
            }

    except Exception as e:
        logger.error(f"Eligibility check failed: {e}", exc_info=True)
        return {
            "eligible": True,
            "reason": f"Eligibility check error — allowing scan",
            "remaining_scans": CommitTracker.INITIAL_SCAN_ALLOWANCE,
            "latest_commit": "error",
            "commit_message": "Error checking commits",
            "is_first_scan": True,
            "has_new_commits": False,
            "new_commits_count": 0,
            "last_scanned_commit": None,
            "scan_strategy": "full",
        }


# ─────────────────────────────────────────────────────────────────────────────
# START SCAN — Three-path routing
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/repos/{owner}/{repo}/scan")
async def start_scan(
    owner: str,
    repo: str,
    request: Request,
    background_tasks: BackgroundTasks,
    branch: Optional[str] = "main",
    force: bool = False,
):
    """
    Start vulnerability scan — routes to one of three paths:

    PATH 1 (first scan):    full scan, no DB history
    PATH 2 (no changes):    return existing DB results instantly, no scan launched
    PATH 3 (new commits):   incremental scan on changed files only

    force=True skips PATH 2 — always triggers a new scan.
    """
    try:
        github_token = request.cookies.get("github_access_token")
        if not github_token:
            raise HTTPException(status_code=401, detail="GitHub token required")

        user_id = await get_user_id(request)

        # ── Fetch latest commit ───────────────────────────────────────────────
        latest_commit = await CommitTracker.get_latest_commit(
            github_token, owner, repo, branch
        )
        if not latest_commit:
            raise HTTPException(
                status_code=400,
                detail="Could not fetch repository commit information",
            )

        current_commit_sha = latest_commit["sha"]

        from backend.database import config as db_config
        from backend.database.scan_models import Repository

        if not db_config.is_db_available() or not db_config.AsyncSessionLocal:
            raise HTTPException(status_code=503, detail="Database not available")

        last_scan_commit_sha: Optional[str] = None
        repository = None

        async with db_config.AsyncSessionLocal() as db:
            result = await db.execute(
                select(Repository).where(
                    Repository.user_id == user_id,
                    Repository.owner == owner,
                    Repository.name == repo,
                )
            )
            repository = result.scalar_one_or_none()

            if not repository:
                # ── PATH 1: First scan — create repo record ───────────────────
                from backend.database.scan_service import ScanService
                repository = await ScanService.get_or_create_repository(
                    db=db,
                    user_id=user_id,
                    owner=owner,
                    repo_name=repo,
                    github_url=f"https://github.com/{owner}/{repo}",
                    default_branch=branch,
                )
                await db.commit()
                await db.refresh(repository)
                logger.info(f"[PATH 1] First scan — created repo record for {owner}/{repo}")
            else:
                last_scan_commit_sha = repository.last_scan_commit_sha

            # ── PATH 2: Same commit, not forced — return from DB ─────────────
            if (
                not force
                and last_scan_commit_sha is not None
                and last_scan_commit_sha == current_commit_sha
            ):
                logger.info(
                    f"[PATH 2] No commits since last scan for {owner}/{repo} "
                    f"(commit: {current_commit_sha[:7]}) — serving from DB"
                )

                cached = await _load_previous_scan_as_result(
                    user_id=user_id,
                    repo_owner=owner,
                    repo_name=repo,
                )

                if cached:
                    # Register in memory so status/summary endpoints work
                    synthetic_scan_id = cached["scan_id"]
                    from .background_tasks import _scan_results, _lock
                    with _lock:
                        _scan_results[synthetic_scan_id] = cached

                    logger.info(
                        f"[PATH 2] Returned {cached['total_issues']} cached vulnerabilities "
                        f"for {owner}/{repo} in <1s"
                    )
                    return {
                        "scan_id": synthetic_scan_id,
                        "status": "completed",
                        "message": f"No changes since last scan — results from {cached['completed_at'][:10] if cached.get('completed_at') else 'previous scan'}",
                        "commit_sha": current_commit_sha[:7],
                        "scan_strategy": "cached",
                        "served_from_cache": True,
                        "total_issues": cached["total_issues"],
                    }
                else:
                    # No cached result found — fall through to full scan
                    logger.warning(
                        f"[PATH 2] No cached results in DB for {owner}/{repo} "
                        f"— falling back to full scan"
                    )

            # ── Check eligibility for PATH 1 and PATH 3 ──────────────────────
            if not force:
                async with db_config.AsyncSessionLocal() as db2:
                    result2 = await db2.execute(
                        select(Repository).where(Repository.id == repository.id)
                    )
                    repo_fresh = result2.scalar_one_or_none()
                    if repo_fresh:
                        is_eligible, reason, remaining, has_new_commits = \
                            await CommitTracker.check_scan_eligibility(
                                db2, str(repo_fresh.id), current_commit_sha
                            )

                        if not is_eligible:
                            raise HTTPException(status_code=403, detail=reason)

                        if has_new_commits:
                            await CommitTracker.reset_allowance_for_new_commits(
                                db2, str(repo_fresh.id), current_commit_sha
                            )

        # ── PATH 1 or PATH 3 — launch background scan ────────────────────────
        scan_id = str(uuid.uuid4())
        semgrep_token = get_semgrep_token(SEMGREP_APP_TOKEN)

        # PATH 3 if we have a previous SHA different from current
        # PATH 1 if no previous SHA exists
        if last_scan_commit_sha and last_scan_commit_sha != current_commit_sha:
            strategy_hint = "incremental"
            path = "PATH 3"
        else:
            strategy_hint = "full"
            path = "PATH 1"

        logger.info(
            f"[{path}] Launching scan [{scan_id}] for {owner}/{repo}@{branch} "
            f"(current: {current_commit_sha[:7]}, "
            f"prev: {last_scan_commit_sha[:7] if last_scan_commit_sha else 'none'})"
        )

        # Pre-populate in-memory state BEFORE launching background task
        # so the first status poll never gets a 404
        initialize_scan(
            scan_id=scan_id,
            repo_owner=owner,
            repo_name=repo,
            user_id=user_id,
            branch=branch,
        )

        background_tasks.add_task(
            perform_scan,
            scan_id=scan_id,
            user_id=user_id,
            github_token=github_token,
            repo_owner=owner,
            repo_name=repo,
            branch=branch,
            semgrep_token=semgrep_token,
            scanner_choice="semgrep",
            max_files=1000,
            current_commit_sha=current_commit_sha,
            last_scan_commit_sha=last_scan_commit_sha,
        )

        return {
            "scan_id": scan_id,
            "status": "queued",
            "message": f"Scan initiated for {owner}/{repo}",
            "commit_sha": current_commit_sha[:7],
            "scan_strategy": strategy_hint,
            "served_from_cache": False,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ✅ FIX: This MUST be defined BEFORE /scans/{scan_id} to prevent FastAPI
# from matching the literal string "history" as a scan_id parameter.
@router.get("/scans/history")
async def get_scan_history(
    request: Request,
    limit: Optional[int] = 50
):
    """
    Get user's scan history.
    ✅ FIXED: Reads from PostgreSQL — survives uvicorn restarts.
    Falls back to in-memory store only if DB is unavailable.
    """
    try:
        user_id = await get_user_id(request)

        # ── DB path (primary) ─────────────────────────────────────
        from backend.database import config as db_config
        from backend.database.scan_models import ScanHistory, Repository
        from sqlalchemy import select, desc

        if db_config.is_db_available() and db_config.AsyncSessionLocal:
            async with db_config.AsyncSessionLocal() as db:
                rows = await db.execute(
                    select(ScanHistory, Repository.owner, Repository.name)
                    .join(Repository, ScanHistory.repository_id == Repository.id, isouter=True)
                    .where(ScanHistory.user_id == user_id)
                    .order_by(desc(ScanHistory.queued_at))
                    .limit(limit)
                )

                scans = []
                for scan, repo_owner, repo_name in rows:
                    # Use getattr with fallbacks so missing model fields never crash
                    critical = getattr(scan, 'critical_count', None) or 0
                    high     = getattr(scan, 'high_count', None) or 0
                    medium   = getattr(scan, 'medium_count', None) or 0
                    low      = getattr(scan, 'low_count', None) or 0

                    severity_summary = None
                    if any([critical, high, medium, low]):
                        severity_summary = {
                            "critical": critical,
                            "high":     high,
                            "medium":   medium,
                            "low":      low,
                            "info":     0,
                            "warning":  0,
                        }

                    # scan_duration may be stored under different column names
                    duration = (
                        getattr(scan, 'scan_duration', None)
                        or getattr(scan, 'duration_seconds', None)
                        or getattr(scan, 'duration', None)
                    )

                    completed_at = getattr(scan, 'completed_at', None)
                    started_at   = getattr(scan, 'started_at', None)
                    queued_at    = getattr(scan, 'queued_at', None)

                    scans.append({
                        "scan_id":          str(scan.scan_id),
                        "repo_owner":       repo_owner or "unknown",
                        "repo_name":        repo_name or "unknown",
                        "status":           scan.status,
                        "total_issues":     getattr(scan, 'total_vulnerabilities', None) or 0,
                        "severity_summary": severity_summary,
                        "scan_duration":    duration,
                        "completed_at":     completed_at.isoformat() if completed_at else None,
                        "started_at":       (started_at or queued_at or completed_at),
                        "started_at":       (started_at.isoformat() if started_at else
                                             queued_at.isoformat() if queued_at else None),
                        "error_message":    getattr(scan, 'error_message', None),
                    })

                logger.info(f"Scan history fetched from DB for user {user_id}: {len(scans)} records")
                return {"total_scans": len(scans), "scans": scans}

        # ── Memory fallback (DB unavailable) ─────────────────────
        logger.warning("DB unavailable — falling back to in-memory scan history")
        all_scans = get_all_scan_results()
        scans = sorted(
            all_scans.values(),
            key=lambda x: x.get('started_at') or x.get('scan_id', ''),
            reverse=True
        )[:limit]

        return {
            "total_scans": len(all_scans),
            "scans": [
                {
                    "scan_id":          s.get('scan_id'),
                    "repo_owner":       s.get('repo_owner'),
                    "repo_name":        s.get('repo_name'),
                    "status":           s.get('status'),
                    "total_issues":     s.get('total_issues', 0),
                    "severity_summary": s.get('severity_summary'),
                    "scan_duration":    s.get('scan_duration'),
                    "completed_at":     s.get('completed_at'),
                    "started_at":       s.get('started_at'),
                    "error_message":    s.get('error_message'),
                }
                for s in scans
            ]
        }

    except Exception as e:
        logger.error(f"Error retrieving scan history: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving scan history: {str(e)}"
        )


@router.get("/scans/{scan_id}")
async def get_scan_result_endpoint(scan_id: str, request: Request):
    """
    Get detailed scan results by scan ID.
    ✅ FIXED: Reads from PostgreSQL first, falls back to in-memory.
    """
    try:
        logger.info(f"[{scan_id}] Retrieving scan result")

        # ── 1. Try in-memory first (covers live/in-progress scans) ──
        result = get_scan_result(scan_id)
        if result is not None:
            logger.info(f"[{scan_id}] Served from in-memory cache")
            return JSONResponse(content=result)

        # ── 2. Fall back to PostgreSQL (covers completed scans after restart) ──
        from backend.database import config as db_config
        from backend.database.scan_models import ScanHistory, Repository, Vulnerability as VulnModel
        from sqlalchemy import select

        if not db_config.is_db_available() or not db_config.AsyncSessionLocal:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

        async with db_config.AsyncSessionLocal() as db:
            # Load scan + repo in one query
            row = await db.execute(
                select(ScanHistory, Repository.owner, Repository.name)
                .join(Repository, ScanHistory.repository_id == Repository.id, isouter=True)
                .where(ScanHistory.scan_id == scan_id)
            )
            record = row.first()

            if not record:
                logger.warning(f"[{scan_id}] Not found in DB either")
                raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

            scan, repo_owner, repo_name = record

            # Load vulnerabilities for this scan
            vuln_rows = await db.execute(
                select(VulnModel).where(VulnModel.scan_id == scan.id)
            )
            vuln_records = vuln_rows.scalars().all()

            vulnerabilities = []
            for v in vuln_records:
                vulnerabilities.append({
                    "id":                   str(v.id),
                    "rule_id":              v.rule_id or "",
                    "scanner_name":         v.scanner_name or "",
                    "severity":             (v.severity or "info").lower(),
                    "message":              v.message or "",
                    "vulnerability_type":   v.vulnerability_type or "",
                    "confidence":           v.confidence or "",
                    "file_path":            v.file_path or "",
                    "start_line":           v.start_line or 0,
                    "end_line":             v.end_line or 0,
                    "code_snippet":         v.code_snippet or "",
                    "cwe_ids":              v.cwe_ids or [],
                    "owasp_categories":     v.owasp_categories or [],
                })

            severity_summary = {
                "critical": scan.critical_count or 0,
                "high":     scan.high_count or 0,
                "medium":   scan.medium_count or 0,
                "low":      scan.low_count or 0,
                "info":     0,
                "warning":  0,
            }

            completed_at = scan.completed_at
            started_at   = scan.started_at or scan.queued_at

            result = {
                "scan_id":            str(scan.scan_id),
                "repo_owner":         repo_owner or "unknown",
                "repo_name":          repo_name  or "unknown",
                "repo_url":           f"https://github.com/{repo_owner}/{repo_name}",
                "status":             scan.status,
                "vulnerabilities":    vulnerabilities,
                "scanner_used":       scan.scanner_mode or "",
                "total_issues":       scan.total_vulnerabilities or len(vulnerabilities),
                "severity_summary":   severity_summary,
                "detected_languages": scan.detected_languages or [],
                "scan_duration":      scan.scan_duration_seconds,
                "started_at":         started_at.isoformat()  if started_at   else None,
                "completed_at":       completed_at.isoformat() if completed_at else None,
                "error_message":      scan.error_message or None,
            }

            logger.info(f"[{scan_id}] Served from PostgreSQL — {len(vulnerabilities)} vulns")
            return JSONResponse(content=result)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{scan_id}] Error retrieving scan result: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving scan result: {str(e)}")


@router.get("/scans/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    try:
        result = get_scan_result(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Scan not found. ID: {scan_id}")

        status = result.get("status", "unknown")

        progress_map = {
            "queued": "0%", "cloning": "10%", "analyzing": "20%",
            "scanning": "30%", "scanning_semgrep": "50%",
            "scanning_codeql": "70%", "completed": "100%", "failed": "0%",
        }

        total_issues = result.get("total_issues", 0)
        error_msg = result.get("error_message", "Unknown error")
        is_inc = result.get("is_incremental", False)
        is_cached = result.get("served_from_cache", False)
        files_scanned = result.get("files_scanned")

        if is_cached:
            suffix = " (no changes — served from cache)"
        elif is_inc and files_scanned:
            suffix = f" (incremental — {files_scanned} files)"
        elif is_inc:
            suffix = " (incremental)"
        else:
            suffix = ""

        messages = {
            "completed": f"✓ Scan completed{suffix}! Found {total_issues} issue{'s' if total_issues != 1 else ''}",
            "failed": f"✗ Scan failed: {error_msg}",
            "queued": "⏳ Scan queued, waiting to start...",
            "cloning": "📥 Cloning repository...",
            "analyzing": "🔍 Analyzing repository structure...",
            "scanning": f"🔎 Starting security scan{suffix}...",
            "scanning_semgrep": f"🔎 Running Semgrep analysis{suffix}...",
            "scanning_codeql": "🔬 Running CodeQL analysis...",
        }

        return ScanStatus(
            scan_id=scan_id,
            status=status,
            message=messages.get(status, f"Status: {status}"),
            progress=progress_map.get(status, "0%"),
            repo_name=result.get("repo_name"),
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}/summary")
async def get_scan_summary(scan_id: str):
    try:
        result = get_scan_result(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Scan not found. ID: {scan_id}")

        summary = {
            "scan_id": result.get("scan_id"),
            "repo_owner": result.get("repo_owner"),
            "repo_name": result.get("repo_name"),
            "repo_url": result.get("repo_url"),
            "status": result.get("status"),
            "total_issues": result.get("total_issues", 0),
            "severity_summary": result.get("severity_summary"),
            "scanner_used": result.get("scanner_used"),
            "detected_languages": result.get("detected_languages", []),
            "scan_duration": result.get("scan_duration"),
            "started_at": result.get("started_at"),
            "completed_at": result.get("completed_at"),
            "error_message": result.get("error_message"),
            "vulnerabilities": result.get("vulnerabilities", []),
            "is_incremental": result.get("is_incremental", False),
            "scan_strategy": result.get("scan_strategy"),
            "files_scanned": result.get("files_scanned"),
            "files_skipped": result.get("files_skipped"),
            "changed_files_count": result.get("changed_files_count"),
            "served_from_cache": result.get("served_from_cache", False),
        }

        return JSONResponse(content=summary)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/history")
async def get_scan_history(request: Request, limit: Optional[int] = 50):
    try:
        all_scans = get_all_scan_results()
        scans = list(all_scans.values())
        scans.sort(key=lambda x: x.get("started_at") or x.get("scan_id", ""), reverse=True)
        scans = scans[:limit]
        return {
            "total_scans": len(all_scans),
            "scans": [
                {
                    "scan_id": s.get("scan_id"),
                    "repo_owner": s.get("repo_owner"),
                    "repo_name": s.get("repo_name"),
                    "status": s.get("status"),
                    "total_issues": s.get("total_issues", 0),
                    "severity_summary": s.get("severity_summary"),
                    "scan_duration": s.get("scan_duration"),
                    "completed_at": s.get("completed_at"),
                    "is_incremental": s.get("is_incremental", False),
                    "scan_strategy": s.get("scan_strategy"),
                    "changed_files_count": s.get("changed_files_count"),
                    "served_from_cache": s.get("served_from_cache", False),
                }
                for s in scans
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/scans/{scan_id}")
async def delete_scan_endpoint(scan_id: str):
    try:
        result = get_scan_result(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Scan not found. ID: {scan_id}")

        in_progress = ["queued", "cloning", "analyzing", "scanning", "scanning_semgrep", "scanning_codeql"]
        if result.get("status") in in_progress:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete scan in progress. Status: {result.get('status')}",
            )

        if delete_scan(scan_id):
            return {"message": "Scan deleted successfully", "scan_id": scan_id,
                    "deleted_at": datetime.now().isoformat()}
        raise HTTPException(status_code=500, detail="Failed to delete scan")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD ENDPOINTS — unchanged
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/dashboard/stats")
async def get_dashboard_stats(request: Request):
    user_id = await get_user_id(request)
    if user_id == "anonymous":
        return {"stats": {"totalRepos": 0, "totalScans": 0, "criticalVulns": 0,
                          "highVulns": 0, "mediumVulns": 0, "lowVulns": 0,
                          "filesScanned": 0, "recentAlerts": 0}}
    try:
        from backend.database import config as db_config
        from sqlalchemy import select, func
        from backend.database.scan_models import ScanHistory, Repository

        if not db_config.is_db_available() or not db_config.AsyncSessionLocal:
            return {"stats": {"totalRepos": 0, "totalScans": 0, "criticalVulns": 0,
                              "highVulns": 0, "mediumVulns": 0, "lowVulns": 0,
                              "filesScanned": 0, "recentAlerts": 0}}

        async with db_config.AsyncSessionLocal() as db:
            latest_sq = (
                select(ScanHistory.repository_id,
                       func.max(ScanHistory.completed_at).label("max_completed"))
                .where(ScanHistory.user_id == user_id)
                .where(ScanHistory.status == "completed")
                .group_by(ScanHistory.repository_id)
                .subquery()
            )
            latest_res = await db.execute(
                select(ScanHistory).join(
                    latest_sq,
                    (ScanHistory.repository_id == latest_sq.c.repository_id) &
                    (ScanHistory.completed_at == latest_sq.c.max_completed),
                )
            )
            tc = th = tm = tl = tf = 0
            for s in latest_res.scalars():
                tc += s.critical_count or 0
                th += s.high_count or 0
                tm += s.medium_count or 0
                tl += s.low_count or 0
                tf += s.files_scanned or 0

            repos = (await db.execute(
                select(func.count(Repository.id)).where(Repository.user_id == user_id)
            )).scalar() or 0
            scans = (await db.execute(
                select(func.count(ScanHistory.id)).where(ScanHistory.user_id == user_id)
            )).scalar() or 0

            return {"stats": {"totalRepos": repos, "totalScans": scans,
                              "criticalVulns": tc, "highVulns": th,
                              "mediumVulns": tm, "lowVulns": tl,
                              "filesScanned": tf, "recentAlerts": tc + th}}
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        return {"stats": {"totalRepos": 0, "totalScans": 0, "criticalVulns": 0,
                          "highVulns": 0, "mediumVulns": 0, "lowVulns": 0,
                          "filesScanned": 0, "recentAlerts": 0}}



@router.get("/dashboard/trends")
async def get_vulnerability_trends(request: Request, days: int = 7):
    user_id = await get_user_id(request)
    if user_id == "anonymous":
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        from backend.database import config as db_config
        from sqlalchemy import select, func, and_
        from backend.database.scan_models import ScanHistory
        from datetime import timezone
        async with db_config.AsyncSessionLocal() as db:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            rows = await db.execute(
                select(func.date_trunc("day", ScanHistory.completed_at).label("day"),
                       func.sum(ScanHistory.critical_count).label("critical"),
                       func.sum(ScanHistory.high_count).label("high"),
                       func.sum(ScanHistory.medium_count).label("medium"))
                .where(and_(ScanHistory.user_id == user_id,
                            ScanHistory.status == "completed",
                            ScanHistory.completed_at >= cutoff))
                .group_by("day").order_by("day")
            )
            trends = [{"name": r.day.strftime("%a"), "critical": int(r.critical or 0),
                       "high": int(r.high or 0), "medium": int(r.medium or 0)} for r in rows]
            if not trends:
                trends = [{"name": d, "critical": 0, "high": 0, "medium": 0}
                          for d in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]]
            return {"trends": trends}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/recent-scans")
async def get_recent_scans(request: Request, limit: int = 10):
    user_id = await get_user_id(request)
    if user_id == "anonymous":
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        from backend.database import config as db_config
        from sqlalchemy import select, desc
        from backend.database.scan_models import ScanHistory, Repository
        async with db_config.AsyncSessionLocal() as db:
            rows = await db.execute(
                select(ScanHistory, Repository.name)
                .join(Repository, ScanHistory.repository_id == Repository.id, isouter=True)
                .where(ScanHistory.user_id == user_id)
                .order_by(desc(ScanHistory.queued_at)).limit(limit)
            )
            return {"recentActivity": [
                {"id": str(s.id), "repo": rn or "Unknown", "status": s.status,
                 "time": _time_ago(s.completed_at or s.queued_at),
                 "issues": s.total_vulnerabilities or 0}
                for s, rn in rows
            ]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/vulnerable-files")
async def get_vulnerable_files(request: Request, limit: int = 10):
    user_id = await get_user_id(request)
    if user_id == "anonymous":
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        from backend.database import config as db_config
        from sqlalchemy import select, and_, desc
        from backend.database.scan_models import Vulnerability, ScanHistory
        async with db_config.AsyncSessionLocal() as db:
            rows = await db.execute(
                select(Vulnerability)
                .join(ScanHistory, Vulnerability.scan_id == ScanHistory.id)
                .where(and_(ScanHistory.user_id == user_id,
                            Vulnerability.severity.in_(["CRITICAL", "HIGH"])))
                .order_by(desc(Vulnerability.severity), desc(Vulnerability.detected_at))
                .limit(limit)
            )
            return {"vulnerableFiles": [
                {"file": v.file_path, "type": v.vulnerability_type or v.rule_id,
                 "severity": v.severity}
                for v in rows.scalars()
            ]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _time_ago(dt):
    if not dt:
        return "Unknown"
    from datetime import timezone
    diff = datetime.now(timezone.utc) - dt
    s = diff.total_seconds()
    if s < 60: return "Just now"
    if s < 3600: return f"{int(s/60)} min ago"
    if s < 86400: return f"{int(s/3600)} hour ago"
    return f"{int(s/86400)} days ago"