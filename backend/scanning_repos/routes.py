"""
API routes for repository scanning
Integrates with authentication and GitHub repositories
"""
import uuid
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, Header, Request, Depends
from fastapi.responses import JSONResponse
from ..auth.authentication import get_current_user, store as auth_store, JWTManager
from .config import (
    logger, MAX_CONCURRENT_SCANS, SEMGREP_APP_TOKEN
)
from .models import ScanRequest, ScanStatus, ScanResult
from .utils import get_semgrep_token
from .background_tasks import (
    perform_scan,
    initialize_scan,
    get_scan_result,
    get_all_scan_results,
    get_active_scans,
    delete_scan,
    get_user_scans
)
from .commit_tracker import CommitTracker
from sqlalchemy import select

router = APIRouter()

async def get_user_id(request: Request) -> str:
    """
    Extract user_id from request cookies or JWT token
    FIXED: Proper UUID validation and database fallback
    """
    import uuid as uuid_module
    user_id = None
    # Try to get user session from cookie
    session_token = request.cookies.get("session_token")
    if session_token:
        try:
            payload = await JWTManager.verify_token(session_token)
            if payload:
                user_id = payload.get("user_id") or payload.get("id")
        except Exception as e:
            logger.debug(f"Session decode failed: {e}")
    
    # Try JWT from Authorization header as fallback
    if not user_id:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                token = auth_header.split(" ")[1]
                payload = await JWTManager.verify_token(token)
                if payload:
                    user_id = payload.get("user_id") or payload.get("id")
                    
                    # If no user_id but have email, try database lookup
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
                                        logger.info(f"✅ Retrieved user_id from database: {user_id}")
                        except Exception as db_error:
                            logger.warning(f"Database lookup failed: {db_error}")
                            
            except Exception as e:
                logger.error(f"Error extracting from JWT: {e}")
    
    # Validate UUID format
    if user_id and user_id != "anonymous":
        try:
            uuid_module.UUID(user_id)
            logger.debug(f"Valid user_id: {user_id}")
            return user_id
        except (ValueError, AttributeError):
            logger.warning(f"Invalid UUID format: {user_id}")
    
    logger.warning("No valid user_id found, returning anonymous")
    return "anonymous"

@router.post("/repos/{owner}/{repo}/check-eligibility")
async def check_scan_eligibility(
    owner: str,
    repo: str,
    request: Request,
    branch: Optional[str] = "main"
):
    """
    Check if repository can be scanned
    ✅ FIXED: Returns accurate eligibility without modifying database state
    """
    try:
        github_token = request.cookies.get("github_access_token")
        if not github_token:
            raise HTTPException(status_code=401, detail="GitHub token required")
        
        user_id = await get_user_id(request)
        
        # STEP 1: Fetch latest commit from GitHub
        latest_commit = await CommitTracker.get_latest_commit(
            github_token, owner, repo, branch
        )
        
        # Handle GitHub API failure gracefully
        if not latest_commit:
            logger.warning(
                f"⚠️ Could not fetch commits for {owner}/{repo}@{branch}. "
                f"Allowing scan anyway (first-time or API issue)."
            )
            return {
                "eligible": True,
                "reason": "Unable to verify commits - allowing scan",
                "remaining_scans": CommitTracker.INITIAL_SCAN_ALLOWANCE,
                "latest_commit": "unknown",
                "commit_message": "Could not fetch commit info",
                "is_first_scan": True,
                "has_new_commits": False,
                "new_commits_count": 0,
                "last_scanned_commit": None
            }
        
        # STEP 2: Get repository from database
        from backend.database import config as db_config
        from backend.database.scan_models import Repository
        
        if not db_config.is_db_available() or not db_config.AsyncSessionLocal:
            logger.warning("Database not available, allowing scan")
            return {
                "eligible": True,
                "reason": "First scan (database unavailable)",
                "remaining_scans": CommitTracker.INITIAL_SCAN_ALLOWANCE,
                "latest_commit": latest_commit["sha"][:7],
                "commit_message": latest_commit["message"][:100],
                "is_first_scan": True,
                "has_new_commits": False,
                "new_commits_count": 0,
                "last_scanned_commit": None
            }
        
        async with db_config.AsyncSessionLocal() as db:
            result = await db.execute(
                select(Repository).where(
                    Repository.user_id == user_id,
                    Repository.owner == owner,
                    Repository.name == repo
                )
            )
            repository = result.scalar_one_or_none()
            
            # CASE 1: Repository not in database (first scan)
            if not repository:
                logger.info(f"✅ First scan for {owner}/{repo}")
                return {
                    "eligible": True,
                    "reason": "First scan of this repository",
                    "remaining_scans": CommitTracker.INITIAL_SCAN_ALLOWANCE,
                    "latest_commit": latest_commit["sha"][:7],
                    "commit_message": latest_commit["message"][:100],
                    "is_first_scan": True,
                    "has_new_commits": False,
                    "new_commits_count": 0,
                    "last_scanned_commit": None
                }
            
            # STEP 3: Check eligibility (this does NOT modify database)
            is_eligible, reason, remaining, has_new_commits = await CommitTracker.check_scan_eligibility(
                db, str(repository.id), latest_commit["sha"]
            )
            
            # STEP 4: Get commit comparison
            new_commits_count = 0
            last_scanned = None
            
            if repository.last_scan_commit_sha:
                last_scanned = repository.last_scan_commit_sha[:7]
                
                # Only fetch commit history if commits are different
                if latest_commit["sha"] != repository.last_scan_commit_sha:
                    new_commits = await CommitTracker.get_commits_since(
                        github_token, owner, repo,
                        repository.last_scan_commit_sha, branch
                    )
                    new_commits_count = len(new_commits)
            
            return {
                "eligible": is_eligible,
                "reason": reason,
                "remaining_scans": remaining if not has_new_commits else CommitTracker.INITIAL_SCAN_ALLOWANCE,
                "latest_commit": latest_commit["sha"][:7],
                "commit_message": latest_commit["message"][:100],
                "is_first_scan": repository.last_scan_commit_sha is None,
                "has_new_commits": has_new_commits,
                "new_commits_count": new_commits_count,
                "last_scanned_commit": last_scanned
            }
            
    except Exception as e:
        logger.error(f"Eligibility check failed: {e}", exc_info=True)
        # Fail open - allow scan if we can't check
        return {
            "eligible": True,
            "reason": f"Eligibility check failed: {str(e)}",
            "remaining_scans": CommitTracker.INITIAL_SCAN_ALLOWANCE,
            "latest_commit": "error",
            "commit_message": "Error checking commits",
            "is_first_scan": True,
            "has_new_commits": False,
            "new_commits_count": 0,
            "last_scanned_commit": None
        }


@router.post("/repos/{owner}/{repo}/scan")
async def start_scan(
    owner: str,
    repo: str,
    request: Request,
    background_tasks: BackgroundTasks,
    branch: Optional[str] = "main",
    force: bool = False
):
    """
    Start vulnerability scan.
    """
    try:
        github_token = request.cookies.get("github_access_token")
        if not github_token:
            raise HTTPException(status_code=401, detail="GitHub token required")
        
        user_id = await get_user_id(request)
        
        # STEP 1: Fetch latest commit
        latest_commit = await CommitTracker.get_latest_commit(
            github_token, owner, repo, branch
        )
        
        if not latest_commit:
            raise HTTPException(
                status_code=400,
                detail="Could not fetch repository commit information"
            )
        
        current_commit_sha = latest_commit["sha"]
        
        # STEP 2: Get or create repository in database
        from backend.database import config as db_config
        from backend.database.scan_models import Repository
        
        if not db_config.is_db_available() or not db_config.AsyncSessionLocal:
            raise HTTPException(
                status_code=503,
                detail="Database not available"
            )
        
        async with db_config.AsyncSessionLocal() as db:
            result = await db.execute(
                select(Repository).where(
                    Repository.user_id == user_id,
                    Repository.owner == owner,
                    Repository.name == repo
                )
            )
            repository = result.scalar_one_or_none()
            
            # Create repository if it doesn't exist
            if not repository:
                from backend.database.scan_service import ScanService
                repository = await ScanService.get_or_create_repository(
                    db=db,
                    user_id=user_id,
                    owner=owner,
                    repo_name=repo,
                    github_url=f"https://github.com/{owner}/{repo}",
                    default_branch=branch
                )
                await db.commit()
                await db.refresh(repository)
                logger.info(f"✅ Created new repository record for {owner}/{repo}")
            
            # STEP 3: Check eligibility (unless forced)
            if not force:
                is_eligible, reason, remaining, has_new_commits = await CommitTracker.check_scan_eligibility(
                    db, str(repository.id), current_commit_sha
                )
                
                if not is_eligible:
                    raise HTTPException(status_code=403, detail=reason)
                
                # Reset allowance if new commits detected
                if has_new_commits:
                    await CommitTracker.reset_allowance_for_new_commits(
                        db, str(repository.id), current_commit_sha
                    )
                    logger.info(f"✅ Allowance reset for new commits in {owner}/{repo}")
        
        # STEP 4: Generate scan ID
        scan_id = str(uuid.uuid4())
        semgrep_token = get_semgrep_token(SEMGREP_APP_TOKEN)
        
        logger.info(
            f"[{scan_id}] Starting scan for {owner}/{repo}@{branch} "
            f"(commit: {current_commit_sha[:7]})"
        )

        # Pre-populate in-memory state BEFORE launching the background task
        initialize_scan(
            scan_id=scan_id,
            repo_owner=owner,
            repo_name=repo,
            user_id=user_id,
            branch=branch
        )
        logger.info(f"[{scan_id}] ✅ In-memory state pre-populated before background task")

        # STEP 5: Launch background scan task
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
            current_commit_sha=current_commit_sha
        )
        
        return {
            "scan_id": scan_id,
            "status": "queued",
            "message": f"Scan initiated for {owner}/{repo}",
            "commit_sha": current_commit_sha[:7]
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
    """Get scan status with progress information"""
    try:
        logger.debug(f"[{scan_id}] Status check requested")
        
        result = get_scan_result(scan_id)
        
        if result is None:
            logger.warning(f"[{scan_id}] Scan not found")
            raise HTTPException(
                status_code=404,
                detail=f"Scan not found. ID: {scan_id}"
            )
        
        status = result.get('status', 'unknown')
        
        progress_map = {
            'queued': '0%',
            'cloning': '10%',
            'analyzing': '20%',
            'scanning': '30%',
            'scanning_semgrep': '50%',
            'scanning_codeql': '70%',
            'completed': '100%',
            'failed': '0%'
        }
        
        progress = progress_map.get(status, '0%')
        
        total_issues = result.get('total_issues', 0)
        error_msg = result.get('error_message', 'Unknown error')
        
        messages = {
            'completed': f"✓ Scan completed! Found {total_issues} issue{'s' if total_issues != 1 else ''}",
            'failed': f"✗ Scan failed: {error_msg}",
            'queued': "⏳ Scan queued, waiting to start...",
            'cloning': f"📥 Cloning repository...",
            'analyzing': f"🔍 Analyzing repository structure...",
            'scanning': f"🔎 Starting security scan...",
            'scanning_semgrep': f"🔎 Running Semgrep analysis...",
            'scanning_codeql': f"🔬 Running CodeQL analysis..."
        }
        
        message = messages.get(status, f"Status: {status}")
        
        return ScanStatus(
            scan_id=scan_id,
            status=status,
            message=message,
            progress=progress,
            repo_name=result.get('repo_name')
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{scan_id}] Error retrieving scan status: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving scan status: {str(e)}"
        )


@router.get("/scans/{scan_id}/summary")
async def get_scan_summary(scan_id: str):
    """Get scan summary with vulnerability details"""
    try:
        logger.info(f"[{scan_id}] Retrieving scan summary")
        
        result = get_scan_result(scan_id)
        
        if result is None:
            logger.warning(f"[{scan_id}] Scan not found")
            raise HTTPException(
                status_code=404,
                detail=f"Scan not found. ID: {scan_id}"
            )
        
        summary = {
            "scan_id": result.get('scan_id'),
            "repo_owner": result.get('repo_owner'),
            "repo_name": result.get('repo_name'),
            "repo_url": result.get('repo_url'),
            "status": result.get('status'),
            "total_issues": result.get('total_issues', 0),
            "severity_summary": result.get('severity_summary'),
            "scanner_used": result.get('scanner_used'),
            "detected_languages": result.get('detected_languages', []),
            "scan_duration": result.get('scan_duration'),
            "started_at": result.get('started_at'),
            "completed_at": result.get('completed_at'),
            "error_message": result.get('error_message'),
            "vulnerabilities": result.get('vulnerabilities', [])
        }
        
        logger.info(f"[{scan_id}] Summary retrieved - {summary['total_issues']} issues found")
        
        return JSONResponse(content=summary)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{scan_id}] Error retrieving summary: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving scan summary: {str(e)}"
        )


@router.delete("/scans/{scan_id}")
async def delete_scan_endpoint(scan_id: str):
    """Delete a scan result"""
    try:
        logger.info(f"[{scan_id}] Delete request received")
        
        result = get_scan_result(scan_id)
        
        if result is None:
            logger.warning(f"[{scan_id}] Scan not found")
            raise HTTPException(
                status_code=404,
                detail=f"Scan not found. ID: {scan_id}"
            )
        
        in_progress_statuses = [
            'queued', 'cloning', 'analyzing',
            'scanning', 'scanning_semgrep', 'scanning_codeql'
        ]
        
        status = result.get('status')
        if status in in_progress_statuses:
            logger.warning(f"[{scan_id}] Cannot delete scan in progress")
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete scan in progress. Current status: {status}"
            )
        
        deleted = delete_scan(scan_id)
        
        if deleted:
            logger.info(f"[{scan_id}] Scan deleted successfully")
            return {
                "message": "Scan deleted successfully",
                "scan_id": scan_id,
                "deleted_at": datetime.now().isoformat()
            }
        else:
            logger.error(f"[{scan_id}] Failed to delete scan")
            raise HTTPException(
                status_code=500,
                detail="Failed to delete scan"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{scan_id}] Error deleting scan: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error deleting scan: {str(e)}"
        )


@router.get("/dashboard/stats")
async def get_dashboard_stats(request: Request):
    """Get REAL-TIME dashboard statistics (current state, not cumulative)"""
    user_id = await get_user_id(request)
    
    if user_id == "anonymous":
        return {
            "stats": {
                "totalRepos": 0,
                "totalScans": 0,
                "criticalVulns": 0,
                "highVulns": 0,
                "mediumVulns": 0,
                "lowVulns": 0,
                "filesScanned": 0,
                "recentAlerts": 0
            }
        }
    
    try:
        from backend.database import config as db_config
        from sqlalchemy import select, func, desc
        from backend.database.scan_models import ScanHistory, Repository
        
        if not db_config.is_db_available() or not db_config.AsyncSessionLocal:
            return {"stats": {
                "totalRepos": 0, "totalScans": 0,
                "criticalVulns": 0, "highVulns": 0,
                "mediumVulns": 0, "lowVulns": 0,
                "filesScanned": 0, "recentAlerts": 0
            }}
        
        async with db_config.AsyncSessionLocal() as db:
            latest_scans_subquery = (
                select(
                    ScanHistory.repository_id,
                    func.max(ScanHistory.completed_at).label('max_completed')
                )
                .where(ScanHistory.user_id == user_id)
                .where(ScanHistory.status == "completed")
                .group_by(ScanHistory.repository_id)
                .subquery()
            )
            
            latest_scans_result = await db.execute(
                select(ScanHistory)
                .join(
                    latest_scans_subquery,
                    (ScanHistory.repository_id == latest_scans_subquery.c.repository_id) &
                    (ScanHistory.completed_at == latest_scans_subquery.c.max_completed)
                )
            )
            
            total_critical = 0
            total_high = 0
            total_medium = 0
            total_low = 0
            total_files = 0
            
            for scan in latest_scans_result.scalars():
                total_critical += scan.critical_count or 0
                total_high += scan.high_count or 0
                total_medium += scan.medium_count or 0
                total_low += scan.low_count or 0
                total_files += scan.files_scanned or 0
            
            repos_count = await db.execute(
                select(func.count(Repository.id)).where(Repository.user_id == user_id)
            )
            total_repos = repos_count.scalar() or 0
            
            scans_count = await db.execute(
                select(func.count(ScanHistory.id)).where(ScanHistory.user_id == user_id)
            )
            total_scans = scans_count.scalar() or 0
            
            return {
                "stats": {
                    "totalRepos": total_repos,
                    "totalScans": total_scans,
                    "criticalVulns": total_critical,
                    "highVulns": total_high,
                    "mediumVulns": total_medium,
                    "lowVulns": total_low,
                    "filesScanned": total_files,
                    "recentAlerts": total_critical + total_high
                }
            }
            
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        return {"stats": {
            "totalRepos": 0, "totalScans": 0,
            "criticalVulns": 0, "highVulns": 0,
            "mediumVulns": 0, "lowVulns": 0,
            "filesScanned": 0, "recentAlerts": 0
        }}


@router.get("/dashboard/trends")
async def get_vulnerability_trends(request: Request, days: int = 7):
    """Get vulnerability trends over time"""
    user_id = await get_user_id(request)
    
    if user_id == "anonymous":
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        from backend.database import config as db_config
        from sqlalchemy import select, func, and_
        from backend.database.scan_models import ScanHistory
        from datetime import datetime, timedelta, timezone
        
        async with db_config.AsyncSessionLocal() as db:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            scans = await db.execute(
                select(
                    func.date_trunc('day', ScanHistory.completed_at).label('day'),
                    func.sum(ScanHistory.critical_count).label('critical'),
                    func.sum(ScanHistory.high_count).label('high'),
                    func.sum(ScanHistory.medium_count).label('medium')
                )
                .where(
                    and_(
                        ScanHistory.user_id == user_id,
                        ScanHistory.status == "completed",
                        ScanHistory.completed_at >= cutoff_date
                    )
                )
                .group_by('day')
                .order_by('day')
            )
            
            trends = []
            for row in scans:
                trends.append({
                    "name": row.day.strftime("%a"),
                    "critical": int(row.critical or 0),
                    "high": int(row.high or 0),
                    "medium": int(row.medium or 0)
                })
            
            if len(trends) == 0:
                day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
                trends = [{"name": d, "critical": 0, "high": 0, "medium": 0} for d in day_names]
            
            return {"trends": trends}
            
    except Exception as e:
        logger.error(f"Trends error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/recent-scans")
async def get_recent_scans(request: Request, limit: int = 10):
    """Get recent scan activity"""
    user_id = await get_user_id(request)
    
    if user_id == "anonymous":
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        from backend.database import config as db_config
        from backend.database.scan_service import ScanService
        from sqlalchemy import select, desc
        from backend.database.scan_models import ScanHistory, Repository
        
        async with db_config.AsyncSessionLocal() as db:
            scans = await db.execute(
                select(ScanHistory, Repository.name)
                .join(Repository, ScanHistory.repository_id == Repository.id, isouter=True)
                .where(ScanHistory.user_id == user_id)
                .order_by(desc(ScanHistory.queued_at))
                .limit(limit)
            )
            
            activity = []
            for scan, repo_name in scans:
                activity.append({
                    "id": str(scan.id),
                    "repo": repo_name or "Unknown",
                    "status": scan.status,
                    "time": _time_ago(scan.completed_at or scan.queued_at),
                    "issues": scan.total_vulnerabilities or 0
                })
            
            return {"recentActivity": activity}
            
    except Exception as e:
        logger.error(f"Recent scans error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard/vulnerable-files")
async def get_vulnerable_files(request: Request, limit: int = 10):
    """Get top vulnerable files"""
    user_id = await get_user_id(request)
    
    if user_id == "anonymous":
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        from backend.database import config as db_config
        from sqlalchemy import select, and_, desc
        from backend.database.scan_models import Vulnerability, ScanHistory
        
        async with db_config.AsyncSessionLocal() as db:
            vulns = await db.execute(
                select(Vulnerability)
                .join(ScanHistory, Vulnerability.scan_id == ScanHistory.id)
                .where(
                    and_(
                        ScanHistory.user_id == user_id,
                        Vulnerability.severity.in_(["CRITICAL", "HIGH"])
                    )
                )
                .order_by(
                    desc(Vulnerability.severity),
                    desc(Vulnerability.detected_at)
                )
                .limit(limit)
            )
            
            vulnerable_files = []
            for vuln in vulns.scalars():
                vulnerable_files.append({
                    "file": vuln.file_path,
                    "type": vuln.vulnerability_type or vuln.rule_id,
                    "severity": vuln.severity
                })
            
            return {"vulnerableFiles": vulnerable_files}
            
    except Exception as e:
        logger.error(f"Vulnerable files error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _time_ago(dt):
    """Helper to format time ago"""
    if not dt:
        return "Unknown"
    
    from datetime import datetime, timezone
    diff = datetime.now(timezone.utc) - dt
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "Just now"
    elif seconds < 3600:
        return f"{int(seconds / 60)} min ago"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hour ago"
    else:
        return f"{int(seconds / 86400)} days ago"