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
    ✅ FIXED: Always returns proper JSON, never crashes
    """
    try:
        github_token = request.cookies.get("github_access_token")
        if not github_token:
            raise HTTPException(status_code=401, detail="GitHub token required")
        
        user_id = await get_user_id(request)
        
        # ✅ STEP 1: Fetch latest commit from GitHub (with error handling)
        latest_commit = await CommitTracker.get_latest_commit(
            github_token, owner, repo, branch
        )
        
        # ✅ FIXED: Handle GitHub API failure gracefully
        if not latest_commit:
            logger.warning(
                f"⚠️ Could not fetch commits for {owner}/{repo}@{branch}. "
                f"Allowing scan anyway (first-time or API issue)."
            )
            # Return safe default response
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
        
        # ✅ STEP 2: Get repository from database
        from backend.database import config as db_config
        from backend.database.scan_models import Repository
        
        # ✅ FIXED: Check database availability
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
            
            # ✅ CASE 1: Repository not in database (first scan)
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
            
            # ✅ STEP 3: Check eligibility with database record
            is_eligible, reason, remaining = await CommitTracker.check_scan_eligibility(
                db, str(repository.id), latest_commit["sha"]
            )
            
            # ✅ STEP 4: Get commit comparison (if we have history)
            has_new_commits = False
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
                    has_new_commits = len(new_commits) > 0
                    new_commits_count = len(new_commits)
            
            # ✅ FIXED: Always return consistent response structure
            return {
                "eligible": is_eligible,
                "reason": reason,
                "remaining_scans": remaining,
                "latest_commit": latest_commit["sha"][:7],
                "commit_message": latest_commit["message"][:100],
                "last_scanned_commit": last_scanned,
                "has_new_commits": has_new_commits,
                "new_commits_count": new_commits_count,
                "is_first_scan": False
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Eligibility check error for {owner}/{repo}: {e}", exc_info=True)
        # ✅ FIXED: Return safe fallback instead of 500 error
        return {
            "eligible": True,  # Allow scan on error
            "reason": f"Error checking eligibility - allowing scan",
            "remaining_scans": CommitTracker.INITIAL_SCAN_ALLOWANCE,
            "latest_commit": "unknown",
            "commit_message": "Error fetching commit info",
            "is_first_scan": True,
            "has_new_commits": False,
            "new_commits_count": 0,
            "last_scanned_commit": None
        }

@router.get("/scans/{scan_id}")
async def get_scan_result_endpoint(scan_id: str):
    """Get detailed scan results by scan ID"""
    try:
        logger.info(f"[{scan_id}] Retrieving scan result")
        
        result = get_scan_result(scan_id)
        
        if result is None:
            logger.warning(f"[{scan_id}] Scan not found")
            raise HTTPException(
                status_code=404,
                detail=f"Scan not found. ID: {scan_id}"
            )
        
        return JSONResponse(content=result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{scan_id}] Error retrieving scan result: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving scan result: {str(e)}"
        )


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


@router.get("/scans/history")
async def get_scan_history(
    request: Request,
    limit: Optional[int] = 50
):
    """Get user's scan history"""
    try:
        all_scans = get_all_scan_results()
        scans = list(all_scans.values())
        
        scans.sort(
            key=lambda x: x.get('started_at') or x.get('scan_id', ''),
            reverse=True
        )
        
        scans = scans[:limit]
        
        return {
            "total_scans": len(all_scans),
            "scans": [
                {
                    "scan_id": s.get('scan_id'),
                    "repo_owner": s.get('repo_owner'),
                    "repo_name": s.get('repo_name'),
                    "status": s.get('status'),
                    "total_issues": s.get('total_issues', 0),
                    "severity_summary": s.get('severity_summary'),
                    "scan_duration": s.get('scan_duration'),
                    "completed_at": s.get('completed_at')
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
            return {"stats": {...}}  # empty
        
        async with db_config.AsyncSessionLocal() as db:
            # Get LATEST scan per repository (not sum of all scans!)
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
            
            # Get actual latest scans
            latest_scans_result = await db.execute(
                select(ScanHistory)
                .join(
                    latest_scans_subquery,
                    (ScanHistory.repository_id == latest_scans_subquery.c.repository_id) &
                    (ScanHistory.completed_at == latest_scans_subquery.c.max_completed)
                )
            )
            
            # Calculate CURRENT state (not cumulative!)
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
            
            # Total repositories
            repos_count = await db.execute(
                select(func.count(Repository.id)).where(Repository.user_id == user_id)
            )
            total_repos = repos_count.scalar() or 0
            
            # Total scans ever performed
            scans_count = await db.execute(
                select(func.count(ScanHistory.id)).where(ScanHistory.user_id == user_id)
            )
            total_scans = scans_count.scalar() or 0
            
            logger.info(f"📊 REAL-TIME Dashboard: {total_repos} repos, {total_files} files, {total_critical} critical")
            
            return {
                "stats": {
                    "totalRepos": total_repos,
                    "totalScans": total_scans,
                    "criticalVulns": total_critical,  # CURRENT state
                    "highVulns": total_high,
                    "mediumVulns": total_medium,
                    "lowVulns": total_low,
                    "filesScanned": total_files,  # ACTUAL files
                    "recentAlerts": total_critical + total_high
                }
            }
            
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        return {"stats": {...}}

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
            
            # Get scans grouped by day
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
            
            # If no trends data, generate empty week
            if len(trends) == 0:
                days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
                trends = [{"name": day, "critical": 0, "high": 0, "medium": 0} for day in days]
            
            logger.info(f"📈 Trends: {len(trends)} days of data")
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
            # Get critical and high severity vulnerabilities
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