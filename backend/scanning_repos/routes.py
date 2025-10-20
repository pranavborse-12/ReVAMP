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

router = APIRouter()


@router.post("/repos/{owner}/{repo}/scan", response_model=ScanStatus)
async def scan_repository(
    owner: str,
    repo: str,
    request: Request,
    background_tasks: BackgroundTasks,
    branch: Optional[str] = "main",
    scanner: Optional[str] = "auto",
    authorization: Optional[str] = Header(None)
):
    """
    Initiate a security scan on a user's GitHub repository
    
    Parameters:
    - owner: Repository owner (GitHub username)
    - repo: Repository name
    - branch: Branch to scan (default: main)
    - scanner: Scanner mode - auto, semgrep, codeql, both (default: auto)
    - authorization: Optional custom Semgrep token
    """
    try:
        # Get GitHub token from request
        github_token = None
        
        # Try cookie first
        github_token = request.cookies.get("github_access_token")
        
        # Try JWT payload
        if not github_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                try:
                    token = auth_header.split(" ")[1]
                    payload = await JWTManager.verify_token(token)
                    if payload and "github_token" in payload:
                        github_token = payload["github_token"]
                except Exception as e:
                    logger.error(f"Error extracting GitHub token: {e}")
        
        if not github_token:
            raise HTTPException(
                status_code=401,
                detail="GitHub authentication required. Please reconnect your GitHub account."
            )
        
        # Check concurrent scan limit
        current_active = get_active_scans()
        if current_active >= MAX_CONCURRENT_SCANS:
            logger.warning(f"Scan request rejected: {current_active}/{MAX_CONCURRENT_SCANS} active scans")
            raise HTTPException(
                status_code=429,
                detail=f"Too many concurrent scans. Currently {current_active}/{MAX_CONCURRENT_SCANS} active. Please wait."
            )
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        logger.info(f"[{scan_id}] New scan request for {owner}/{repo}")
        logger.info(f"[{scan_id}] Branch: {branch}, Scanner: {scanner}")
        
        # Get Semgrep token
        semgrep_token = get_semgrep_token(authorization)
        if semgrep_token:
            logger.info(f"[{scan_id}] Using custom Semgrep token")
        
        # Initialize scan in global state
        initialize_scan(scan_id, owner, repo)
        logger.info(f"[{scan_id}] Scan initialized")
        
        # Verify scan was initialized
        verify_scan = get_scan_result(scan_id)
        if verify_scan is None:
            logger.error(f"[{scan_id}] Failed to initialize scan!")
            raise HTTPException(
                status_code=500,
                detail="Failed to initialize scan. Please try again."
            )
        
        # Add background task (non-async wrapper needed)
        background_tasks.add_task(
            perform_scan,
            scan_id,
            github_token,
            owner,
            repo,
            branch,
            semgrep_token,
            scanner,
            10000
        )
        
        logger.info(f"[{scan_id}] Background task queued")
        
        return ScanStatus(
            scan_id=scan_id,
            status='queued',
            message=f'Scan queued for {owner}/{repo} in {scanner} mode',
            progress='0%',
            repo_name=repo
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating scan: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to initiate scan: {str(e)}"
        )


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