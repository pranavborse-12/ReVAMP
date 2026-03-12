"""
Complete storage interface for scans with FIXED commit tracking
✅ Updates commit SHA and consumes allowance atomically
✅ Proper error handling and logging
✅ Clean separation of concerns
"""
from typing import Optional, Any
from backend.database.config import get_db, is_db_available
from backend.database import config as db_config
from backend.database.scan_service import ScanService
from backend.database.scan_models import ScanStatusEnum
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


async def save_scan_to_db(
    scan_id, 
    user_id, 
    repo_owner, 
    repo_name, 
    branch, 
    scanner_mode,
    commit_sha: Optional[str] = None
):
    """
    Initialize scan in database
    Creates repository record and scan_history record
    ✅ FIXED: Doesn't pass commit_sha to create_scan (not supported)
    """
    if not is_db_available():
        logger.warning(f"[{scan_id}] Database not available - using memory only")
        return False
    
    if db_config.AsyncSessionLocal is None:
        logger.warning(f"[{scan_id}] AsyncSessionLocal not initialized yet")
        return False
    
    try:
        async with db_config.AsyncSessionLocal() as db:
            try:
                # Create or get repository
                repo = await ScanService.get_or_create_repository(
                    db=db,
                    user_id=user_id,
                    owner=repo_owner,
                    repo_name=repo_name,
                    github_url=f"https://github.com/{repo_owner}/{repo_name}",
                    default_branch=branch
                )
                
                await db.flush()
                logger.info(f"[{scan_id}] Repository: {repo.id}")
                
                # ✅ FIXED: Create scan history record WITHOUT commit_sha
                # (ScanService.create_scan doesn't accept commit_sha parameter)
                scan = await ScanService.create_scan(
                    db=db,
                    scan_id=scan_id,
                    user_id=user_id,
                    repository_id=repo.id,
                    branch_name=branch,
                    scanner_mode=scanner_mode
                    # ✅ Removed: commit_sha parameter (not supported)
                )
                
                logger.info(f"[{scan_id}] Scan record created: {scan.id}")
                
                # ✅ Store commit SHA in the scan record if provided
                if commit_sha and hasattr(scan, 'commit_sha'):
                    scan.commit_sha = commit_sha
                    logger.info(f"[{scan_id}] Commit SHA stored: {commit_sha[:7]}")
                
                await db.commit()
                
                logger.info(f"[{scan_id}] ✅ Successfully saved to database")
                return True
                
            except Exception as e:
                await db.rollback()
                logger.error(f"[{scan_id}] Database transaction failed: {e}", exc_info=True)
                return False
                
    except Exception as e:
        logger.error(f"[{scan_id}] Database connection failed: {e}", exc_info=True)
        return False


async def update_scan_status_in_db(scan_id, status, started_at=None):
    """Update scan status in database"""
    if not is_db_available() or db_config.AsyncSessionLocal is None:
        return False
    
    try:
        status_map = {
            'queued': 'queued',
            'cloning': 'cloning',
            'analyzing': 'analyzing',
            'scanning': 'scanning',
            'scanning_semgrep': 'scanning_semgrep',
            'scanning_codeql': 'scanning_codeql',
            'completed': 'completed',
            'failed': 'failed',
            'cancelled': 'cancelled'
        }
        
        status_str = status_map.get(status.lower() if isinstance(status, str) else status, 'queued')
        
        async with db_config.AsyncSessionLocal() as db:
            try:
                await ScanService.update_scan_status(
                    db=db,
                    scan_id=scan_id,
                    status=status_str
                )
                
                await db.commit()
                logger.info(f"[{scan_id}] Status updated to: {status_str}")
                return True
                
            except Exception as e:
                await db.rollback()
                logger.error(f"[{scan_id}] Status update failed: {e}", exc_info=True)
                return False
                
    except Exception as e:
        logger.error(f"[{scan_id}] Database error: {e}", exc_info=True)
        return False


async def complete_scan_in_db(
    scan_id, 
    vulnerabilities, 
    scanner_used, 
    languages, 
    duration, 
    size_mb=None, 
    files=None
):
    """Mark scan as completed and save all vulnerabilities"""
    if not is_db_available() or db_config.AsyncSessionLocal is None:
        logger.warning(f"[{scan_id}] Database not available")
        return False
    
    try:
        from sqlalchemy import select
        from backend.database.scan_models import ScanHistory
        
        async with db_config.AsyncSessionLocal() as db:
            try:
                result = await db.execute(
                    select(ScanHistory).where(ScanHistory.scan_id == scan_id)
                )
                scan_record = result.scalar_one_or_none()
                
                if not scan_record:
                    logger.error(f"[{scan_id}] Scan not found for completion")
                    return False
                
                user_id = scan_record.user_id
                
                # Complete scan with vulnerabilities
                scan = await ScanService.complete_scan(
                    db=db,
                    scan_id=scan_id,
                    vulnerabilities=vulnerabilities,
                    scanner_used=scanner_used,
                    detected_languages=languages,
                    scan_duration=int(duration) if duration else 0,
                    repo_size_mb=int(size_mb) if size_mb else None,
                    files_scanned=files
                )
                
                await db.commit()
                
                logger.info(f"[{scan_id}] ✅ Scan completed in database")
                logger.info(f"[{scan_id}] Saved {len(vulnerabilities)} vulnerabilities")
                
                # Update statistics (don't fail if this fails)
                try:
                    from backend.scanning_repos.scan_statistics_updater import update_scan_statistics
                    await update_scan_statistics(str(user_id))
                except Exception as stats_error:
                    logger.warning(f"[{scan_id}] Failed to update statistics: {stats_error}")
                
                return True
                
            except Exception as e:
                await db.rollback()
                logger.error(f"[{scan_id}] Complete scan failed: {e}", exc_info=True)
                return False
                
    except Exception as e:
        logger.error(f"[{scan_id}] Database error: {e}", exc_info=True)
        return False


async def mark_scan_failed_in_db(scan_id, error_message, error_code="SCAN_ERROR"):
    """Mark scan as failed with error details"""
    if not is_db_available() or db_config.AsyncSessionLocal is None:
        return False
    
    try:
        async with db_config.AsyncSessionLocal() as db:
            try:
                await ScanService.update_scan_status(
                    db=db,
                    scan_id=scan_id,
                    status='failed',
                    error_message=error_message,
                    error_code=error_code
                )
                
                await db.commit()
                logger.info(f"[{scan_id}] Marked as failed in database")
                return True
                
            except Exception as e:
                await db.rollback()
                logger.error(f"[{scan_id}] Failed to mark as failed: {e}", exc_info=True)
                return False
                
    except Exception as e:
        logger.error(f"[{scan_id}] Database error: {e}", exc_info=True)
        return False


# ══════════════════════════════════════════════════════════
# CRITICAL FIX: ATOMIC COMMIT TRACKING UPDATE
# ══════════════════════════════════════════════════════════

async def update_repository_commit_tracking(
    user_id: str,
    repo_owner: str,
    repo_name: str,
    commit_sha: str,
    consume_allowance: bool = True
) -> bool:
    """
    Update repository's last_scan_commit_sha after successful scan
    ✅ ATOMIC: Updates commit SHA, allowance, and scan count in single transaction
    ✅ Called ONLY after scan completes successfully
    
    Args:
        user_id: User UUID
        repo_owner: Repository owner
        repo_name: Repository name
        commit_sha: The commit SHA that was just scanned
        consume_allowance: Whether to decrease scan_allowance_remaining
    
    Returns:
        bool: True if update succeeded, False otherwise
    """
    if not is_db_available() or db_config.AsyncSessionLocal is None:
        logger.warning("Database not available for commit tracking")
        return False
    
    try:
        from sqlalchemy import select, and_
        from backend.database.scan_models import Repository
        
        full_name = f"{repo_owner}/{repo_name}"
        
        async with db_config.AsyncSessionLocal() as db:
            try:
                # Get repository
                result = await db.execute(
                    select(Repository).where(
                        and_(
                            Repository.user_id == user_id,
                            Repository.full_name == full_name
                        )
                    )
                )
                
                repo = result.scalar_one_or_none()
                
                if not repo:
                    logger.error(f"Repository not found: {full_name} for user {user_id}")
                    return False
                
                old_sha = repo.last_scan_commit_sha
                old_allowance = repo.scan_allowance_remaining
                
                # ✅ CRITICAL: Update commit tracking fields
                repo.last_scan_commit_sha = commit_sha
                repo.last_commit_sha = commit_sha
                repo.last_scan_at = datetime.now(timezone.utc)
                repo.updated_at = datetime.now(timezone.utc)
                
                # Increment scan count
                repo.total_scans = (repo.total_scans or 0) + 1
                
                # ✅ Consume allowance if requested
                if consume_allowance and repo.scan_allowance_remaining > 0:
                    repo.scan_allowance_remaining -= 1
                
                await db.commit()
                
                logger.info(
                    f"✅ COMMIT TRACKING UPDATED for {full_name}:\n"
                    f"   SHA: {old_sha[:7] if old_sha else 'none'} → {commit_sha[:7]}\n"
                    f"   Allowance: {old_allowance} → {repo.scan_allowance_remaining}\n"
                    f"   Total scans: {repo.total_scans}"
                )
                return True
                
            except Exception as e:
                await db.rollback()
                logger.error(
                    f"❌ Failed to update commit tracking for {full_name}: {e}",
                    exc_info=True
                )
                return False
                
    except Exception as e:
        logger.error(f"❌ Database error in commit tracking: {e}", exc_info=True)
        return False


# ══════════════════════════════════════════════════════════
# EXISTING FUNCTIONS (Keep for backward compatibility)
# ══════════════════════════════════════════════════════════

async def save_repository_to_db(
    user_id: str,
    owner: str,
    repo_name: str,
    github_url: str,
    default_branch: str = "main",
    primary_language: Optional[str] = None,
    is_private: bool = False
) -> Optional[Any]:
    """Save repository to database"""
    from backend.database import config as db_config
    from backend.database.scan_service import ScanService
    import uuid as uuid_module
    
    if not user_id or user_id == "anonymous":
        logger.warning(f"Cannot save repository {owner}/{repo_name}: user not authenticated")
        return None
    
    try:
        uuid_module.UUID(user_id)
    except (ValueError, AttributeError):
        logger.error(f"Invalid user_id UUID format: {user_id}")
        return None
    
    if not db_config.is_db_available() or db_config.AsyncSessionLocal is None:
        logger.warning("Database not available, cannot save repository")
        return None
    
    try:
        async with db_config.AsyncSessionLocal() as db:
            repo = await ScanService.get_or_create_repository(
                db=db,
                user_id=user_id,
                owner=owner,
                repo_name=repo_name,
                github_url=github_url,
                default_branch=default_branch,
                primary_language=primary_language,
                is_private=is_private
            )
            await db.commit()
            await db.refresh(repo)
            
            logger.info(f"✅ Repository saved: {owner}/{repo_name} for user {user_id}")
            return repo
            
    except Exception as e:
        logger.error(f"Failed to save repository {owner}/{repo_name}: {e}", exc_info=True)
        return None


async def get_user_repositories_from_db(user_id, limit=50, offset=0):
    """Get user's repositories from database"""
    if not is_db_available() or db_config.AsyncSessionLocal is None:
        return []
    
    try:
        from sqlalchemy import select, desc
        from backend.database.scan_models import Repository
        
        async with db_config.AsyncSessionLocal() as db:
            try:
                result = await db.execute(
                    select(Repository)
                    .where(Repository.user_id == user_id)
                    .order_by(desc(Repository.created_at))
                    .limit(limit)
                    .offset(offset)
                )
                
                repos = result.scalars().all()
                
                return [
                    {
                        'id': str(repo.id),
                        'owner': repo.owner,
                        'name': repo.name,
                        'full_name': repo.full_name,
                        'github_url': repo.github_url,
                        'default_branch': repo.default_branch,
                        'primary_language': repo.primary_language,
                        'is_private': repo.is_private,
                        'total_scans': repo.total_scans,
                        'last_scan_at': repo.last_scan_at.isoformat() if repo.last_scan_at else None,
                        'created_at': repo.created_at.isoformat() if repo.created_at else None,
                        'last_scan_commit_sha': repo.last_scan_commit_sha,
                        'scan_allowance_remaining': repo.scan_allowance_remaining
                    }
                    for repo in repos
                ]
                
            except Exception as e:
                logger.error(f"Failed to fetch repositories: {e}", exc_info=True)
                return []
                
    except Exception as e:
        logger.error(f"Database error: {e}", exc_info=True)
        return []