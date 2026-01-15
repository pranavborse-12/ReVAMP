"""
Complete storage interface for scans with proper error handling
FIXED: Proper enum value handling for PostgreSQL
"""
from typing import Optional, Any
from backend.database.config import get_db, is_db_available
from backend.database.scan_service import ScanService
from backend.database.scan_models import ScanStatusEnum
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


async def save_scan_to_db(scan_id, user_id, repo_owner, repo_name, branch, scanner_mode):
    """
    Initialize scan in database
    Creates repository record and scan_history record
    FIXED: Proper enum handling
    """
    if not is_db_available():
        logger.warning(f"[{scan_id}] Database not available - using memory only")
        return False
    
    try:
        async for db in get_db():
            try:
                # Step 1: Create or get repository
                repo = await ScanService.get_or_create_repository(
                    db=db,
                    user_id=user_id,
                    owner=repo_owner,
                    repo_name=repo_name,
                    github_url=f"https://github.com/{repo_owner}/{repo_name}",
                    default_branch=branch
                )
                
                # Ensure the repository has an ID
                await db.flush()

                logger.info(f"[{scan_id}] Repository record created/retrieved: {repo.id}")
                
                # Step 2: Create scan history record with UUID directly
                scan = await ScanService.create_scan(
                    db=db,
                    scan_id=scan_id,
                    user_id=user_id,
                    repository_id=repo.id,  # ← Pass UUID object directly
                    branch_name=branch,
                    scanner_mode=scanner_mode
                )
                
                logger.info(f"[{scan_id}] Scan history record created: {scan.id}")
                
                # Step 3: Commit transaction
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
    """
    Update scan status in database
    FIXED: Pass lowercase strings directly
    """
    if not is_db_available():
        return False
    
    try:
        # FIXED: Map to lowercase strings directly (no enum conversion)
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
        
        # Get lowercase status string
        status_str = status_map.get(status.lower() if isinstance(status, str) else status, 'queued')
        
        async for db in get_db():
            try:
                # Pass lowercase string directly
                await ScanService.update_scan_status(
                    db=db,
                    scan_id=scan_id,
                    status=status_str  # ← Now a lowercase string
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


async def complete_scan_in_db(scan_id, vulnerabilities, scanner_used, languages, duration, size_mb=None, files=None):
    """
    Mark scan as completed and save all vulnerabilities
    Also updates scan statistics
    """
    if not is_db_available():
        logger.warning(f"[{scan_id}] Database not available")
        return False
    
    try:
        from sqlalchemy import select
        from backend.database.scan_models import ScanHistory
        
        async for db in get_db():
            try:
                # Get scan to retrieve user_id
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
                
                # Update scan statistics (don't fail if this fails)
                try:
                    from backend.scanning_repos.scan_statistics_updater import update_scan_statistics
                    await update_scan_statistics(str(user_id))
                except Exception as stats_error:
                    logger.warning(f"[{scan_id}] Failed to update statistics: {stats_error}")
                
                # Update repository scan count
                try:
                    await update_repository_scan_stats(
                        scan_record.repository.owner,
                        scan_record.repository.name,
                        str(user_id)
                    )
                except Exception as repo_error:
                    logger.warning(f"[{scan_id}] Failed to update repo stats: {repo_error}")
                
                return True
                
            except Exception as e:
                await db.rollback()
                logger.error(f"[{scan_id}] Complete scan failed: {e}", exc_info=True)
                return False
                
    except Exception as e:
        logger.error(f"[{scan_id}] Database error: {e}", exc_info=True)
        return False


async def mark_scan_failed_in_db(scan_id, error_message, error_code="SCAN_ERROR"):
    """
    Mark scan as failed with error details
    FIXED: Pass lowercase string directly
    """
    if not is_db_available():
        return False
    
    try:
        async for db in get_db():
            try:
                # Pass 'failed' as lowercase string
                await ScanService.update_scan_status(
                    db=db,
                    scan_id=scan_id,
                    status='failed',  # ← Lowercase string
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


async def save_repository_to_db(
    user_id: str,
    owner: str,
    repo_name: str,
    github_url: str,
    default_branch: str = "main",
    primary_language: Optional[str] = None,
    is_private: bool = False
) -> Optional[Any]:
    """
    Save repository to database with proper user_id validation
    FIXED: Better handling of anonymous users and UUID validation
    """
    from backend.database import config as db_config
    from backend.database.scan_service import ScanService
    import uuid as uuid_module
    
    # Validate user_id
    if not user_id or user_id == "anonymous":
        logger.warning(f"Cannot save repository {owner}/{repo_name}: user not authenticated (user_id={user_id})")
        return None
    
    # Validate UUID format
    try:
        uuid_module.UUID(user_id)
    except (ValueError, AttributeError):
        logger.error(f"Invalid user_id UUID format: {user_id}")
        return None
    
    # Check if database is available
    if not db_config.is_db_available():
        logger.warning("Database not available, cannot save repository")
        return None
    
    if db_config.AsyncSessionLocal is None:
        logger.warning("AsyncSessionLocal not initialized")
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
    if not is_db_available():
        return []
    
    try:
        from sqlalchemy import select, and_, desc
        from backend.database.scan_models import Repository
        
        async for db in get_db():
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
                        'created_at': repo.created_at.isoformat() if repo.created_at else None
                    }
                    for repo in repos
                ]
                
            except Exception as e:
                logger.error(f"Failed to fetch repositories: {e}", exc_info=True)
                return []
                
    except Exception as e:
        logger.error(f"Database error: {e}", exc_info=True)
        return []


async def update_repository_scan_stats(repo_owner, repo_name, user_id):
    """Update repository statistics after a scan"""
    if not is_db_available():
        return False
    
    try:
        from sqlalchemy import select, and_
        from backend.database.scan_models import Repository
        
        async for db in get_db():
            try:
                full_name = f"{repo_owner}/{repo_name}"
                
                result = await db.execute(
                    select(Repository).where(
                        and_(
                            Repository.user_id == user_id,
                            Repository.full_name == full_name
                        )
                    )
                )
                
                repo = result.scalar_one_or_none()
                
                if repo:
                    repo.total_scans += 1
                    repo.last_scan_at = datetime.now(timezone.utc)
                    repo.updated_at = datetime.now(timezone.utc)
                    
                    await db.commit()
                    logger.info(f"Updated scan stats for {full_name}")
                    return True
                else:
                    logger.warning(f"Repository not found: {full_name}")
                    return False
                    
            except Exception as e:
                await db.rollback()
                logger.error(f"Failed to update repository stats: {e}", exc_info=True)
                return False
                
    except Exception as e:
        logger.error(f"Database error: {e}", exc_info=True)
        return False