"""
Scan Statistics Updater
Updates scan_statistics table after each scan completes
"""
from backend.database.config import get_db, is_db_available
from backend.database.scan_models import ScanStatistics, ScanHistory
from sqlalchemy import select, func
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


async def update_scan_statistics(user_id: str):
    """
    Update user's scan statistics after a scan completes
    Creates or updates the scan_statistics record
    """
    if not is_db_available():
        logger.warning(f"Database not available - statistics not updated for user {user_id}")
        return False
    
    try:
        async for db in get_db():
            try:
                # Get or create statistics record
                result = await db.execute(
                    select(ScanStatistics).where(ScanStatistics.user_id == user_id)
                )
                stats = result.scalar_one_or_none()
                
                if not stats:
                    # Create new statistics record
                    stats = ScanStatistics(user_id=user_id)
                    db.add(stats)
                    logger.info(f"Created new statistics record for user {user_id}")
                
                # Calculate statistics from scan_history
                scan_result = await db.execute(
                    select(
                        func.count(ScanHistory.id).label('total_scans'),
                        func.count(ScanHistory.id).filter(ScanHistory.status == 'completed').label('completed'),
                        func.count(ScanHistory.id).filter(ScanHistory.status == 'failed').label('failed'),
                        func.count(func.distinct(ScanHistory.repository_id)).label('total_repos'),
                        func.sum(ScanHistory.total_vulnerabilities).label('total_vulns'),
                        func.sum(ScanHistory.critical_count).label('total_critical'),
                        func.sum(ScanHistory.high_count).label('total_high'),
                        func.sum(ScanHistory.medium_count).label('total_medium'),
                        func.sum(ScanHistory.low_count).label('total_low'),
                        func.avg(ScanHistory.scan_duration_seconds).label('avg_duration'),
                        func.max(ScanHistory.completed_at).label('last_scan')
                    ).where(ScanHistory.user_id == user_id)
                )
                
                scan_stats = scan_result.first()
                
                # Update statistics
                stats.total_scans = scan_stats.total_scans or 0
                stats.completed_scans = scan_stats.completed or 0
                stats.failed_scans = scan_stats.failed or 0
                stats.total_repositories = scan_stats.total_repos or 0
                stats.total_vulnerabilities = scan_stats.total_vulns or 0
                stats.total_critical = scan_stats.total_critical or 0
                stats.total_high = scan_stats.total_high or 0
                stats.total_medium = scan_stats.total_medium or 0
                stats.total_low = scan_stats.total_low or 0
                stats.avg_scan_duration_seconds = int(scan_stats.avg_duration) if scan_stats.avg_duration else None
                stats.last_scan_at = scan_stats.last_scan
                stats.updated_at = datetime.now(timezone.utc)
                
                await db.commit()
                
                logger.info(f"✅ Updated scan statistics for user {user_id}")
                logger.info(f"   Total scans: {stats.total_scans}")
                logger.info(f"   Total vulnerabilities: {stats.total_vulnerabilities}")
                logger.info(f"   Severity: {stats.total_critical}C / {stats.total_high}H / {stats.total_medium}M / {stats.total_low}L")
                
                return True
                
            except Exception as e:
                await db.rollback()
                logger.error(f"Failed to update statistics for user {user_id}: {e}", exc_info=True)
                return False
                
    except Exception as e:
        logger.error(f"Database error while updating statistics: {e}", exc_info=True)
        return False


async def get_user_statistics(user_id: str):
    """
    Get user's scan statistics
    """
    if not is_db_available():
        return None
    
    try:
        async for db in get_db():
            try:
                result = await db.execute(
                    select(ScanStatistics).where(ScanStatistics.user_id == user_id)
                )
                stats = result.scalar_one_or_none()
                
                if not stats:
                    logger.info(f"No statistics found for user {user_id}")
                    return None
                
                return {
                    'total_scans': stats.total_scans,
                    'completed_scans': stats.completed_scans,
                    'failed_scans': stats.failed_scans,
                    'total_repositories': stats.total_repositories,
                    'total_vulnerabilities': stats.total_vulnerabilities,
                    'total_critical': stats.total_critical,
                    'total_high': stats.total_high,
                    'total_medium': stats.total_medium,
                    'total_low': stats.total_low,
                    'avg_scan_duration_seconds': stats.avg_scan_duration_seconds,
                    'last_scan_at': stats.last_scan_at.isoformat() if stats.last_scan_at else None,
                    'updated_at': stats.updated_at.isoformat() if stats.updated_at else None
                }
                
            except Exception as e:
                logger.error(f"Failed to get statistics for user {user_id}: {e}", exc_info=True)
                return None
                
    except Exception as e:
        logger.error(f"Database error: {e}", exc_info=True)
        return None