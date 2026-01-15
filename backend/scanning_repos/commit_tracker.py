"""
Commit Tracking Service - FIXED VERSION
✅ Proper error handling for API failures
✅ Consistent response format
✅ Graceful fallbacks
"""
import httpx
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from backend.database.scan_models import Repository, ScanHistory

logger = logging.getLogger(__name__)


class CommitTracker:
    """Handles commit tracking and scan eligibility"""
    
    INITIAL_SCAN_ALLOWANCE = 5  # Allow 5 scans initially
    
    @staticmethod
    async def get_latest_commit(
        github_token: str,
        owner: str,
        repo: str,
        branch: str = "main"
    ) -> Optional[Dict]:
        """
        Fetch latest commit from GitHub with proper error handling
        ✅ FIXED: Returns None on failure instead of crashing
        """
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers={
                        "Authorization": f"token {github_token}",
                        "Accept": "application/vnd.github.v3+json"
                    },
                    timeout=10.0
                )
            
            if response.status_code == 200:
                commit_data = response.json()
                return {
                    "sha": commit_data["sha"],
                    "date": commit_data["commit"]["committer"]["date"],
                    "author": commit_data["commit"]["author"]["name"],
                    "message": commit_data["commit"]["message"]
                }
            
            # ✅ FIXED: Log specific error
            logger.warning(
                f"Failed to fetch commit for {owner}/{repo}@{branch}: "
                f"HTTP {response.status_code}"
            )
            return None
            
        except httpx.TimeoutException:
            logger.error(f"Timeout fetching commit for {owner}/{repo}@{branch}")
            return None
        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching commit for {owner}/{repo}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching commit for {owner}/{repo}: {e}")
            return None
    
    @staticmethod
    async def get_commits_since(
        github_token: str,
        owner: str,
        repo: str,
        since_sha: str,
        branch: str = "main"
    ) -> List[Dict]:
        """Get all commits since a specific SHA"""
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/commits"
            params = {"sha": branch, "per_page": 100}
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    params=params,
                    headers={
                        "Authorization": f"token {github_token}",
                        "Accept": "application/vnd.github.v3+json"
                    },
                    timeout=10.0
                )
            
            if response.status_code != 200:
                return []
            
            all_commits = response.json()
            
            # Find commits until we hit the since_sha
            new_commits = []
            for commit in all_commits:
                if commit["sha"] == since_sha:
                    break
                new_commits.append({
                    "sha": commit["sha"],
                    "date": commit["commit"]["committer"]["date"],
                    "author": commit["commit"]["author"]["name"],
                    "message": commit["commit"]["message"]
                })
            
            return new_commits
            
        except Exception as e:
            logger.error(f"Error fetching commits: {e}")
            return []
    
    @staticmethod
    async def check_scan_eligibility(
        db: AsyncSession,
        repository_id: str,
        current_commit_sha: str
    ) -> Tuple[bool, str, int]:
        """
        Check if repository is eligible for scanning
        ✅ FIXED: Handles None values gracefully
        
        Returns:
            (is_eligible, reason, remaining_allowance)
        """
        try:
            # Get repository
            result = await db.execute(
                select(Repository).where(Repository.id == repository_id)
            )
            repo = result.scalar_one_or_none()
            
            if not repo:
                logger.error(f"Repository not found: {repository_id}")
                return False, "Repository not found", 0
            
            # Get last scan
            last_scan_result = await db.execute(
                select(ScanHistory)
                .where(ScanHistory.repository_id == repository_id)
                .where(ScanHistory.status == "completed")
                .order_by(desc(ScanHistory.completed_at))
                .limit(1)
            )
            last_scan = last_scan_result.scalar_one_or_none()
            
            # First scan - always allow
            if not last_scan:
                logger.info(f"✅ First scan for repository {repo.full_name}")
                return True, "First scan", CommitTracker.INITIAL_SCAN_ALLOWANCE
            
            last_scanned_sha = repo.last_scan_commit_sha
            
            # ✅ FIXED: Handle None last_scanned_sha
            if not last_scanned_sha:
                logger.info(f"✅ No previous commit tracked for {repo.full_name}")
                return True, "First tracked scan", CommitTracker.INITIAL_SCAN_ALLOWANCE
            
            # New commits detected - reset allowance
            if current_commit_sha != last_scanned_sha:
                logger.info(
                    f"✅ New commits detected for {repo.full_name}: "
                    f"{last_scanned_sha[:7]} -> {current_commit_sha[:7]}"
                )
                # Reset allowance when commits change
                repo.scan_allowance_remaining = CommitTracker.INITIAL_SCAN_ALLOWANCE
                repo.last_allowance_reset = datetime.now(timezone.utc)
                await db.commit()
                return True, "New commits detected", CommitTracker.INITIAL_SCAN_ALLOWANCE
            
            # No new commits - check allowance
            remaining = repo.scan_allowance_remaining or 0
            
            if remaining > 0:
                logger.info(f"✅ Rescan allowed for {repo.full_name} ({remaining} remaining)")
                return True, f"Rescan allowed ({remaining} remaining)", remaining
            
            # No allowance left
            logger.warning(f"⚠️ No scan allowance for {repo.full_name}")
            return (
                False, 
                "No new commits since last scan. Please make changes to scan again.", 
                0
            )
            
        except Exception as e:
            logger.error(f"Error checking eligibility: {e}", exc_info=True)
            # ✅ FIXED: Return safe fallback instead of crashing
            return False, f"Error checking eligibility: {str(e)}", 0
    
    @staticmethod
    async def consume_scan_allowance(
        db: AsyncSession,
        repository_id: str
    ):
        """Decrease scan allowance after successful scan"""
        try:
            result = await db.execute(
                select(Repository).where(Repository.id == repository_id)
            )
            repo = result.scalar_one_or_none()
            
            if repo and repo.scan_allowance_remaining > 0:
                repo.scan_allowance_remaining -= 1
                await db.commit()
                logger.info(
                    f"📉 Scan allowance consumed for {repo.full_name}. "
                    f"Remaining: {repo.scan_allowance_remaining}"
                )
                
        except Exception as e:
            logger.error(f"Error consuming allowance: {e}")
    
    @staticmethod
    async def update_repository_commit(
        db: AsyncSession,
        repository_id: str,
        commit_sha: str
    ):
        """Update repository's last scanned commit"""
        try:
            result = await db.execute(
                select(Repository).where(Repository.id == repository_id)
            )
            repo = result.scalar_one_or_none()
            
            if repo:
                repo.last_scan_commit_sha = commit_sha
                repo.last_commit_sha = commit_sha
                await db.commit()
                logger.info(f"✅ Updated commit SHA for {repo.full_name}: {commit_sha[:7]}")
                
        except Exception as e:
            logger.error(f"Error updating commit: {e}")