"""
Commit Tracking Service - FIXED VERSION
✅ check_scan_eligibility returns (is_eligible, reason, remaining, has_new_commits) — 4-tuple
✅ reset_allowance_for_new_commits added (called by routes.py)
✅ Properly detects new commits using GitHub API
✅ Always allows first scan
✅ Handles edge cases gracefully
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
        Fetch latest commit from GitHub with proper error handling.
        Returns None on failure instead of crashing.
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
    ) -> Tuple[bool, str, int, bool]:
        """
        Check if repository is eligible for scanning.

        FIXED: Now returns a 4-tuple so routes.py can unpack correctly:
            (is_eligible, reason, remaining_allowance, has_new_commits)

        Previously returned 3-tuple which caused a ValueError when routes.py
        tried to unpack 4 values, silently crashing the eligibility check and
        allowing every scan regardless of state.
        """
        try:
            # Get repository
            result = await db.execute(
                select(Repository).where(Repository.id == repository_id)
            )
            repo = result.scalar_one_or_none()

            if not repo:
                logger.error(f"Repository not found: {repository_id}")
                return False, "Repository not found", 0, False

            # Get last COMPLETED scan
            last_scan_result = await db.execute(
                select(ScanHistory)
                .where(ScanHistory.repository_id == repository_id)
                .where(ScanHistory.status == "completed")
                .order_by(desc(ScanHistory.completed_at))
                .limit(1)
            )
            last_scan = last_scan_result.scalar_one_or_none()

            # CASE 1: First scan ever — ALWAYS allow
            if not last_scan:
                logger.info(f"✅ First scan for repository {repo.full_name}")
                return True, "First scan of this repository", CommitTracker.INITIAL_SCAN_ALLOWANCE, False

            # Get last scanned commit SHA
            last_scanned_sha = repo.last_scan_commit_sha

            # CASE 2: No previous commit tracked — allow
            if not last_scanned_sha:
                logger.info(f"✅ No previous commit tracked for {repo.full_name}")
                return True, "First tracked scan", CommitTracker.INITIAL_SCAN_ALLOWANCE, False

            # CASE 3: NEW COMMITS DETECTED
            if current_commit_sha != last_scanned_sha:
                logger.info(
                    f"✅ New commits detected for {repo.full_name}: "
                    f"{last_scanned_sha[:7]} → {current_commit_sha[:7]}"
                )
                # NOTE: We do NOT reset allowance here; that is done by
                # reset_allowance_for_new_commits() called from routes.py
                # after this check, keeping concerns separated.
                return (
                    True,
                    f"New commits detected ({CommitTracker.INITIAL_SCAN_ALLOWANCE} scans available)",
                    CommitTracker.INITIAL_SCAN_ALLOWANCE,
                    True   # ← has_new_commits = True
                )

            # CASE 4: NO NEW COMMITS — check remaining allowance
            remaining = repo.scan_allowance_remaining or 0

            if remaining > 0:
                logger.info(
                    f"✅ Rescan allowed for {repo.full_name} "
                    f"(Allowance: {remaining}/{CommitTracker.INITIAL_SCAN_ALLOWANCE})"
                )
                return (
                    True,
                    f"Rescan allowed ({remaining} remaining)",
                    remaining,
                    False
                )

            # CASE 5: No allowance remaining
            logger.warning(f"❌ No scan allowance remaining for {repo.full_name}")
            return (
                False,
                "No new commits since last scan and no rescans remaining. "
                "Make code changes and commit to scan again.",
                0,
                False
            )

        except Exception as e:
            logger.error(f"Error checking eligibility: {e}", exc_info=True)
            # Fail open — allow scan on unexpected error
            return (
                True,
                "Error checking eligibility - allowing scan anyway",
                CommitTracker.INITIAL_SCAN_ALLOWANCE,
                False
            )

    @staticmethod
    async def reset_allowance_for_new_commits(
        db: AsyncSession,
        repository_id: str,
        current_commit_sha: str
    ):
        """
        Reset scan allowance when new commits are detected.
        Called from routes.py AFTER check_scan_eligibility confirms new commits.
        Separated from check_scan_eligibility so the check remains side-effect free.
        """
        try:
            result = await db.execute(
                select(Repository).where(Repository.id == repository_id)
            )
            repo = result.scalar_one_or_none()

            if repo:
                repo.scan_allowance_remaining = CommitTracker.INITIAL_SCAN_ALLOWANCE
                repo.last_allowance_reset = datetime.now(timezone.utc)
                await db.commit()
                logger.info(
                    f"✅ Allowance reset to {CommitTracker.INITIAL_SCAN_ALLOWANCE} "
                    f"for {repo.full_name} at commit {current_commit_sha[:7]}"
                )
        except Exception as e:
            logger.error(f"Error resetting allowance: {e}", exc_info=True)

    @staticmethod
    async def consume_scan_allowance(
        db: AsyncSession,
        repository_id: str
    ):
        """
        Decrease scan allowance after successful scan.
        Only called AFTER scan completes.
        """
        try:
            result = await db.execute(
                select(Repository).where(Repository.id == repository_id)
            )
            repo = result.scalar_one_or_none()

            if repo and repo.scan_allowance_remaining > 0:
                old_allowance = repo.scan_allowance_remaining
                repo.scan_allowance_remaining -= 1
                await db.commit()

                logger.info(
                    f"📉 Scan allowance consumed for {repo.full_name}: "
                    f"{old_allowance} → {repo.scan_allowance_remaining}"
                )
            elif repo:
                logger.warning(
                    f"⚠️ Tried to consume allowance for {repo.full_name} "
                    f"but already at {repo.scan_allowance_remaining}"
                )

        except Exception as e:
            logger.error(f"Error consuming allowance: {e}", exc_info=True)

    @staticmethod
    async def update_repository_commit(
        db: AsyncSession,
        repository_id: str,
        commit_sha: str
    ):
        """
        Update repository's last scanned commit SHA.
        Called AFTER successful scan completion.
        """
        try:
            result = await db.execute(
                select(Repository).where(Repository.id == repository_id)
            )
            repo = result.scalar_one_or_none()

            if repo:
                old_sha = repo.last_scan_commit_sha
                repo.last_scan_commit_sha = commit_sha
                repo.last_commit_sha = commit_sha
                repo.last_scan_at = datetime.now(timezone.utc)
                await db.commit()

                logger.info(
                    f"✅ Updated commit SHA for {repo.full_name}: "
                    f"{old_sha[:7] if old_sha else 'none'} → {commit_sha[:7]}"
                )
            else:
                logger.error(f"❌ Repository {repository_id} not found for commit update")

        except Exception as e:
            logger.error(f"Error updating commit SHA: {e}", exc_info=True)