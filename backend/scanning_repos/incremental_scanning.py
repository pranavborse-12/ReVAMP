"""
Incremental Scan Engine
=======================
Computes the diff between two commits via the GitHub Compare API and returns
the set of file paths that were added, modified, or renamed.  The scanner
then restricts itself to those files only, merging their fresh findings with
the cached findings from unchanged files.

Design decisions
----------------
* We never skip *deleted* files — they no longer exist, so they produce zero
  findings naturally.
* We never restrict to *renamed-only* paths; both old and new paths are
  treated as changed so stale findings on the old path get evicted.
* If the GitHub Compare API fails OR the diff exceeds GITHUB_COMPARE_MAX_FILES,
  we first try a LOCAL `git diff --name-status` against a cached working
  directory for the repo (see get_local_diff / config.REPO_CACHE_DIR). Only
  if no cached clone exists do we fall back to a full scan — correctness
  over speed, but full scan is the last resort, not the default fallback.
* Previous findings are loaded from the DB, not from the in-memory cache,
  so they survive process restarts.
* base_sha == head_sha is a ZERO-WORK case (is_unchanged=True), not a
  fallback to full scan. See DiffResult.is_unchanged.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import httpx

logger = logging.getLogger(__name__)

# GitHub returns at most 300 files per compare response.
# If a diff is larger than this we cannot trust the file list and must
# try the local diff fallback (or full scan if no cached clone exists).
GITHUB_COMPARE_MAX_FILES = 300

# Source file extensions we consider "scannable" — used to filter both the
# GitHub Compare API response and the local `git diff` fallback, so the two
# paths always agree on what counts as a changed file.
SOURCE_EXTENSIONS = {
    ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
    ".cs", ".swift", ".kt", ".kts", ".rs", ".scala",
    ".sh", ".bash", ".zsh", ".lua", ".groovy",
    ".vue", ".svelte",
}


@dataclass
class DiffResult:
    """Output of a diff computation."""

    changed_files: Set[str]         # relative paths that need re-scanning
    is_incremental: bool            # False → caller must run full scan
    fallback_reason: str = ""       # human-readable reason when not incremental
    total_diff_files: int = 0       # how many files the diff contained
    is_unchanged: bool = False      # True → base_sha == head_sha, ZERO work needed.
                                     # Distinct from is_incremental=False, which means
                                     # "must fall back to full scan". Caller MUST check
                                     # this before treating is_incremental=False as "run
                                     # a full scan" — see get_changed_files() docstring.


@dataclass
class IncrementalResult:
    """Final merged vulnerability list after incremental scan."""

    vulnerabilities: List[Dict]
    is_incremental: bool
    files_scanned: int              # how many files were actually scanned
    files_skipped: int              # how many files reused cached findings
    changed_files: Set[str] = field(default_factory=set)
    fallback_reason: str = ""


class IncrementalEngine:
    """
    Orchestrates incremental scanning.

    Usage
    -----
    engine = IncrementalEngine(github_token)
    diff   = await engine.get_changed_files(owner, repo, base_sha, head_sha)

    if diff.is_incremental:
        # pass diff.changed_files to VulnerabilityScanner
        fresh_vulns = scanner.scan(target_files=diff.changed_files)
        result = engine.merge_findings(
            fresh_vulns,
            previous_vulns,
            diff.changed_files,
            repo_path,
        )
    else:
        # full scan — diff too large or API failed
        all_vulns = scanner.scan()
    """

    def __init__(self, github_token: str):
        self.github_token = github_token
        self._headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_changed_files(
        self,
        owner: str,
        repo: str,
        base_sha: str,
        head_sha: str,
        branch: str = "main",
        local_repo_path: Optional[str] = None,
    ) -> DiffResult:
        """
        Return the set of file paths changed between base_sha and head_sha.

        Falls back gracefully — never raises.

        local_repo_path:
            Path to a cached, already-cloned working directory for this repo
            (see background_tasks.get_or_refresh_repo_clone / config.REPO_CACHE_DIR),
            if one exists. When provided, it is used as a LOCAL fallback for
            diff computation if the GitHub Compare API fails or the diff is
            too large — avoiding an escalation to full scan in those cases.
            If None, those cases still fall back to full scan as before.
        """
        if not base_sha or not head_sha:
            return DiffResult(
                changed_files=set(),
                is_incremental=False,
                fallback_reason="Missing base or head SHA — first scan",
            )

        if base_sha == head_sha:
            # Nothing changed since the last scan. This is a ZERO-WORK case,
            # not a fallback — previous scan is still fully valid for this
            # commit. Caller (background_tasks.perform_scan) must check
            # is_unchanged BEFORE checking is_incremental, and short-circuit
            # to returning the cached/previous result without cloning,
            # detecting languages, or invoking any scanner.
            #
            # A force-rescan of the same commit is a legitimate use case
            # (e.g. user changed scanner config) — that decision belongs to
            # the caller, not here. This method's job is only to report
            # "nothing changed", not to decide what to do about it.
            return DiffResult(
                changed_files=set(),
                is_incremental=False,
                is_unchanged=True,
                fallback_reason="No new commits since last scan",
                total_diff_files=0,
            )

        try:
            files, total = await self._fetch_compare(owner, repo, base_sha, head_sha)
        except Exception as exc:
            logger.error(
                f"[IncrementalEngine] Compare API failed for "
                f"{owner}/{repo} ({base_sha[:7]}..{head_sha[:7]}): {exc}",
                exc_info=True,
            )
            local_result = await self._try_local_diff_fallback(
                local_repo_path, base_sha, head_sha,
                reason=f"GitHub Compare API error: {exc}",
            )
            if local_result is not None:
                return local_result
            return DiffResult(
                changed_files=set(),
                is_incremental=False,
                fallback_reason=f"GitHub Compare API error: {exc}",
            )

        if total > GITHUB_COMPARE_MAX_FILES:
            logger.warning(
                f"[IncrementalEngine] Diff too large ({total} files > "
                f"{GITHUB_COMPARE_MAX_FILES} limit) — trying local diff fallback"
            )
            local_result = await self._try_local_diff_fallback(
                local_repo_path, base_sha, head_sha,
                reason=f"Diff too large ({total} files via API)",
            )
            if local_result is not None:
                return local_result
            return DiffResult(
                changed_files=set(),
                is_incremental=False,
                fallback_reason=f"Diff too large ({total} files — full scan required)",
                total_diff_files=total,
            )

        if not files:
            return DiffResult(
                changed_files=set(),
                is_incremental=False,
                fallback_reason="Diff contained no scannable source files",
                total_diff_files=0,
            )

        logger.info(
            f"[IncrementalEngine] {owner}/{repo}: {len(files)} files changed "
            f"({base_sha[:7]}..{head_sha[:7]})"
        )
        return DiffResult(
            changed_files=files,
            is_incremental=True,
            total_diff_files=total,
        )

    def merge_findings(
        self,
        fresh_findings: List[Dict],
        previous_findings: List[Dict],
        changed_files: Set[str],
        repo_path: str,
    ) -> IncrementalResult:
        """
        Merge fresh findings (only changed files) with previous findings
        (only unchanged files).

        Rules
        -----
        1. Drop all previous findings whose file is in changed_files — those
           were rescanned and fresh_findings supersede them.
        2. Keep all previous findings whose file is NOT in changed_files —
           those files were not touched.
        3. Add all fresh_findings unconditionally (scanner already scoped them).

        Parameters
        ----------
        fresh_findings:    results from the incremental (partial) scan
        previous_findings: results from the previous completed scan (from DB)
        changed_files:     set of relative paths that were rescanned
        repo_path:         repo root for normalising absolute paths (unused here
                           but kept for future use)
        """
        # Normalise changed_files to forward-slash relative paths
        normalised_changed = {p.replace("\\", "/").lstrip("/") for p in changed_files}

        # Retain previous findings from UNchanged files only
        retained: List[Dict] = []
        skipped_files: Set[str] = set()

        for vuln in previous_findings:
            vuln_file = (
                vuln.get("location", {}).get("file", "")
                .replace("\\", "/")
                .lstrip("/")
            )
            if vuln_file in normalised_changed:
                # This file was rescanned — discard stale finding
                continue
            retained.append(vuln)
            skipped_files.add(vuln_file)

        merged = retained + fresh_findings

        logger.info(
            f"[IncrementalEngine] Merge: "
            f"{len(fresh_findings)} fresh + {len(retained)} retained "
            f"= {len(merged)} total vulnerabilities"
        )

        return IncrementalResult(
            vulnerabilities=merged,
            is_incremental=True,
            files_scanned=len(normalised_changed),
            files_skipped=len(skipped_files),
            changed_files=normalised_changed,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_compare(
        self,
        owner: str,
        repo: str,
        base: str,
        head: str,
    ) -> Tuple[Set[str], int]:
        """
        Call the GitHub compare endpoint and return
        (changed_source_files, total_file_count).

        GitHub paginates compare via ?page=N when there are >300 files,
        but once total > 300 we immediately fall back to a full scan —
        so we only need page 1.
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/compare/{base}...{head}"

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=self._headers)

        if response.status_code == 404:
            raise ValueError(
                f"Compare endpoint 404 — commits may not exist or repo is private"
            )
        if response.status_code != 200:
            raise ValueError(
                f"GitHub Compare API returned HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )

        data = response.json()
        raw_files = data.get("files", [])
        total_count = len(raw_files)

        changed: Set[str] = set()
        for f in raw_files:
            status = f.get("status", "")
            filename = f.get("filename", "")

            # Always include added/modified/renamed; skip pure deletions
            if status == "removed":
                continue

            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext in SOURCE_EXTENSIONS:
                changed.add(filename)

            # For renames, also track the old path so stale findings are evicted
            if status == "renamed":
                previous = f.get("previous_filename", "")
                if previous:
                    changed.add(previous)

        return changed, total_count

    # ------------------------------------------------------------------
    # Local git diff fallback (used when GitHub API fails or diff is too
    # large) — avoids escalating straight to a full scan when we already
    # have a cached, checked-out working copy of the repo on disk.
    # ------------------------------------------------------------------

    async def _try_local_diff_fallback(
        self,
        local_repo_path: Optional[str],
        base_sha: str,
        head_sha: str,
        reason: str,
    ) -> Optional["DiffResult"]:
        """
        Attempt a local `git diff --name-status` fallback.

        Returns a DiffResult if the local fallback succeeded, or None if
        no cached repo is available / the local diff itself failed — in
        which case the caller proceeds to its existing full-scan fallback.
        Never raises.
        """
        if not local_repo_path or not os.path.isdir(local_repo_path):
            logger.info(
                f"[IncrementalEngine] No cached local clone available for "
                f"local diff fallback ({reason}) — will fall back to full scan"
            )
            return None

        try:
            changed = await self._local_git_diff(local_repo_path, base_sha, head_sha)
        except Exception as exc:
            logger.warning(
                f"[IncrementalEngine] Local diff fallback also failed "
                f"({exc}) — will fall back to full scan"
            )
            return None

        if not changed:
            logger.info(
                f"[IncrementalEngine] Local diff fallback found no scannable "
                f"source files changed — treating as no-op incremental scan"
            )
            return DiffResult(
                changed_files=set(),
                is_incremental=False,
                fallback_reason="Local diff contained no scannable source files",
                total_diff_files=0,
            )

        logger.info(
            f"[IncrementalEngine] Local diff fallback succeeded ({reason}): "
            f"{len(changed)} files changed — avoided full scan"
        )
        return DiffResult(
            changed_files=changed,
            is_incremental=True,
            fallback_reason=f"Used local git diff (reason for API fallback: {reason})",
            total_diff_files=len(changed),
        )

    async def _local_git_diff(
        self,
        repo_path: str,
        base_sha: str,
        head_sha: str,
    ) -> Set[str]:
        """
        Run `git diff --name-status base_sha head_sha` against a cached
        local clone and return the set of changed source file paths.

        Requires that repo_path already has both base_sha and head_sha
        reachable locally (i.e. a `git fetch` was done beforehand — see
        background_tasks.get_or_refresh_repo_clone). If either commit is
        missing locally, git will error and we propagate that so the
        caller treats it as a failed fallback.
        """
        proc = await asyncio.create_subprocess_exec(
            "git", "diff", "--name-status", f"{base_sha}", f"{head_sha}",
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError("local git diff timed out")

        if proc.returncode != 0:
            raise RuntimeError(
                f"git diff exited {proc.returncode}: {stderr.decode(errors='replace')[:300]}"
            )

        changed: Set[str] = set()
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            status = parts[0]
            if status.startswith("D"):
                # Pure deletion — skip, same rule as the API path
                continue

            if status.startswith("R") and len(parts) == 3:
                # Rename: "R100\told_path\tnew_path" — track both, matching
                # the same logic _fetch_compare uses for GitHub renames
                old_path, new_path = parts[1], parts[2]
                for p in (old_path, new_path):
                    ext = "." + p.rsplit(".", 1)[-1].lower() if "." in p else ""
                    if ext in SOURCE_EXTENSIONS:
                        changed.add(p)
                continue

            if len(parts) >= 2:
                filename = parts[-1]
                ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                if ext in SOURCE_EXTENSIONS:
                    changed.add(filename)

        return changed


# ------------------------------------------------------------------
# DB helpers — fetch previous scan's vulnerabilities
# ------------------------------------------------------------------

# Above this many changed files, pushing a NOT IN (...) filter to the DB
# stops being worth it (query plan / param count) — fall back to loading
# everything and filtering in Python, same as before.
_EXCLUDE_FILTER_MAX_FILES = 200


async def get_previous_scan_vulnerabilities(
    user_id: str,
    repo_owner: str,
    repo_name: str,
    exclude_files: Optional[Set[str]] = None,
) -> List[Dict]:
    """
    Retrieve vulnerability dicts from the most recent *completed* scan for
    this repository.  Returns [] if nothing is found or DB is unavailable.

    exclude_files:
        Optional set of relative file paths to exclude at the DB level
        (i.e. the files that were just rescanned, whose stale findings
        merge_findings() would discard anyway). When provided and small
        enough (<= _EXCLUDE_FILTER_MAX_FILES), we push a `file_path NOT IN
        (...)` filter into the query instead of loading every finding for
        the repo and discarding most of them in Python on every incremental
        scan. This is purely a performance optimization — merge_findings()
        still re-applies its own filter afterwards, so correctness doesn't
        depend on this parameter being passed or being complete.
    """
    try:
        from backend.database import config as db_config
        from backend.database.scan_models import Repository, ScanHistory, Vulnerability
        from sqlalchemy import select, and_, desc

        if not db_config.is_db_available() or not db_config.AsyncSessionLocal:
            logger.warning("[IncrementalEngine] DB unavailable — no previous findings to reuse")
            return []

        async with db_config.AsyncSessionLocal() as db:
            # Find the repository
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
                return []

            # Latest completed scan for this repo
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
                return []

            # All vulnerabilities for that scan — with an optional DB-side
            # exclusion of files we already know were just rescanned, to
            # avoid loading rows we're going to discard immediately after.
            query = select(Vulnerability).where(Vulnerability.scan_id == scan.id)

            pushed_exclude_filter = False
            if exclude_files and len(exclude_files) <= _EXCLUDE_FILTER_MAX_FILES:
                query = query.where(Vulnerability.file_path.notin_(exclude_files))
                pushed_exclude_filter = True

            vuln_result = await db.execute(query)
            vuln_rows = vuln_result.scalars().all()

            # Convert ORM objects → plain dicts matching the scanner output format
            findings: List[Dict] = []
            for v in vuln_rows:
                findings.append({
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

            logger.info(
                f"[IncrementalEngine] Loaded {len(findings)} previous findings "
                f"from scan {scan.scan_id[:8]} for {repo_owner}/{repo_name}"
                + (" (DB-side exclude filter applied)" if pushed_exclude_filter else "")
            )
            return findings

    except Exception as exc:
        logger.error(
            f"[IncrementalEngine] Failed to load previous findings: {exc}",
            exc_info=True,
        )
        return []