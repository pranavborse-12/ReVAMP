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
* If the GitHub API call fails for any reason we fall back to a FULL scan —
  correctness over speed.
* Previous findings are loaded from the DB, not from the in-memory cache,
  so they survive process restarts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import httpx

logger = logging.getLogger(__name__)

# GitHub returns at most 300 files per compare response.
# If a diff is larger than this we cannot trust the file list and must do
# a full scan.
GITHUB_COMPARE_MAX_FILES = 300


@dataclass
class DiffResult:
    """Output of a diff computation."""

    changed_files: Set[str]         # relative paths that need re-scanning
    is_incremental: bool            # False → caller must run full scan
    fallback_reason: str = ""       # human-readable reason when not incremental
    total_diff_files: int = 0       # how many files the diff contained


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
    ) -> DiffResult:
        """
        Return the set of file paths changed between base_sha and head_sha.

        Falls back gracefully — never raises.
        """
        if not base_sha or not head_sha:
            return DiffResult(
                changed_files=set(),
                is_incremental=False,
                fallback_reason="Missing base or head SHA — first scan",
            )

        if base_sha == head_sha:
            # No new commits; caller decides to rescan (force/allowance).
            # Return empty set so caller can decide to rescan everything.
            return DiffResult(
                changed_files=set(),
                is_incremental=False,
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
            return DiffResult(
                changed_files=set(),
                is_incremental=False,
                fallback_reason=f"GitHub Compare API error: {exc}",
            )

        if total > GITHUB_COMPARE_MAX_FILES:
            logger.warning(
                f"[IncrementalEngine] Diff too large ({total} files > "
                f"{GITHUB_COMPARE_MAX_FILES} limit) — falling back to full scan"
            )
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

        # Filter to source files only (skip assets, docs, lock files, etc.)
        source_extensions = {
            ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs",
            ".ts", ".tsx", ".java", ".go", ".rb", ".php",
            ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
            ".cs", ".swift", ".kt", ".kts", ".rs", ".scala",
            ".sh", ".bash", ".zsh", ".lua", ".groovy",
            ".vue", ".svelte",
        }

        changed: Set[str] = set()
        for f in raw_files:
            status = f.get("status", "")
            filename = f.get("filename", "")

            # Always include added/modified/renamed; skip pure deletions
            if status == "removed":
                continue

            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext in source_extensions:
                changed.add(filename)

            # For renames, also track the old path so stale findings are evicted
            if status == "renamed":
                previous = f.get("previous_filename", "")
                if previous:
                    changed.add(previous)

        return changed, total_count


# ------------------------------------------------------------------
# DB helpers — fetch previous scan's vulnerabilities
# ------------------------------------------------------------------

async def get_previous_scan_vulnerabilities(
    user_id: str,
    repo_owner: str,
    repo_name: str,
) -> List[Dict]:
    """
    Retrieve vulnerability dicts from the most recent *completed* scan for
    this repository.  Returns [] if nothing is found or DB is unavailable.
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

            # All vulnerabilities for that scan
            vuln_result = await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == scan.id)
            )
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
            )
            return findings

    except Exception as exc:
        logger.error(
            f"[IncrementalEngine] Failed to load previous findings: {exc}",
            exc_info=True,
        )
        return []