"""
Production Scanner Core - Parallel multi-engine vulnerability detection

Execution model:
  - Semgrep, Bandit, ESLint all run IN PARALLEL via ThreadPoolExecutor
  - Total scan time ≈ slowest scanner (not sum of all)

Incremental mode (new):
  - Pass changed_files=set_of_relative_paths to scan()
  - Each scanner uses scan_files() instead of scan() — restricts work to
    only those paths
  - CustomRules removed — Semgrep covers all patterns with higher accuracy
"""
import os
import json
import hashlib
import stat
import shutil
from typing import List, Dict, Tuple, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from datetime import datetime, timedelta
from .config import logger
from .scanner_semgrep import SemgrepScanner
from .scanner_bandit import BanditScanner
from .scanner_eslint import ESLintScanner


class VulnerabilityScanner:
    """
    Multi-engine vulnerability scanner with parallel execution.

    Primary scanners run simultaneously:
      - Semgrep  → all languages, OWASP rules, secrets
      - Bandit   → Python deep analysis (if Python detected)
      - ESLint   → JS/TS security rules (if JS/TS detected)

    Incremental mode:
      scanner.scan(changed_files={"src/auth.py", "api/routes.py"})
      Each scanner's scan_files() is called instead of scan(), so only
      changed files are processed.  Caller is responsible for merging
      fresh findings with cached findings from unchanged files
      (see IncrementalEngine.merge_findings()).
    """

    def __init__(self, repo_path: str, languages: Set[str]):
        self.repo_path = repo_path
        self.languages = languages
        self.cache_dir = os.path.join(repo_path, ".scan_cache")
        self.scanners = self._initialize_scanners()

    def _initialize_scanners(self) -> List:
        """
        Initialize primary scanners only — all run in parallel.
        Semgrep is the main scanner. Bandit and ESLint for their languages.
        """
        scanners = []
        scanners.append(SemgrepScanner(self.repo_path, self.languages))

        if "python" in self.languages:
            scanners.append(BanditScanner(self.repo_path))

        if any(lang in self.languages for lang in ["javascript", "typescript"]):
            scanners.append(ESLintScanner(self.repo_path))

        logger.info(f"✓ Scanners (parallel): {[s.name for s in scanners]}")
        return scanners

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    def scan(
        self,
        use_cache: bool = True,
        changed_files: Optional[Set[str]] = None,
    ) -> Tuple[List[Dict], str]:
        """
        Run vulnerability scan.

        Parameters
        ----------
        use_cache:     Whether to check/write the 1-hour result cache.
                       Automatically disabled for incremental scans.
        changed_files: Optional set of relative file paths that changed.
                       When provided, scanners run in INCREMENTAL mode —
                       each scanner restricts itself to those paths only.
                       Caller must then merge results with previous findings.
                       When None/empty, full repo scan is performed.

        Returns
        -------
        (vulnerabilities, error_message)
        """
        is_incremental = bool(changed_files)

        if is_incremental:
            logger.info("=" * 60)
            logger.info("STARTING INCREMENTAL SECURITY SCAN")
            logger.info(f"Changed files: {len(changed_files)}")
            logger.info(f"Scanners (parallel): {[s.name for s in self.scanners]}")
            logger.info("=" * 60)
            # Never use cache for incremental — cache represents full-scan results
            return self._run_incremental(changed_files)

        logger.info("=" * 60)
        logger.info("STARTING FULL PARALLEL SECURITY SCAN")
        logger.info(f"Scanners (parallel): {[s.name for s in self.scanners]}")
        logger.info("=" * 60)

        # Check cache for full scans only
        if use_cache:
            cached = self._get_cached_results()
            if cached:
                logger.info("✓ Using cached scan results")
                return cached, ""

        all_vulnerabilities, errors = self._run_full(self.scanners)
        unique_vulns = self._deduplicate_vulnerabilities(all_vulnerabilities)

        logger.info("\n" + "=" * 60)
        logger.info(f"SCAN COMPLETE: {len(unique_vulns)} unique vulnerabilities")
        logger.info("=" * 60)

        if use_cache:
            self._cache_results(unique_vulns)

        return unique_vulns, "; ".join(errors) if errors else ""

    # ------------------------------------------------------------------
    # Incremental execution
    # ------------------------------------------------------------------

    def _run_incremental(self, changed_files: Set[str]) -> Tuple[List[Dict], str]:
        """
        Run each scanner's scan_files() method in parallel.

        Scanners that don't implement scan_files() (e.g., ESLint at present)
        fall back to their full scan() — the IncrementalEngine.merge_findings()
        caller will evict their stale results correctly based on file paths.
        """
        all_vulns: List[Dict] = []
        errors: List[str] = []

        with ThreadPoolExecutor(max_workers=len(self.scanners)) as executor:
            future_to_scanner: Dict[Future, object] = {}

            for scanner in self.scanners:
                if hasattr(scanner, "scan_files"):
                    future = executor.submit(scanner.scan_files, changed_files)
                else:
                    # Fallback: full scan (result will still be merged correctly)
                    logger.warning(
                        f"{scanner.name} does not support scan_files() — "
                        f"running full scan as fallback"
                    )
                    future = executor.submit(scanner.scan)
                future_to_scanner[future] = scanner

            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    vulns, error = future.result()
                    if vulns:
                        all_vulns.extend(vulns)
                        logger.info(f"✓ {scanner.name}: Found {len(vulns)} issues (incremental)")
                    else:
                        logger.info(f"✓ {scanner.name}: No issues found (incremental)")
                    if error:
                        errors.append(f"{scanner.name}: {error}")
                        logger.warning(f"⚠ {scanner.name} error: {error}")
                except Exception as e:
                    err = f"{scanner.name} failed: {str(e)}"
                    errors.append(err)
                    logger.error(f"✗ {err}", exc_info=True)

        unique_vulns = self._deduplicate_vulnerabilities(all_vulns)

        logger.info("\n" + "=" * 60)
        logger.info(
            f"INCREMENTAL SCAN COMPLETE: {len(unique_vulns)} unique vulnerabilities "
            f"in {len(changed_files)} files"
        )
        logger.info("=" * 60)

        return unique_vulns, "; ".join(errors) if errors else ""

    # ------------------------------------------------------------------
    # Full scan execution
    # ------------------------------------------------------------------

    def _run_full(self, scanners: List) -> Tuple[List[Dict], List[str]]:
        """Run a list of scanners simultaneously using ThreadPoolExecutor."""
        all_vulns: List[Dict] = []
        errors: List[str] = []

        with ThreadPoolExecutor(max_workers=len(scanners)) as executor:
            future_to_scanner: Dict[Future, object] = {
                executor.submit(scanner.scan): scanner
                for scanner in scanners
            }

            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    vulns, error = future.result()
                    if vulns:
                        all_vulns.extend(vulns)
                        logger.info(f"✓ {scanner.name}: Found {len(vulns)} issues")
                    else:
                        logger.info(f"✓ {scanner.name}: No issues found")
                    if error:
                        errors.append(f"{scanner.name}: {error}")
                        logger.warning(f"⚠ {scanner.name} error: {error}")
                except Exception as e:
                    err = f"{scanner.name} failed: {str(e)}"
                    errors.append(err)
                    logger.error(f"✗ {err}", exc_info=True)

        return all_vulns, errors

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _deduplicate_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """Deduplicate with scanner priority (higher severity wins)."""
        seen: Dict[str, Dict] = {}
        unique: List[Dict] = []

        for vuln in vulns:
            location = vuln.get("location", {})
            fingerprint = self._create_fingerprint(
                location.get("file", ""),
                location.get("start_line", 0),
                vuln.get("message", "")[:100],
                vuln.get("vulnerability_type", ""),
            )

            if fingerprint not in seen:
                seen[fingerprint] = vuln
                unique.append(vuln)
            else:
                existing = seen[fingerprint]
                if self._should_replace(existing, vuln):
                    idx = unique.index(existing)
                    unique[idx] = vuln
                    seen[fingerprint] = vuln

        logger.info(f"Deduplication: {len(vulns)} → {len(unique)} vulnerabilities")

        scanner_counts: Dict[str, int] = {}
        for v in unique:
            s = v.get("scanner", "Unknown")
            scanner_counts[s] = scanner_counts.get(s, 0) + 1
        for scanner, count in sorted(scanner_counts.items()):
            logger.info(f"  {scanner}: {count} unique findings")

        return unique

    def _should_replace(self, existing: Dict, challenger: Dict) -> bool:
        return self._severity_score(challenger) > self._severity_score(existing)

    def _create_fingerprint(self, file: str, line: int, message: str, vuln_type: str) -> str:
        data = f"{file}:{line}:{message}:{vuln_type}"
        return hashlib.md5(data.encode()).hexdigest()

    def _severity_score(self, vuln: Dict) -> int:
        return {
            "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3,
            "LOW": 2, "INFO": 1, "WARNING": 1,
        }.get(vuln.get("severity", "INFO"), 0)

    # ------------------------------------------------------------------
    # Cache (full scan only)
    # ------------------------------------------------------------------

    def _get_cached_results(self) -> List[Dict]:
        try:
            cache_file = os.path.join(self.cache_dir, "scan_results.json")
            if not os.path.exists(cache_file):
                return None
            cache_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(cache_file))
            if cache_age > timedelta(hours=1):
                logger.info("Cache expired (> 1 hour old)")
                return None
            with open(cache_file, "r") as f:
                data = json.load(f)
            if data.get("repo_hash") != self._get_repo_hash():
                logger.info("Cache invalid (repo changed)")
                return None
            return data.get("vulnerabilities", [])
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            return None

    def _cache_results(self, vulns: List[Dict]):
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            cache_file = os.path.join(self.cache_dir, "scan_results.json")
            with open(cache_file, "w") as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "repo_hash": self._get_repo_hash(),
                    "vulnerabilities": vulns,
                }, f, indent=2)
            logger.info("✓ Results cached")
        except Exception as e:
            logger.warning(f"Failed to cache results: {e}")

    def _get_repo_hash(self) -> str:
        try:
            hash_md5 = hashlib.md5()
            extensions = {".py", ".js", ".ts", ".java", ".go", ".rb"}
            files_checked = 0
            for root, dirs, files in os.walk(self.repo_path):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for file in files:
                    if files_checked >= 100:
                        break
                    if os.path.splitext(file)[1] in extensions:
                        try:
                            with open(os.path.join(root, file), "rb") as f:
                                hash_md5.update(f.read())
                            files_checked += 1
                        except Exception:
                            pass
            return hash_md5.hexdigest()
        except Exception as e:
            logger.warning(f"Failed to hash repo: {e}")
            return ""

    # ------------------------------------------------------------------
    # Windows-safe temp directory cleanup
    # ------------------------------------------------------------------

    @staticmethod
    def remove_temp_dir(path: str):
        """Safely remove temp directory including read-only .git files on Windows."""
        def handle_readonly(func, fpath, _):
            os.chmod(fpath, stat.S_IWRITE)
            func(fpath)

        try:
            shutil.rmtree(path, onerror=handle_readonly)
            logger.info(f"✓ Cleaned temp directory: {path}")
        except Exception as e:
            logger.warning(f"Could not clean temp directory: {e}")


class BaseScanner:
    """Base class for all scanners."""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.name = self.__class__.__name__

    def scan(self) -> Tuple[List[Dict], str]:
        raise NotImplementedError("Scanner must implement scan() method")

    def is_available(self) -> bool:
        return True