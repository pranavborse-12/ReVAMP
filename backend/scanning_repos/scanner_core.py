"""
Production Scanner Core - Parallel multi-engine vulnerability detection

Execution model:
  - Semgrep, Bandit, ESLint all run IN PARALLEL via ThreadPoolExecutor
  - Total scan time ≈ slowest scanner (not sum of all)
  - CustomRules removed — Semgrep covers all patterns with higher accuracy
"""
import os
import json
import hashlib
import stat
import shutil
from typing import List, Dict, Tuple, Set
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

    Supplemental (runs after primary):
      - CustomRules → pattern matching, fills gaps, works offline
    """

    def __init__(self, repo_path: str, languages: Set[str]):
        self.repo_path = repo_path
        self.languages = languages
        self.cache_dir = os.path.join(repo_path, '.scan_cache')
        self.scanners = self._initialize_scanners()

    def _initialize_scanners(self) -> List:
        """
        Initialize primary scanners only — all run in parallel.
        Semgrep is the main scanner. Bandit and ESLint added for their languages.
        CustomRules removed — Semgrep covers all patterns with higher accuracy.
        """
        scanners = []

        # Semgrep — always runs, handles all languages
        scanners.append(SemgrepScanner(self.repo_path, self.languages))

        # Bandit — Python deep analysis
        if 'python' in self.languages:
            scanners.append(BanditScanner(self.repo_path))

        # ESLint — JS/TS security rules
        if any(lang in self.languages for lang in ['javascript', 'typescript']):
            scanners.append(ESLintScanner(self.repo_path))

        logger.info(f"✓ Scanners (parallel): {[s.name for s in scanners]}")
        return scanners

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    def scan(self, use_cache: bool = True) -> Tuple[List[Dict], str]:
        """
        Run full scan — primary scanners in parallel, then supplemental.
        Returns: (vulnerabilities, error_message)
        """
        logger.info("=" * 60)
        logger.info("STARTING PARALLEL SECURITY SCAN")
        logger.info(f"Scanners (parallel): {[s.name for s in self.scanners]}")
        logger.info("=" * 60)

        # Check cache
        if use_cache:
            cached = self._get_cached_results()
            if cached:
                logger.info("✓ Using cached scan results")
                return cached, ""

        # Run all scanners in parallel
        all_vulnerabilities, errors = self._run_parallel(self.scanners)

        # Deduplicate
        unique_vulns = self._deduplicate_vulnerabilities(all_vulnerabilities)

        logger.info("\n" + "=" * 60)
        logger.info(f"SCAN COMPLETE: {len(unique_vulns)} unique vulnerabilities")
        logger.info("=" * 60)

        if use_cache:
            self._cache_results(unique_vulns)

        return unique_vulns, "; ".join(errors) if errors else ""

    # ------------------------------------------------------------------
    # Parallel execution engine
    # ------------------------------------------------------------------

    def _run_parallel(self, scanners: List) -> Tuple[List[Dict], List[str]]:
        """
        Run a list of scanners simultaneously using ThreadPoolExecutor.
        Each scanner.scan() runs in its own thread (safe since they're subprocesses).
        Returns: (all_vulnerabilities_combined, errors)
        """
        all_vulns = []
        errors = []

        # Use as many workers as there are scanners
        max_workers = len(scanners)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scanner jobs
            future_to_scanner: Dict[Future, object] = {
                executor.submit(scanner.scan): scanner
                for scanner in scanners
            }

            # Collect results as they complete
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
    # Deduplication with scanner priority
    # ------------------------------------------------------------------

    def _deduplicate_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """
        Deduplicate vulnerabilities with scanner priority weighting.

        Rules:
        1. If same issue found by primary + custom → keep primary version
        2. If same issue found by two primaries → keep highest severity
        3. CustomRules findings only kept if no primary scanner caught it
        """
        seen: Dict[str, Dict] = {}
        unique: List[Dict] = []

        for vuln in vulns:
            location = vuln.get('location', {})
            fingerprint = self._create_fingerprint(
                location.get('file', ''),
                location.get('start_line', 0),
                vuln.get('message', '')[:100],
                vuln.get('vulnerability_type', '')
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

        # Log scanner contribution breakdown
        scanner_counts: Dict[str, int] = {}
        for v in unique:
            s = v.get('scanner', 'Unknown')
            scanner_counts[s] = scanner_counts.get(s, 0) + 1
        for scanner, count in sorted(scanner_counts.items()):
            logger.info(f"  {scanner}: {count} unique findings")

        return unique

    def _should_replace(self, existing: Dict, challenger: Dict) -> bool:
        """Higher severity wins between any two scanners"""
        return self._severity_score(challenger) > self._severity_score(existing)

    def _create_fingerprint(self, file: str, line: int, message: str, vuln_type: str) -> str:
        data = f"{file}:{line}:{message}:{vuln_type}"
        return hashlib.md5(data.encode()).hexdigest()

    def _severity_score(self, vuln: Dict) -> int:
        return {
            'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3,
            'LOW': 2, 'INFO': 1, 'WARNING': 1
        }.get(vuln.get('severity', 'INFO'), 0)

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _get_cached_results(self) -> List[Dict]:
        try:
            cache_file = os.path.join(self.cache_dir, 'scan_results.json')
            if not os.path.exists(cache_file):
                return None
            cache_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(cache_file))
            if cache_age > timedelta(hours=1):
                logger.info("Cache expired (> 1 hour old)")
                return None
            with open(cache_file, 'r') as f:
                data = json.load(f)
            if data.get('repo_hash') != self._get_repo_hash():
                logger.info("Cache invalid (repo changed)")
                return None
            return data.get('vulnerabilities', [])
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            return None

    def _cache_results(self, vulns: List[Dict]):
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            cache_file = os.path.join(self.cache_dir, 'scan_results.json')
            with open(cache_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'repo_hash': self._get_repo_hash(),
                    'vulnerabilities': vulns
                }, f, indent=2)
            logger.info(f"✓ Results cached")
        except Exception as e:
            logger.warning(f"Failed to cache results: {e}")

    def _get_repo_hash(self) -> str:
        try:
            hash_md5 = hashlib.md5()
            extensions = {'.py', '.js', '.ts', '.java', '.go', '.rb'}
            files_checked = 0
            for root, dirs, files in os.walk(self.repo_path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for file in files:
                    if files_checked >= 100:
                        break
                    if os.path.splitext(file)[1] in extensions:
                        try:
                            with open(os.path.join(root, file), 'rb') as f:
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
        """
        Safely remove temp directory including read-only .git files on Windows.
        Fixes: [WinError 5] Access is denied on .git/objects/pack files.
        """
        def handle_readonly(func, fpath, _):
            os.chmod(fpath, stat.S_IWRITE)
            func(fpath)

        try:
            shutil.rmtree(path, onerror=handle_readonly)
            logger.info(f"✓ Cleaned temp directory: {path}")
        except Exception as e:
            logger.warning(f"Could not clean temp directory: {e}")


class BaseScanner:
    """Base class for all scanners"""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.name = self.__class__.__name__

    def scan(self) -> Tuple[List[Dict], str]:
        raise NotImplementedError("Scanner must implement scan() method")

    def is_available(self) -> bool:
        return True