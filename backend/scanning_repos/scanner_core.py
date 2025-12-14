"""
Production Scanner Core - Multi-engine vulnerability detection
Permanent solution with custom rules, caching, and multiple scanners
"""
import os
import json
import hashlib
from typing import List, Dict, Tuple, Set
from pathlib import Path
from datetime import datetime, timedelta
from .config import logger
from .scanner_semgrep import SemgrepScanner
from .scanner_bandit import BanditScanner
from .scanner_eslint import ESLintScanner
from .scanner_custom import CustomRuleScanner
from .scanner_custom import CustomRuleScanner


class VulnerabilityScanner:
    """
    Multi-engine vulnerability scanner with intelligent orchestration
    Combines multiple tools for maximum accuracy
    """
    
    def __init__(self, repo_path: str, languages: Set[str]):
        self.repo_path = repo_path
        self.languages = languages
        self.cache_dir = os.path.join(repo_path, '.scan_cache')
        self.scanners = self._initialize_scanners()
        
    def _initialize_scanners(self) -> List:
        """Initialize available scanners based on detected languages"""
        scanners = []
        
        # Always add custom scanner (works for all languages)
        scanners.append(CustomRuleScanner(self.repo_path))
        
        # Add Semgrep (universal, best for multi-language)
        scanners.append(SemgrepScanner(self.repo_path))
        
        # Add language-specific scanners
        if 'python' in self.languages:
            scanners.append(BanditScanner(self.repo_path))
            
        if any(lang in self.languages for lang in ['javascript', 'typescript']):
            scanners.append(ESLintScanner(self.repo_path))
        
        logger.info(f"✓ Initialized {len(scanners)} scanners: {[s.name for s in scanners]}")
        return scanners
    
    def scan(self, use_cache: bool = True) -> Tuple[List[Dict], str]:
        """
        Run comprehensive scan with all available scanners
        Returns: (vulnerabilities, error_message)
        """
        logger.info("=" * 60)
        logger.info("STARTING COMPREHENSIVE SECURITY SCAN")
        logger.info("=" * 60)
        
        all_vulnerabilities = []
        errors = []
        
        # Check cache first
        if use_cache:
            cached = self._get_cached_results()
            if cached:
                logger.info("✓ Using cached scan results")
                return cached, ""
        
        # Run each scanner
        for scanner in self.scanners:
            try:
                logger.info(f"\n{'─' * 60}")
                logger.info(f"Running {scanner.name}...")
                logger.info(f"{'─' * 60}")
                
                vulns, error = scanner.scan()
                
                if vulns:
                    all_vulnerabilities.extend(vulns)
                    logger.info(f"✓ {scanner.name}: Found {len(vulns)} issues")
                else:
                    logger.info(f"✓ {scanner.name}: No issues found")
                
                if error:
                    errors.append(f"{scanner.name}: {error}")
                    logger.warning(f"⚠ {scanner.name} error: {error}")
                    
            except Exception as e:
                error_msg = f"{scanner.name} failed: {str(e)}"
                errors.append(error_msg)
                logger.error(f"✗ {error_msg}", exc_info=True)
        
        # Deduplicate and merge vulnerabilities
        unique_vulns = self._deduplicate_vulnerabilities(all_vulnerabilities)
        
        logger.info("\n" + "=" * 60)
        logger.info(f"SCAN COMPLETE: {len(unique_vulns)} unique vulnerabilities")
        logger.info("=" * 60)
        
        # Cache results
        if use_cache:
            self._cache_results(unique_vulns)
        
        error_summary = "; ".join(errors) if errors else ""
        return unique_vulns, error_summary
    
    def _deduplicate_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities intelligently"""
        seen = {}
        unique = []
        
        for vuln in vulns:
            # Create fingerprint
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
                # If duplicate, keep the one with higher severity
                existing = seen[fingerprint]
                if self._severity_score(vuln) > self._severity_score(existing):
                    # Replace with higher severity version
                    idx = unique.index(existing)
                    unique[idx] = vuln
                    seen[fingerprint] = vuln
        
        logger.info(f"Deduplication: {len(vulns)} → {len(unique)} vulnerabilities")
        return unique
    
    def _create_fingerprint(self, file: str, line: int, message: str, vuln_type: str) -> str:
        """Create unique fingerprint for vulnerability"""
        data = f"{file}:{line}:{message}:{vuln_type}"
        return hashlib.md5(data.encode()).hexdigest()
    
    def _severity_score(self, vuln: Dict) -> int:
        """Get numeric severity score"""
        severity_map = {
            'CRITICAL': 5,
            'HIGH': 4,
            'MEDIUM': 3,
            'LOW': 2,
            'INFO': 1,
            'WARNING': 1
        }
        return severity_map.get(vuln.get('severity', 'INFO'), 0)
    
    def _get_cached_results(self) -> List[Dict]:
        """Get cached scan results if still valid"""
        try:
            cache_file = os.path.join(self.cache_dir, 'scan_results.json')
            if not os.path.exists(cache_file):
                return None
            
            # Check if cache is fresh (< 1 hour old)
            cache_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(cache_file))
            if cache_age > timedelta(hours=1):
                logger.info("Cache expired (> 1 hour old)")
                return None
            
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            # Verify repo hasn't changed
            current_hash = self._get_repo_hash()
            if data.get('repo_hash') != current_hash:
                logger.info("Cache invalid (repo changed)")
                return None
            
            return data.get('vulnerabilities', [])
            
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            return None
    
    def _cache_results(self, vulns: List[Dict]):
        """Cache scan results"""
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            cache_file = os.path.join(self.cache_dir, 'scan_results.json')
            
            data = {
                'timestamp': datetime.now().isoformat(),
                'repo_hash': self._get_repo_hash(),
                'vulnerabilities': vulns
            }
            
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"✓ Results cached to {cache_file}")
            
        except Exception as e:
            logger.warning(f"Failed to cache results: {e}")
    
    def _get_repo_hash(self) -> str:
        """Get hash of repository state for cache invalidation"""
        try:
            # Hash all Python/JS files (quick approximation)
            hash_md5 = hashlib.md5()
            
            extensions = {'.py', '.js', '.ts', '.java', '.go', '.rb'}
            files_checked = 0
            
            for root, dirs, files in os.walk(self.repo_path):
                # Skip hidden and cache directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    if files_checked >= 100:  # Limit for speed
                        break
                    
                    ext = os.path.splitext(file)[1]
                    if ext in extensions:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'rb') as f:
                                hash_md5.update(f.read())
                            files_checked += 1
                        except:
                            pass
            
            return hash_md5.hexdigest()
            
        except Exception as e:
            logger.warning(f"Failed to hash repo: {e}")
            return ""


class BaseScanner:
    """Base class for all scanners"""
    
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.name = self.__class__.__name__
    
    def scan(self) -> Tuple[List[Dict], str]:
        """
        Run scan and return results
        Returns: (vulnerabilities, error_message)
        """
        raise NotImplementedError("Scanner must implement scan() method")
    
    def is_available(self) -> bool:
        """Check if scanner is available"""
        return True