"""
Semgrep Scanner - Optimized with local rules fallback
"""
import os
import json
import subprocess
from typing import List, Dict, Tuple
from .config import logger, SEMGREP_TIMEOUT, SEMGREP_APP_TOKEN
from .utils import normalize_severity, extract_vulnerability_type


class SemgrepScanner:
    """
    Optimized Semgrep scanner with intelligent rule selection
    """
    
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.name = "Semgrep"
    
    def is_available(self) -> bool:
        """Check if Semgrep is installed"""
        try:
            subprocess.run(['semgrep', '--version'], capture_output=True, timeout=5, check=True)
            return True
        except:
            return False
    
    def scan(self) -> Tuple[List[Dict], str]:
        """Run optimized Semgrep scan"""
        if not self.is_available():
            logger.warning("Semgrep not installed")
            return [], "Semgrep not installed"
        
        # Use focused rulesets for speed
        rulesets = [
            'p/security-audit',
            'p/owasp-top-ten',
            'p/secrets',
        ]
        
        vulnerabilities = []
        
        try:
            config_args = []
            for ruleset in rulesets:
                config_args.extend(['--config', ruleset])
            
            cmd = [
                'semgrep',
                'scan',
                *config_args,
                '--json',
                '--timeout', '30',
                '--max-memory', '2048',
                '--jobs', '2',
                '--optimizations', 'all',
                '--metrics', 'off',
                '--exclude', 'node_modules',
                '--exclude', 'vendor',
                '--exclude', '.git',
                '--exclude', 'test',
                '--exclude', 'tests',
                self.repo_path
            ]
            
            env = os.environ.copy()
            if SEMGREP_APP_TOKEN:
                env['SEMGREP_APP_TOKEN'] = SEMGREP_APP_TOKEN
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SEMGREP_TIMEOUT,
                env=env
            )
            
            if result.stdout:
                output = json.loads(result.stdout)
                results = output.get('results', [])
                
                for finding in results:
                    extra = finding.get('extra', {})
                    metadata = extra.get('metadata', {})
                    
                    vulnerability = {
                        'scanner': 'Semgrep',
                        'rule_id': finding.get('check_id', 'unknown'),
                        'severity': normalize_severity(
                            extra.get('severity', 'INFO'),
                            finding.get('check_id', ''),
                            metadata.get('cwe', [])
                        ),
                        'message': extra.get('message', ''),
                        'vulnerability_type': extract_vulnerability_type(
                            finding.get('check_id', ''),
                            extra.get('message', '')
                        ),
                        'location': {
                            'file': os.path.relpath(finding.get('path', ''), self.repo_path),
                            'start_line': finding.get('start', {}).get('line', 0),
                            'end_line': finding.get('end', {}).get('line', 0),
                            'start_col': finding.get('start', {}).get('col'),
                            'end_col': finding.get('end', {}).get('col')
                        },
                        'cwe': metadata.get('cwe', []),
                        'owasp': metadata.get('owasp', []),
                        'confidence': metadata.get('confidence', 'MEDIUM'),
                        'code_snippet': extra.get('lines', '')[:200]
                    }
                    
                    vulnerabilities.append(vulnerability)
                
                logger.info(f"Semgrep found {len(vulnerabilities)} issues")
        
        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep timeout after {SEMGREP_TIMEOUT}s")
            return vulnerabilities, "Timeout"
        except Exception as e:
            logger.error(f"Semgrep error: {e}", exc_info=True)
            return [], str(e)
        
        return vulnerabilities, ""