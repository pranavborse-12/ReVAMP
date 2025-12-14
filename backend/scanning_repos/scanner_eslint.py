"""
ESLint Scanner - JavaScript/TypeScript security analysis
"""
import os
import json
import subprocess
from typing import List, Dict, Tuple
from .config import logger


class ESLintScanner:
    """
    ESLint security scanner for JavaScript/TypeScript
    """
    
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.name = "ESLint"
    
    def is_available(self) -> bool:
        """Check if ESLint is available"""
        try:
            subprocess.run(['npx', 'eslint', '--version'], capture_output=True, timeout=5, check=True)
            return True
        except:
            return False
    
    def scan(self) -> Tuple[List[Dict], str]:
        """Run ESLint security scan"""
        if not self.is_available():
            logger.info("ESLint not available - skipping JS/TS security checks")
            return [], ""
        
        vulnerabilities = []
        
        try:
            logger.info("Running ESLint security scanner...")
            
            cmd = [
                'npx', 'eslint',
                '--ext', '.js,.jsx,.ts,.tsx',
                '--format', 'json',
                '--plugin', 'security',
                self.repo_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.stdout:
                output = json.loads(result.stdout)
                
                for file_result in output:
                    for message in file_result.get('messages', []):
                        if message.get('ruleId', '').startswith('security/'):
                            vulnerability = {
                                'scanner': 'ESLint',
                                'rule_id': message.get('ruleId', ''),
                                'severity': 'MEDIUM' if message.get('severity') == 2 else 'LOW',
                                'message': message.get('message', ''),
                                'vulnerability_type': 'JavaScript Security Issue',
                                'location': {
                                    'file': os.path.relpath(file_result['filePath'], self.repo_path),
                                    'start_line': message.get('line', 0),
                                    'end_line': message.get('endLine', message.get('line', 0)),
                                    'start_col': message.get('column'),
                                    'end_col': message.get('endColumn')
                                },
                                'cwe': None,
                                'owasp': [],
                                'confidence': 'MEDIUM',
                                'code_snippet': None
                            }
                            
                            vulnerabilities.append(vulnerability)
                
                logger.info(f"ESLint found {len(vulnerabilities)} JS/TS security issues")
        
        except subprocess.TimeoutExpired:
            return [], "ESLint timeout"
        except Exception as e:
            logger.warning(f"ESLint error: {e}")
            return [], str(e)
        
        return vulnerabilities, ""