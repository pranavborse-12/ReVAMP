"""
Bandit Scanner - Python-specific security analysis
Fast, accurate, no API limits
"""
import os
import json
import subprocess
from typing import List, Dict, Tuple
from .config import logger
from .utils import normalize_severity, extract_vulnerability_type


class BanditScanner:
    """
    Bandit security scanner for Python code
    Lightweight, fast, no external API needed
    """
    
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.name = "Bandit"
    
    def is_available(self) -> bool:
        """Check if Bandit is installed"""
        try:
            subprocess.run(['bandit', '--version'], capture_output=True, timeout=5, check=True)
            return True
        except:
            return False
    
    def scan(self) -> Tuple[List[Dict], str]:
        """Run Bandit security scan"""
        vulnerabilities = []
        
        if not self.is_available():
            logger.warning("Bandit not installed - skipping Python security checks")
            logger.info("Install with: pip install bandit")
            return [], "Bandit not installed"
        
        try:
            logger.info("Running Bandit Python security scanner...")
            
            # Run Bandit
            cmd = [
                'bandit',
                '-r', self.repo_path,
                '-f', 'json',
                '-ll',  # Only report medium and above
                '--exclude', '*/test/*,*/tests/*,*/.venv/*,*/venv/*,*/node_modules/*'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Bandit returns 1 if issues found, 0 if clean
            if result.stdout:
                try:
                    output = json.loads(result.stdout)
                    results = output.get('results', [])
                    
                    for finding in results:
                        # Extract info
                        issue_severity = finding.get('issue_severity', 'MEDIUM')
                        issue_confidence = finding.get('issue_confidence', 'MEDIUM')
                        issue_text = finding.get('issue_text', '')
                        test_id = finding.get('test_id', '')
                        test_name = finding.get('test_name', '')
                        
                        # Location
                        filename = finding.get('filename', '')
                        line_number = finding.get('line_number', 0)
                        code = finding.get('code', '')
                        
                        # Map Bandit severity to our standard
                        severity_map = {
                            'HIGH': 'HIGH',
                            'MEDIUM': 'MEDIUM',
                            'LOW': 'LOW'
                        }
                        severity = severity_map.get(issue_severity.upper(), 'MEDIUM')
                        
                        # Extract CWE if available
                        cwe_list = []
                        if 'cwe' in finding:
                            cwe_data = finding['cwe']
                            if isinstance(cwe_data, dict):
                                cwe_id = cwe_data.get('id')
                                if cwe_id:
                                    cwe_list.append(f"CWE-{cwe_id}")
                            elif isinstance(cwe_data, str):
                                cwe_list.append(f"CWE-{cwe_data}")
                        
                        # Make path relative
                        rel_path = os.path.relpath(filename, self.repo_path)
                        
                        vulnerability = {
                            'scanner': 'Bandit',
                            'rule_id': test_id or test_name,
                            'severity': severity,
                            'message': issue_text,
                            'vulnerability_type': extract_vulnerability_type(test_name, issue_text),
                            'location': {
                                'file': rel_path,
                                'start_line': line_number,
                                'end_line': line_number,
                                'start_col': None,
                                'end_col': None
                            },
                            'cwe': cwe_list if cwe_list else None,
                            'owasp': [],
                            'confidence': issue_confidence,
                            'code_snippet': code.strip()[:200] if code else None
                        }
                        
                        vulnerabilities.append(vulnerability)
                    
                    logger.info(f"Bandit found {len(vulnerabilities)} Python security issues")
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Bandit output: {e}")
                    return [], "Failed to parse Bandit output"
            
        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timeout")
            return [], "Bandit scan timeout"
        except Exception as e:
            error_msg = f"Bandit error: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [], error_msg
        
        return vulnerabilities, ""