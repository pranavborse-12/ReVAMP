"""
Custom Rule Scanner - Pattern-based vulnerability detection
Works offline, no API limits, fully customizable
"""
import os
import re
from typing import List, Dict, Tuple
from pathlib import Path
from .config import logger


class CustomRuleScanner:
    """
    Custom pattern-based vulnerability scanner
    No external dependencies, works offline
    """
    
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.name = "CustomRules"
        self.rules = self._load_rules()
    
    def _load_rules(self) -> List[Dict]:
        """Load custom vulnerability detection rules"""
        return [
            # SQL Injection patterns
            {
                'id': 'sql-injection-1',
                'pattern': r'execute\s*\(\s*["\'].*\{.*\}.*["\']\s*\)',
                'languages': ['python'],
                'severity': 'CRITICAL',
                'message': 'Potential SQL injection - dynamic query construction',
                'cwe': ['CWE-89'],
                'type': 'SQL Injection'
            },
            {
                'id': 'sql-injection-2',
                'pattern': r'(cursor|conn)\.execute\s*\(\s*.*\+.*\)',
                'languages': ['python'],
                'severity': 'CRITICAL',
                'message': 'SQL injection - string concatenation in query',
                'cwe': ['CWE-89'],
                'type': 'SQL Injection'
            },
            {
                'id': 'sql-injection-3',
                'pattern': r'(SELECT|INSERT|UPDATE|DELETE).*\+.*WHERE',
                'languages': ['python', 'java', 'javascript'],
                'severity': 'CRITICAL',
                'message': 'SQL injection - concatenated WHERE clause',
                'cwe': ['CWE-89'],
                'type': 'SQL Injection'
            },
            
            # Command Injection
            {
                'id': 'command-injection-1',
                'pattern': r'os\.system\s*\([^)]*\+[^)]*\)',
                'languages': ['python'],
                'severity': 'CRITICAL',
                'message': 'Command injection via os.system',
                'cwe': ['CWE-78'],
                'type': 'Command Injection'
            },
            {
                'id': 'command-injection-2',
                'pattern': r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*\)',
                'languages': ['python'],
                'severity': 'CRITICAL',
                'message': 'Command injection - shell=True',
                'cwe': ['CWE-78'],
                'type': 'Command Injection'
            },
            {
                'id': 'command-injection-3',
                'pattern': r'eval\s*\([^)]*\)',
                'languages': ['python', 'javascript'],
                'severity': 'CRITICAL',
                'message': 'Dangerous eval() usage',
                'cwe': ['CWE-95'],
                'type': 'Code Injection'
            },
            {
                'id': 'command-injection-4',
                'pattern': r'exec\s*\([^)]*\)',
                'languages': ['python'],
                'severity': 'CRITICAL',
                'message': 'Dangerous exec() usage',
                'cwe': ['CWE-95'],
                'type': 'Code Injection'
            },
            
            # Hardcoded Secrets
            {
                'id': 'hardcoded-password-1',
                'pattern': r'(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
                'languages': ['python', 'java', 'javascript', 'go'],
                'severity': 'HIGH',
                'message': 'Hardcoded password detected',
                'cwe': ['CWE-798'],
                'type': 'Hardcoded Credentials'
            },
            {
                'id': 'hardcoded-secret-1',
                'pattern': r'(secret_key|api_key|apikey|token)\s*=\s*["\'][^"\']{10,}["\']',
                'languages': ['python', 'java', 'javascript', 'go'],
                'severity': 'HIGH',
                'message': 'Hardcoded API key or secret',
                'cwe': ['CWE-798'],
                'type': 'Hardcoded Credentials'
            },
            {
                'id': 'hardcoded-secret-2',
                'pattern': r'(AWS|aws)_(access_key_id|secret_access_key)\s*=\s*["\'][A-Za-z0-9+/]{20,}["\']',
                'languages': ['python', 'java', 'javascript'],
                'severity': 'CRITICAL',
                'message': 'Hardcoded AWS credentials',
                'cwe': ['CWE-798'],
                'type': 'Hardcoded Credentials'
            },
            
            # Path Traversal
            {
                'id': 'path-traversal-1',
                'pattern': r'open\s*\([^)]*\+[^)]*\)',
                'languages': ['python'],
                'severity': 'HIGH',
                'message': 'Path traversal - dynamic file path',
                'cwe': ['CWE-22'],
                'type': 'Path Traversal'
            },
            {
                'id': 'path-traversal-2',
                'pattern': r'\.\./',
                'languages': ['python', 'java', 'javascript'],
                'severity': 'MEDIUM',
                'message': 'Potential path traversal sequence',
                'cwe': ['CWE-22'],
                'type': 'Path Traversal'
            },
            
            # XSS
            {
                'id': 'xss-1',
                'pattern': r'innerHTML\s*=\s*.*\+',
                'languages': ['javascript', 'typescript'],
                'severity': 'HIGH',
                'message': 'XSS via innerHTML assignment',
                'cwe': ['CWE-79'],
                'type': 'Cross-Site Scripting (XSS)'
            },
            {
                'id': 'xss-2',
                'pattern': r'document\.write\s*\([^)]*\+[^)]*\)',
                'languages': ['javascript', 'typescript'],
                'severity': 'HIGH',
                'message': 'XSS via document.write',
                'cwe': ['CWE-79'],
                'type': 'Cross-Site Scripting (XSS)'
            },
            {
                'id': 'xss-3',
                'pattern': r'dangerouslySetInnerHTML',
                'languages': ['javascript', 'typescript'],
                'severity': 'MEDIUM',
                'message': 'Potentially unsafe HTML rendering',
                'cwe': ['CWE-79'],
                'type': 'Cross-Site Scripting (XSS)'
            },
            
            # Weak Crypto
            {
                'id': 'weak-crypto-1',
                'pattern': r'hashlib\.md5\s*\(',
                'languages': ['python'],
                'severity': 'MEDIUM',
                'message': 'Weak cryptographic hash MD5',
                'cwe': ['CWE-328'],
                'type': 'Weak Cryptography'
            },
            {
                'id': 'weak-crypto-2',
                'pattern': r'hashlib\.sha1\s*\(',
                'languages': ['python'],
                'severity': 'MEDIUM',
                'message': 'Weak cryptographic hash SHA1',
                'cwe': ['CWE-328'],
                'type': 'Weak Cryptography'
            },
            {
                'id': 'weak-crypto-3',
                'pattern': r'Random\s*\(\s*\)',
                'languages': ['python'],
                'severity': 'MEDIUM',
                'message': 'Weak random number generator',
                'cwe': ['CWE-338'],
                'type': 'Weak Cryptography'
            },
            
            # Insecure Deserialization
            {
                'id': 'deserialization-1',
                'pattern': r'pickle\.loads?\s*\(',
                'languages': ['python'],
                'severity': 'HIGH',
                'message': 'Insecure deserialization with pickle',
                'cwe': ['CWE-502'],
                'type': 'Insecure Deserialization'
            },
            {
                'id': 'deserialization-2',
                'pattern': r'yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=)',
                'languages': ['python'],
                'severity': 'HIGH',
                'message': 'Unsafe YAML deserialization',
                'cwe': ['CWE-502'],
                'type': 'Insecure Deserialization'
            },
            
            # Debug/Development Issues
            {
                'id': 'debug-1',
                'pattern': r'DEBUG\s*=\s*True',
                'languages': ['python'],
                'severity': 'MEDIUM',
                'message': 'Debug mode enabled in production',
                'cwe': ['CWE-489'],
                'type': 'Debug Mode'
            },
            {
                'id': 'debug-2',
                'pattern': r'console\.(log|error|warn)\s*\(',
                'languages': ['javascript', 'typescript'],
                'severity': 'LOW',
                'message': 'Console logging may expose sensitive data',
                'cwe': ['CWE-532'],
                'type': 'Information Exposure'
            },
        ]
    
    def scan(self) -> Tuple[List[Dict], str]:
        """Scan repository with custom rules"""
        vulnerabilities = []
        
        try:
            logger.info(f"Scanning {self.repo_path} with {len(self.rules)} custom rules")
            
            # Get all source files
            source_files = self._get_source_files()
            logger.info(f"Found {len(source_files)} source files")
            
            files_scanned = 0
            
            for file_path in source_files:
                try:
                    # Determine language
                    lang = self._detect_language(file_path)
                    if not lang:
                        continue
                    
                    # Read file content
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                    
                    # Apply rules
                    for rule in self.rules:
                        if lang not in rule['languages']:
                            continue
                        
                        # Search for pattern
                        pattern = re.compile(rule['pattern'], re.IGNORECASE)
                        
                        for line_num, line in enumerate(lines, 1):
                            matches = pattern.finditer(line)
                            
                            for match in matches:
                                # Create vulnerability
                                rel_path = os.path.relpath(file_path, self.repo_path)
                                
                                vulnerability = {
                                    'scanner': 'CustomRules',
                                    'rule_id': rule['id'],
                                    'severity': rule['severity'],
                                    'message': rule['message'],
                                    'vulnerability_type': rule['type'],
                                    'location': {
                                        'file': rel_path,
                                        'start_line': line_num,
                                        'end_line': line_num,
                                        'start_col': match.start(),
                                        'end_col': match.end()
                                    },
                                    'cwe': rule['cwe'],
                                    'owasp': [],
                                    'confidence': 'HIGH',
                                    'code_snippet': line.strip()[:200]
                                }
                                
                                vulnerabilities.append(vulnerability)
                    
                    files_scanned += 1
                    
                except Exception as e:
                    logger.debug(f"Error scanning {file_path}: {e}")
                    continue
            
            logger.info(f"Custom scanner: Scanned {files_scanned} files, found {len(vulnerabilities)} issues")
            
        except Exception as e:
            error_msg = f"Custom scanner error: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return [], error_msg
        
        return vulnerabilities, ""
    
    def _get_source_files(self) -> List[str]:
        """Get all source code files"""
        source_files = []
        
        extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx',
            '.java', '.go', '.rb', '.php', '.cs',
            '.cpp', '.c', '.h', '.hpp'
        }
        
        skip_dirs = {
            '.git', 'node_modules', '__pycache__', 'venv', 'env',
            'dist', 'build', 'vendor', '.venv', 'target'
        }
        
        for root, dirs, files in os.walk(self.repo_path):
            # Skip unwanted directories
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                ext = os.path.splitext(file)[1]
                if ext in extensions:
                    source_files.append(os.path.join(root, file))
        
        return source_files
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext = os.path.splitext(file_path)[1]
        
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c',
            '.h': 'c',
            '.hpp': 'cpp'
        }
        
        return lang_map.get(ext)