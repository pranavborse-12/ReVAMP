"""
Enhanced utility functions for scanning module
Improved language detection and GitHub integration
"""
import os
import subprocess
import asyncio
from pathlib import Path
from typing import Optional, Tuple, Set, Dict, Any
import httpx
from .config import (
    logger, LANGUAGE_EXTENSIONS, SKIP_DIRS,
    SEVERITY_RULES, CWE_SEVERITY_MAP, GITHUB_API_URL
)
from .models import SeveritySummary


def run_command_with_timeout(
    cmd: list,
    timeout: int,
    cwd: str = None,
    env: dict = None
) -> Tuple[int, str, str]:
    """Run a command with timeout and proper error handling"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            cwd=cwd,
            env=env or os.environ.copy()
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd[:3])}")
        return -1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        logger.error(f"Command failed: {str(e)}")
        return -1, "", str(e)


def get_dir_size(path: str) -> int:
    """
    Get directory size in bytes (fast implementation)
    """
    total = 0
    try:
        with os.scandir(path) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat().st_size
                elif entry.is_dir(follow_symlinks=False):
                    # Skip .git directory for speed
                    if entry.name != '.git':
                        total += get_dir_size(entry.path)
    except (PermissionError, OSError):
        pass
    return total


def detect_languages(repo_path: str, max_files: int = 10000) -> Set[str]:
    """
    Enhanced language detection with better coverage
    Scans repository for programming languages based on file extensions
    """
    languages = set()
    file_count = 0
    
    # Extended language mapping with more file types
    extended_extensions = {
        # Python
        ".py": "python",
        ".pyw": "python",
        ".pyx": "python",
        
        # JavaScript/TypeScript
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        
        # Java
        ".java": "java",
        ".jsp": "java",
        
        # C/C++
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
        ".hxx": "cpp",
        ".hh": "cpp",
        
        # C#
        ".cs": "csharp",
        ".cshtml": "csharp",
        
        # Go
        ".go": "go",
        
        # Ruby
        ".rb": "ruby",
        ".erb": "ruby",
        
        # PHP
        ".php": "php",
        ".php3": "php",
        ".php4": "php",
        ".php5": "php",
        ".phtml": "php",
        
        # Swift
        ".swift": "swift",
        
        # Kotlin
        ".kt": "kotlin",
        ".kts": "kotlin",
        
        # Rust
        ".rs": "rust",
        
        # Scala
        ".scala": "scala",
        ".sc": "scala",
        
        # Shell
        ".sh": "shell",
        ".bash": "shell",
        ".zsh": "shell",
        
        # Web
        ".html": "html",
        ".htm": "html",
        ".css": "css",
        ".scss": "scss",
        ".sass": "sass",
        ".less": "less",
        
        # Data/Config
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".sql": "sql",
        ".toml": "toml",
        
        # Others
        ".vue": "javascript",
        ".svelte": "javascript",
        ".dart": "dart",
        ".r": "r",
        ".R": "r",
        ".m": "objective-c",
        ".mm": "objective-c",
    }

    try:
        logger.info(f"Starting language detection in {repo_path}")
        
        for root, dirs, files in os.walk(repo_path):
            # Skip unwanted directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for file in files:
                if file_count >= max_files:
                    logger.warning(f"File limit ({max_files}) reached during language detection")
                    break

                # Get file extension
                ext = Path(file).suffix.lower()
                
                # Check in extended mapping
                if ext in extended_extensions:
                    lang = extended_extensions[ext]
                    languages.add(lang)
                    file_count += 1
                    logger.debug(f"Detected {lang} from {file}")
                
                # Also check for specific filenames (Dockerfiles, Makefiles, etc.)
                elif file.lower() in ['dockerfile', 'makefile', 'rakefile', 'gemfile']:
                    languages.add("shell")
                    file_count += 1

            if file_count >= max_files:
                break

        # Additional detection: Check for package managers and config files
        config_indicators = {
            'package.json': 'javascript',
            'package-lock.json': 'javascript',
            'yarn.lock': 'javascript',
            'pom.xml': 'java',
            'build.gradle': 'java',
            'requirements.txt': 'python',
            'Pipfile': 'python',
            'setup.py': 'python',
            'Gemfile': 'ruby',
            'Cargo.toml': 'rust',
            'go.mod': 'go',
            'composer.json': 'php',
        }
        
        for config_file, lang in config_indicators.items():
            config_path = os.path.join(repo_path, config_file)
            if os.path.exists(config_path):
                languages.add(lang)
                logger.info(f"Detected {lang} from config file: {config_file}")

        logger.info(f"Language detection complete: {languages} (scanned {file_count} files)")
        
        if not languages:
            logger.warning("No languages detected! This might indicate an issue with the repository.")
            # Add a default to ensure some scanning happens
            languages.add("python")  # Default fallback
            
    except Exception as e:
        logger.error(f"Language detection error: {str(e)}", exc_info=True)
        # Ensure we have at least one language
        languages.add("python")

    return languages


def get_code_snippet(
    file_path: str,
    start_line: int,
    end_line: int,
    max_lines: int = 10,
    context_lines: int = 2
) -> Optional[str]:
    """
    Extract code snippet from file with context lines
    Shows lines before and after the vulnerability for better context
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        # Add context lines
        context_start = max(0, start_line - 1 - context_lines)
        context_end = min(len(lines), end_line + context_lines)

        # Limit total lines
        if context_end - context_start > max_lines:
            context_end = context_start + max_lines

        snippet_lines = []
        for i in range(context_start, context_end):
            line_num = i + 1
            line_content = lines[i].rstrip()
            
            # Mark the vulnerable lines
            if start_line <= line_num <= end_line:
                snippet_lines.append(f">>> {line_num:4d} | {line_content}")
            else:
                snippet_lines.append(f"    {line_num:4d} | {line_content}")
        
        snippet = '\n'.join(snippet_lines)
        return snippet[:1000]  # Increased limit for better context
        
    except Exception as e:
        logger.debug(f"Error reading code snippet from {file_path}: {e}")
        return None


def normalize_severity(severity: str, rule_id: str = "", cwe_list: list = None) -> str:
    """
    Intelligently normalize severity based on multiple factors
    Enhanced with better rule pattern matching
    """
    severity_upper = severity.upper()

    # Validate severity
    if severity_upper in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'WARNING']:
        
        # Enhanced rule pattern matching
        rule_lower = rule_id.lower()
        
        # Critical patterns
        critical_patterns = [
            'sql-injection', 'sqli', 'command-injection', 'os-command',
            'rce', 'remote-code', 'xxe', 'deserialization',
            'path-traversal', 'directory-traversal', 'arbitrary-file'
        ]
        
        # High severity patterns
        high_patterns = [
            'xss', 'cross-site-scripting', 'csrf', 'cross-site-request',
            'auth', 'authentication', 'authorization', 'session',
            'hardcoded-secret', 'hardcoded-password', 'hardcoded-key',
            'weak-crypto', 'weak-hash', 'insecure-hash'
        ]
        
        # Medium severity patterns
        medium_patterns = [
            'crypto', 'encryption', 'insecure', 'unsafe',
            'validation', 'sanitization', 'exposure'
        ]
        
        # Check for critical patterns
        for pattern in critical_patterns:
            if pattern in rule_lower:
                logger.info(f"Upgraded severity to CRITICAL based on pattern: {pattern}")
                return 'CRITICAL'
        
        # Check for high patterns
        for pattern in high_patterns:
            if pattern in rule_lower:
                severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                if severity_order.index('HIGH') > severity_order.index(severity_upper):
                    logger.info(f"Upgraded severity to HIGH based on pattern: {pattern}")
                    return 'HIGH'
        
        # Check for medium patterns
        for pattern in medium_patterns:
            if pattern in rule_lower:
                severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                if severity_order.index('MEDIUM') > severity_order.index(severity_upper):
                    logger.info(f"Upgraded severity to MEDIUM based on pattern: {pattern}")
                    return 'MEDIUM'

        # Check CWE mappings
        if cwe_list:
            for cwe in cwe_list:
                cwe_num = cwe.replace('CWE-', '').strip()
                if cwe_num in CWE_SEVERITY_MAP:
                    mapped_severity = CWE_SEVERITY_MAP[cwe_num]
                    severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                    if severity_order.index(mapped_severity) > severity_order.index(severity_upper):
                        logger.info(f"Upgraded severity to {mapped_severity} based on CWE-{cwe_num}")
                        return mapped_severity

        return severity_upper

    # Map non-standard severities
    severity_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "NOTE": "LOW",
        "NOTICE": "LOW"
    }

    return severity_map.get(severity_upper, "MEDIUM")


def extract_vulnerability_type(rule_id: str, message: str) -> str:
    """
    Extract vulnerability type from rule ID and message
    Enhanced with more patterns
    """
    rule_lower = rule_id.lower()
    message_lower = message.lower()

    patterns = {
        "SQL Injection": [
            'sql-injection', 'sqli', 'sql injection', 'sql query'
        ],
        "Command Injection": [
            'command-injection', 'os-command', 'shell-injection',
            'command execution', 'shell command'
        ],
        "Cross-Site Scripting (XSS)": [
            'xss', 'cross-site-scripting', 'dom-xss', 'reflected-xss',
            'stored-xss', 'javascript injection'
        ],
        "Path Traversal": [
            'path-traversal', 'directory-traversal', 'file-path',
            'arbitrary-file', 'file inclusion'
        ],
        "Cross-Site Request Forgery (CSRF)": [
            'csrf', 'cross-site-request', 'request forgery'
        ],
        "Hardcoded Credentials": [
            'hardcoded', 'secret', 'password', 'api-key', 'credential',
            'token', 'private-key', 'access-key'
        ],
        "Cryptographic Issue": [
            'crypto', 'encryption', 'weak-hash', 'weak-cipher',
            'insecure-random', 'md5', 'sha1'
        ],
        "Server-Side Request Forgery (SSRF)": [
            'ssrf', 'server-side-request', 'url-redirect'
        ],
        "Insecure Deserialization": [
            'deserialization', 'pickle', 'unsafe-load', 'serialize'
        ],
        "Information Disclosure": [
            'information-disclosure', 'sensitive-data', 'exposure',
            'leak', 'debug-info'
        ],
        "XML External Entity (XXE)": [
            'xxe', 'xml-external', 'xml-parser'
        ],
        "Authentication Issue": [
            'authentication', 'auth-bypass', 'weak-auth', 'session'
        ],
        "Authorization Issue": [
            'authorization', 'access-control', 'privilege', 'permission'
        ],
        "Input Validation": [
            'validation', 'sanitization', 'input-check', 'user-input'
        ],
        "Race Condition": [
            'race-condition', 'toctou', 'concurrent'
        ],
        "Buffer Overflow": [
            'buffer-overflow', 'buffer-overrun', 'memory-corruption'
        ],
        "Denial of Service": [
            'dos', 'denial-of-service', 'resource-exhaustion'
        ],
    }

    for vuln_type, terms in patterns.items():
        if any(term in rule_lower or term in message_lower for term in terms):
            return vuln_type

    return "Security Issue"


def calculate_severity_summary(vulnerabilities: list) -> SeveritySummary:
    """Calculate severity summary from vulnerabilities"""
    summary = SeveritySummary()

    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'INFO').upper()
        if severity == 'CRITICAL':
            summary.critical += 1
        elif severity == 'HIGH':
            summary.high += 1
        elif severity == 'MEDIUM':
            summary.medium += 1
        elif severity == 'LOW':
            summary.low += 1
        elif severity == 'WARNING':
            summary.warning += 1
        else:
            summary.info += 1

    return summary


def get_semgrep_token(authorization: Optional[str] = None) -> Optional[str]:
    """Get Semgrep token from env or header"""
    from .config import SEMGREP_APP_TOKEN
    if authorization and authorization.startswith("Bearer "):
        return authorization.replace("Bearer ", "")
    return SEMGREP_APP_TOKEN


async def clone_github_repo(
    github_token: str,
    owner: str,
    repo: str,
    branch: str,
    target_path: str,
    timeout: int = 120
) -> Tuple[bool, str]:
    """
    Clone a GitHub repository using GitHub token for authentication
    Optimized with sparse checkout and depth limiting
    """
    try:
        # Use GitHub API to get clone URL with token
        clone_url = f"https://{github_token}@github.com/{owner}/{repo}.git"

        # Enhanced clone command with better options
        cmd = [
            'git', 'clone',
            '--depth', '1',  # Shallow clone - faster
            '--single-branch',  # Only the specified branch
            '--branch', branch,
            clone_url,
            target_path
        ]

        logger.info(f"Cloning {owner}/{repo} from branch {branch}...")
        returncode, stdout, stderr = run_command_with_timeout(cmd, timeout)

        if returncode != 0:
            # Sanitize error message to not expose token
            error_msg = stderr.replace(github_token, '***')
            
            # Try alternate branch names if main fails
            if 'main' in branch.lower() or 'master' in branch.lower():
                alternate_branch = 'master' if 'main' in branch.lower() else 'main'
                logger.info(f"Trying alternate branch: {alternate_branch}")
                
                cmd[5] = alternate_branch  # Update branch in command
                returncode, stdout, stderr = run_command_with_timeout(cmd, timeout)
                
                if returncode == 0:
                    logger.info(f"Successfully cloned using branch {alternate_branch}")
                    return True, "Repository cloned successfully"
            
            logger.error(f"Clone failed: {error_msg}")
            return False, f"Failed to clone repository: {error_msg[:200]}"

        logger.info(f"Repository cloned successfully to {target_path}")
        
        # Count files for logging
        file_count = sum(1 for _ in Path(target_path).rglob('*') if _.is_file())
        logger.info(f"Repository contains approximately {file_count} files")
        
        return True, "Repository cloned successfully"

    except Exception as e:
        logger.error(f"Clone error: {str(e)}", exc_info=True)
        return False, f"Clone failed: {str(e)}"