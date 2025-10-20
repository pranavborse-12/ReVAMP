"""
Enhanced configuration for scanning module
Extended language support and severity mappings
"""
import os
import logging
from dotenv import load_dotenv

load_dotenv()

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanning.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Security Scanner Configuration
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
MAX_REPO_SIZE_MB = int(os.getenv("MAX_REPO_SIZE_MB", "500"))
CLONE_TIMEOUT = int(os.getenv("CLONE_TIMEOUT", "120"))
SEMGREP_TIMEOUT = int(os.getenv("SEMGREP_TIMEOUT", "300"))
CODEQL_ANALYZE_TIMEOUT = int(os.getenv("CODEQL_ANALYZE_TIMEOUT", "600"))
CODEQL_DB_TIMEOUT = int(os.getenv("CODEQL_DB_TIMEOUT", "300"))

# Scanner configuration
SEMGREP_APP_TOKEN = os.getenv("SEMGREP_APP_TOKEN")
CODEQL_LANGUAGES = {
    "java", "cpp", "csharp", "python", "javascript", 
    "go", "swift", "kotlin", "ruby", "typescript", "c"
}

# Extended Language detection - More comprehensive
LANGUAGE_EXTENSIONS = {
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
    ".vue": "javascript",
    ".svelte": "javascript",
    
    # Java
    ".java": "java",
    ".jsp": "java",
    ".jspx": "java",
    
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
    ".aspx": "csharp",
    
    # Go
    ".go": "go",
    
    # Ruby
    ".rb": "ruby",
    ".erb": "ruby",
    ".rake": "ruby",
    
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
    
    # Shell/Bash
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".fish": "shell",
    
    # Web technologies
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "scss",
    ".sass": "sass",
    ".less": "less",
    
    # Data/Config formats
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".sql": "sql",
    ".toml": "toml",
    ".ini": "ini",
    
    # Other languages
    ".dart": "dart",
    ".r": "r",
    ".R": "r",
    ".m": "objective-c",
    ".mm": "objective-c",
    ".pl": "perl",
    ".pm": "perl",
    ".lua": "lua",
    ".groovy": "groovy",
    ".clj": "clojure",
    ".ex": "elixir",
    ".exs": "elixir",
}

SKIP_DIRS = {
    ".git", ".github", ".vscode", ".idea", ".vs",
    "node_modules", "__pycache__", ".pytest_cache",
    "venv", "env", ".env", "virtualenv",
    "dist", "build", "target", "out",
    ".egg-info", ".tox", "htmlcov", ".coverage",
    "site-packages", "vendor", "bower_components",
    ".nuxt", ".next", ".cache",
    "bin", "obj", "packages"
}

# Enhanced Severity Rules - More comprehensive patterns
SEVERITY_RULES = {
    # CRITICAL - Remote Code Execution & Injection
    "sql-injection": "CRITICAL",
    "sqli": "CRITICAL",
    "command-injection": "CRITICAL",
    "os-command": "CRITICAL",
    "rce": "CRITICAL",
    "remote-code": "CRITICAL",
    "code-injection": "CRITICAL",
    "deserialization": "CRITICAL",
    "unsafe-deserialization": "CRITICAL",
    "xxe": "CRITICAL",
    "xml-external": "CRITICAL",
    "path-traversal": "CRITICAL",
    "directory-traversal": "CRITICAL",
    "arbitrary-file": "CRITICAL",
    "file-inclusion": "CRITICAL",
    
    # HIGH - Authentication, Authorization, XSS, Secrets
    "xss": "HIGH",
    "cross-site-scripting": "HIGH",
    "csrf": "HIGH",
    "cross-site-request": "HIGH",
    "auth": "HIGH",
    "authentication": "HIGH",
    "authorization": "HIGH",
    "session": "HIGH",
    "hardcoded": "HIGH",
    "hardcoded-secret": "HIGH",
    "hardcoded-password": "HIGH",
    "hardcoded-key": "HIGH",
    "secret": "HIGH",
    "api-key": "HIGH",
    "private-key": "HIGH",
    "weak-crypto": "HIGH",
    "weak-hash": "HIGH",
    "ssrf": "HIGH",
    "server-side-request": "HIGH",
    
    # MEDIUM - Crypto, Validation, Information Disclosure
    "crypto": "MEDIUM",
    "encryption": "MEDIUM",
    "insecure": "MEDIUM",
    "unsafe": "MEDIUM",
    "validation": "MEDIUM",
    "sanitization": "MEDIUM",
    "exposure": "MEDIUM",
    "information-disclosure": "MEDIUM",
    "sensitive-data": "MEDIUM",
    "weak-cipher": "MEDIUM",
    "insecure-random": "MEDIUM",
}

# Enhanced CWE to Severity mapping
CWE_SEVERITY_MAP = {
    # CRITICAL - Code Execution & Injection
    "89": "CRITICAL",     # SQL Injection
    "78": "CRITICAL",     # OS Command Injection
    "94": "CRITICAL",     # Code Injection
    "91": "CRITICAL",     # XML Injection
    "90": "CRITICAL",     # LDAP Injection
    "77": "CRITICAL",     # Command Injection
    "502": "CRITICAL",    # Deserialization
    "611": "CRITICAL",    # XXE
    "22": "CRITICAL",     # Path Traversal
    "98": "CRITICAL",     # File Inclusion
    
    # HIGH - XSS, CSRF, Auth, Secrets
    "79": "HIGH",         # XSS
    "352": "HIGH",        # CSRF
    "798": "HIGH",        # Hardcoded Credentials
    "259": "HIGH",        # Hardcoded Password
    "321": "HIGH",        # Hardcoded Cryptographic Key
    "287": "HIGH",        # Authentication Issues
    "306": "HIGH",        # Missing Authentication
    "862": "HIGH",        # Missing Authorization
    "863": "HIGH",        # Incorrect Authorization
    "918": "HIGH",        # SSRF
    "327": "HIGH",        # Weak Crypto
    "328": "HIGH",        # Weak Hash
    "759": "HIGH",        # Use of One-Way Hash without Salt
    
    # MEDIUM - Validation, Information Disclosure
    "20": "MEDIUM",       # Improper Input Validation
    "200": "MEDIUM",      # Information Exposure
    "284": "MEDIUM",      # Access Control
    "345": "MEDIUM",      # Insufficient Verification
    "346": "MEDIUM",      # Origin Validation Error
    "347": "MEDIUM",      # Cryptographic Signature Verification
    "384": "MEDIUM",      # Session Fixation
    "522": "MEDIUM",      # Insufficiently Protected Credentials
    "523": "MEDIUM",      # Unprotected Transport
    "319": "MEDIUM",      # Cleartext Transmission
    "330": "MEDIUM",      # Weak Random
    "338": "MEDIUM",      # Weak PRNG
    
    # LOW - Deprecated Functions, Warnings
    "477": "LOW",         # Use of Obsolete Function
    "676": "LOW",         # Use of Potentially Dangerous Function
    "710": "LOW",         # Improper Adherence to Coding Standards
}

# GitHub API Configuration
GITHUB_API_URL = "https://api.github.com"
GITHUB_API_TIMEOUT = 30.0

# Log configuration summary
logger.info("=" * 60)
logger.info("SCANNING CONFIGURATION LOADED")
logger.info("=" * 60)
logger.info(f"Max Concurrent Scans: {MAX_CONCURRENT_SCANS}")
logger.info(f"Max Repo Size: {MAX_REPO_SIZE_MB} MB")
logger.info(f"Clone Timeout: {CLONE_TIMEOUT}s")
logger.info(f"Semgrep Timeout: {SEMGREP_TIMEOUT}s")
logger.info(f"CodeQL Timeout: {CODEQL_ANALYZE_TIMEOUT}s")
logger.info(f"Semgrep Token: {'✓ Configured' if SEMGREP_APP_TOKEN else '✗ Not Configured'}")
logger.info(f"Supported Languages: {len(LANGUAGE_EXTENSIONS)}")
logger.info(f"CodeQL Languages: {', '.join(sorted(CODEQL_LANGUAGES))}")
logger.info(f"Severity Rules: {len(SEVERITY_RULES)}")
logger.info(f"CWE Mappings: {len(CWE_SEVERITY_MAP)}")
logger.info("=" * 60)