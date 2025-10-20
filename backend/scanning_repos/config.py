"""
Configuration for scanning module
Integrates with environment and shared settings
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
CODEQL_LANGUAGES = {"java", "cpp", "csharp", "python", "javascript", "go", "swift", "kotlin"}

# Language detection
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".ts": "typescript",
    ".cpp": "cpp",
    ".c": "c",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".sh": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".sql": "sql"
}

SKIP_DIRS = {
    ".git", ".github", ".vscode", "node_modules", "__pycache__",
    ".pytest_cache", "venv", "env", "dist", "build", ".egg-info",
    ".tox", "htmlcov", ".coverage", "site-packages"
}

# Severity mapping
SEVERITY_RULES = {
    "sql-injection": "CRITICAL",
    "command-injection": "CRITICAL",
    "rce": "CRITICAL",
    "auth": "HIGH",
    "xss": "HIGH",
    "csrf": "HIGH",
    "hardcoded": "HIGH",
    "crypto": "MEDIUM",
    "insecure": "MEDIUM",
}

CWE_SEVERITY_MAP = {
    "89": "CRITICAL",    # SQL Injection
    "78": "CRITICAL",    # OS Command Injection
    "79": "HIGH",        # XSS
    "200": "HIGH",       # Information Exposure
    "352": "HIGH",       # CSRF
    "327": "HIGH",       # Weak Crypto
    "501": "MEDIUM",     # Trust Boundary Violation
    "502": "MEDIUM",     # External Control
}

# GitHub API Configuration
GITHUB_API_URL = "https://api.github.com"
GITHUB_API_TIMEOUT = 30.0