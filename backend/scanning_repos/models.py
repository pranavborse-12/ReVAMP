"""
Pydantic models for scanning requests and responses
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime


class ScanRequest(BaseModel):
    """Request to scan a user's repository"""
    repo_owner: str = Field(..., description="Repository owner (GitHub username)")
    repo_name: str = Field(..., description="Repository name")
    branch: Optional[str] = Field("main", description="Branch to scan")
    scanner: Optional[Literal["auto", "semgrep", "codeql", "both"]] = Field(
        "auto",
        description="Scanner selection mode"
    )
    max_files: Optional[int] = Field(10000, description="Maximum files to scan")


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    message: Optional[str] = None
    progress: Optional[str] = None
    repo_name: Optional[str] = None
    started_at: Optional[str] = None


class VulnerabilityLocation(BaseModel):
    file: str
    start_line: int
    end_line: int
    start_col: Optional[int] = None
    end_col: Optional[int] = None


class Vulnerability(BaseModel):
    scanner: str
    rule_id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARNING"]
    message: str
    location: VulnerabilityLocation
    cwe: Optional[List[str]] = None
    owasp: Optional[List[str]] = None
    confidence: Optional[str] = None
    code_snippet: Optional[str] = None
    vulnerability_type: Optional[str] = None


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    warning: int = 0


class ScanResult(BaseModel):
    scan_id: str
    repo_owner: str
    repo_name: str
    repo_url: str
    status: str
    vulnerabilities: List[Vulnerability]
    scanner_used: str
    total_issues: int
    severity_summary: Optional[SeveritySummary] = None
    detected_languages: Optional[List[str]] = None
    error_message: Optional[str] = None
    scan_duration: Optional[float] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class ScanHistoryItem(BaseModel):
    """Scan history entry for user dashboard"""
    scan_id: str
    repo_name: str
    repo_owner: str
    status: str
    total_issues: int
    severity_summary: Optional[SeveritySummary] = None
    scan_duration: Optional[float] = None
    completed_at: Optional[str] = None