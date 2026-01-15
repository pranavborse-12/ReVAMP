"""
Clean Scan Service - Simple, reliable database operations
FIXED: Proper enum value handling for PostgreSQL
Place this in: backend/database/scan_service.py
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc, func
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import logging
import uuid

from .scan_models import (
    Repository, ScanHistory, Vulnerability, 
    ScanStatistics, ScanStatusEnum, SeverityEnum
)

logger = logging.getLogger(__name__)


class ScanService:
    """Clean, simple database service for scans"""
    
    # ========================================================================
    # REPOSITORY OPERATIONS
    # ========================================================================
    
    @staticmethod
    async def get_or_create_repository(
        db: AsyncSession,
        user_id: str,
        owner: str,
        repo_name: str,
        github_url: str,
        **kwargs
    ) -> Repository:
        """Get existing repository or create new one"""
        full_name = f"{owner}/{repo_name}"
        
        # Try to find existing
        result = await db.execute(
            select(Repository).where(
                and_(
                    Repository.user_id == user_id,
                    Repository.full_name == full_name
                )
            )
        )
        repo = result.scalar_one_or_none()
        
        if repo:
            # Update if needed
            for key, value in kwargs.items():
                if hasattr(repo, key) and value is not None:
                    setattr(repo, key, value)
            repo.updated_at = datetime.now(timezone.utc)
            return repo
        
        # Create new
        repo = Repository(
            user_id=user_id,
            owner=owner,
            name=repo_name,
            full_name=full_name,
            github_url=github_url,
            **kwargs
        )
        db.add(repo)
        return repo
    
    # ========================================================================
    # SCAN OPERATIONS - FIXED ENUM HANDLING
    # ========================================================================
    
    @staticmethod
    async def create_scan(
        db: AsyncSession,
        scan_id: str,
        user_id: str,
        repository_id: Optional[str] = None,
        branch_name: str = "main",
        scanner_mode: str = "auto"
    ) -> ScanHistory:
        """
        Create a new scan record with proper enum handling
        FIXED: Always converts to lowercase string value for PostgreSQL
        """
        parsed_repo_id = None
        if repository_id is not None:
            # Reject literal 'None' strings
            if isinstance(repository_id, str) and repository_id.strip().lower() == 'none':
                raise ValueError("Invalid repository_id: got string 'None'; expected None or a UUID")

            # Parse UUID
            if isinstance(repository_id, str):
                try:
                    parsed_repo_id = uuid.UUID(repository_id)
                except Exception:
                    raise ValueError("repository_id must be a valid UUID string or None")
            else:
                parsed_repo_id = repository_id

        # CRITICAL FIX: Explicitly set status to lowercase string value
        scan = ScanHistory(
            scan_id=scan_id,
            user_id=user_id,
            repository_id=parsed_repo_id,
            branch_name=branch_name,
            scanner_mode=scanner_mode,
            status="queued"  # ← FIXED: Use lowercase string directly
        )
        db.add(scan)
        return scan
    
    @staticmethod
    async def update_scan_status(
        db: AsyncSession,
        scan_id: str,
        status: "ScanStatusEnum | str",
        error_message: str = None,
        error_code: str = None
    ) -> None:
        """
        Update scan status with proper enum handling
        FIXED: Always normalizes to lowercase string values
        """
        def _normalize_status(s):
            """Convert any status input to lowercase string matching DB enum"""
            if isinstance(s, ScanStatusEnum):
                return s.value  # Already lowercase
            if isinstance(s, str):
                s_lower = s.lower()
                # Validate against known enum values
                valid_values = {e.value for e in ScanStatusEnum}
                if s_lower in valid_values:
                    return s_lower
                raise ValueError(f"Invalid scan status: {s}")
            raise ValueError("status must be a ScanStatusEnum or a string")

        normalized = _normalize_status(status)

        result = await db.execute(
            select(ScanHistory).where(ScanHistory.scan_id == scan_id)
        )
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise ValueError(f"Scan not found: {scan_id}")
        
        # Set status as lowercase string
        scan.status = normalized
        
        # Set timestamps
        if normalized == "scanning" and not scan.started_at:
            scan.started_at = datetime.now(timezone.utc)
        elif normalized in ["completed", "failed"]:
            scan.completed_at = datetime.now(timezone.utc)
        
        # Set error info
        if error_message:
            scan.error_message = error_message
        if error_code:
            scan.error_code = error_code
    
    @staticmethod
    async def complete_scan(
        db: AsyncSession,
        scan_id: str,
        vulnerabilities: List[Dict[str, Any]],
        scanner_used: str,
        detected_languages: List[str],
        scan_duration: int,
        repo_size_mb: int = None,
        files_scanned: int = None
    ) -> ScanHistory:
        """
        Complete a scan with results
        FIXED: Proper enum handling for status and severity
        """
        
        # Get scan
        result = await db.execute(
            select(ScanHistory).where(ScanHistory.scan_id == scan_id)
        )
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise ValueError(f"Scan not found: {scan_id}")
        
        # Calculate severity counts
        severity_counts = {
            'critical': 0, 'high': 0, 'medium': 0,
            'low': 0, 'info': 0, 'warning': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '').upper()
            if severity == 'CRITICAL':
                severity_counts['critical'] += 1
            elif severity == 'HIGH':
                severity_counts['high'] += 1
            elif severity == 'MEDIUM':
                severity_counts['medium'] += 1
            elif severity == 'LOW':
                severity_counts['low'] += 1
            elif severity == 'INFO':
                severity_counts['info'] += 1
            elif severity == 'WARNING':
                severity_counts['warning'] += 1
        
        # FIXED: Set status as lowercase string
        scan.status = "completed"  # ← Use lowercase string directly
        scan.scanner_used = scanner_used
        scan.detected_languages = detected_languages
        scan.total_vulnerabilities = len(vulnerabilities)
        scan.critical_count = severity_counts['critical']
        scan.high_count = severity_counts['high']
        scan.medium_count = severity_counts['medium']
        scan.low_count = severity_counts['low']
        scan.info_count = severity_counts['info']
        scan.warning_count = severity_counts['warning']
        scan.scan_duration_seconds = scan_duration
        scan.repo_size_mb = repo_size_mb
        scan.files_scanned = files_scanned
        scan.completed_at = datetime.now(timezone.utc)
        
        # Add vulnerabilities
        for vuln_data in vulnerabilities:
            # FIXED: Proper severity enum handling
            severity_str = vuln_data.get('severity', 'INFO').upper()
            try:
                severity_enum = SeverityEnum[severity_str]
            except KeyError:
                logger.warning(f"Unknown severity: {severity_str}, defaulting to INFO")
                severity_enum = SeverityEnum.INFO
            
            vuln = Vulnerability(
                scan_id=scan.id,
                rule_id=vuln_data.get('rule_id', 'unknown'),
                scanner_name=vuln_data.get('scanner', scanner_used),
                severity=severity_enum.value,  # ← Use .value for uppercase string
                message=vuln_data.get('message', ''),
                vulnerability_type=vuln_data.get('vulnerability_type'),
                confidence=vuln_data.get('confidence'),
                file_path=vuln_data.get('location', {}).get('file', ''),
                start_line=vuln_data.get('location', {}).get('start_line', 1),
                end_line=vuln_data.get('location', {}).get('end_line', 1),
                start_column=vuln_data.get('location', {}).get('start_col'),
                end_column=vuln_data.get('location', {}).get('end_col'),
                code_snippet=vuln_data.get('code_snippet'),
                cwe_ids=vuln_data.get('cwe'),
                owasp_categories=vuln_data.get('owasp'),
                vulnerability_metadata=vuln_data.get('metadata')
            )
            db.add(vuln)
        
        return scan
    
    # ========================================================================
    # QUERY OPERATIONS
    # ========================================================================
    
    @staticmethod
    async def get_scan(
        db: AsyncSession,
        scan_id: str,
        user_id: str = None
    ) -> Optional[ScanHistory]:
        """Get scan by ID"""
        query = select(ScanHistory).where(ScanHistory.scan_id == scan_id)
        
        if user_id:
            query = query.where(ScanHistory.user_id == user_id)
        
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_user_scans(
        db: AsyncSession,
        user_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> List[ScanHistory]:
        """Get user's scan history"""
        result = await db.execute(
            select(ScanHistory)
            .where(
                and_(
                    ScanHistory.user_id == user_id,
                    ScanHistory.deleted_at.is_(None)
                )
            )
            .order_by(desc(ScanHistory.queued_at))
            .limit(limit)
            .offset(offset)
        )
        return result.scalars().all()
    
    @staticmethod
    async def get_scan_vulnerabilities(
        db: AsyncSession,
        scan_id: str
    ) -> List[Vulnerability]:
        """Get all vulnerabilities for a scan"""
        # First get the scan's UUID
        result = await db.execute(
            select(ScanHistory.id).where(ScanHistory.scan_id == scan_id)
        )
        scan_uuid = result.scalar_one_or_none()
        
        if not scan_uuid:
            return []
        
        result = await db.execute(
            select(Vulnerability)
            .where(Vulnerability.scan_id == scan_uuid)
            .order_by(
                Vulnerability.severity,
                Vulnerability.file_path,
                Vulnerability.start_line
            )
        )
        return result.scalars().all()