"""
Clean SQLAlchemy Models - Perfectly matches PostgreSQL schema
Place this in: backend/database/scan_models.py
"""
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ForeignKey, ARRAY, TypeDecorator
from sqlalchemy.dialects.postgresql import UUID, JSONB, ENUM
from sqlalchemy.orm import relationship, declarative_base, validates
from datetime import datetime, timezone
import uuid
import enum

Base = declarative_base()


def utc_now():
    """Helper for UTC timestamps"""
    return datetime.now(timezone.utc)


# ============================================================================
# ENUMS - Matching PostgreSQL exactly
# ============================================================================

class ScanStatusEnum(str, enum.Enum):
    """Scan status enum - LOWERCASE values to match PostgreSQL"""
    QUEUED = "queued"
    CLONING = "cloning"
    ANALYZING = "analyzing"
    SCANNING = "scanning"
    SCANNING_SEMGREP = "scanning_semgrep"
    SCANNING_CODEQL = "scanning_codeql"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityEnum(str, enum.Enum):
    """Severity enum - UPPERCASE values to match PostgreSQL"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    WARNING = "WARNING"


# ============================================================================
# CUSTOM TYPE DECORATORS
# ============================================================================

class ScanStatusEnumType(TypeDecorator):
    """
    Custom type decorator for ScanStatusEnum that ensures the .value (not .name)
    is sent to the database. This fixes the issue where SQLAlchemy's native ENUM
    type was using the enum member name (uppercase like 'QUEUED') instead of the
    value (lowercase like 'queued').
    """
    impl = ENUM
    cache_ok = True
    
    def __init__(self):
        # Initialize the ENUM type with ScanStatusEnum
        super().__init__(ScanStatusEnum, name="scan_status_enum", create_type=False)
    
    def bind_processor(self, dialect):
        """Process value before sending to database - ensure we use .value not .name"""
        def process(value):
            if value is None:
                return None
            # If it's an enum member, extract the value (lowercase)
            if isinstance(value, ScanStatusEnum):
                return value.value
            # If it's a string, normalize to lowercase
            if isinstance(value, str):
                return value.lower()
            return value
        return process
    
    def result_processor(self, dialect, coltype):
        """Process value from database - convert lowercase string to enum value"""
        def process(value):
            if value is None:
                return None
            # If it's a string, return as-is (it will be lowercase from DB)
            # The ORM will handle conversion to enum if needed
            if isinstance(value, str):
                return value
            return value
        return process



class Repository(Base):
    __tablename__ = "repositories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Repository identification
    owner = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    full_name = Column(String(512), nullable=False)
    github_url = Column(Text, nullable=False)
    
    # Repository metadata
    default_branch = Column(String(100), default="main")
    primary_language = Column(String(50))
    is_private = Column(Boolean, default=False)
    
    # User association
    user_id = Column(UUID(as_uuid=True), nullable=False)
    
    # Statistics
    last_scan_at = Column(DateTime(timezone=True))
    total_scans = Column(Integer, default=0, nullable=False)

    # Statistics
    last_scan_at = Column(DateTime(timezone=True))
    total_scans = Column(Integer, default=0, nullable=False)
    
    # NEW: Commit tracking
    last_commit_sha = Column(String(255), nullable=True)
    last_scan_commit_sha = Column(String(255), nullable=True)
    scan_allowance_remaining = Column(Integer, default=5, nullable=False)
    last_allowance_reset = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    
    # Relationships
    scans = relationship("ScanHistory", back_populates="repository", cascade="all, delete-orphan")


# ============================================================================
# SCAN HISTORY TABLE
# ============================================================================

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(255), unique=True, nullable=False)
    
    # Associations
    user_id = Column(UUID(as_uuid=True), nullable=False)
    # repository_id is optional - allow NULL so scans can be recorded even if repo is not tracked
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=True)
    
    # Scan configuration
    branch_name = Column(String(255), default="main", nullable=False)
    scanner_used = Column(String(100))
    scanner_mode = Column(String(50))
    last_commit_sha = Column(String(255), nullable=True)
    is_rescan = Column(Boolean, default=False, nullable=False)
    
    # Status - Use custom TypeDecorator that ensures .value is sent (not .name)
    status = Column(
        ScanStatusEnumType(),
        default=ScanStatusEnum.QUEUED.value,
        nullable=False
    )

    def __init__(self, **kwargs):
        """Override __init__ to normalize status to lowercase on initialization."""
        # Normalize status if provided
        if 'status' in kwargs:
            status_val = kwargs['status']
            # If enum member, extract value
            if isinstance(status_val, ScanStatusEnum):
                status_val = status_val.value
            # Normalize to lowercase
            if isinstance(status_val, str):
                kwargs['status'] = status_val.lower()
        # Call parent init
        super().__init__(**kwargs)

    @validates('status')
    def validate_status(self, key, value):
        """Normalize and validate status assignments.
        Accepts ScanStatusEnum members or strings (case-insensitive).
        Normalizes to lowercase enum value before database write.
        This catches issues early at the ORM layer.
        """
        # If enum member, extract value
        if isinstance(value, ScanStatusEnum):
            value = value.value
        
        if not isinstance(value, str):
            raise ValueError(f"status must be a string or ScanStatusEnum, got {type(value)}")
        
        # Normalize to lowercase
        normalized = value.lower()
        
        # Validate against known enum values
        valid = {e.value for e in ScanStatusEnum}
        if normalized not in valid:
            raise ValueError(
                f"Invalid scan status '{value}'. Valid values: {', '.join(sorted(valid))}"
            )
        
        return normalized
    
    # Vulnerability counts
    total_vulnerabilities = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    info_count = Column(Integer, default=0, nullable=False)
    warning_count = Column(Integer, default=0, nullable=False)
    
    # Scan metadata
    detected_languages = Column(ARRAY(Text))
    repo_size_mb = Column(Integer)
    files_scanned = Column(Integer)
    scan_duration_seconds = Column(Integer)
    
    # Error handling
    error_message = Column(Text)
    error_code = Column(String(50))
    
    # Additional metadata
    scan_metadata = Column(JSONB)
    
    # Timestamps
    queued_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    deleted_at = Column(DateTime(timezone=True))
    
    # Relationships
    repository = relationship("Repository", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


# ============================================================================
# VULNERABILITIES TABLE
# ============================================================================

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_history.id", ondelete="CASCADE"), nullable=False)
    
    # Vulnerability identification
    rule_id = Column(String(255), nullable=False)
    scanner_name = Column(String(50), nullable=False)
    severity = Column(
        ENUM(SeverityEnum, name="severity_enum", create_type=False),
        nullable=False
    )
    
    # Description
    message = Column(Text, nullable=False)
    vulnerability_type = Column(String(100))
    confidence = Column(String(20))
    
    # Location in code
    file_path = Column(Text, nullable=False)
    start_line = Column(Integer, nullable=False)
    end_line = Column(Integer, nullable=False)
    start_column = Column(Integer)
    end_column = Column(Integer)
    
    # Code context
    code_snippet = Column(Text)
    
    # Security classifications
    cwe_ids = Column(ARRAY(Text))
    owasp_categories = Column(ARRAY(Text))
    
    # Additional metadata
    vulnerability_metadata = Column(JSONB)
    
    # Timestamp
    detected_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    
    # Relationships
    scan = relationship("ScanHistory", back_populates="vulnerabilities")


# ============================================================================
# SCAN STATISTICS TABLE
# ============================================================================

class ScanStatistics(Base):
    __tablename__ = "scan_statistics"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), unique=True, nullable=False)
    
    # Scan counts
    total_scans = Column(Integer, default=0, nullable=False)
    completed_scans = Column(Integer, default=0, nullable=False)
    failed_scans = Column(Integer, default=0, nullable=False)
    total_repositories = Column(Integer, default=0, nullable=False)
    
    # Vulnerability counts
    total_vulnerabilities = Column(Integer, default=0, nullable=False)
    total_critical = Column(Integer, default=0, nullable=False)
    total_high = Column(Integer, default=0, nullable=False)
    total_medium = Column(Integer, default=0, nullable=False)
    total_low = Column(Integer, default=0, nullable=False)
    
    # Performance metrics
    avg_scan_duration_seconds = Column(Integer)
    last_scan_at = Column(DateTime(timezone=True))
    
    # Timestamp
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)