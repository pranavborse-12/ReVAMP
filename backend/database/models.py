from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text, Index, CheckConstraint, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import uuid
from .config import Base

# Helper function for UTC timestamps
def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    
    # Primary identification
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    github_id = Column(String(255), unique=True, nullable=True, index=True)
    github_login = Column(String(255), nullable=True)
    name = Column(String(255), nullable=True)
    avatar_url = Column(Text, nullable=True)
    
    # Security flags
    email_verified = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps (timezone-aware)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    last_login = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(INET, nullable=True)
    
    # Soft delete support
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    
    # ============================================
    # NEW: Helper methods for authentication
    # ============================================
    
    def to_dict(self):
        """Convert user to dictionary for compatibility with in-memory store"""
        return {
            'id': str(self.id),
            'email': self.email,
            'github_id': self.github_id,
            'github_login': self.github_login,
            'name': self.name,
            'avatar_url': self.avatar_url,
            'email_verified': self.email_verified,
            'is_active': self.is_active,
            'login_attempts': self.login_attempts,
            'locked_until': self.locked_until,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'last_login': self.last_login,
            'last_login_ip': str(self.last_login_ip) if self.last_login_ip else None,
            'deleted_at': self.deleted_at
        }
    
    def is_locked(self) -> bool:
        """Check if account is locked"""
        if self.locked_until:
            return datetime.now(timezone.utc) < self.locked_until
        return False
    
    # Constraints
    __table_args__ = (
        CheckConstraint('login_attempts >= 0', name='check_login_attempts_positive'),
        CheckConstraint("email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'", 
                       name='check_valid_email'),
        Index('idx_user_active_email', 'is_active', 'email'),
        Index('idx_user_deleted', 'deleted_at'),
    )


class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(String(255), primary_key=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    user_email = Column(String(255), nullable=False)  # Denormalized for backward compatibility
    verification_code_hash = Column(String(255), nullable=False)
    
    # Security tracking
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    fingerprint_hash = Column(String(255), nullable=True)
    
    # Device tracking (optional)
    device_name = Column(String(255), nullable=True)
    browser = Column(String(100), nullable=True)
    os = Column(String(100), nullable=True)
    
    # Session state
    verified = Column(Boolean, default=False, nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_attempt = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    # Constraints & Indexes
    __table_args__ = (
        CheckConstraint('attempts >= 0', name='check_attempts_positive'),
        CheckConstraint('expires_at > created_at', name='check_valid_expiry'),
        Index('idx_session_user_verified', 'user_id', 'verified'),
        Index('idx_session_expires', 'expires_at'),
        Index('idx_session_user_email', 'user_email'),
    )


class OAuthState(Base):
    __tablename__ = "oauth_states"
    
    state = Column(String(255), primary_key=True)
    redirect_to = Column(Text, nullable=True)
    used = Column(Boolean, default=False, nullable=False)
    ip_address = Column(INET, nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    __table_args__ = (
        CheckConstraint('expires_at > created_at', name='check_oauth_valid_expiry'),
        Index('idx_oauth_state_expires', 'expires_at'),
        Index('idx_oauth_state_used', 'used', 'created_at'),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    
    id = Column(String(255), primary_key=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    user_email = Column(String(255), nullable=False)  # Denormalized
    token_hash = Column(String(255), nullable=False, unique=True)
    
    # Revocation
    is_revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoke_reason = Column(String(255), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_used = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="refresh_tokens")
    
    # Constraints & Indexes
    __table_args__ = (
        CheckConstraint('expires_at > created_at', name='check_token_valid_expiry'),
        Index('idx_refresh_token_user', 'user_id', 'is_revoked'),
        Index('idx_refresh_token_expires', 'expires_at'),
        Index('idx_refresh_token_email', 'user_email'),
    )


class RateLimit(Base):
    __tablename__ = "rate_limits"
    
    identifier = Column(String(255), primary_key=True)  # IP or user_id
    endpoint = Column(String(100), primary_key=True)
    attempts = Column(Integer, default=0, nullable=False)
    window_start = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    blocked_until = Column(DateTime(timezone=True), nullable=True)
    
    __table_args__ = (
        CheckConstraint('attempts >= 0', name='check_rate_limit_attempts_positive'),
        Index('idx_rate_limit_blocked', 'blocked_until'),
    )


class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"
    
    token_hash = Column(String(255), primary_key=True)
    user_email = Column(String(255), nullable=True)
    reason = Column(String(255), nullable=True)
    blacklisted_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    __table_args__ = (
        Index('idx_blacklisted_expires', 'expires_at'),
        Index('idx_blacklisted_email', 'user_email'),
    )


class AuditLog(Base):
    __tablename__ = "audit_log"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    user_email = Column(String(255), nullable=True)  # Denormalized for when user is deleted
    
    # Action details
    action = Column(String(100), nullable=False)
    resource = Column(String(100), nullable=True)
    
    # Request context
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Result
    success = Column(Boolean, nullable=False)
    error_message = Column(Text, nullable=True)
    meta_data = Column(JSONB, nullable=True)
    
    # Timestamp
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    # Constraints & Indexes (optimized for queries)
    __table_args__ = (
        Index('idx_audit_user_action', 'user_id', 'action', 'created_at'),
        Index('idx_audit_email_action', 'user_email', 'action', 'created_at'),
        Index('idx_audit_created', 'created_at'),
        Index('idx_audit_success', 'success', 'created_at'),
        Index('idx_audit_action', 'action', 'created_at'),
        # Partial index for failures only
        Index('idx_audit_failures', 'user_email', 'created_at', 
              postgresql_where=(Column('success') == False)),
    )