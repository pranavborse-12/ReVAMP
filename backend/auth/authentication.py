from backend.database import config as db_config
from backend.database.service import DatabaseService
from fastapi import HTTPException, Depends, status, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, field_validator
from urllib.parse import urlencode, quote
import os
import time
import uuid
import secrets
import hashlib
import hmac
import httpx
import logging
import jwt
import bcrypt
import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Set
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import smtplib
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
import re
from functools import wraps
from fastapi import APIRouter, BackgroundTasks
import aiofiles
import uuid as uuid_module

# Load environment variables
load_dotenv()

_http_client: Optional[httpx.AsyncClient] = None

async def get_http_client() -> httpx.AsyncClient:
    """Get or create global HTTP client with connection pooling"""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=10.0,
            limits=httpx.Limits(
                max_keepalive_connections=5,
                max_connections=10,
                keepalive_expiry=30.0
            )
        )
    return _http_client


# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth_api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ----------------- Configuration Management -----------------
class Config:
    # GitHub OAuth
    GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
    
    # URLs
    HOST_URL = os.getenv("HOST_URL", "http://localhost:8000")
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
    DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:3001")
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    if not JWT_SECRET_KEY and os.getenv("ENVIRONMENT") == "production":
        raise RuntimeError("JWT_SECRET_KEY must be set in production")
    JWT_SECRET_KEY = JWT_SECRET_KEY or secrets.token_urlsafe(64)
    
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    
    # SMTP Configuration (use aiosmtplib in production)
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@securescan.local")
    SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "10"))
    
    # Security
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY and os.getenv("ENVIRONMENT") == "production":
        raise RuntimeError("SECRET_KEY must be set in production")
    SECRET_KEY = SECRET_KEY or secrets.token_urlsafe(64)
    
    SESSION_EXPIRE_MINUTES = int(os.getenv("SESSION_EXPIRE_MINUTES", "10"))
    CODE_EXPIRE_MINUTES = int(os.getenv("CODE_EXPIRE_MINUTES", "5"))
    MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "3"))
    
    # Rate Limiting - Stricter defaults
    RATE_LIMIT_WINDOW_MINUTES = int(os.getenv("RATE_LIMIT_WINDOW_MINUTES", "15"))
    RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "5"))
    
    # Environment
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"
    
    # Persistence - JSON ONLY (no pickle)
    ENABLE_PERSISTENCE = os.getenv("ENABLE_PERSISTENCE", "false").lower() == "true"
    PERSISTENCE_FILE = os.getenv("PERSISTENCE_FILE", "auth_data.json")
    
    # Database settings
    DB_TIMEOUT = int(os.getenv("DB_TIMEOUT", "5"))
    DB_MAX_RETRIES = int(os.getenv("DB_MAX_RETRIES", "3"))

    @classmethod
    def validate(cls):
        """Validate required configuration"""
        errors = []
        if not cls.GITHUB_CLIENT_ID:
            errors.append("GITHUB_CLIENT_ID is required")
        if not cls.GITHUB_CLIENT_SECRET:
            errors.append("GITHUB_CLIENT_SECRET is required")
            
        if cls.ENVIRONMENT == "production":
            if not cls.SMTP_HOST:
                errors.append("SMTP_HOST is required for production")
            if not cls.SMTP_USER:
                errors.append("SMTP_USER is required for production")
            if not cls.SMTP_PASS:
                errors.append("SMTP_PASS is required for production")
            if not cls.JWT_SECRET_KEY:
                errors.append("JWT_SECRET_KEY is required for production")
            if not cls.SECRET_KEY:
                errors.append("SECRET_KEY is required for production")
                
        if errors:
            if cls.ENVIRONMENT == "production":
                raise RuntimeError(f"Configuration errors: {', '.join(errors)}")
            else:
                logger.warning(f"Configuration warnings: {', '.join(errors)}")

# Validate configuration
Config.validate()

# ----------------- Data Models -----------------
@dataclass
class User:
    email: str
    github_id: Optional[str] = None
    email_verified: bool = False
    created_at: datetime = None
    updated_at: datetime = None
    last_login: Optional[datetime] = None
    is_active: bool = True
    login_attempts: int = 0
    last_attempt: Optional[datetime] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
        if self.updated_at is None:
            self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict"""
        return {
            'email': self.email,
            'github_id': self.github_id,
            'email_verified': self.email_verified,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'login_attempts': self.login_attempts,
            'last_attempt': self.last_attempt.isoformat() if self.last_attempt else None
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'User':
        """Create from dict with ISO datetime strings"""
        data = data.copy()
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('updated_at'), str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        if data.get('last_login') and isinstance(data['last_login'], str):
            data['last_login'] = datetime.fromisoformat(data['last_login'])
        if data.get('last_attempt') and isinstance(data['last_attempt'], str):
            data['last_attempt'] = datetime.fromisoformat(data['last_attempt'])
        return cls(**data)

@dataclass
class Session:
    id: str
    user_email: str
    verification_code_hash: str
    expires_at: datetime
    verified: bool = False
    attempts: int = 0
    created_at: datetime = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    fingerprint: Optional[str] = None  # NEW: Session fingerprint

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'user_email': self.user_email,
            'verification_code_hash': self.verification_code_hash,
            'expires_at': self.expires_at.isoformat(),
            'verified': self.verified,
            'attempts': self.attempts,
            'created_at': self.created_at.isoformat(),
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'fingerprint': self.fingerprint
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Session':
        data = data.copy()
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('expires_at'), str):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        return cls(**data)

@dataclass
class OAuthState:
    state: str
    redirect_to: str
    user_email: Optional[str] = None
    created_at: datetime = None
    used: bool = False

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict:
        return {
            'state': self.state,
            'redirect_to': self.redirect_to,
            'user_email': self.user_email,
            'created_at': self.created_at.isoformat(),
            'used': self.used
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'OAuthState':
        data = data.copy()
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        return cls(**data)

@dataclass
class RateLimitEntry:
    identifier: str
    attempts: int = 0
    window_start: datetime = None
    blocked_until: Optional[datetime] = None

    def __post_init__(self):
        if self.window_start is None:
            self.window_start = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict:
        return {
            'identifier': self.identifier,
            'attempts': self.attempts,
            'window_start': self.window_start.isoformat(),
            'blocked_until': self.blocked_until.isoformat() if self.blocked_until else None
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'RateLimitEntry':
        data = data.copy()
        if isinstance(data.get('window_start'), str):
            data['window_start'] = datetime.fromisoformat(data['window_start'])
        if data.get('blocked_until') and isinstance(data['blocked_until'], str):
            data['blocked_until'] = datetime.fromisoformat(data['blocked_until'])
        return cls(**data)

@dataclass
class RefreshToken:
    id: str
    user_email: str
    expires_at: datetime
    created_at: datetime = None
    is_revoked: bool = False

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'user_email': self.user_email,
            'expires_at': self.expires_at.isoformat(),
            'created_at': self.created_at.isoformat(),
            'is_revoked': self.is_revoked
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'RefreshToken':
        data = data.copy()
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('expires_at'), str):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        return cls(**data)

@dataclass
class BlacklistedToken:
    token_hash: str
    expires_at: datetime
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict:
        return {
            'token_hash': self.token_hash,
            'expires_at': self.expires_at.isoformat(),
            'created_at': self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'BlacklistedToken':
        data = data.copy()
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('expires_at'), str):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        return cls(**data)

# ----------------- Enhanced Secure In-Memory Storage -----------------
class SecureInMemoryStore:
    """
    Production-ready in-memory store with:
    - JSON persistence (no pickle)
    - Async file operations
    - Database sync with retry logic
    - Proper error handling
    """
    
    def __init__(self, persistence_file: str = None):
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.oauth_states: Dict[str, OAuthState] = {}
        self.rate_limits: Dict[str, RateLimitEntry] = {}
        self.refresh_tokens: Dict[str, RefreshToken] = {}
        self.blacklisted_tokens: Dict[str, BlacklistedToken] = {}
        self._lock = asyncio.Lock()
        self.persistence_file = persistence_file
        self.db_sync_enabled = True
        self._save_task: Optional[asyncio.Task] = None
        self._last_save = datetime.now(timezone.utc)

        # Load from JSON (safe)
        if self.persistence_file and Config.ENABLE_PERSISTENCE:
            asyncio.create_task(self._load_from_disk())

    async def _load_from_disk(self):
        """Load data from JSON file (SAFE - no pickle)"""
        try:
            if os.path.exists(self.persistence_file):
                async with aiofiles.open(self.persistence_file, 'r') as f:
                    content = await f.read()
                    data = json.loads(content)
                
                # Reconstruct objects from dicts
                self.users = {k: User.from_dict(v) for k, v in data.get('users', {}).items()}
                self.sessions = {k: Session.from_dict(v) for k, v in data.get('sessions', {}).items()}
                self.oauth_states = {k: OAuthState.from_dict(v) for k, v in data.get('oauth_states', {}).items()}
                self.rate_limits = {k: RateLimitEntry.from_dict(v) for k, v in data.get('rate_limits', {}).items()}
                self.refresh_tokens = {k: RefreshToken.from_dict(v) for k, v in data.get('refresh_tokens', {}).items()}
                self.blacklisted_tokens = {k: BlacklistedToken.from_dict(v) for k, v in data.get('blacklisted_tokens', {}).items()}
                
                logger.info(f"✅ Loaded persisted data: {len(self.users)} users, {len(self.sessions)} sessions")
        except json.JSONDecodeError as e:
            logger.error(f"❌ Failed to parse JSON: {e}")
        except Exception as e:
            logger.warning(f"⚠️ Failed to load persisted data: {e}")

    async def _sync_to_database_with_retry(self, max_retries: int = 3):
        """Sync to database with retry logic"""
        if not self.db_sync_enabled or not db_config.is_db_available:
            return
        
        if db_config.AsyncSessionLocal is None:
            logger.warning("AsyncSessionLocal is not initialized")
            return 
        
        for attempt in range(max_retries):
            try:
                async with asyncio.timeout(Config.DB_TIMEOUT):
                    async with db_config.AsyncSessionLocal() as db:
                        for email, user in self.users.items():
                            db_user = await DatabaseService.get_user_by_email(db, email)
                            
                            if not db_user:
                                await DatabaseService.create_user(
                                    db=db,
                                    email=user.email,
                                    github_id=user.github_id,
                                    email_verified=user.email_verified
                                )
                            else:
                                await DatabaseService.update_user_login(
                                    db=db,
                                    email=user.email,
                                    ip_address=None
                                )
                        
                        await db.commit()
                        logger.info(f"✅ Synced {len(self.users)} users to database")
                        return
                        
            except asyncio.TimeoutError:
                logger.warning(f"⚠️ Database sync timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
            except Exception as e:
                logger.error(f"❌ Database sync error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        
        logger.error("❌ Database sync failed after all retries")

    async def _save_to_disk(self):
        """Save data to JSON file with debouncing"""
        if not self.persistence_file or not Config.ENABLE_PERSISTENCE:
            return
        
        # Debounce: don't save more than once per second
        now = datetime.now(timezone.utc)
        if (now - self._last_save).total_seconds() < 1:
            return
        
        try:
            data = {
                'users': {k: v.to_dict() for k, v in self.users.items()},
                'sessions': {k: v.to_dict() for k, v in self.sessions.items()},
                'oauth_states': {k: v.to_dict() for k, v in self.oauth_states.items()},
                'rate_limits': {k: v.to_dict() for k, v in self.rate_limits.items()},
                'refresh_tokens': {k: v.to_dict() for k, v in self.refresh_tokens.items()},
                'blacklisted_tokens': {k: v.to_dict() for k, v in self.blacklisted_tokens.items()},
                'timestamp': now.isoformat()
            }
            
            # Write atomically
            temp_file = f"{self.persistence_file}.tmp"
            async with aiofiles.open(temp_file, 'w') as f:
                await f.write(json.dumps(data, indent=2))
            
            # Atomic rename
            os.replace(temp_file, self.persistence_file)
            self._last_save = now
            
            # Sync to database (non-blocking)
            if self.db_sync_enabled:
                asyncio.create_task(self._sync_to_database_with_retry())
                
        except Exception as e:
            logger.error(f"❌ Failed to save data: {e}")

    async def _cleanup_expired_data(self):
        """Clean up expired data"""
        async with self._lock:
            current_time = datetime.now(timezone.utc)
            
            # Clean expired sessions
            expired_sessions = [
                sid for sid, session in self.sessions.items() 
                if session.expires_at < current_time
            ]
            for sid in expired_sessions:
                del self.sessions[sid]

            # Clean old OAuth states (10 minutes)
            expired_states = [
                state for state, state_obj in self.oauth_states.items()
                if state_obj.created_at + timedelta(minutes=10) < current_time
            ]
            for state in expired_states:
                del self.oauth_states[state]

            # Clean old rate limits (1 hour)
            expired_limits = [
                identifier for identifier, limit in self.rate_limits.items()
                if limit.window_start + timedelta(hours=1) < current_time
            ]
            for identifier in expired_limits:
                del self.rate_limits[identifier]

            # Clean expired refresh tokens
            expired_refresh = [
                tid for tid, token in self.refresh_tokens.items()
                if token.expires_at < current_time or token.is_revoked
            ]
            for tid in expired_refresh:
                del self.refresh_tokens[tid]
            
            # Clean expired blacklisted tokens
            expired_blacklist = [
                token_hash for token_hash, token in self.blacklisted_tokens.items()
                if token.expires_at < current_time
            ]
            for token_hash in expired_blacklist:
                del self.blacklisted_tokens[token_hash]

            if any([expired_sessions, expired_states, expired_limits, expired_refresh, expired_blacklist]):
                logger.info(f"🧹 Cleanup: {len(expired_sessions)} sessions, {len(expired_states)} states, "
                           f"{len(expired_limits)} rate limits, {len(expired_refresh)} refresh tokens, "
                           f"{len(expired_blacklist)} blacklisted tokens")
                await self._save_to_disk()

    # User operations with database sync
    async def create_user(self, email: str, github_id: Optional[str] = None) -> User:
        """Create a new user (memory + database)"""
        async with self._lock:
            if email in self.users:
                raise ValueError("User already exists")
            
            user = User(email=email, github_id=github_id)
            self.users[email] = user
            
            # Sync to database with retry
            if self.db_sync_enabled and db_config.is_db_available() and db_config.AsyncSessionLocal is not None:
                try:
                    async with asyncio.timeout(Config.DB_TIMEOUT):
                        async with db_config.AsyncSessionLocal() as db:
                            await DatabaseService.create_user(
                                db=db,
                                email=email,
                                github_id=github_id,
                                email_verified=False
                            )
                            await db.commit()
                            logger.info(f"✅ User created in database: {email}")
                except asyncio.TimeoutError:
                    logger.warning(f"⚠️ Database Timeout creating User :{email}")
                except Exception as e:
                    logger.error(f"⚠️ Failed to create user in database: {e}")
            else:
                logger.info(f"✅ User created in memory only: {email}")
            
            await self._save_to_disk()
            return user

    async def update_user(self, email: str, **kwargs) -> Optional[User]:
        """Update user (memory + database)"""
        async with self._lock:
            if email not in self.users:
                return None
            
            user = self.users[email]
            for key, value in kwargs.items():
                if hasattr(user, key):
                    setattr(user, key, value)
            user.updated_at = datetime.now(timezone.utc)
            
            # Sync to database
            if self.db_sync_enabled and db_config.is_db_available() and db_config.AsyncSessionLocal is not None:
                try:
                    async with asyncio.timeout(Config.DB_TIMEOUT):
                        async with db_config.AsyncSessionLocal() as db:
                            db_user = await DatabaseService.get_user_by_email(db, email)
                            if db_user:
                                for key, value in kwargs.items():
                                    if hasattr(db_user, key):
                                        setattr(db_user, key, value)
                                await db.commit()
                                logger.info(f"✅ User updated in database: {email}")
                except asyncio.TimeoutError:
                    logger.warning(f"⚠️ Database Timeout updating User :{email}")
                except Exception as e:
                    logger.error(f"⚠️ Failed to update user in database: {e}")
            
            else:
                logger.info(f"✅ User updated in memory only: {email}")
            
            await self._save_to_disk()
            return user

    async def get_user(self, email: str) -> Optional[User]:
        """Get user by email"""
        return self.users.get(email)

    async def create_session(self, session: Session) -> None:
        """Create a new session"""
        async with self._lock:
            self.sessions[session.id] = session
            await self._save_to_disk()

    async def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        return self.sessions.get(session_id)

    async def update_session(self, session_id: str, **kwargs) -> Optional[Session]:
        """Update session"""
        async with self._lock:
            if session_id not in self.sessions:
                return None
            session = self.sessions[session_id]
            for key, value in kwargs.items():
                if hasattr(session, key):
                    setattr(session, key, value)
            await self._save_to_disk()
            return session

    async def delete_session(self, session_id: str) -> None:
        """Delete session"""
        async with self._lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                await self._save_to_disk()

    async def create_oauth_state(self, state: OAuthState) -> None:
        """Create OAuth state"""
        async with self._lock:
            self.oauth_states[state.state] = state
            await self._save_to_disk()

    async def get_oauth_state(self, state: str) -> Optional[OAuthState]:
        """Get OAuth state"""
        return self.oauth_states.get(state)

    async def mark_oauth_state_used(self, state: str) -> None:
        """Mark OAuth state as used"""
        async with self._lock:
            if state in self.oauth_states:
                self.oauth_states[state].used = True
                await self._save_to_disk()

    async def get_rate_limit(self, identifier: str) -> Optional[RateLimitEntry]:
        """Get rate limit entry"""
        return self.rate_limits.get(identifier)

    async def update_rate_limit(self, entry: RateLimitEntry) -> None:
        """Update rate limit entry"""
        async with self._lock:
            self.rate_limits[entry.identifier] = entry
            await self._save_to_disk()

    async def create_refresh_token(self, token: RefreshToken) -> None:
        """Create refresh token"""
        async with self._lock:
            self.refresh_tokens[token.id] = token
            await self._save_to_disk()

    async def get_refresh_token(self, token_id: str) -> Optional[RefreshToken]:
        """Get refresh token"""
        return self.refresh_tokens.get(token_id)

    async def revoke_refresh_token(self, token_id: str) -> None:
        """Revoke refresh token"""
        async with self._lock:
            if token_id in self.refresh_tokens:
                self.refresh_tokens[token_id].is_revoked = True
                await self._save_to_disk()

    async def blacklist_token(self, token: str, expires_at: datetime) -> None:
        """Add token to blacklist with expiration"""
        async with self._lock:
            token_hash = SecurityUtils.hash_token(token)
            self.blacklisted_tokens[token_hash] = BlacklistedToken(
                token_hash=token_hash,
                expires_at=expires_at
            )
            await self._save_to_disk()

    async def is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted and not expired"""
        token_hash = SecurityUtils.hash_token(token)
        blacklisted = self.blacklisted_tokens.get(token_hash)
        if not blacklisted:
            return False
        
        # Check if expired
        if datetime.now(timezone.utc) > blacklisted.expires_at:
            # Clean up expired token
            async with self._lock:
                del self.blacklisted_tokens[token_hash]
            return False
        
        return True

# Initialize store
store = SecureInMemoryStore(
    persistence_file=Config.PERSISTENCE_FILE if Config.ENABLE_PERSISTENCE else None
)
logger.info(f"✅ Initialized secure in-memory store (persistence: {Config.ENABLE_PERSISTENCE})")

# ----------------- Security Utilities -----------------
class SecurityUtils:
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_verification_code() -> str:
        """Generate 6-digit verification code"""
        return f"{secrets.randbelow(1000000):06d}"

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    @staticmethod
    def hash_token(token: str) -> str:
        """Hash token with secret key"""
        return hmac.new(
            Config.SECRET_KEY.encode(),
            token.encode(),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify_token_hash(token: str, token_hash: str) -> bool:
        """Verify token against its hash"""
        return hmac.compare_digest(
            SecurityUtils.hash_token(token),
            token_hash
        )

    @staticmethod
    def mask_email(email: str) -> str:
        """Mask email for frontend display"""
        try:
            name, domain = email.split("@", 1)
            if "." in domain:
                dom_head, dom_tail = domain.rsplit(".", 1)
            else:
                dom_head, dom_tail = domain, "com"
            
            name_mask = name[0] + "*" * min(3, len(name) - 1) if len(name) > 1 else "*"
            dom_mask = dom_head[0] + "*" * min(3, len(dom_head) - 1) if len(dom_head) > 1 else "*"
            return f"{name_mask}@{dom_mask}.{dom_tail}"
        except Exception:
            return "****@****"

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 255) -> str:
        """Sanitize user input"""
        if not input_str:
            return ""
        return input_str.strip()[:max_length]

# ----------------- JWT Token Management -----------------
class JWTManager:
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=Config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({
            "exp": expire, 
            "type": "access", 
            "jti": secrets.token_hex(16),
            "iat": datetime.utcnow(),
            "iss": Config.HOST_URL
        })
        encoded_jwt = jwt.encode(to_encode, Config.JWT_SECRET_KEY, algorithm=Config.JWT_ALGORITHM)
        return encoded_jwt

    @staticmethod
    async def create_refresh_token(email: str) -> str:
        """Create refresh token and store in memory"""
        token_id = SecurityUtils.generate_secure_token()
        expires_at = datetime.utcnow() + timedelta(days=Config.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        
        token = RefreshToken(
            id=token_id,
            user_email=email,
            expires_at=expires_at
        )
        await store.create_refresh_token(token)
        return token_id

    @staticmethod
    async def verify_token(token: str) -> Optional[dict]:
        """Verify JWT token"""
        try:
            if await store.is_token_blacklisted(token):
                return None
            payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=[Config.JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTError:
            return None

    @staticmethod
    async def verify_refresh_token(token_id: str) -> Optional[str]:
        """Verify refresh token and return email"""
        token = await store.get_refresh_token(token_id)
        if not token:
            return None
        if token.is_revoked or datetime.utcnow() > token.expires_at:
            return None
        return token.user_email

    @staticmethod
    async def revoke_refresh_token(token_id: str):
        """Revoke refresh token"""
        await store.revoke_refresh_token(token_id)

# ----------------- Request/Response Models -----------------
class EmailRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=100)
    
    @field_validator('email')
    def validate_email_format(cls, v):
        if not SecurityUtils.validate_email(v):
            raise ValueError('Invalid email format')
        return v.lower().strip()

class VerifyRequest(BaseModel):
    session: str = Field(..., min_length=1, max_length=100, pattern=r'^[A-Za-z0-9_-]+$')
    code: str = Field(..., min_length=6, max_length=6, pattern=r'^\d{6}$')

class AuthStatusResponse(BaseModel):
    exists: bool
    verified: Optional[bool] = None
    email_hint: Optional[str] = None
    attempts_remaining: Optional[int] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1)

class UserInfo(BaseModel):
    email: str
    email_verified: bool
    created_at: datetime
    last_login: Optional[datetime]

# ----------------- Rate Limiting -----------------
class RateLimiter:
    @staticmethod
    async def check_rate_limit(identifier: str, max_attempts: int = None, window_minutes: int = None):
        """Advanced rate limiting with memory persistence"""
        max_attempts = max_attempts or Config.MAX_LOGIN_ATTEMPTS
        window_minutes = window_minutes or Config.RATE_LIMIT_WINDOW_MINUTES
        current_time = datetime.utcnow()

        entry = await store.get_rate_limit(identifier)
        
        if entry:
            # Check if still blocked
            if entry.blocked_until and current_time < entry.blocked_until:
                remaining_seconds = int((entry.blocked_until - current_time).total_seconds())
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many attempts. Try again in {remaining_seconds} seconds"
                )

            # Reset window if expired
            if current_time - entry.window_start > timedelta(minutes=window_minutes):
                entry.attempts = 0
                entry.window_start = current_time
                entry.blocked_until = None

            # Check attempts
            if entry.attempts >= max_attempts:
                entry.blocked_until = current_time + timedelta(minutes=window_minutes)
                await store.update_rate_limit(entry)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many attempts. Blocked for {window_minutes} minutes"
                )

            # Update attempts
            entry.attempts += 1
            await store.update_rate_limit(entry)
        else:
            # Create new rate limit entry
            entry = RateLimitEntry(identifier=identifier, attempts=1)
            await store.update_rate_limit(entry)

# ----------------- GitHub OAuth Client -----------------
class GitHubClient:
    BASE_URL = "https://api.github.com"
    OAUTH_URL = "https://github.com/login/oauth"

    @classmethod
    async def exchange_code_for_token(cls, code: str) -> Optional[str]:
        """Exchange code for token - OPTIMIZED: 2-3s max"""
        url = f"{cls.OAUTH_URL}/access_token"
        data = {
            "client_id": Config.GITHUB_CLIENT_ID,
            "client_secret": Config.GITHUB_CLIENT_SECRET,
            "code": code,
        }
        headers = {"Accept": "application/json"}

        try:
            client = await get_http_client()
            
            # Use aggressive 5 second timeout
            async with asyncio.timeout(5.0):
                response = await client.post(url, data=data, headers=headers)
                response.raise_for_status()
                payload = response.json()
                
                if "error" in payload:
                    logger.error(f"GitHub OAuth error: {payload}")
                    return None
                    
                return payload.get("access_token")
                
        except asyncio.TimeoutError:
            logger.error("GitHub OAuth timeout after 5s")
            return None
        except Exception as e:
            logger.error(f"GitHub OAuth error: {e}")
            return None

    @classmethod
    async def get_user_info(cls, access_token: str) -> Optional[dict]:
        """Get user info - OPTIMIZED: Parallel requests, 3s max"""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "SecureScan-Auth/2.0"
        }

        try:
            client = await get_http_client()
            
            # CRITICAL: Run both API calls in parallel - 2x faster!
            async with asyncio.timeout(4.0):
                emails_task = client.get(f"{cls.BASE_URL}/user/emails", headers=headers)
                user_task = client.get(f"{cls.BASE_URL}/user", headers=headers)
                
                emails_resp, user_resp = await asyncio.gather(
                    emails_task, user_task, return_exceptions=True
                )
                
                # Handle errors
                if isinstance(emails_resp, Exception) or isinstance(user_resp, Exception):
                    logger.error(f"GitHub API error: {emails_resp if isinstance(emails_resp, Exception) else user_resp}")
                    return None

                if emails_resp.status_code != 200 or user_resp.status_code != 200:
                    logger.error(f"GitHub API status: emails={emails_resp.status_code}, user={user_resp.status_code}")
                    return None

                emails = emails_resp.json()
                user = user_resp.json()

                # Find primary verified email (fast iteration)
                primary_email = None
                for e in emails:
                    if e.get("primary") and e.get("verified"):
                        primary_email = e.get("email")
                        break
                
                if not primary_email:
                    for e in emails:
                        if e.get("verified"):
                            primary_email = e.get("email")
                            break
                
                primary_email = primary_email or user.get("email")

                return {
                    "email": primary_email,
                    "github_id": str(user.get("id")),
                    "login": user.get("login"),
                    "name": user.get("name"),
                    "avatar_url": user.get("avatar_url")
                }
                
        except asyncio.TimeoutError:
            logger.error("GitHub API timeout after 4s")
            return None
        except Exception as e:
            logger.error(f"GitHub API error: {e}")
            return None



# ----------------- Email Service -----------------
def sanitize_email_header(email: str) -> str:
        return email.replace('\n', '').replace('\r', '')
class EmailService:
    @staticmethod
    def create_verification_email(code: str, email: str) -> MIMEMultipart:
        """Create professional verification email"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "SecureScan - Email Verification"
        msg["From"] = Config.FROM_EMAIL
        msg["To"] = sanitize_email_header(email)
        msg["X-Priority"] = "1"

        text_content = f"""
SecureScan Email Verification

Hello,

Your verification code is: {code}

This code will expire in {Config.CODE_EXPIRE_MINUTES} minutes.

If you didn't request this verification, please ignore this email.

Best regards,
SecureScan Security Team

---
This is an automated message. Please do not reply to this email.
        """.strip()

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SecureScan - Email Verification</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .logo {{
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
            margin-bottom: 10px;
        }}
        .code-container {{
            background: #f8f9fa;
            border: 2px dashed #007bff;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 30px 0;
        }}
        .code {{
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 8px;
            color: #007bff;
            font-family: 'Courier New', monospace;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 14px;
            color: #666;
            text-align: center;
        }}
        .warning {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 12px;
            margin: 20px 0;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🔐 SecureScan</div>
            <h1 style="color: #333; margin: 0;">Email Verification</h1>
        </div>
        
        <p>Hello,</p>
        
        <p>You're just one step away from securing your account. Please use the verification code below:</p>
        
        <div class="code-container">
            <div class="code">{code}</div>
            <p style="margin: 10px 0 0 0; color: #666;">Enter this code to complete your verification</p>
        </div>
        
        <div class="warning">
            ⏰ This code will expire in {Config.CODE_EXPIRE_MINUTES} minutes for your security.
        </div>
        
        <p>If you didn't request this verification, you can safely ignore this email.</p>
        
        <div class="footer">
            <p><strong>SecureScan Security Team</strong></p>
            <p>This is an automated message. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
        """

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))
        return msg

    @staticmethod
    async def send_verification_email(email: str, code: str) -> bool:
        """Send verification email"""
        if not all([Config.SMTP_HOST, Config.SMTP_USER, Config.SMTP_PASS]):
            logger.warning("SMTP not configured, skipping email send")
            return True  # Return True for development

        try:
            msg = EmailService.create_verification_email(code, email)
            
            with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT) as server:
                if Config.SMTP_PORT == 587:
                    server.starttls()
                server.login(Config.SMTP_USER, Config.SMTP_PASS)
                server.send_message(msg)
                
            logger.info(f"Verification email sent to {SecurityUtils.mask_email(email)}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {SecurityUtils.mask_email(email)}: {e}")
            return False

# ----------------- Helper Functions -----------------
def get_client_identifier(request: Request) -> str:
    """Get client identifier for rate limiting"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def get_user_agent(request: Request) -> str:
    """Get user agent from request"""
    return request.headers.get("User-Agent", "Unknown")[:255]

async def _commit_and_log(db, email, github_id, github_login, user_uuid, 
                         is_new, ip_address, user_agent):
    """Background task to commit DB and log audit event"""
    try:
        await DatabaseService.log_audit_event(
            db=db,
            action="GITHUB_OAUTH_SUCCESS",
            resource="users",
            success=True,
            user_email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            meta_data={
                "github_id": github_id,
                "github_login": github_login,
                "is_new_user": is_new,
                "user_uuid": user_uuid
            }
        )
        await db.commit()
    except Exception as e:
        logger.error(f"Background commit failed: {e}")


# ----------------- Authentication Dependencies -----------------
security = HTTPBearer(auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Get current authenticated user"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = await JWTManager.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return payload

# ----------------- Create Router -----------------
router = APIRouter()

# ----------------- API Routes -----------------

@router.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "SecureScan Auth API",
        "version": "2.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "users_count": len(store.users),
        "active_sessions": len(store.sessions),
        "environment": Config.ENVIRONMENT
    }

@router.post("/initiate", response_model=dict)
async def initiate_auth(
    request: EmailRequest,
    background_tasks: BackgroundTasks,
    http_request: Request
):
    """Initiate authentication process"""
    client_id = get_client_identifier(http_request)
    await RateLimiter.check_rate_limit(f"auth_initiate:{client_id}")
    
    email = SecurityUtils.sanitize_input(request.email.lower().strip())
    
    # Check if user exists
    user = await store.get_user(email)
    user_exists = user is not None
    
    # Generate session and verification code
    session_id = SecurityUtils.generate_secure_token()
    verification_code = SecurityUtils.generate_verification_code()
    code_hash = SecurityUtils.hash_token(verification_code)
    
    # Create session
    session = Session(
        id=session_id,
        user_email=email,
        verification_code_hash=code_hash,
        expires_at=datetime.utcnow() + timedelta(minutes=Config.SESSION_EXPIRE_MINUTES),
        ip_address=client_id,
        user_agent=get_user_agent(http_request)
    )
    await store.create_session(session)
    
    # Send verification email
    try:
        background_tasks.add_task(EmailService.send_verification_email, email, verification_code)
    except Exception as e:
        logger.error(f"Failed to schedule email: {e}")
    
    # Create or update user
    if not user_exists:
        await store.create_user(email)
    
    logger.info(f"Auth initiated for {SecurityUtils.mask_email(email)}")
    
    return {
        "session": session_id,
        "expires_in": Config.SESSION_EXPIRE_MINUTES * 60,
        "message": f"Verification code sent to {SecurityUtils.mask_email(email)}"
    }

@router.post("/verify", response_model=TokenResponse)
async def verify_auth(
    request: VerifyRequest,
    http_request: Request
):
    """Verify authentication code"""
    client_id = get_client_identifier(http_request)
    await RateLimiter.check_rate_limit(f"auth_verify:{client_id}", max_attempts=10)
    
    # Get session
    session = await store.get_session(request.session)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired"
        )
    
    # Check if session expired
    if datetime.utcnow() > session.expires_at:
        await store.delete_session(request.session)
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Session expired. Please request a new verification code."
        )
    
    # Check attempts
    if session.attempts >= 5:
        await store.delete_session(request.session)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many verification attempts"
        )
    
    # Verify code
    is_valid = SecurityUtils.verify_token_hash(request.code, session.verification_code_hash)
    await asyncio.sleep(0.1)
    
    if not is_valid :
        await store.update_session(request.session, attempts=session.attempts + 1)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
    
    # Mark session as verified
    await store.update_session(request.session, verified=True)
    
    # Get/update user
    user = await store.get_user(session.user_email)
    if not user:
        user = await store.create_user(session.user_email)
    
    await store.update_user(
        session.user_email,
        email_verified=True,
        last_login=datetime.utcnow(),
        login_attempts=0
    )
    
    # Generate tokens
    access_token = JWTManager.create_access_token({"sub": user.email, "verified": True})
    refresh_token = await JWTManager.create_refresh_token(user.email)
    
    # Cleanup session
    await store.delete_session(request.session)
    
    logger.info(f"Auth verified for {SecurityUtils.mask_email(user.email)}")
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=Config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@router.get("/github/login")
async def github_login(request: Request, redirect_to: str = "/"):
    """Initiate GitHub OAuth flow"""
    # Validate GitHub OAuth configuration
    if not Config.GITHUB_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub OAuth not configured"
        )
    
    # Generate state token and store in session
    state = SecurityUtils.generate_secure_token()
    oauth_state = OAuthState(
        state=state,
        redirect_to=redirect_to,
        created_at=datetime.utcnow()
    )
    await store.create_oauth_state(oauth_state)
    
    # Build GitHub authorization URL
    github_auth_url = (
        "https://github.com/login/oauth/authorize?"
        f"client_id={Config.GITHUB_CLIENT_ID}"
        f"&redirect_uri={Config.HOST_URL}/auth/github/callback"
        f"&state={state}"
        "&scope=user:email"
    )
    
    logger.info(f"Initiating GitHub OAuth with state: {state[:8]}...")
    return RedirectResponse(url=github_auth_url)

@router.get("/github/callback")
async def github_oauth_callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    request: Request = None
):
    """
    Ultra-fast GitHub OAuth callback
    Target: <3s for existing users, <10s for new users
    """
    try:
        # === PHASE 1: Quick Validation (< 50ms) ===
        if error:
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error={error}")
        
        if not code or not state:
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=invalid_request")
        
        # Verify state (memory lookup - instant)
        oauth_state = await store.get_oauth_state(state)
        if not oauth_state or oauth_state.used:
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=invalid_state")
        
        if datetime.utcnow() - oauth_state.created_at > timedelta(minutes=10):
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=state_expired")
        
        # Mark used immediately
        await store.mark_oauth_state_used(state)
        
        # === PHASE 2: GitHub API (2-5s) - CANNOT BE AVOIDED ===
        logger.info("Exchanging code for token...")
        start_time = datetime.utcnow()
        
        github_token = await GitHubClient.exchange_code_for_token(code)
        if not github_token:
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=token_exchange_failed")
        
        token_time = (datetime.utcnow() - start_time).total_seconds()
        logger.info(f"Token exchange: {token_time:.2f}s")
        
        # Get user info (parallel requests)
        user_start = datetime.utcnow()
        github_user = await GitHubClient.get_user_info(github_token)
        if not github_user or not github_user.get("email"):
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=email_required")
        
        user_info_time = (datetime.utcnow() - user_start).total_seconds()
        logger.info(f"User info fetch: {user_info_time:.2f}s")
        
        email = github_user["email"].lower().strip()
        github_id = github_user["github_id"]
        github_login = github_user.get("login")
        name = github_user.get("name")
        avatar_url = github_user.get("avatar_url")
        
        # === PHASE 3: User Management (< 1s) ===
        db_start = datetime.utcnow()
        user_uuid = None
        
        # Check memory first (instant)
        user = await store.get_user(email)
        is_existing_user = user is not None
        
        # Database operations - SKIP FOR EXISTING USERS IF POSSIBLE
        if db_config.is_db_available() and db_config.AsyncSessionLocal is not None:
            try:
                # CRITICAL: Only 2 second timeout for DB
                async with asyncio.timeout(2.0):
                    async with db_config.AsyncSessionLocal() as db:
                        # Fast lookup by email
                        db_user = await DatabaseService.get_user_by_email(db, email)
                        
                        if db_user:
                            # === EXISTING USER PATH - MINIMAL WORK ===
                            user_uuid = str(db_user.id)
                            
                            # Only update last_login (single UPDATE query)
                            db_user.last_login = datetime.utcnow()
                            db_user.login_attempts = 0
                            db_user.locked_until = None
                            
                            # CRITICAL: Don't wait for commit, fire and forget
                            asyncio.create_task(_commit_and_log(
                                db, email, github_id, github_login, 
                                user_uuid, False, get_client_identifier(request),
                                get_user_agent(request)
                            ))
                            
                        else:
                            # === NEW USER PATH - Full creation ===
                            db_user, created = await DatabaseService.get_or_create_user_by_github(
                                db=db,
                                email=email,
                                github_id=github_id,
                                github_login=github_login,
                                name=name,
                                avatar_url=avatar_url
                            )
                            user_uuid = str(db_user.id)
                            
                            # Fire and forget for new users too
                            asyncio.create_task(_commit_and_log(
                                db, email, github_id, github_login,
                                user_uuid, created, get_client_identifier(request),
                                get_user_agent(request)
                            ))
                        
                        db_time = (datetime.utcnow() - db_start).total_seconds()
                        logger.info(f"Database ops: {db_time:.2f}s (existing: {is_existing_user})")
                        
            except asyncio.TimeoutError:
                logger.warning("DB timeout - continuing without UUID")
            except Exception as db_error:
                logger.error(f"DB error: {db_error}")
        
        # Update memory store (fast - < 50ms)
        if not user:
            user = await store.create_user(email, github_id=github_id)
        else:
            # Don't await - fire and forget for speed
            asyncio.create_task(store.update_user(
                email,
                github_id=github_id,
                email_verified=True,
                last_login=datetime.utcnow(),
                login_attempts=0
            ))
        
        # === PHASE 4: Token Generation (< 100ms) ===
        access_token = JWTManager.create_access_token({
            "sub": email,
            "email": email,
            "user_id": user_uuid,
            "github_id": github_id,
            "github_login": github_login,
            "verified": True,
            "provider": "github"
        })
        
        refresh_token = await JWTManager.create_refresh_token(email)
        
        # === PHASE 5: Redirect (< 50ms) ===
        redirect_url = oauth_state.redirect_to
        if not redirect_url or redirect_url == "/":
            redirect_url = f"{Config.DASHBOARD_URL}/dashboard"
        elif not redirect_url.startswith("http"):
            redirect_url = f"{Config.DASHBOARD_URL}{redirect_url}"
        
        response = RedirectResponse(url=redirect_url, status_code=303)
        
        # Set cookies
        is_production = Config.ENVIRONMENT == "production"
        cookie_settings = {
            "httponly": True,
            "secure": is_production,
            "samesite": "lax",
            "path": "/"
        }
        
        response.set_cookie("access_token", access_token, 
                          max_age=Config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60, 
                          **cookie_settings)
        response.set_cookie("session_token", access_token,
                          max_age=Config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                          **cookie_settings)
        response.set_cookie("refresh_token", refresh_token,
                          max_age=Config.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                          **cookie_settings)
        response.set_cookie("github_access_token", github_token,
                          max_age=int(os.getenv("GITHUB_TOKEN_EXPIRE_MINUTES", "480")) * 60,
                          **cookie_settings)
        response.set_cookie("user_email", email,
                          max_age=Config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                          httponly=False, secure=is_production, 
                          samesite="lax", path="/")
        
        total_time = (datetime.utcnow() - start_time).total_seconds()
        logger.info(f"✅ OAuth completed in {total_time:.2f}s for {SecurityUtils.mask_email(email)}")
        
        return response
        
    except Exception as e:
        logger.error(f"OAuth error: {str(e)}", exc_info=True)
        return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=server_error")

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token"""
    email = await JWTManager.verify_refresh_token(request.refresh_token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Verify user still exists and is active
    user = await store.get_user(email)
    if not user or not user.is_active:
        await JWTManager.revoke_refresh_token(request.refresh_token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Generate new tokens
    access_token = JWTManager.create_access_token({"sub": email, "verified": user.email_verified})
    new_refresh_token = await JWTManager.create_refresh_token(email)
    
    # Revoke old refresh token
    await JWTManager.revoke_refresh_token(request.refresh_token)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=Config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@router.post("/logout")
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    refresh_token: Optional[str] = None
):
    """Logout user and revoke tokens"""
    # Create response that will clear cookies
    response = JSONResponse(content={"message": "Logged out successfully"})
    
    # Clear ALL authentication cookies
    cookie_names = ["access_token", "refresh_token", "github_access_token", "user_email"]
    for cookie_name in cookie_names:
        response.delete_cookie(
            key=cookie_name,
            path="/",
            domain=None,
            secure=False,  # Set to True in production with HTTPS
            httponly=True,
            samesite="lax"
        )
    
    # Blacklist the access token if provided
    if credentials:
        await store.blacklist_token(credentials.credentials)
    
    # Revoke refresh token if provided
    if refresh_token:
        await JWTManager.revoke_refresh_token(refresh_token)
    
    logger.info("User logged out, cookies cleared")
    return response

@router.get("/me", response_model=UserInfo)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    user = await store.get_user(current_user["sub"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserInfo(
        email=user.email,
        email_verified=user.email_verified,
        created_at=user.created_at,
        last_login=user.last_login
    )

@router.get("/session")
async def get_session_info(request: Request):
    """Get current session information from cookies or Authorization header"""
    try:
        # Try to get access token from cookie first
        access_token = request.cookies.get("access_token")
        
        # Fallback to Authorization header
        if not access_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                access_token = auth_header.split(" ", 1)[1]
        
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No authentication token found"
            )
        
        # Verify token
        payload = await JWTManager.verify_token(access_token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
        
        # Get user
        email = payload.get("sub")
        user = await store.get_user(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Get GitHub token if available
        github_token = request.cookies.get("github_access_token")
        
        return {
            "authenticated": True,
            "user": {
                "email": user.email,
                "email_verified": user.email_verified,
                "created_at": user.created_at.isoformat(),
                "last_login": user.last_login.isoformat() if user.last_login else None,
                "github_id": user.github_id
            },
            "tokens": {
                "has_github_token": github_token is not None
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Session info error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve session information"
        )

@router.get("/status", response_model=AuthStatusResponse)
async def check_auth_status(identifier: str):
    """Check authentication status by email or session token"""
    # First try: if it's a valid email, handle as email
    if SecurityUtils.validate_email(identifier):
        email = SecurityUtils.sanitize_input(identifier.lower().strip())
        user = await store.get_user(email)

        if not user:
            return AuthStatusResponse(
                exists=False,
                email_hint=SecurityUtils.mask_email(email)
            )

        return AuthStatusResponse(
            exists=True,
            verified=user.email_verified,
            email_hint=SecurityUtils.mask_email(email),
            attempts_remaining=max(0, Config.MAX_LOGIN_ATTEMPTS - user.login_attempts)
        )

    # Otherwise treat as session token
    session = await store.get_session(identifier)
    if not session:
        return AuthStatusResponse(
            exists=False,
            email_hint="****@****"
        )

    user = await store.get_user(session.user_email)
    if not user:
        return AuthStatusResponse(
            exists=False,
            email_hint=SecurityUtils.mask_email(session.user_email)
        )

    return AuthStatusResponse(
        exists=True,
        verified=user.email_verified,
        email_hint=SecurityUtils.mask_email(session.user_email),
        attempts_remaining=max(0, Config.MAX_LOGIN_ATTEMPTS - user.login_attempts)
    )

# ----------------- Background Tasks -----------------
async def cleanup_task():
    """Periodic cleanup of expired data"""
    while True:
        try:
            await store._cleanup_expired_data()
            await asyncio.sleep(3600)  # Run every hour
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")
            await asyncio.sleep(300)  # Wait 5 minutes on error

# ----------------- Lifespan (for standalone mode only) -----------------
@asynccontextmanager
async def lifespan(app):
    """Application lifespan - ensure HTTP client is closed"""
    # Startup
    logger.info("Starting SecureScan Auth API...")
    await initialize_database()
    await store._cleanup_expired_data()
    cleanup_task_handle = asyncio.create_task(cleanup_task())
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    cleanup_task_handle.cancel()
    
    # Close HTTP client
    global _http_client
    if _http_client and not _http_client.is_closed:
        await _http_client.aclose()
        logger.info("HTTP client closed")
    
    try:
        await cleanup_task_handle
    except asyncio.CancelledError:
        pass
# ----------------- Export router and store -----------------
__all__ = ['router', 'store', 'lifespan']

async def initialize_database():
    """Initialize database tables on startup"""
    try:
        from database.models import Base
        from database.config import engine, test_connection
        
        # Test connection
        logger.info("Testing database connection...")
        is_connected = await test_connection()
        
        if is_connected:
            # Create all tables
            logger.info("Creating database tables...")
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("✅ Database initialized successfully")
        else:
            logger.warning("⚠️  Database connection failed - running in memory-only mode")
            store.db_sync_enabled = False
    except Exception as e:
        logger.error(f"❌ Database initialization error: {e}")
        logger.warning("⚠️  Running in memory-only mode")
        store.db_sync_enabled = False


# ----------------- Standalone Mode (for testing) -----------------
if __name__ == "__main__":
    import uvicorn
    from fastapi import FastAPI
    
    # Create standalone app only when running directly
    standalone_app = FastAPI(
        title="SecureScan Auth API (Standalone)",
        description="Secure authentication service - Standalone Mode",
        version="2.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # Include router in standalone app
    standalone_app.include_router(router)
    
    logger.info("Running in STANDALONE mode - for testing only")
    logger.info("In production, import router into main.py")
    
    uvicorn.run(
        standalone_app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )