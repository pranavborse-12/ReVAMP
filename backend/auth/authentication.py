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
import smtplib
import httpx
import logging
import jwt
import bcrypt
import asyncio
import json
import pickle
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Set
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
from threading import Lock
import re
from functools import wraps
from fastapi import APIRouter, BackgroundTasks

# Load environment variables
load_dotenv()

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
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(64))
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    
    # SMTP Configuration
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@securescan.local")
    
    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(64))
    SESSION_EXPIRE_MINUTES = int(os.getenv("SESSION_EXPIRE_MINUTES", "30"))
    CODE_EXPIRE_MINUTES = int(os.getenv("CODE_EXPIRE_MINUTES", "10"))
    MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    
    # Rate Limiting
    RATE_LIMIT_WINDOW_MINUTES = int(os.getenv("RATE_LIMIT_WINDOW_MINUTES", "15"))
    RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "100"))
    
    # Environment
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"
    
    # Persistence
    ENABLE_PERSISTENCE = os.getenv("ENABLE_PERSISTENCE", "true").lower() == "true"
    PERSISTENCE_FILE = os.getenv("PERSISTENCE_FILE", "auth_data.pkl")

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
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.utcnow()

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

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()

@dataclass
class OAuthState:
    state: str
    redirect_to: str
    user_email: Optional[str] = None
    created_at: datetime = None
    used: bool = False

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()

@dataclass
class RateLimitEntry:
    identifier: str
    attempts: int = 0
    window_start: datetime = None
    blocked_until: Optional[datetime] = None

    def __post_init__(self):
        if self.window_start is None:
            self.window_start = datetime.utcnow()

@dataclass
class RefreshToken:
    id: str
    user_email: str
    expires_at: datetime
    created_at: datetime = None
    is_revoked: bool = False

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()

# ----------------- Enhanced In-Memory Storage -----------------
class SecureInMemoryStore:
    def __init__(self, persistence_file: str = None):
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.oauth_states: Dict[str, OAuthState] = {}
        self.rate_limits: Dict[str, RateLimitEntry] = {}
        self.refresh_tokens: Dict[str, RefreshToken] = {}
        self.blacklisted_tokens: Set[str] = set()
        self._lock = asyncio.Lock()
        self.persistence_file = persistence_file
        self.db_sync_enabled = True

        # Load from pickle first (backwards compatibility)
        if self.persistence_file and Config.ENABLE_PERSISTENCE:
            self._load_from_disk()

    def _load_from_disk(self):
        """Load data from pickle file (existing functionality)"""
        try:
            if os.path.exists(self.persistence_file):
                with open(self.persistence_file, 'rb') as f:
                    data = pickle.load(f)
                self.users = data.get('users', {})
                self.sessions = data.get('sessions', {})
                self.oauth_states = data.get('oauth_states', {})
                self.rate_limits = data.get('rate_limits', {})
                self.refresh_tokens = data.get('refresh_tokens', {})
                self.blacklisted_tokens = data.get('blacklisted_tokens', set())
                logger.info(f"Loaded persisted data: {len(self.users)} users, {len(self.sessions)} sessions")
        except Exception as e:
            logger.warning(f"Failed to load persisted data: {e}")

    async def _sync_to_database(self):
        """Sync all data to PostgreSQL database"""
        if not self.db_sync_enabled:
            return

        if db_config.AsyncSessionLocal is None:
            logger.debug("AsyncSessionLocal not available, skipping database sync")
            return

        try:
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

                await db.commit()
                logger.info(f"✅ Synced {len(self.users)} users to database")
        except Exception as e:
            logger.error(f"❌ Database sync error: {e}")

    async def _save_to_disk(self):
        """Save data to disk (existing + database sync)"""
        if not self.persistence_file or not Config.ENABLE_PERSISTENCE:
            return
        try:
            data = {
                'users': self.users,
                'sessions': self.sessions,
                'oauth_states': self.oauth_states,
                'rate_limits': self.rate_limits,
                'refresh_tokens': self.refresh_tokens,
                'blacklisted_tokens': self.blacklisted_tokens,
                'timestamp': datetime.utcnow()
            }
            with open(self.persistence_file, 'wb') as f:
                pickle.dump(data, f)

            await self._sync_to_database()
        except Exception as e:
            logger.error(f"Failed to save data: {e}")

    async def _cleanup_expired_data(self):
        """Clean up expired data"""
        async with self._lock:
            current_time = datetime.utcnow()

            expired_sessions = [
                sid for sid, session in self.sessions.items()
                if session.expires_at < current_time
            ]
            for sid in expired_sessions:
                del self.sessions[sid]

            expired_states = [
                state for state, state_obj in self.oauth_states.items()
                if state_obj.created_at + timedelta(minutes=10) < current_time
            ]
            for state in expired_states:
                del self.oauth_states[state]

            expired_limits = [
                identifier for identifier, limit in self.rate_limits.items()
                if limit.window_start + timedelta(hours=1) < current_time
            ]
            for identifier in expired_limits:
                del self.rate_limits[identifier]

            expired_refresh = [
                tid for tid, token in self.refresh_tokens.items()
                if token.expires_at < current_time or token.is_revoked
            ]
            for tid in expired_refresh:
                del self.refresh_tokens[tid]

            if any([expired_sessions, expired_states, expired_limits, expired_refresh]):
                logger.info(f"Cleanup: {len(expired_sessions)} sessions, {len(expired_states)} states, "
                           f"{len(expired_limits)} rate limits, {len(expired_refresh)} refresh tokens")
                await self._save_to_disk()

    async def create_user(self, email: str, github_id: Optional[str] = None) -> User:
        """Create a new user (memory + database)"""
        async with self._lock:
            if email in self.users:
                raise ValueError("User already exists")

            user = User(email=email, github_id=github_id)
            self.users[email] = user

            if self.db_sync_enabled and db_config.AsyncSessionLocal is not None:
                try:
                    async with db_config.AsyncSessionLocal() as db:
                        await DatabaseService.create_user(
                            db=db,
                            email=email,
                            github_id=github_id,
                            email_verified=False
                        )
                        await db.commit()
                        logger.info(f"✅ User created in database: {email}")
                except Exception as e:
                    logger.error(f"❌ Failed to create user in database: {e}")

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
            user.updated_at = datetime.utcnow()

            if self.db_sync_enabled and db_config.AsyncSessionLocal is not None:
                try:
                    async with db_config.AsyncSessionLocal() as db:
                        db_user = await DatabaseService.get_user_by_email(db, email)
                        if db_user:
                            db_updates = {}
                            if 'github_id' in kwargs:
                                db_updates['github_id'] = kwargs['github_id']
                            if 'email_verified' in kwargs:
                                db_updates['email_verified'] = kwargs['email_verified']
                            if 'last_login' in kwargs:
                                db_updates['last_login'] = kwargs['last_login']

                            for key, value in db_updates.items():
                                setattr(db_user, key, value)

                            await db.commit()
                            logger.info(f"✅ User updated in database: {email}")
                except Exception as e:
                    logger.error(f"❌ Failed to update user in database: {e}")

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

    async def blacklist_token(self, token: str) -> None:
        """Add token to blacklist"""
        async with self._lock:
            self.blacklisted_tokens.add(token)
            await self._save_to_disk()

    async def is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        return token in self.blacklisted_tokens

store = SecureInMemoryStore(
    persistence_file=Config.PERSISTENCE_FILE if Config.ENABLE_PERSISTENCE else None
)
logger.info(f"✅ Initialized in-memory store (persistence: {Config.ENABLE_PERSISTENCE})")

# ----------------- Security Utilities -----------------
class SecurityUtils:
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_verification_code() -> str:
        return f"{secrets.randbelow(1000000):06d}"

    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    @staticmethod
    def hash_token(token: str) -> str:
        return hmac.new(
            Config.SECRET_KEY.encode(),
            token.encode(),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify_token_hash(token: str, token_hash: str) -> bool:
        return hmac.compare_digest(
            SecurityUtils.hash_token(token),
            token_hash
        )

    @staticmethod
    def mask_email(email: str) -> str:
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
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 255) -> str:
        if not input_str:
            return ""
        return input_str.strip()[:max_length]

# ----------------- JWT Token Management -----------------
class JWTManager:
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
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
        token_id = SecurityUtils.generate_secure_token()
        expires_at = datetime.utcnow() + timedelta(days=Config.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        token = RefreshToken(id=token_id, user_email=email, expires_at=expires_at)
        await store.create_refresh_token(token)
        return token_id

    @staticmethod
    async def verify_token(token: str) -> Optional[dict]:
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
        token = await store.get_refresh_token(token_id)
        if not token:
            return None
        if token.is_revoked or datetime.utcnow() > token.expires_at:
            return None
        return token.user_email

    @staticmethod
    async def revoke_refresh_token(token_id: str):
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
        max_attempts = max_attempts or Config.MAX_LOGIN_ATTEMPTS
        window_minutes = window_minutes or Config.RATE_LIMIT_WINDOW_MINUTES
        current_time = datetime.utcnow()

        entry = await store.get_rate_limit(identifier)

        if entry:
            if entry.blocked_until and current_time < entry.blocked_until:
                remaining_seconds = int((entry.blocked_until - current_time).total_seconds())
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many attempts. Try again in {remaining_seconds} seconds"
                )

            if current_time - entry.window_start > timedelta(minutes=window_minutes):
                entry.attempts = 0
                entry.window_start = current_time
                entry.blocked_until = None

            if entry.attempts >= max_attempts:
                entry.blocked_until = current_time + timedelta(minutes=window_minutes)
                await store.update_rate_limit(entry)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many attempts. Blocked for {window_minutes} minutes"
                )

            entry.attempts += 1
            await store.update_rate_limit(entry)
        else:
            entry = RateLimitEntry(identifier=identifier, attempts=1)
            await store.update_rate_limit(entry)

# ----------------- GitHub OAuth Client -----------------
class GitHubClient:
    BASE_URL = "https://api.github.com"
    OAUTH_URL = "https://github.com/login/oauth"

    @classmethod
    async def exchange_code_for_token(cls, code: str) -> Optional[str]:
        url = f"{cls.OAUTH_URL}/access_token"
        data = {
            "client_id": Config.GITHUB_CLIENT_ID,
            "client_secret": Config.GITHUB_CLIENT_SECRET,
            "code": code,
        }
        headers = {"Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(url, data=data, headers=headers)
                response.raise_for_status()
                payload = response.json()
                if "error" in payload:
                    logger.error(f"GitHub OAuth error: {payload}")
                    return None
                return payload.get("access_token")
        except Exception as e:
            logger.error(f"GitHub OAuth error: {e}")
            return None

    @classmethod
    async def get_user_info(cls, access_token: str) -> Optional[dict]:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "SecureScan-Auth/2.0"
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                emails_resp = await client.get(f"{cls.BASE_URL}/user/emails", headers=headers)
                user_resp = await client.get(f"{cls.BASE_URL}/user", headers=headers)

                if emails_resp.status_code == 200 and user_resp.status_code == 200:
                    emails = emails_resp.json()
                    user = user_resp.json()

                    primary_email = None
                    for email_obj in emails:
                        if email_obj.get("primary") and email_obj.get("verified"):
                            primary_email = email_obj.get("email")
                            break

                    if not primary_email:
                        for email_obj in emails:
                            if email_obj.get("verified"):
                                primary_email = email_obj.get("email")
                                break

                    if not primary_email:
                        primary_email = user.get("email")

                    return {
                        "email": primary_email,
                        "github_id": str(user.get("id")),
                        "login": user.get("login"),
                        "name": user.get("name"),
                        "avatar_url": user.get("avatar_url")
                    }
                return None
        except Exception as e:
            logger.error(f"GitHub API error: {e}")
            return None

# ----------------- Email Service -----------------
class EmailService:
    @staticmethod
    def create_verification_email(code: str, email: str) -> MIMEMultipart:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "SecureScan - Email Verification"
        msg["From"] = Config.FROM_EMAIL
        msg["To"] = email
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
        if not all([Config.SMTP_HOST, Config.SMTP_USER, Config.SMTP_PASS]):
            logger.warning("SMTP not configured, skipping email send")
            return True

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
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def get_user_agent(request: Request) -> str:
    return request.headers.get("User-Agent", "Unknown")[:255]

# ----------------- Authentication Dependencies -----------------
security = HTTPBearer(auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
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
    return {
        "service": "SecureScan Auth API",
        "version": "2.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/health")
async def health_check():
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
    client_id = get_client_identifier(http_request)
    await RateLimiter.check_rate_limit(f"auth_initiate:{client_id}")

    email = SecurityUtils.sanitize_input(request.email.lower().strip())
    user = await store.get_user(email)
    user_exists = user is not None

    session_id = SecurityUtils.generate_secure_token()
    verification_code = SecurityUtils.generate_verification_code()
    code_hash = SecurityUtils.hash_token(verification_code)

    session = Session(
        id=session_id,
        user_email=email,
        verification_code_hash=code_hash,
        expires_at=datetime.utcnow() + timedelta(minutes=Config.SESSION_EXPIRE_MINUTES),
        ip_address=client_id,
        user_agent=get_user_agent(http_request)
    )
    await store.create_session(session)

    try:
        background_tasks.add_task(EmailService.send_verification_email, email, verification_code)
    except Exception as e:
        logger.error(f"Failed to schedule email: {e}")

    if not user_exists:
        await store.create_user(email)

    logger.info(f"Auth initiated for {SecurityUtils.mask_email(email)}")

    return {
        "session": session_id,
        "expires_in": Config.SESSION_EXPIRE_MINUTES * 60,
        "message": f"Verification code sent to {SecurityUtils.mask_email(email)}"
    }

@router.post("/verify", response_model=TokenResponse)
async def verify_auth(request: VerifyRequest, http_request: Request):
    client_id = get_client_identifier(http_request)
    await RateLimiter.check_rate_limit(f"auth_verify:{client_id}", max_attempts=10)

    session = await store.get_session(request.session)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found or expired")

    if datetime.utcnow() > session.expires_at:
        await store.delete_session(request.session)
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Session expired. Please request a new verification code.")

    if session.attempts >= 5:
        await store.delete_session(request.session)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many verification attempts")

    if not SecurityUtils.verify_token_hash(request.code, session.verification_code_hash):
        await store.update_session(request.session, attempts=session.attempts + 1)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code")

    await store.update_session(request.session, verified=True)

    user = await store.get_user(session.user_email)
    if not user:
        user = await store.create_user(session.user_email)

    await store.update_user(
        session.user_email,
        email_verified=True,
        last_login=datetime.utcnow(),
        login_attempts=0
    )

    access_token = JWTManager.create_access_token({"sub": user.email, "verified": True})
    refresh_token = await JWTManager.create_refresh_token(user.email)

    await store.delete_session(request.session)

    logger.info(f"Auth verified for {SecurityUtils.mask_email(user.email)}")

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=Config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@router.get("/github/login")
async def github_login(request: Request, redirect_to: str = "/"):
    if not Config.GITHUB_CLIENT_ID:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="GitHub OAuth not configured")

    state = SecurityUtils.generate_secure_token()
    oauth_state = OAuthState(state=state, redirect_to=redirect_to, created_at=datetime.utcnow())
    await store.create_oauth_state(oauth_state)

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
    """Handle GitHub OAuth callback with database persistence"""
    try:
        if error:
            logger.error(f"GitHub OAuth error: {error}")
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error={error}")

        if not code or not state:
            logger.error("Missing code or state parameter")
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=invalid_request")

        oauth_state = await store.get_oauth_state(state)
        if not oauth_state:
            logger.error(f"Invalid OAuth state: {state}")
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=invalid_state")

        if oauth_state.used:
            logger.error(f"OAuth state already used: {state}")
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=state_reused")

        if datetime.utcnow() - oauth_state.created_at > timedelta(minutes=10):
            logger.error(f"OAuth state expired: {state}")
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=state_expired")

        await store.mark_oauth_state_used(state)

        logger.info("Exchanging code for GitHub access token")
        github_token = await GitHubClient.exchange_code_for_token(code)
        if not github_token:
            logger.error("Failed to exchange code for token")
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=token_exchange_failed")

        logger.info("Fetching user info from GitHub")
        github_user = await GitHubClient.get_user_info(github_token)
        if not github_user or not github_user.get("email"):
            logger.error("Failed to get user email from GitHub")
            return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=email_required")

        email = github_user["email"].lower().strip()
        github_id = github_user["github_id"]
        github_login = github_user.get("login")
        name = github_user.get("name")
        avatar_url = github_user.get("avatar_url")

        logger.info(f"GitHub user authenticated: {SecurityUtils.mask_email(email)}")

        client_ip = get_client_identifier(request)

        user = await store.get_user(email)
        is_new_user = user is None

        if not user:
            logger.info(f"Creating new user: {SecurityUtils.mask_email(email)}")
            user = await store.create_user(email, github_id=github_id)
            await store.update_user(email, email_verified=True, last_login=datetime.utcnow())
        else:
            logger.info(f"Updating existing user: {SecurityUtils.mask_email(email)}")
            await store.update_user(
                email,
                github_id=github_id,
                email_verified=True,
                last_login=datetime.utcnow(),
                login_attempts=0
            )

        # FIX: Direct database update with full GitHub info + get user UUID
        user_uuid = None
        if db_config.AsyncSessionLocal is not None:
            try:
                async with db_config.AsyncSessionLocal() as db:
                    db_user, created = await DatabaseService.get_or_create_user_by_github(
                        db=db,
                        email=email,
                        github_id=github_id,
                        github_login=github_login,
                        name=name,
                        avatar_url=avatar_url
                    )
                    # FIX 1: Capture the real UUID from database
                    user_uuid = str(db_user.id)

                    db_user.last_login = datetime.utcnow()

                    await DatabaseService.log_audit_event(
                        db=db,
                        action="GITHUB_OAUTH_SUCCESS",
                        resource="users",
                        success=True,
                        user_email=email,
                        # FIX 2: Use get_client_identifier instead of undefined client_ip var
                        ip_address=get_client_identifier(request),
                        user_agent=get_user_agent(request),
                        meta_data={
                            "github_id": github_id,
                            "github_login": github_login,
                            "is_new_user": created
                        }
                    )

                    await db.commit()
                    logger.info(f"✅ User {'created' if created else 'updated'} in database: {SecurityUtils.mask_email(email)}")
            except Exception as db_error:
                logger.error(f"❌ Database operation failed: {db_error}")

        # FIX 3: Include user_id, email, github_login in JWT token
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

        redirect_url = oauth_state.redirect_to
        if not redirect_url or redirect_url == "/":
            redirect_url = f"{Config.DASHBOARD_URL}/dashboard"
        else:
            if not redirect_url.startswith("http"):
                redirect_url = f"{Config.DASHBOARD_URL}{redirect_url}"

        logger.info(f"Redirecting to: {redirect_url}")

        response = RedirectResponse(url=redirect_url, status_code=303)

        is_production = Config.ENVIRONMENT == "production"
        cookie_settings = {
            "httponly": True,
            "secure": is_production,
            "samesite": "lax",
            "path": "/"
        }

        response.set_cookie(key="access_token", value=access_token,
                            max_age=Config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60, **cookie_settings)
        response.set_cookie(key="session_token", value=access_token,
                            max_age=Config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60, **cookie_settings)
        response.set_cookie(key="refresh_token", value=refresh_token,
                            max_age=Config.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60, **cookie_settings)
        response.set_cookie(key="github_access_token", value=github_token,
                            max_age=int(os.getenv("GITHUB_TOKEN_EXPIRE_MINUTES", "480")) * 60, **cookie_settings)
        response.set_cookie(key="user_email", value=email,
                            max_age=Config.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                            httponly=False, secure=is_production, samesite="lax", path="/")

        logger.info(f"✅ GitHub OAuth successful for {SecurityUtils.mask_email(email)}")
        return response

    except Exception as e:
        logger.error(f"❌ GitHub callback error: {str(e)}", exc_info=True)
        return RedirectResponse(f"{Config.FRONTEND_URL}/auth?error=server_error")

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshTokenRequest):
    email = await JWTManager.verify_refresh_token(request.refresh_token)
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user = await store.get_user(email)
    if not user or not user.is_active:
        await JWTManager.revoke_refresh_token(request.refresh_token)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    access_token = JWTManager.create_access_token({"sub": email, "verified": user.email_verified})
    new_refresh_token = await JWTManager.create_refresh_token(email)
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
    response = JSONResponse(content={"message": "Logged out successfully"})

    # ✅ FIX 1: Revoke GitHub token so GitHub forces re-authentication next login
    # Without this, GitHub silently re-authorizes and skips the login page entirely
    github_token = request.cookies.get("github_access_token")
    if github_token and Config.GITHUB_CLIENT_ID and Config.GITHUB_CLIENT_SECRET:
        try:
            import requests as req_lib
            import asyncio
            revoke_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: req_lib.delete(
                    f"https://api.github.com/applications/{Config.GITHUB_CLIENT_ID}/token",
                    auth=(Config.GITHUB_CLIENT_ID, Config.GITHUB_CLIENT_SECRET),
                    json={"access_token": github_token},
                    headers={"Accept": "application/vnd.github+json"},
                    timeout=10
                )
            )
            logger.info(f"✅ GitHub token revoked — status {revoke_response.status_code}")
        except Exception as e:
            logger.warning(f"⚠️ Failed to revoke GitHub token: {e}")

    # ✅ FIX 2: access_token, session_token, refresh_token, github_access_token
    # were all set with httponly=True — delete with matching attributes
    for cookie_name in ["access_token", "session_token", "refresh_token", "github_access_token"]:
        response.delete_cookie(key=cookie_name, path="/", samesite="lax", httponly=True, secure=False)

    # ✅ FIX 3: user_email was set with httponly=False — must match or browser ignores deletion
    response.delete_cookie(key="user_email", path="/", samesite="lax", httponly=False, secure=False)

    if credentials:
        await store.blacklist_token(credentials.credentials)

    if refresh_token:
        await JWTManager.revoke_refresh_token(refresh_token)

    logger.info("✅ User logged out — cookies cleared, GitHub token revoked")
    return response

@router.get("/me", response_model=UserInfo)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    user = await store.get_user(current_user["sub"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserInfo(
        email=user.email,
        email_verified=user.email_verified,
        created_at=user.created_at,
        last_login=user.last_login
    )

@router.get("/session")
async def get_session_info(request: Request):
    try:
        access_token = request.cookies.get("access_token")

        if not access_token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                access_token = auth_header.split(" ", 1)[1]

        if not access_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No authentication token found")

        payload = await JWTManager.verify_token(access_token)
        if not payload:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

        email = payload.get("sub")
        user = await store.get_user(email)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve session information")

@router.get("/status", response_model=AuthStatusResponse)
async def check_auth_status(identifier: str):
    if SecurityUtils.validate_email(identifier):
        email = SecurityUtils.sanitize_input(identifier.lower().strip())
        user = await store.get_user(email)

        if not user:
            return AuthStatusResponse(exists=False, email_hint=SecurityUtils.mask_email(email))

        return AuthStatusResponse(
            exists=True,
            verified=user.email_verified,
            email_hint=SecurityUtils.mask_email(email),
            attempts_remaining=max(0, Config.MAX_LOGIN_ATTEMPTS - user.login_attempts)
        )

    session = await store.get_session(identifier)
    if not session:
        return AuthStatusResponse(exists=False, email_hint="****@****")

    user = await store.get_user(session.user_email)
    if not user:
        return AuthStatusResponse(exists=False, email_hint=SecurityUtils.mask_email(session.user_email))

    return AuthStatusResponse(
        exists=True,
        verified=user.email_verified,
        email_hint=SecurityUtils.mask_email(session.user_email),
        attempts_remaining=max(0, Config.MAX_LOGIN_ATTEMPTS - user.login_attempts)
    )

# ----------------- Background Tasks -----------------
async def cleanup_task():
    while True:
        try:
            await store._cleanup_expired_data()
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")
            await asyncio.sleep(300)

# ----------------- Lifespan (for standalone mode only) -----------------
@asynccontextmanager
async def lifespan(app):
    logger.info("Starting SecureScan Auth API...")
    await initialize_database()
    await store._cleanup_expired_data()
    cleanup_task_handle = asyncio.create_task(cleanup_task())
    yield
    logger.info("Shutting down SecureScan Auth API...")
    cleanup_task_handle.cancel()
    try:
        await cleanup_task_handle
    except asyncio.CancelledError:
        pass

# ----------------- Export router and store -----------------
__all__ = ['router', 'store', 'lifespan']

async def initialize_database():
    try:
        from database.models import Base
        from database.config import engine, test_connection
        logger.info("Testing database connection...")
        is_connected = await test_connection()
        if is_connected:
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

    standalone_app = FastAPI(
        title="SecureScan Auth API (Standalone)",
        description="Secure authentication service - Standalone Mode",
        version="2.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc"
    )

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