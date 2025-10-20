from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update, and_
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import logging

from .models import (
    User, Session as SessionModel, OAuthState, 
    RefreshToken, RateLimit, BlacklistedToken, AuditLog
)

logger = logging.getLogger(__name__)

class DatabaseService:
    """Database service for authentication operations with security features"""
    
    # ============================================
    # USER OPERATIONS
    # ============================================
    
    @staticmethod
    async def create_user(
        db: AsyncSession, 
        email: str, 
        github_id: Optional[str] = None,
        **kwargs
    ) -> User:
        """Create a new user"""
        user = User(email=email, github_id=github_id, **kwargs)
        db.add(user)
        try:
            await db.flush()
            await db.refresh(user)
            logger.info(f"User created: {email}")
            return user
        except IntegrityError:
            await db.rollback()
            logger.warning(f"User already exists: {email}")
            raise ValueError("User already exists")
    
    @staticmethod
    async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
        """Get user by email"""
        result = await db.execute(
            select(User).where(and_(User.email == email, User.is_active == True))
        )
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_user_by_github_id(db: AsyncSession, github_id: str) -> Optional[User]:
        """Get user by GitHub ID"""
        result = await db.execute(
            select(User).where(and_(User.github_id == github_id, User.is_active == True))
        )
        return result.scalar_one_or_none()
    
    @staticmethod
    async def update_user_login(db: AsyncSession, email: str, ip_address: str) -> None:
        """Update user login information and reset failed attempts"""
        await db.execute(
            update(User)
            .where(User.email == email)
            .values(
                last_login=datetime.utcnow(),
                last_login_ip=ip_address,
                login_attempts=0,
                locked_until=None,
                updated_at=datetime.utcnow()
            )
        )
        await db.flush()
    
    @staticmethod
    async def increment_login_attempts(db: AsyncSession, email: str) -> int:
        """Increment failed login attempts and lock account if necessary"""
        user = await DatabaseService.get_user_by_email(db, email)
        if not user:
            return 0
        
        new_attempts = user.login_attempts + 1
        locked_until = None
        
        if new_attempts >= 5:
            locked_until = datetime.utcnow() + timedelta(minutes=15)
            logger.warning(f"Account locked: {email}")
        
        await db.execute(
            update(User)
            .where(User.email == email)
            .values(
                login_attempts=new_attempts,
                locked_until=locked_until,
                updated_at=datetime.utcnow()
            )
        )
        await db.flush()
        return new_attempts
    
    @staticmethod
    async def get_or_create_user_by_github(
        db: AsyncSession,
        email: str,
        github_id: str,
        github_login: str = None,
        name: str = None,
        avatar_url: str = None
    ) -> tuple[User, bool]:
        """
        Get existing user by GitHub ID or create new one
        Returns (user, is_new)
        """
        # First try to find by GitHub ID
        user = await DatabaseService.get_user_by_github_id(db, github_id)
        
        if user:
            # Update last login
            user.last_login = datetime.utcnow()
            user.login_attempts = 0
            user.locked_until = None
            user.email_verified = True  # GitHub email is verified
            
            # Update GitHub info if changed
            if github_login:
                user.github_login = github_login
            if name:
                user.name = name
            if avatar_url:
                user.avatar_url = avatar_url
            
            await db.flush()
            logger.info(f"Existing user logged in: {email}")
            return user, False
        
        # Check if user exists with same email
        user = await DatabaseService.get_user_by_email(db, email)
        
        if user:
            # Link GitHub account to existing user
            user.github_id = github_id
            user.github_login = github_login
            user.name = name or user.name
            user.avatar_url = avatar_url or user.avatar_url
            user.email_verified = True
            user.last_login = datetime.utcnow()
            user.login_attempts = 0
            user.locked_until = None
            await db.flush()
            logger.info(f"GitHub account linked to existing user: {email}")
            return user, False
        
        # Create new user
        try:
            new_user = await DatabaseService.create_user(
                db=db,
                email=email,
                github_id=github_id,
                github_login=github_login,
                name=name,
                avatar_url=avatar_url,
                email_verified=True,
                is_active=True
            )
            logger.info(f"New user created via GitHub: {email}")
            return new_user, True
        except ValueError:
            # Race condition - user was created between checks
            user = await DatabaseService.get_user_by_email(db, email)
            if user:
                return user, False
            raise
    
    # ============================================
    # SESSION OPERATIONS
    # ============================================
    
    @staticmethod
    async def create_session(db: AsyncSession, session_data: Dict[str, Any]) -> SessionModel:
        """Create authentication session"""
        session = SessionModel(**session_data)
        db.add(session)
        await db.flush()
        logger.info(f"Session created: {session.id}")
        return session
    
    @staticmethod
    async def get_session(db: AsyncSession, session_id: str) -> Optional[SessionModel]:
        """Get non-expired, unverified session"""
        result = await db.execute(
            select(SessionModel).where(
                and_(
                    SessionModel.id == session_id,
                    SessionModel.expires_at > datetime.utcnow(),
                    SessionModel.verified == False
                )
            )
        )
        return result.scalar_one_or_none()
    
    @staticmethod
    async def verify_session(db: AsyncSession, session_id: str) -> None:
        """Mark session as verified"""
        await db.execute(
            update(SessionModel)
            .where(SessionModel.id == session_id)
            .values(verified=True)
        )
        await db.flush()
        logger.info(f"Session verified: {session_id}")
    
    @staticmethod
    async def increment_session_attempts(db: AsyncSession, session_id: str) -> int:
        """Increment verification attempts"""
        session = await DatabaseService.get_session(db, session_id)
        if not session:
            return 0
        
        new_attempts = session.attempts + 1
        await db.execute(
            update(SessionModel)
            .where(SessionModel.id == session_id)
            .values(attempts=new_attempts, last_attempt=datetime.utcnow())
        )
        await db.flush()
        return new_attempts
    
    @staticmethod
    async def delete_session(db: AsyncSession, session_id: str) -> None:
        """Delete session"""
        await db.execute(delete(SessionModel).where(SessionModel.id == session_id))
        await db.flush()
    
    # ============================================
    # OAUTH STATE OPERATIONS
    # ============================================
    
    @staticmethod
    async def create_oauth_state(db: AsyncSession, state_data: Dict[str, Any]) -> OAuthState:
        """Create OAuth state"""
        oauth_state = OAuthState(**state_data)
        db.add(oauth_state)
        await db.flush()
        return oauth_state
    
    @staticmethod
    async def get_oauth_state(db: AsyncSession, state: str) -> Optional[OAuthState]:
        """Get unused, non-expired OAuth state"""
        result = await db.execute(
            select(OAuthState).where(
                and_(
                    OAuthState.state == state,
                    OAuthState.used == False,
                    OAuthState.expires_at > datetime.utcnow()
                )
            )
        )
        return result.scalar_one_or_none()
    
    @staticmethod
    async def mark_oauth_state_used(db: AsyncSession, state: str) -> None:
        """Mark OAuth state as used"""
        await db.execute(
            update(OAuthState)
            .where(OAuthState.state == state)
            .values(used=True)
        )
        await db.flush()
    
    # ============================================
    # RATE LIMITING
    # ============================================
    
    @staticmethod
    async def check_rate_limit(
        db: AsyncSession,
        identifier: str,
        endpoint: str,
        max_attempts: int,
        window_minutes: int
    ) -> tuple[bool, int]:
        """
        Check and update rate limit.
        Returns (is_allowed, remaining_attempts)
        """
        result = await db.execute(
            select(RateLimit).where(
                and_(
                    RateLimit.identifier == identifier,
                    RateLimit.endpoint == endpoint
                )
            )
        )
        rate_limit = result.scalar_one_or_none()
        
        now = datetime.utcnow()
        
        if rate_limit:
            # Check if blocked
            if rate_limit.blocked_until and rate_limit.blocked_until > now:
                return False, 0
            
            # Check if window expired
            window_expired = (now - rate_limit.window_start) > timedelta(minutes=window_minutes)
            
            if window_expired:
                # Reset window
                rate_limit.attempts = 1
                rate_limit.window_start = now
                rate_limit.blocked_until = None
            else:
                # Increment attempts
                rate_limit.attempts += 1
                
                if rate_limit.attempts > max_attempts:
                    # Block
                    rate_limit.blocked_until = now + timedelta(minutes=15)
                    await db.flush()
                    logger.warning(f"Rate limit exceeded: {identifier} on {endpoint}")
                    return False, 0
            
            await db.flush()
            return True, max(0, max_attempts - rate_limit.attempts)
        else:
            # First attempt
            new_rate_limit = RateLimit(
                identifier=identifier,
                endpoint=endpoint,
                attempts=1,
                window_start=now
            )
            db.add(new_rate_limit)
            await db.flush()
            return True, max_attempts - 1
    
    # ============================================
    # AUDIT LOGGING
    # ============================================
    
    @staticmethod
    async def log_audit_event(
        db: AsyncSession,
        action: str,
        resource: str,
        success: bool,
        user_email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        error_message: Optional[str] = None,
        meta_data: Optional[Dict] = None
    ) -> None:
        """Log security audit event"""
        audit_log = AuditLog(
            user_email=user_email,
            action=action,
            resource=resource,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            error_message=error_message,
            meta_data=meta_data
        )
        db.add(audit_log)
        await db.flush()
    
    # ============================================
    # CLEANUP
    # ============================================
    
    @staticmethod
    async def cleanup_expired_data(db: AsyncSession) -> None:
        """Remove expired sessions, tokens, and states"""
        now = datetime.utcnow()
        
        # Delete expired sessions
        await db.execute(delete(SessionModel).where(SessionModel.expires_at < now))
        
        # Delete expired OAuth states
        await db.execute(delete(OAuthState).where(OAuthState.expires_at < now))
        
        # Delete expired refresh tokens
        await db.execute(
            delete(RefreshToken).where(
                and_(RefreshToken.expires_at < now, RefreshToken.is_revoked == True)
            )
        )
        
        # Delete expired blacklisted tokens
        await db.execute(delete(BlacklistedToken).where(BlacklistedToken.expires_at < now))
        
        # Clean old rate limits
        await db.execute(
            delete(RateLimit).where(RateLimit.window_start < now - timedelta(hours=24))
        )
        
        await db.commit()
        logger.info("Expired data cleaned up successfully")
