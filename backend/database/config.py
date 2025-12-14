from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
import os
from dotenv import load_dotenv
import logging
import asyncio

load_dotenv()

logger = logging.getLogger(__name__)

# PostgreSQL connection string
DATABASE_URL = os.getenv("DATABASE_URL")

# Global state
db_available = False
engine = None
AsyncSessionLocal = None
Base = declarative_base()

# In-memory storage fallback
memory_store = {
    "users": {},
    "sessions": {},
    "refresh_tokens": {},
    "oauth_states": {},
    "repositories": {},
    "scans": {},
    "scan_results": {},
}

async def init_database():
    """Initialize database with timeout and fallback"""
    global db_available, engine, AsyncSessionLocal
    
    if not DATABASE_URL:
        logger.warning("⚠️ DATABASE_URL not set - using in-memory storage")
        db_available = False
        return False
    
    try:
        logger.info("Attempting database connection...")
        
        # Create engine with connection timeout
        engine = create_async_engine(
            DATABASE_URL,
            echo=False,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            pool_recycle=3600,
            connect_args={
                "timeout": 5,  # 5 second timeout
                "command_timeout": 5,
            }
        )
        
        # Test connection with timeout
        async with asyncio.timeout(5):  # Overall 5 second timeout
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
        
        # Create session maker
        AsyncSessionLocal = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False
        )
        
        db_available = True
        logger.info("✅ Database connection successful - using PostgreSQL")
        return True
        
    except asyncio.TimeoutError:
        logger.error("❌ Database connection timeout - falling back to in-memory storage")
        db_available = False
        engine = None
        AsyncSessionLocal = None
        return False
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        logger.warning("⚠️ Falling back to in-memory storage")
        db_available = False
        engine = None
        AsyncSessionLocal = None
        return False

async def get_db():
    """FastAPI dependency for database sessions (with fallback)"""
    if not db_available or AsyncSessionLocal is None:
        # Return None to indicate in-memory storage should be used
        logger.debug("Using in-memory storage (no database session)")
        yield None
        return
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()

async def test_connection():
    """Test database connectivity with timeout"""
    if not DATABASE_URL:
        logger.warning("⚠️ DATABASE_URL not configured")
        return False
    
    try:
        # Use a shorter timeout for initial connection test
        async with asyncio.timeout(3):
            if engine is None:
                return await init_database()
            
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
        
        logger.info("✅ Database connection test successful")
        return True
        
    except asyncio.TimeoutError:
        logger.error("❌ Database connection test timeout")
        return False
    except Exception as e:
        logger.error(f"❌ Database connection test failed: {e}")
        return False

def get_memory_store():
    """Get the in-memory storage"""
    return memory_store

def is_db_available():
    """Check if database is available"""
    return db_available

def clear_memory_store():
    """Clear all in-memory data (useful for testing)"""
    global memory_store
    memory_store = {
        "users": {},
        "sessions": {},
        "refresh_tokens": {},
        "oauth_states": {},
        "repositories": {},
        "scans": {},
        "scan_results": {},
    }
    logger.info("🧹 Memory store cleared")