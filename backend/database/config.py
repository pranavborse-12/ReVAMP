from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
    AsyncEngine,
)
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
import os
from dotenv import load_dotenv
import logging
import asyncio

load_dotenv()

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")

# SQLAlchemy base
Base = declarative_base()

# Global state
_engine: AsyncEngine | None = None
AsyncSessionLocal = None
db_available = False

# In-memory storage fallback (persistent JSON for local dev)
from pathlib import Path
import json
import threading

MEMORY_STORE_FILE = Path(os.getenv("DB_MEMORY_FILE", "backend/database/db_memory.json"))
_memory_store_defaults = {
    "users": {},
    "sessions": {},
    "refresh_tokens": {},
    "oauth_states": {},
    "repositories": {},
    "scans": {},
    "scan_results": {},
}

# Load persisted memory store if it exists, otherwise start with defaults
def _load_memory_store() -> dict:
    try:
        if MEMORY_STORE_FILE.exists():
            with MEMORY_STORE_FILE.open("r", encoding="utf-8") as f:
                data = json.load(f)
                logger.info(f"Loaded memory store from {MEMORY_STORE_FILE}")
                # Ensure required top-level keys exist
                for k, v in _memory_store_defaults.items():
                    data.setdefault(k, v)
                return data
    except Exception as e:
        logger.warning(f"Failed to load memory store ({MEMORY_STORE_FILE}): {e}")

    logger.info("Using fresh in-memory store (no persisted file found)")
    return dict(_memory_store_defaults)

memory_store = _load_memory_store()

# Periodically persist the in-memory store to disk (daemon thread)
def _persist_memory_store(interval: float = 5.0):
    try:
        MEMORY_STORE_FILE.parent.mkdir(parents=True, exist_ok=True)
        while True:
            try:
                with MEMORY_STORE_FILE.open("w", encoding="utf-8") as f:
                    json.dump(memory_store, f, default=str, indent=2)
            except Exception as e:
                logger.warning(f"Failed to persist memory store: {e}")
            finally:
                # Sleep in small increments to make thread responsive to shutdown
                threading.Event().wait(interval)
    except Exception as e:
        logger.error(f"Memory store persistence thread terminated: {e}")

# Start background persistence thread
_thread = threading.Thread(target=_persist_memory_store, daemon=True, name="memory_store_persist")
_thread.start()


# ---------------- ENGINE ---------------- #

def get_engine() -> AsyncEngine | None:
    global _engine

    if _engine is None and DATABASE_URL:
        _engine = create_async_engine(
            DATABASE_URL,
            echo=False,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            pool_recycle=3600,
            connect_args={
                "timeout": 5,
                "command_timeout": 5,
            },
        )

    return _engine


# ---------------- INIT ---------------- #

async def init_database() -> bool:
    """
    Initialize database connection.
    Must be called explicitly from an active event loop.
    """
    global db_available, AsyncSessionLocal

    if not DATABASE_URL:
        logger.warning("⚠️ DATABASE_URL not set - using in-memory storage")
        db_available = False
        return False

    try:
        engine = get_engine()
        if engine is None:
            raise RuntimeError("Engine could not be created")

        logger.info("Attempting database connection...")

        async with asyncio.timeout(5):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))

        AsyncSessionLocal = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )

        db_available = True
        logger.info("✅ Database connection successful - using PostgreSQL")
        return True

    except asyncio.TimeoutError:
        logger.error("❌ Database connection timeout - falling back to in-memory storage")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")

    # Inform that we are falling back to the persistent JSON memory store
    try:
        logger.warning(f"⚠️ [FALLBACK] Using persistent JSON memory store: {MEMORY_STORE_FILE}")
    except Exception:
        logger.warning("⚠️ [FALLBACK] Using in-memory storage (no persistent file configured)")

    db_available = False
    return False


# ---------------- SESSION ---------------- #

async def get_db():
    if not db_available or AsyncSessionLocal is None:
        raise RuntimeError("Database is not available")

    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ---------------- UTILS ---------------- #

def is_db_available() -> bool:
    return db_available


def get_memory_store():
    return memory_store


def clear_memory_store():
    """Clear the in-memory store and remove persisted file if present."""
    global memory_store
    memory_store = dict(_memory_store_defaults)
    try:
        if MEMORY_STORE_FILE.exists():
            MEMORY_STORE_FILE.unlink()
            logger.info(f"🧹 Memory store cleared and persisted file removed: {MEMORY_STORE_FILE}")
        else:
            logger.info("🧹 Memory store cleared")
    except Exception as e:
        logger.warning(f"Failed to remove memory store file: {e}")
        logger.info("🧹 Memory store cleared (file remove failed)")
