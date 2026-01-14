"""
Unified Main Entry Point for REVAMP/SecureScan Application
Combines authentication database, GitHub integration, and repository scanning
"""
# CRITICAL: Force UTF-8 encoding for Windows console BEFORE any other imports
import sys
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import uvicorn
import socket
import asyncio
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi import APIRouter, Depends
from sqlalchemy import text, select, func
from backend.database.config import get_db, is_db_available
from contextlib import asynccontextmanager
from datetime import datetime
import os
import logging
from sqlalchemy import text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging with both file and console handlers
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Import configuration
try:
    from backend.auth.authentication import Config as AuthConfig
    logger.info("[OK] Authentication config loaded")
except ImportError as e:
    logger.error(f"[FAIL] Failed to import auth config: {e}")
    AuthConfig = type('Config', (), {'ENVIRONMENT': 'development', 'DEBUG': True})

try:
    from backend.scanning_repos import config as scanning_config
    scanner_logger = scanning_config.logger
    logger.info("[OK] Scanning config loaded")
except ImportError as e:
    logger.error(f"[FAIL] Failed to import scanning config: {e}")
    scanner_logger = logger

# Import routers
try:
    from backend.auth.authentication import router as auth_router
    logger.info("[OK] Auth router loaded")
except ImportError as e:
    logger.error(f"[FAIL] Failed to import auth router: {e}")
    raise

try:
    from backend.user_repositories.github_repos import router as github_router
    logger.info("[OK] GitHub router loaded")
except ImportError as e:
    logger.error(f"[FAIL] Failed to import github router: {e}")
    raise

try:
    from backend.scanning_repos.routes import router as scanning_router
    logger.info("[OK] Scanning router loaded")
except ImportError as e:
    logger.error(f"[FAIL] Failed to import scanning router: {e}")
    raise

# # Import scan history router (FIXED PATH)
# scan_history_router = None
# try:
#     from backend.scanning_repos.scan_history_routes import router as scan_history_router
#     logger.info("[OK] Scan history router loaded")
# except ImportError as e:
#     logger.warning(f"[WARN] Scan history router not available: {e}")

# Import AI fix router (clean module structure - no circular imports)
aifix_router = None
try:
    from backend.AI_fix import router as aifix_router
    logger.info("[OK] AI Fix router loaded")
except ImportError as e:
    logger.warning(f"[WARN] AI fix router not available: {e}")
except Exception as e:
    logger.error(f"[ERROR] Failed to load AI fix router: {e}")


# Lifespan event handler for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    # ========== STARTUP ==========
    logger.info("=" * 80)
    logger.info(">> Starting REVAMP/SecureScan API...")
    logger.info("=" * 80)
    
    # STEP 1: Initialize database FIRST (before anything else)
    db_initialized = False
    try:
        from backend.database.config import init_database, is_db_available
        
        logger.info("🔌 Initializing database connection...")
        
        # Call init_database() directly in async context
        db_initialized = await init_database()
        
        if db_initialized:
            logger.info("✅ [SUCCESS] Database connected and ready")
            
            # Verify with simple query
            try:
                from backend.database.config import get_engine
                engine = get_engine()
                async with engine.begin() as conn:
                    await conn.execute(text("SELECT 1"))
                logger.info("✅ [VERIFIED] Database connection test passed")
            except Exception as e:
                logger.warning(f"⚠️ [WARNING] Database test query failed: {e}")
        else:
            logger.error("❌ [FAILED] Database connection failed")
            try:
                from backend.database.config import MEMORY_STORE_FILE
                logger.warning(f"⚠️ [FALLBACK] Using persistent JSON store at: {MEMORY_STORE_FILE}")
                logger.warning("⚠️ Data will be persisted to the JSON file between restarts")
            except Exception:
                logger.warning("⚠️ [FALLBACK] Running in MEMORY-ONLY mode")
                logger.warning("⚠️ All data will be lost on restart!")
            
    except ImportError:
        logger.warning("⚠️ [WARNING] Database module not configured")
        logger.info("ℹ️ Running in memory-only mode")
    except Exception as e:
        logger.error(f"❌ [ERROR] Database initialization error: {e}", exc_info=True)
        logger.warning("⚠️ [FALLBACK] Running in MEMORY-ONLY mode")
    
    # STEP 2: Initialize auth store (now database is available)
    try:
        from backend.auth.authentication import store
        
        logger.info("🔐 Initializing authentication store...")
        
        # Set database sync flag based on initialization result
        if db_initialized:
            store.db_sync_enabled = True
            logger.info("✅ Auth store configured with DATABASE persistence")
        else:
            store.db_sync_enabled = False
            logger.warning("⚠️ Auth store configured with MEMORY-ONLY persistence")
        
        # Run initial cleanup
        await store._cleanup_expired_data()
        logger.info("✅ Auth store initialized and cleaned")
        
    except Exception as e:
        logger.error(f"❌ [ERROR] Auth store initialization error: {e}", exc_info=True)
    
    # STEP 3: Verify database tables exist (don't recreate - migration handles this)
    # STEP 3: Verify database tables exist
    if db_initialized:
        try:
            from backend.database.config import get_engine
            logger.info("📊 Verifying database tables...")
            engine = get_engine()
            async with engine.begin() as conn:
                result = await conn.execute(text("""
                SELECT COUNT(*) 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('users', 'scan_history', 'repositories', 'vulnerabilities')
            """))
                table_count = result.scalar()
                if table_count >= 4:
                    logger.info(f"✅ Database tables verified ({table_count} core tables found)")
                
                else:
                    logger.warning(f"⚠️ Some tables missing ({table_count}/4 found)")
                    logger.warning("⚠️ Run the SQL schema in pgAdmin first!")
        except Exception as e:
            logger.error(f"❌ [ERROR] Table verification error: {e}", exc_info=True)
    
    logger.info("=" * 80)
    logger.info("✅ All services initialized successfully")
    logger.info("=" * 80)
    
    yield
    
    # ========== SHUTDOWN ==========
    logger.info("=" * 80)
    logger.info(">> Shutting down REVAMP/SecureScan API...")
    logger.info("=" * 80)
    
    # Cleanup tasks
    try:
        from backend.auth.authentication import store
        if store.persistence_file:
            await store._save_to_disk()
            logger.info("💾 Auth data saved to disk")
    except Exception as e:
        logger.error(f"Error saving auth data: {e}")
    
    logger.info("👋 Shutdown complete")


# Create main FastAPI application with lifespan
app = FastAPI(
    title="REVAMP/SecureScan API",
    description="Unified security scanning platform with authentication database, GitHub integration, and vulnerability analysis",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS with proper settings for OAuth
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:8000",
        "https://github.com",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Include routers with proper prefixes
logger.info("Registering API routers...")
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(github_router, prefix="/api/github", tags=["GitHub"])
app.include_router(scanning_router, prefix="/api/scanning", tags=["Scanning"])


# # Include scan history router if available
# if scan_history_router is not None:
#     app.include_router(scan_history_router, tags=["Scan History"])
#     logger.info("[OK] Scan history router registered at /api/v1/scan-history")
# else:
#     logger.warning("[WARN] Scan history router not registered - module not available")

# Include AI fix router if available
if aifix_router is not None:
    app.include_router(aifix_router, prefix="/api/ai", tags=["AI Fix"])
    logger.info("[OK] AI Fix router registered at /api/ai")
else:
    logger.warning("[WARN] AI Fix router not registered - module not available")

logger.info("[OK] All available routers registered")


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint - API health check"""
    features = [
        "GitHub OAuth Authentication",
        "Authentication Database (PostgreSQL)",
        "Repository Management",
        "Security Scanning (Semgrep + CodeQL)",
        "Vulnerability Analysis",
        "Real-time Scan Status",
    ]
    
    # if scan_history_router is not None:
    #     features.append("Scan History & Analytics")
    
    # if aifix_router is not None:
    #     features.append("AI-Powered Vulnerability Fixing")
    
    endpoints = {
        "auth": "/auth",
        "github": "/api/github",
        "scanning": "/api/scanning",
        "health": "/health",
        "status": "/api/status",
        "debug_routes": "/debug/routes"
    }
    
    # if scan_history_router is not None:
    #     endpoints["scan_history"] = "/api/v1/scan-history"
    
    if aifix_router is not None:
        endpoints["ai_fix"] = "/api/ai"
    
    return {
        "message": "REVAMP/SecureScan API is running",
        "version": "3.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "docs": "http://localhost:8000/docs",
        "features": features,
        "endpoints": endpoints
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check with database status"""
    db_status = "not_configured"
    db_details = None
    
    try:
        from backend.database.config import is_db_available, get_engine
        if is_db_available():
            try:
                engine = get_engine()
                async with engine.begin() as conn:
                    result = await conn.execute(text("SELECT version()"))
                    version = result.scalar()
                    db_status = "connected"
                    db_details = version
            except Exception as e:
                db_status = "error"
                db_details = str(e)
        else:
            db_status = "not_available"
    except ImportError:
        db_status = "not_configured"
    except Exception as e:
        logger.error(f"Health check database error: {e}")
        db_status = "disconnected"
        db_details = str(e)
    
    # Check auth store
    auth_status = "unknown"
    auth_details = {}
    try:
        from backend.auth.authentication import store
        auth_status = "healthy"
        auth_details = {
            "users_count": len(store.users),
            "active_sessions": len(store.sessions),
            "db_sync_enabled": store.db_sync_enabled,
            "persistence_enabled": store.persistence_file is not None
        }
    except Exception as e:
        auth_status = f"error: {str(e)}"
    
    services = {
        "auth": "operational",
        "github": "operational",
        "scanning": "operational",
        # "scan_history": "operational" if scan_history_router else "unavailable"
    }
    
    if aifix_router is not None:
        services["ai_fix"] = "operational"
    else:
        services["ai_fix"] = "unavailable"
    
    return {
        "status": "healthy" if db_status in ["connected", "not_configured"] else "degraded",
        "database": {
            "status": db_status,
            "details": db_details
        },
        "auth_store": {
            "status": auth_status,
            "details": auth_details
        },
        "environment": getattr(AuthConfig, 'ENVIRONMENT', 'unknown'),
        "version": "3.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "services": services
    }


@app.get("/api/status", tags=["Status"])
async def api_status():
    """Get API operational status with scanning statistics"""
    try:
        from backend.scanning_repos.background_tasks import get_active_scans, get_all_scan_results
        
        all_scans = get_all_scan_results()
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "version": "3.0.0",
            "scanning": {
                "active_scans": get_active_scans(),
                "total_scans": len(all_scans),
                "queued": sum(1 for s in all_scans.values() if s.get('status') == 'queued'),
                "running": sum(1 for s in all_scans.values() if s.get('status') in ['cloning', 'analyzing', 'scanning', 'scanning_semgrep', 'scanning_codeql']),
                "completed": sum(1 for s in all_scans.values() if s.get('status') == 'completed'),
                "failed": sum(1 for s in all_scans.values() if s.get('status') == 'failed')
            }
        }
    except Exception as e:
        logger.error(f"Error getting API status: {e}")
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "status": "error",
            "error": str(e)
        }


@app.get("/debug/routes", tags=["Debug"])
async def debug_routes():
    """Debug endpoint to list all registered routes"""
    routes = []
    for route in app.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            routes.append({
                "path": route.path,
                "methods": list(route.methods),
                "name": route.name
            })
    return {
        "total_routes": len(routes),
        "routes": routes,
        # "scan_history_router_loaded": scan_history_router is not None,
        "ai_fix_router_loaded": aifix_router is not None
    }

@app.get("/debug/database-status", tags=["Debug"])
async def check_database_status():
    """Check if database is actually working and has data"""
    try:
        from backend.database.config import get_db
        # from backend.database.scan_history_model import ScanHistory, Repository, Vulnerability
        from sqlalchemy import text, select, func
        
        async for db in get_db():
            # Check connection
            await db.execute(text("SELECT 1"))
            
            # # Count records in each table
            # repo_count = await db.execute(select(func.count(Repository.id)))
            # scan_count = await db.execute(select(func.count(ScanHistory.id)))
            # vuln_count = await db.execute(select(func.count(Vulnerability.id)))
            
            # Get recent scans
            # recent_scans = await db.execute(
            #     select(ScanHistory)
            #     .order_by(ScanHistory.queued_at.desc())
            #     .limit(5)
            # )
            # scans = recent_scans.scalars().all()
            
            # return {
            #     "database_available": is_db_available(),
            #     "connection": "OK",
            #     "tables": {
            #         "repositories": repo_count.scalar(),
            #         "scans": scan_count.scalar(),
            #         "vulnerabilities": vuln_count.scalar()
            #     },
            #     "recent_scans": [
            #         {
            #             "scan_id": s.scan_id,
            #             "status": s.status.value,
            #             "total_vulns": s.total_vulnerabilities,
            #             "critical": s.critical_count,
            #             "high": s.high_count,
            #             "queued_at": s.queued_at.isoformat() if s.queued_at else None
            #         }
            #         for s in scans
            #     ]
            # }
    except Exception as e:
        logger.error(f"Database status check failed: {e}", exc_info=True)
        return {
            "database_available": False,
            "connection": "FAILED",
            "error": str(e)
        }

# Error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors"""
    logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
    
    if "/auth/" in str(request.url):
        logger.error(f"Auth request details - Method: {request.method}, Headers: {request.headers}")
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": str(exc) if getattr(AuthConfig, 'DEBUG', False) else "Internal server error",
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url)
        }
    )


def print_banner():
    """Print startup banner"""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = "127.0.0.1"

    env = getattr(AuthConfig, 'ENVIRONMENT', 'unknown')
    debug = getattr(AuthConfig, 'DEBUG', False)

    print("\n" + "=" * 90)
    print("REVAMP/SECURESCAN UNIFIED APPLICATION - v3.0")
    print("=" * 90)
    
    print(f"\nCOMPONENTS LOADED:")
    print(f"   [OK] Authentication Module with Database (backend/auth/)")
    print(f"   [OK] GitHub Integration Module (backend/user_repositories/)")
    print(f"   [OK] Security Scanning Module (backend/scanning_repos/)")
    
    # if scan_history_router is not None:
    #     print(f"   [OK] Scan History & Analytics Module (backend/scanning_repos/)")
    # else:
    #     print(f"   [X]  Scan History Module (Not Available)")
    
    if aifix_router is not None:
        print(f"   [OK] AI Vulnerability Fixing Module (backend/AI_fix/)")
    else:
        print(f"   [X]  AI Vulnerability Fixing Module (Not Available)")
    
    print(f"\nCONFIGURATION:")
    print(f"   Environment: {env}")
    print(f"   Debug Mode: {debug}")
    print(f"   Database: {'[OK] Configured' if os.getenv('DATABASE_URL') else '[X] Not Configured'}")
    print(f"   GitHub OAuth: {'[OK] Configured' if os.getenv('GITHUB_CLIENT_ID') else '[X] Not Configured'}")
    
    if aifix_router is not None:
        print(f"   OpenRouter API: {'[OK] Configured' if os.getenv('OPENROUTER_API_KEY') else '[X] Not Configured'}")
    
    print(f"\nNETWORK:")
    print(f"   Local: http://localhost:8000")
    print(f"   Docs:  http://localhost:8000/docs")
    print(f"   LAN:   http://{local_ip}:8000")
    
    print("\n" + "=" * 90 + "\n")


if __name__ == "__main__":
    print_banner()
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=getattr(AuthConfig, 'DEBUG', False),
        log_level="info" if not getattr(AuthConfig, 'DEBUG', False) else "debug",
        access_log=True
    )