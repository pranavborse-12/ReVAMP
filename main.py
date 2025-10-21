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
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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


# Lifespan event handler for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    # Startup
    logger.info("=" * 80)
    logger.info(">> Starting REVAMP/SecureScan API...")
    logger.info("=" * 80)
    
    # Test database connection
    try:
        from backend.database.config import test_connection
        db_connected = await test_connection()
        if db_connected:
            logger.info("[OK] Database connected successfully")
        else:
            logger.warning("[WARN] Database connection failed - check your DATABASE_URL in .env")
    except ImportError:
        logger.warning("[WARN] Database module not configured")
    except Exception as e:
        logger.error(f"[ERROR] Database connection error: {e}")
    
    # Run auth store cleanup
    try:
        from backend.auth.authentication import store
        await store._cleanup_expired_data()
        logger.info("[OK] Auth store initialized")
    except Exception as e:
        logger.error(f"[WARN] Auth store initialization error: {e}")
    
    logger.info("[OK] All services initialized")
    
    yield
    
    # Shutdown
    logger.info("=" * 80)
    logger.info(">> Shutting down REVAMP/SecureScan API...")
    logger.info("=" * 80)


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
        "https://github.com",  # Allow GitHub OAuth redirects
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Include routers with proper prefixes
logger.info("Registering routers...")
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(github_router, prefix="/api/github", tags=["GitHub"])
app.include_router(scanning_router, prefix="/api/scanning", tags=["Scanning"])
logger.info("[OK] All routers registered")


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint - API health check"""
    return {
        "message": "REVAMP/SecureScan API is running",
        "version": "3.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "docs": "http://localhost:8000/docs",
        "features": [
            "GitHub OAuth Authentication",
            "Authentication Database (PostgreSQL/SQLite)",
            "Repository Management",
            "Security Scanning (Semgrep + CodeQL)",
            "Vulnerability Analysis",
            "Real-time Scan Status"
        ],
        "endpoints": {
            "auth": "/auth",
            "github": "/api/github",
            "scanning": "/api/scanning",
            "health": "/health",
            "status": "/api/status"
        }
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check with database status"""
    db_status = "not_configured"
    
    try:
        from backend.database.config import engine
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        db_status = "connected"
    except ImportError:
        db_status = "not_configured"
    except Exception as e:
        logger.error(f"Health check database error: {e}")
        db_status = "disconnected"
    
    # Check auth store
    auth_status = "unknown"
    try:
        from backend.auth.authentication import store
        auth_status = f"healthy - {len(store.users)} users"
    except Exception as e:
        auth_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "database": db_status,
        "auth_store": auth_status,
        "environment": getattr(AuthConfig, 'ENVIRONMENT', 'unknown'),
        "version": "3.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "auth": "operational",
            "github": "operational",
            "scanning": "operational"
        }
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


# Error handler with better logging for OAuth issues
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors"""
    logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
    
    # Log request details for debugging OAuth issues
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
    
    print(f"\nCONFIGURATION:")
    print(f"   Environment: {env}")
    print(f"   Debug Mode: {debug}")
    print(f"   Database: {'[OK] Configured' if os.getenv('DATABASE_URL') else '[X] Not Configured'}")
    print(f"   GitHub OAuth: {'[OK] Configured' if os.getenv('GITHUB_CLIENT_ID') else '[X] Not Configured'}")
    print(f"   GitHub Callback: {os.getenv('GITHUB_CALLBACK_URL', 'http://localhost:8000/auth/github/callback')}")
    print(f"   Semgrep Token: {'[OK] Configured' if os.getenv('SEMGREP_APP_TOKEN') else '[X] Not Configured'}")
    print(f"   Max Concurrent Scans: {os.getenv('MAX_CONCURRENT_SCANS', '5')}")
    
    print(f"\nAPI ENDPOINTS:")
    print(f"   Root: http://localhost:8000/")
    print(f"   Docs: http://localhost:8000/docs")
    print(f"   ReDoc: http://localhost:8000/redoc")
    print(f"   Health: http://localhost:8000/health")
    print(f"   Status: http://localhost:8000/api/status")
    
    print(f"\nAUTHENTICATION (with Database):")
    print(f"   POST   /auth/auth/initiate")
    print(f"   POST   /auth/auth/verify")
    print(f"   GET    /auth/github/login")
    print(f"   GET    /auth/github/callback")
    
    print(f"\nGITHUB INTEGRATION:")
    print(f"   GET    /api/github/profile")
    print(f"   GET    /api/github/repos")
    print(f"   GET    /api/github/repos/{{owner}}/{{repo}}/files")
    
    print(f"\nSECURITY SCANNING:")
    print(f"   POST   /api/scanning/repos/{{owner}}/{{repo}}/scan")
    print(f"   GET    /api/scanning/scans/{{scan_id}}")
    print(f"   GET    /api/scanning/scans/{{scan_id}}/status")
    print(f"   GET    /api/scanning/scans/{{scan_id}}/summary")
    print(f"   GET    /api/scanning/scans/history")
    print(f"   DELETE /api/scanning/scans/{{scan_id}}")
    
    print(f"\nNETWORK:")
    print(f"   Local: http://localhost:8000")
    print(f"   LAN:   http://{local_ip}:8000")
    
    print("\n" + "=" * 90)
    print("IMPORTANT: Make sure your GitHub OAuth App callback URL is set to:")
    print(f"   {os.getenv('GITHUB_CALLBACK_URL', 'http://localhost:8000/auth/github/callback')}")
    print("=" * 90 + "\n")


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