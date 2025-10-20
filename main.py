"""
Unified Main Entry Point for SecureScan Application
Orchestrates authentication, GitHub integration, and repository scanning
"""
import uvicorn
import socket
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import configuration ONLY - avoid importing models from __init__
try:
    from backend.auth.authentication import Config as AuthConfig
    logger.info("✓ Authentication config loaded")
except ImportError as e:
    logger.error(f"✗ Failed to import auth config: {e}")
    AuthConfig = type('Config', (), {'ENVIRONMENT': 'development', 'DEBUG': True})

try:
    from backend.scanning_repos import config as scanning_config
    scanner_logger = scanning_config.logger
    logger.info("✓ Scanning config loaded")
except ImportError as e:
    logger.error(f"✗ Failed to import scanning config: {e}")
    scanner_logger = logger

# Import routers DIRECTLY from modules (not from __init__.py)
try:
    from backend.auth.authentication import router as auth_router
    logger.info("✓ Auth router loaded")
except ImportError as e:
    logger.error(f"✗ Failed to import auth router: {e}")
    raise

try:
    from backend.user_repositories.github_repos import router as github_router
    logger.info("✓ GitHub router loaded")
except ImportError as e:
    logger.error(f"✗ Failed to import github router: {e}")
    raise

try:
    from backend.scanning_repos.routes import router as scanning_router
    logger.info("✓ Scanning router loaded")
except ImportError as e:
    logger.error(f"✗ Failed to import scanning router: {e}")
    raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    logger.info("=" * 80)
    logger.info("STARTING SECURESCAN APPLICATION")
    logger.info("=" * 80)
    yield
    logger.info("=" * 80)
    logger.info("SHUTTING DOWN SECURESCAN APPLICATION")
    logger.info("=" * 80)


# Create FastAPI app
app = FastAPI(
    title="SecureScan API",
    description="Unified security scanning platform with GitHub integration",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Include routers with proper prefixes
logger.info("Registering routers...")
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(github_router, prefix="/api/github", tags=["GitHub"])
app.include_router(scanning_router, prefix="/api/scanning", tags=["Scanning"])
logger.info("✓ All routers registered")


@app.get("/")
async def root():
    """Root endpoint - API health check"""
    return {
        "message": "SecureScan API is running",
        "version": "3.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "features": [
            "GitHub OAuth Authentication",
            "Repository Management",
            "Security Scanning (Semgrep + CodeQL)",
            "Vulnerability Analysis",
            "Real-time Scan Status"
        ]
    }


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "environment": getattr(AuthConfig, 'ENVIRONMENT', 'unknown'),
        "services": {
            "auth": "operational",
            "github": "operational",
            "scanning": "operational"
        }
    }


@app.get("/api/status")
async def api_status():
    """Get API operational status"""
    try:
        from backend.scanning_repos.background_tasks import get_active_scans, get_all_scan_results
        
        all_scans = get_all_scan_results()
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
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
    print("SECURESCAN UNIFIED APPLICATION - v3.0")
    print("=" * 90)
    
    print(f"\nCOMPONENTS LOADED:")
    print(f"   ✓ Authentication Module (backend/auth/)")
    print(f"   ✓ GitHub Integration Module (backend/user_repositories/)")
    print(f"   ✓ Security Scanning Module (backend/scanning_repos/)")
    
    print(f"\nCONFIGURATION:")
    print(f"   Environment: {env}")
    print(f"   Debug Mode: {debug}")
    print(f"   GitHub OAuth: {'✓ Configured' if os.getenv('GITHUB_CLIENT_ID') else '✗ Not Configured'}")
    print(f"   Semgrep Token: {'✓ Configured' if os.getenv('SEMGREP_APP_TOKEN') else '✗ Not Configured'}")
    print(f"   Max Concurrent Scans: {os.getenv('MAX_CONCURRENT_SCANS', '5')}")
    
    print(f"\nAPI ENDPOINTS:")
    print(f"   Root: http://localhost:8000/")
    print(f"   Docs: http://localhost:8000/docs")
    print(f"   ReDoc: http://localhost:8000/redoc")
    print(f"   Status: http://localhost:8000/api/status")
    
    print(f"\nAUTHENTICATION:")
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