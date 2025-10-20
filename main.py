# from fastapi import FastAPI, Request
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.responses import JSONResponse
# from contextlib import asynccontextmanager
# from datetime import datetime
# import os
# import logging
# from sqlalchemy import text
# from dotenv import load_dotenv

# # Load environment variables
# load_dotenv()

# # Setup logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
# )
# logger = logging.getLogger(__name__)

# # Lifespan event handler for startup/shutdown
# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     """Handle startup and shutdown events"""
#     # Startup
#     logger.info("🚀 Starting REVAMP API...")
    
#     # Test database connection
#     try:
#         from backend.database.config import test_connection
#         db_connected = await test_connection()
#         if db_connected:
#             logger.info("✅ Database connected successfully")
#         else:
#             logger.warning("⚠️ Database connection failed - check your DATABASE_URL in .env")
#     except Exception as e:
#         logger.error(f"❌ Database connection error: {e}")
    
#     # Run auth store cleanup
#     try:
#         from backend.auth.authentication import store
#         await store._cleanup_expired_data()
#         logger.info("✅ Auth store initialized")
#     except Exception as e:
#         logger.error(f"⚠️ Auth store initialization error: {e}")
    
#     yield
    
#     # Shutdown
#     logger.info("👋 Shutting down REVAMP API...")

# # Create main FastAPI application with lifespan
# app = FastAPI(
#     title="REVAMP API",
#     description="Security scanning and repository management API with authentication",
#     version="2.0.0",
#     docs_url="/docs",
#     redoc_url="/redoc",
#     lifespan=lifespan  # Use this lifespan instead of auth's
# )

# # Configure CORS with proper settings
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[
#         "http://localhost:3000",
#         "http://localhost:3001",
#         "http://localhost:8000",
#         "http://127.0.0.1:3000",
#         "http://127.0.0.1:3001",
#         "http://127.0.0.1:8000",
#     ],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
#     expose_headers=["*"]
# )

# # Import routers (import router, not app)
# from backend.auth.authentication import router as auth_router
# from backend.user_repositories.github_repos import router as github_router

# # Include routers with correct prefixes
# app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
# app.include_router(github_router, prefix="/api/github", tags=["GitHub"])

# @app.get("/", tags=["Root"])
# async def root():
#     """Root endpoint - API health check"""
#     return {
#         "message": "REVAMP API is running",
#         "version": "2.0.0",
#         "status": "healthy",
#         "timestamp": datetime.utcnow().isoformat(),
#         "docs": "http://localhost:8000/docs",
#         "endpoints": {
#             "auth": "/auth",
#             "github": "/api/github",
#             "health": "/health"
#         }
#     }

# @app.get("/health", tags=["Health"])
# async def health_check():
#     """Detailed health check with database status"""
#     db_status = "not_configured"
    
#     try:
#         from backend.database.config import engine
#         async with engine.begin() as conn:
#             await conn.execute(text("SELECT 1"))
#         db_status = "connected"
#     except ImportError:
#         db_status = "not_configured"
#     except Exception as e:
#         logger.error(f"Health check database error: {e}")
#         db_status = "disconnected"
    
#     # Check auth store
#     auth_status = "unknown"
#     try:
#         from backend.auth.authentication import store
#         auth_status = f"healthy - {len(store.users)} users"
#     except Exception as e:
#         auth_status = f"error: {str(e)}"
    
#     return {
#         "status": "healthy",
#         "database": db_status,
#         "auth_store": auth_status,
#         "version": "2.0.0",
#         "timestamp": datetime.utcnow().isoformat()
#     }

# # Error handler
# @app.exception_handler(Exception)
# async def global_exception_handler(request: Request, exc: Exception):
#     """Handle unexpected errors"""
#     logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
#     return JSONResponse(
#         status_code=500,
#         content={
#             "detail": str(exc) if app.debug else "Internal server error",
#             "timestamp": datetime.utcnow().isoformat(),
#             "path": str(request.url)
#         }
#     )

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(
#         "main:app",
#         host="0.0.0.0",
#         port=8000,
#         reload=True,
#         log_level="info"
#     )
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

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Lifespan event handler for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    # Startup
    logger.info("🚀 Starting REVAMP API...")
    
    # Test database connection
    try:
        from backend.database.config import test_connection
        db_connected = await test_connection()
        if db_connected:
            logger.info("✅ Database connected successfully")
        else:
            logger.warning("⚠️ Database connection failed - check your DATABASE_URL in .env")
    except Exception as e:
        logger.error(f"❌ Database connection error: {e}")
    
    # Run auth store cleanup
    try:
        from backend.auth.authentication import store
        await store._cleanup_expired_data()
        logger.info("✅ Auth store initialized")
    except Exception as e:
        logger.error(f"⚠️ Auth store initialization error: {e}")
    
    yield
    
    # Shutdown
    logger.info("👋 Shutting down REVAMP API...")

# Create main FastAPI application with lifespan
app = FastAPI(
    title="REVAMP API",
    description="Security scanning and repository management API with authentication",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan  # Use this lifespan instead of auth's
)

# Configure CORS with proper settings
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

# Import routers (import router, not app)
from backend.auth.authentication import router as auth_router
from backend.user_repositories.github_repos import router as github_router

# Include routers with correct prefixes
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(github_router, prefix="/api/github", tags=["GitHub"])

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint - API health check"""
    return {
        "message": "REVAMP API is running",
        "version": "2.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "docs": "http://localhost:8000/docs",
        "endpoints": {
            "auth": "/auth",
            "github": "/api/github",
            "health": "/health"
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
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

# Error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors"""
    logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": str(exc) if app.debug else "Internal server error",
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url)
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )