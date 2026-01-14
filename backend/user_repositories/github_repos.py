"""
GitHub Repository Routes with Database Integration
FIXED: Proper JWT user_id extraction and repository storage
"""
from fastapi import APIRouter, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
import httpx
import logging
from typing import Optional, List
import uuid as uuid_module
import asyncio

# Import database storage
from backend.scanning_repos.storage import save_repository_to_db, get_user_repositories_from_db

logger = logging.getLogger(__name__)

router = APIRouter()


async def get_github_token(request: Request) -> str:
    """Extract GitHub token from request"""
    # Try cookie first (most reliable for same-origin requests)
    github_token = request.cookies.get("github_access_token")
    
    if github_token:
        logger.debug(f"GitHub token found in cookies")
        return github_token
    
    # Try Authorization header (Bearer token)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        github_token = auth_header.replace("Bearer ", "")
        logger.debug(f"GitHub token found in Authorization header")
        return github_token
    
    # Try to extract from JWT payload if available
    try:
        from backend.auth.authentication import JWTManager
        
        # Try multiple token sources
        token = request.cookies.get("session_token") or request.cookies.get("access_token")
        
        if token:
            payload = await JWTManager.verify_token(token)
            if payload and payload.get("github_token"):
                logger.debug(f"GitHub token found in JWT payload")
                return payload["github_token"]
    except Exception as e:
        logger.debug(f"Could not extract GitHub token from JWT: {e}")
    
    # No token found - log what we have
    logger.warning(f"GitHub token not found. Available cookies: {list(request.cookies.keys())}")
    raise HTTPException(
        status_code=401,
        detail="GitHub authentication required. Please login with GitHub."
    )

async def get_user_id(request: Request) -> str:
    """
    Extract user ID from JWT token with proper fallback handling
    """
    from backend.auth.authentication import JWTManager
    
    # Try to get token from multiple sources
    token = None
    
    # 1. Try session_token cookie (most reliable)
    token = request.cookies.get("session_token")
    
    # 2. Try access_token cookie
    if not token:
        token = request.cookies.get("access_token")
    
    # 3. Try Authorization header
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1]
    
    if not token:
        logger.warning("No JWT token found in request")
        return "anonymous"
    
    # Verify and decode token
    try:
        payload = await JWTManager.verify_token(token)
        
        if not payload:
            logger.warning("JWT token verification failed")
            return "anonymous"
        
        # Try to extract user_id
        user_id = None
        
        # 1. Try direct user_id field (from database)
        if "user_id" in payload and payload["user_id"]:
            user_id = payload["user_id"]
        
        # 2. Try sub field (email fallback)
        elif "sub" in payload:
            email = payload["sub"]
            
            # Try to get UUID from database
            try:
                from backend.database import config as db_config
                from backend.database.service import DatabaseService
                
                if db_config.is_db_available() and db_config.AsyncSessionLocal:
                    async with db_config.AsyncSessionLocal() as db:
                        db_user = await DatabaseService.get_user_by_email(db, email)
                        if db_user:
                            user_id = str(db_user.id)
            except Exception as e:
                logger.warning(f"Could not fetch user from database: {e}")
        
        # 3. Validate UUID format
        if user_id and user_id != "anonymous":
            try:
                uuid_module.UUID(user_id)
                return user_id
            except (ValueError, AttributeError) as e:
                logger.warning(f"Invalid UUID format: {user_id} - {e}")
        
        return "anonymous"
        
    except Exception as e:
        logger.error(f"Error extracting user_id from JWT: {e}", exc_info=True)
        return "anonymous"

async def save_repos_in_background(repos_data: List[dict], user_id: str):
    """
    ✅ NEW: Save repositories to database in parallel (background task)
    This runs AFTER the API response is sent to the client
    """
    if user_id == "anonymous":
        logger.info("Skipping database save for anonymous user")
        return
    
    logger.info(f"🔄 Background task: Saving {len(repos_data)} repositories...")
    
    # ✅ Save all repos in parallel using asyncio.gather
    tasks = [
        save_repository_to_db(
            user_id=user_id,
            owner=repo["owner"]["login"],
            repo_name=repo["name"],
            github_url=repo["html_url"],
            default_branch=repo.get("default_branch", "main"),
            primary_language=repo.get("language"),
            is_private=repo.get("private", False)
        )
        for repo in repos_data
    ]
    
    # Run all saves concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Count successes
    saved_count = sum(1 for r in results if r and not isinstance(r, Exception))
    failed_count = len(results) - saved_count
    
    logger.info(
        f"✅ Background save complete: {saved_count} saved, {failed_count} failed"
    )


@router.get("/repos")
async def get_user_repos(
    request: Request,
    background_tasks: BackgroundTasks,
    page: int = 1,
    per_page: int = 50,
    sort: str = "updated",
    direction: str = "desc",
    visibility: Optional[str] = None
):
    """
    Get user's GitHub repositories
    ✅ OPTIMIZED: Returns immediately, saves to DB in background
    """
    try:
        # Get authentication
        github_token = await get_github_token(request)
        user_id = await get_user_id(request)
        
        logger.info(f"📦 Fetching repositories for user: {user_id}")
        
        # Build GitHub API URL
        url = "https://api.github.com/user/repos"
        params = {
            "page": page,
            "per_page": per_page,
            "sort": sort,
            "direction": direction,
        }
        
        if visibility:
            params["visibility"] = visibility
        
        # ✅ Fetch from GitHub API (this is the bottleneck)
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                params=params,
                headers={
                    "Authorization": f"token {github_token}",
                    "Accept": "application/vnd.github.v3+json"
                },
                timeout=30.0
            )
        
        if response.status_code != 200:
            logger.error(f"GitHub API error: {response.status_code}")
            raise HTTPException(
                status_code=response.status_code,
                detail=f"GitHub API error: {response.text}"
            )
        
        repos_data = response.json()
        logger.info(f"📊 Fetched {len(repos_data)} repositories from GitHub")
        
        # ✅ OPTIMIZATION: Add background task for database saves
        # This runs AFTER we return the response to the client
        if user_id != "anonymous":
            background_tasks.add_task(save_repos_in_background, repos_data, user_id)
        
        # ✅ Transform and return immediately (don't wait for DB)
        transformed_repos = [
            {
                "id": repo["id"],
                "name": repo["name"],
                "full_name": repo["full_name"],
                "owner": {
                    "login": repo["owner"]["login"],
                    "avatar_url": repo["owner"]["avatar_url"]
                },
                "private": repo["private"],
                "html_url": repo["html_url"],
                "description": repo["description"],
                "fork": repo["fork"],
                "created_at": repo["created_at"],
                "updated_at": repo["updated_at"],
                "pushed_at": repo["pushed_at"],
                "language": repo["language"],
                "stargazers_count": repo["stargazers_count"],
                "watchers_count": repo["watchers_count"],
                "forks_count": repo["forks_count"],
                "open_issues_count": repo["open_issues_count"],
                "default_branch": repo["default_branch"],
                "visibility": repo.get("visibility", "private" if repo["private"] else "public")
            }
            for repo in repos_data
        ]
        
        # ✅ Return immediately (database save happens in background)
        return {
            "repositories": transformed_repos,
            "page": page,
            "per_page": per_page,
            "total": len(transformed_repos),
            "user_authenticated": user_id != "anonymous",
            "saved_to_db": "background"  # Indicate it's happening in background
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching repositories: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch repositories: {str(e)}"
        )


@router.get("/repos/from-database")
async def get_repos_from_database(
    request: Request,
    limit: int = 50,
    offset: int = 0
):
    """
    Get user's repositories from database
    ✅ Fast local cache lookup
    """
    try:
        user_id = await get_user_id(request)
        
        if user_id == "anonymous":
            return {
                "repositories": [],
                "count": 0,
                "limit": limit,
                "offset": offset,
                "error": "User not authenticated"
            }
        
        logger.info(f"📊 Fetching repositories from database for user: {user_id}")
        
        repos = await get_user_repositories_from_db(
            user_id=user_id,
            limit=limit,
            offset=offset
        )
        
        return {
            "repositories": repos,
            "count": len(repos),
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error fetching from database: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Database error: {str(e)}"
        )

@router.get("/repos/{owner}/{repo}")
async def get_repo_details(
    owner: str,
    repo: str,
    request: Request
):
    """
    Get detailed information about a specific repository
    """
    try:
        github_token = await get_github_token(request)
        
        url = f"https://api.github.com/repos/{owner}/{repo}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers={
                    "Authorization": f"token {github_token}",
                    "Accept": "application/vnd.github.v3+json"
                },
                timeout=30.0
            )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"GitHub API error: {response.text}"
            )
        
        return response.json()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching repository details: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch repository details: {str(e)}"
        )


@router.get("/repos/{owner}/{repo}/branches")
async def get_repo_branches(
    owner: str,
    repo: str,
    request: Request
):
    """
    Get branches for a specific repository
    """
    try:
        github_token = await get_github_token(request)
        
        url = f"https://api.github.com/repos/{owner}/{repo}/branches"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers={
                    "Authorization": f"token {github_token}",
                    "Accept": "application/vnd.github.v3+json"
                },
                timeout=30.0
            )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"GitHub API error: {response.text}"
            )
        
        return response.json()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching branches: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch branches: {str(e)}"
        )


@router.get("/user")
async def get_github_user(request: Request):
    """
    Get authenticated GitHub user information
    """
    try:
        github_token = await get_github_token(request)
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"token {github_token}",
                    "Accept": "application/vnd.github.v3+json"
                },
                timeout=30.0
            )
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail="Failed to fetch user information"
            )
        
        return response.json()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch user information: {str(e)}"
        )


@router.get("/profile")
async def get_github_profile(request: Request):
    """
    Alias for /user endpoint - Get authenticated GitHub user information
    """
    return await get_github_user(request)