"""
GitHub Repository Management Backend
Handles fetching repositories, files, and repository contents with proper authentication
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
import httpx
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime, timedelta
import asyncio
from functools import lru_cache

# Import from authentication module
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from backend.auth.authentication import get_current_user, store, Config, JWTManager

logger = logging.getLogger(__name__)

# Create router WITHOUT prefix (prefix will be added in main.py)
router = APIRouter(tags=["github-repos"])

GITHUB_API_URL = "https://api.github.com"
GITHUB_API_TIMEOUT = 30.0

# Simple in-memory cache for repository data
repo_cache: Dict[str, Dict[str, Any]] = {}
CACHE_DURATION = timedelta(minutes=5)


class GitHubAPIError(Exception):
    """Custom exception for GitHub API errors"""
    def __init__(self, status_code: int, message: str, details: Optional[str] = None):
        self.status_code = status_code
        self.message = message
        self.details = details
        super().__init__(self.message)


async def get_github_token(request: Request) -> Optional[str]:
    """
    Extract GitHub access token from various sources
    """
    # Try cookie first
    github_token = request.cookies.get("github_access_token")
    if github_token:
        logger.info("Found GitHub token in cookie")
        return github_token
        
    # Try JWT payload
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
            payload = await JWTManager.verify_token(token)
            if payload and "github_token" in payload:
                logger.info("Found GitHub token in JWT")
                return payload["github_token"]
        except Exception as e:
            logger.error(f"Error extracting GitHub token from JWT: {e}")
    
    # Try access_token cookie (JWT)
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = await JWTManager.verify_token(access_token)
            if payload and "github_token" in payload:
                logger.info("Found GitHub token in access_token cookie")
                return payload["github_token"]
        except Exception as e:
            logger.error(f"Error extracting GitHub token from access_token cookie: {e}")
    
    logger.warning("No GitHub token found in request")
    return None


async def make_github_request(
    endpoint: str,
    github_token: str,
    params: Optional[Dict[str, Any]] = None,
    method: str = "GET",
    timeout: float = GITHUB_API_TIMEOUT
) -> Dict[str, Any]:
    """
    Make authenticated request to GitHub API with proper error handling
    """
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SecureScan-App/1.0",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    url = f"{GITHUB_API_URL}{endpoint}"
    
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            if method == "GET":
                response = await client.get(url, headers=headers, params=params or {})
            elif method == "POST":
                response = await client.post(url, headers=headers, json=params or {})
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            # Handle rate limiting
            if response.status_code == 403:
                rate_limit_remaining = response.headers.get("X-RateLimit-Remaining", "0")
                if rate_limit_remaining == "0":
                    reset_time = response.headers.get("X-RateLimit-Reset", "")
                    raise GitHubAPIError(
                        403,
                        "GitHub API rate limit exceeded",
                        f"Rate limit resets at: {reset_time}"
                    )
            
            # Handle other errors
            if response.status_code == 401:
                raise GitHubAPIError(401, "GitHub authentication failed", "Invalid or expired token")
            
            if response.status_code == 404:
                raise GitHubAPIError(404, "Resource not found", "The requested resource does not exist")
            
            if response.status_code >= 400:
                error_detail = response.json().get("message", "Unknown error") if response.text else "Unknown error"
                raise GitHubAPIError(
                    response.status_code,
                    f"GitHub API error: {response.status_code}",
                    error_detail
                )
            
            return response.json()
            
    except httpx.TimeoutException:
        logger.error(f"GitHub API timeout for endpoint: {endpoint}")
        raise GitHubAPIError(504, "GitHub API request timed out", "Please try again later")
    except httpx.RequestError as e:
        logger.error(f"GitHub API request error: {e}")
        raise GitHubAPIError(503, "Failed to connect to GitHub", str(e))
    except GitHubAPIError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error calling GitHub API: {e}")
        raise GitHubAPIError(500, "Internal server error", str(e))


def get_cache_key(prefix: str, *args) -> str:
    """Generate cache key"""
    return f"{prefix}:{':'.join(str(arg) for arg in args)}"


def get_cached_data(cache_key: str) -> Optional[Dict[str, Any]]:
    """Get data from cache if valid"""
    if cache_key in repo_cache:
        cached_entry = repo_cache[cache_key]
        if datetime.utcnow() < cached_entry["expires_at"]:
            return cached_entry["data"]
        else:
            del repo_cache[cache_key]
    return None


def set_cached_data(cache_key: str, data: Any, duration: timedelta = CACHE_DURATION):
    """Store data in cache"""
    repo_cache[cache_key] = {
        "data": data,
        "expires_at": datetime.utcnow() + duration,
        "cached_at": datetime.utcnow()
    }


# ==================== API ENDPOINTS ====================

@router.get("/profile")
async def get_github_profile(request: Request):
    """Get GitHub user profile"""
    try:
        github_token = await get_github_token(request)
        if not github_token:
            logger.error("No GitHub token found")
            raise HTTPException(
                status_code=401,
                detail="GitHub token not found. Please reconnect your GitHub account."
            )

        logger.info("Fetching GitHub profile...")
        profile = await make_github_request("/user", github_token)
        
        logger.info(f"GitHub profile fetched successfully: {profile.get('login')}")
        
        return {
            "login": profile.get("login"),
            "name": profile.get("name"),
            "avatar_url": profile.get("avatar_url"),
            "html_url": profile.get("html_url"),
            "bio": profile.get("bio")
        }

    except GitHubAPIError as e:
        logger.error(f"GitHub API error: {e.message}")
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error fetching GitHub profile: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/repos")
async def get_user_repositories(
    request: Request,
    query: str = Query("", description="Search query for repositories"),
    type: str = Query("all", description="Type of repositories (all, owner, member)"),
    sort: str = Query("updated", description="Sort by (updated, full_name, created, pushed)"),
    direction: str = Query("desc", description="Sort direction (asc, desc)"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(30, ge=1, le=100, description="Items per page")
):
    """
    Get user's GitHub repositories with filtering, sorting, and pagination
    """
    github_token = await get_github_token(request)
    
    if not github_token:
        logger.error("No GitHub token for repos request")
        raise HTTPException(
            status_code=401,
            detail="GitHub account not connected. Please reconnect your GitHub account."
        )
    
    try:
        # Build cache key
        cache_key = get_cache_key("repos", github_token[:10], query, type, sort, direction, page, per_page)
        cached = get_cached_data(cache_key)
        if cached:
            logger.info("Returning cached repos")
            return cached
        
        # Prepare query parameters for GitHub API
        params = {
            "per_page": per_page,
            "page": page,
            "sort": sort,
            "direction": direction
        }
        
        # Determine endpoint based on type
        if type == "all":
            endpoint = "/user/repos"
            params["affiliation"] = "owner,collaborator,organization_member"
        elif type == "owner":
            endpoint = "/user/repos"
            params["affiliation"] = "owner"
        elif type == "member":
            endpoint = "/user/repos"
            params["affiliation"] = "collaborator,organization_member"
        else:
            endpoint = "/user/repos"
        
        logger.info(f"Fetching repos from GitHub: {endpoint} with params {params}")
        
        # Fetch repositories
        repos = await make_github_request(endpoint, github_token, params)
        
        # Client-side filtering by query if needed
        if query:
            query_lower = query.lower()
            repos = [
                repo for repo in repos
                if query_lower in repo.get("name", "").lower() or
                   query_lower in repo.get("description", "").lower() or
                   query_lower in repo.get("full_name", "").lower()
            ]
        
        logger.info(f"Fetched {len(repos)} repositories")
        
        # Cache the results
        set_cached_data(cache_key, repos, timedelta(minutes=3))
        
        return repos
        
    except GitHubAPIError as e:
        logger.error(f"GitHub API error fetching repos: {e.message}")
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        logger.error(f"Error fetching repositories: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch repositories")


@router.get("/repos/{owner}/{repo}/files")
async def get_repository_files(
    owner: str,
    repo: str,
    request: Request,
    branch: Optional[str] = Query(None, description="Branch name (default: default branch)"),
    path: Optional[str] = Query("", description="Path to fetch files from"),
    recursive: bool = Query(True, description="Fetch files recursively")
):
    """
    Get all files from a specific repository
    Returns a tree structure of files with metadata
    """
    github_token = await get_github_token(request)
    
    if not github_token:
        raise HTTPException(
            status_code=401,
            detail="GitHub account not connected"
        )
    
    try:
        cache_key = get_cache_key("repo_files", owner, repo, branch or "default", path, recursive)
        cached = get_cached_data(cache_key)
        if cached:
            return cached
        
        # First, get repository info to get default branch
        repo_info = await make_github_request(f"/repos/{owner}/{repo}", github_token)
        default_branch = branch or repo_info.get("default_branch", "main")
        
        # Get the tree recursively
        tree_endpoint = f"/repos/{owner}/{repo}/git/trees/{default_branch}"
        params = {}
        if recursive:
            params["recursive"] = "1"
        
        tree_response = await make_github_request(tree_endpoint, github_token, params)
        
        # Process the tree
        files = []
        directories = []
        
        for item in tree_response.get("tree", []):
            item_path = item.get("path", "")
            
            if path and not item_path.startswith(path):
                continue
            
            item_data = {
                "path": item_path,
                "name": item_path.split("/")[-1],
                "type": item.get("type"),
                "sha": item.get("sha"),
                "size": item.get("size", 0),
                "url": item.get("url"),
                "mode": item.get("mode")
            }
            
            if item.get("type") == "blob":
                files.append(item_data)
            elif item.get("type") == "tree":
                directories.append(item_data)
        
        result = {
            "repository": repo,
            "owner": owner,
            "branch": default_branch,
            "path": path,
            "total_files": len(files),
            "total_directories": len(directories),
            "files": files,
            "directories": directories,
            "truncated": tree_response.get("truncated", False)
        }
        
        set_cached_data(cache_key, result, timedelta(minutes=10))
        
        return result
        
    except GitHubAPIError as e:
        logger.error(f"GitHub API error fetching files: {e.message}")
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        logger.error(f"Error fetching repository files: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch repository files")


@router.post("/repos/{owner}/{repo}/scan")
async def scan_repository(
    owner: str,
    repo: str,
    request: Request
):
    """
    Trigger a security scan on a repository
    """
    github_token = await get_github_token(request)
    
    if not github_token:
        raise HTTPException(status_code=401, detail="GitHub account not connected")
    
    try:
        # Verify repository exists and user has access
        repo_info = await make_github_request(f"/repos/{owner}/{repo}", github_token)
        
        # TODO: Implement actual scanning logic
        return {
            "status": "scan_initiated",
            "repository": f"{owner}/{repo}",
            "message": "Security scan has been initiated",
            "scan_id": f"scan_{datetime.utcnow().timestamp()}"
        }
        
    except GitHubAPIError as e:
        logger.error(f"GitHub API error initiating scan: {e.message}")
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        logger.error(f"Error initiating scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate scan")