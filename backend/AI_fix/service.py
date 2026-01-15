"""
AI Fix Service
Business logic layer - orchestrates the fix generation process
"""

from fastapi import HTTPException
from .models import AIFixRequest, AIFixResponse
from .config import get_config
from .githubclient import GitHubClient
from .openrouterclient import OpenRouterClient
from .utils import normalize_path_for_github, extract_code_section
import logging

logger = logging.getLogger(__name__)


class AIFixService:
    """Service for generating AI-powered security fixes"""
    
    def __init__(self):
        """Initialize service with configuration"""
        self.config = get_config()
        
        # Validate configuration
        if not self.config.openrouter_api_key:
            raise HTTPException(
                status_code=500,
                detail="OPENROUTER_API_KEY not configured. Set it in your .env file."
            )
        
        if not self.config.github_token:
            raise HTTPException(
                status_code=500,
                detail="GITHUB_TOKEN not configured. Set it in your .env file."
            )
        
        # Initialize clients
        self.github = GitHubClient(self.config.github_token)
        self.ai = OpenRouterClient(
            self.config.openrouter_api_key, 
            self.config.model
        )
    
    async def generate_fix(self, request: AIFixRequest) -> AIFixResponse:
        """
        Generate AI-powered fix for a vulnerability
        
        Args:
            request: Fix request with vulnerability details
        
        Returns:
            AIFixResponse with generated fix
        
        Raises:
            HTTPException: If fix generation fails
        """
        
        # Step 1: Normalize file path (Windows → Unix)
        normalized_path = normalize_path_for_github(request.file_path)
        
        if not normalized_path:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file path: {request.file_path}"
            )
        
        logger.info(f"📁 Normalized path: {request.file_path} → {normalized_path}")
        
        # Step 2: Fetch file from GitHub
        logger.info("Step 1/3: Fetching file from GitHub...")
        try:
            full_code = self.github.fetch_file_content(
                repo_owner=request.repo_owner,
                repo_name=request.repo_name,
                file_path=normalized_path
            )
        except HTTPException as e:
            logger.error(f"Failed to fetch file: {e.detail}")
            raise
        
        # Step 3: Extract vulnerable section with context
        logger.info("Step 2/3: Extracting vulnerable code section...")
        vulnerable_section = extract_code_section(
            full_code=full_code,
            start_line=request.vulnerability.location.start_line,
            end_line=request.vulnerability.location.end_line,
            context_lines=15
        )
        
        # Step 4: Generate AI fix
        logger.info("Step 3/3: Generating AI-powered fix...")
        try:
            ai_result = self.ai.generate_fix(
                full_code=full_code,
                vulnerable_section=vulnerable_section,
                vulnerability=request.vulnerability
            )
        except HTTPException as e:
            logger.error(f"AI fix generation failed: {e.detail}")
            raise
        
        # Step 5: Build response
        return AIFixResponse(
            success=True,
            vulnerability_analysis=ai_result["vulnerability_analysis"],
            code_analysis=ai_result["code_analysis"],
            fix_explanation=ai_result["fix_explanation"],
            original_code=ai_result["original_code"],
            fixed_code=ai_result["fixed_code"],
            changes_made=ai_result["changes_made"],
            security_improvement=ai_result["security_improvement"]
        )