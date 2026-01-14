"""
AI Vulnerability Fix Backend - FIXED VERSION
Clean imports, no startup HTTP calls
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import os
import requests
import base64
import logging
import json

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

# Global rotation manager (initialized lazily)
_rotation_manager = None

# ============================================================================
# MODELS
# ============================================================================

class VulnerabilityLocation(BaseModel):
    file: str
    start_line: int
    end_line: int

class Vulnerability(BaseModel):
    scanner: str
    rule_id: str
    severity: str
    message: str
    vulnerability_type: str
    location: VulnerabilityLocation
    code_snippet: Optional[str] = None
    cwe: Optional[List[str]] = None
    owasp: Optional[List[str]] = None

class AIFixRequest(BaseModel):
    vulnerability: Vulnerability
    repo_owner: str
    repo_name: str
    file_path: str

class AIFixResponse(BaseModel):
    success: bool
    vulnerability_analysis: str
    code_analysis: str
    fix_explanation: str
    original_code: str
    fixed_code: str
    changes_made: List[str]
    security_improvement: str
    api_key_used: Optional[str] = None

# ============================================================================
# CONFIGURATION
# ============================================================================

def get_rotation_manager():
    """Get or create rotation manager (lazy initialization)"""
    global _rotation_manager
    
    if _rotation_manager is None:
        # Try to import rotation manager
        try:
            from .API_key_rotation import APIKeyRotationManager
            
            # Load API keys
            api_keys_str = os.getenv("OPENROUTER_API_KEYS") or os.getenv("OPENROUTER_API_KEY", "")
            
            if not api_keys_str:
                logger.warning("⚠️ No OpenRouter API keys configured")
                return None
            
            api_keys = [key.strip() for key in api_keys_str.split(",") if key.strip()]
            
            if not api_keys:
                logger.warning("⚠️ No valid API keys found")
                return None
            
            # Get configuration
            requests_per_day = int(os.getenv("OPENROUTER_REQUESTS_PER_DAY", "10"))
            cooldown_minutes = int(os.getenv("OPENROUTER_COOLDOWN_MINUTES", "60"))
            
            _rotation_manager = APIKeyRotationManager(
                api_keys=api_keys,
                requests_per_day=requests_per_day,
                cooldown_minutes=cooldown_minutes
            )
            
            logger.info(f"✅ API Key Rotation Manager initialized with {len(api_keys)} key(s)")
            
        except ImportError:
            logger.warning("⚠️ API Key Rotation Manager not available - using single key mode")
            return None
        except Exception as e:
            logger.error(f"❌ Failed to initialize rotation manager: {e}")
            return None
    
    return _rotation_manager

def get_settings():
    """Get environment settings"""
    return {
        "github_token": os.getenv("GITHUB_TOKEN"),
        "model": os.getenv("OPENROUTER_MODEL", "nex-agi/deepseek-v3.1-nex-n1:free"),
        "single_api_key": os.getenv("OPENROUTER_API_KEY"),  # Fallback to single key
    }

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def normalize_path_for_github(file_path: str) -> str:
    """Convert Windows paths to GitHub-compatible Unix paths"""
    if not file_path:
        return ""
    
    file_path = file_path.lstrip('./')
    file_path = file_path.lstrip('.\\')
    normalized = file_path.replace('\\', '/')
    
    while '//' in normalized:
        normalized = normalized.replace('//', '/')
    
    normalized = normalized.strip('/')
    
    logger.debug(f"Path normalized: '{file_path}' → '{normalized}'")
    return normalized

def fetch_full_file_content(
    repo_owner: str, 
    repo_name: str, 
    file_path: str, 
    github_token: str
) -> str:
    """Fetch complete file content from GitHub"""
    normalized_path = normalize_path_for_github(file_path)
    
    if not normalized_path:
        raise HTTPException(status_code=400, detail="Invalid file path")
    
    try:
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{normalized_path}"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        logger.info(f"📥 Fetching: {repo_owner}/{repo_name}/{normalized_path}")
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail=f"File not found: {normalized_path}")
        elif response.status_code == 403:
            raise HTTPException(status_code=403, detail="GitHub API access denied")
        
        response.raise_for_status()
        content_data = response.json()
        
        if "content" in content_data:
            content = base64.b64decode(content_data["content"]).decode("utf-8")
            logger.info(f"✅ File fetched ({len(content)} chars)")
            return content
        else:
            raise HTTPException(status_code=500, detail="Unexpected GitHub response")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ GitHub error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch file: {str(e)}")

def extract_vulnerable_section(
    full_code: str, 
    start_line: int, 
    end_line: int, 
    context_lines: int = 15
) -> str:
    """Extract vulnerable section with context"""
    try:
        lines = full_code.split("\n")
        total_lines = len(lines)
        
        context_start = max(0, start_line - context_lines - 1)
        context_end = min(total_lines, end_line + context_lines)
        
        vulnerable_section_lines = []
        for i in range(context_start, context_end):
            line_num = i + 1
            line_content = lines[i]
            
            if start_line <= line_num <= end_line:
                vulnerable_section_lines.append(f"→ {line_num:4d} | {line_content}")
            else:
                vulnerable_section_lines.append(f"  {line_num:4d} | {line_content}")
        
        return "\n".join(vulnerable_section_lines)
        
    except Exception as e:
        logger.error(f"❌ Extraction error: {e}")
        return f"Lines {start_line}-{end_line}"

class RateLimitError(Exception):
    """Custom exception for rate limiting"""
    pass

def call_ai_with_key(
    full_code: str,
    vulnerable_section: str,
    vulnerability: Vulnerability,
    api_key: str,
    model: str
) -> tuple[dict, str]:
    """Call OpenRouter API with a specific key"""
    
    prompt = f"""You are a senior security engineer. Analyze and fix this security vulnerability.

**VULNERABILITY DETAILS**:
- Type: {vulnerability.vulnerability_type}
- Severity: {vulnerability.severity}
- Message: {vulnerability.message}
- Location: {vulnerability.location.file} (Lines {vulnerability.location.start_line}-{vulnerability.location.end_line})

**COMPLETE FILE**:
```
{full_code[:8000]}{'... (truncated)' if len(full_code) > 8000 else ''}
```

**VULNERABLE SECTION**:
```
{vulnerable_section}
```

Provide a security fix as valid JSON:

{{
  "vulnerability_analysis": "What is vulnerable and why",
  "code_analysis": "How this relates to the codebase",
  "original_code": "The vulnerable code",
  "fixed_code": "The secure fixed code",
  "changes_made": ["Change 1", "Change 2"],
  "fix_explanation": "How the fix works",
  "security_improvement": "Security improvements"
}}

Return ONLY valid JSON, no markdown."""

    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://revamp-security.app",
            "X-Title": "ReVAMP-Security"
        }
        
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 3500
        }
        
        logger.info(f"🤖 Calling AI with {model}...")
        
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=120
        )
        
        if response.status_code == 429:
            logger.warning(f"⚠️ Key ...{api_key[-8:]} is rate limited")
            raise RateLimitError("Rate limited")
        
        if response.status_code != 200:
            error_data = response.json() if response.content else {}
            error_msg = error_data.get("error", {}).get("message", "Unknown error")
            raise HTTPException(status_code=500, detail=f"AI error: {error_msg}")
        
        result = response.json()
        
        if "choices" not in result or len(result["choices"]) == 0:
            raise HTTPException(status_code=500, detail="Invalid AI response")
        
        ai_response = result["choices"][0]["message"]["content"].strip()
        ai_response = ai_response.replace("```json", "").replace("```", "").strip()
        
        parsed = json.loads(ai_response)
        
        # Ensure all fields exist
        if "original_code" not in parsed:
            parsed["original_code"] = vulnerable_section
        if "changes_made" not in parsed:
            parsed["changes_made"] = ["Security fix applied"]
        if "security_improvement" not in parsed:
            parsed["security_improvement"] = "Vulnerability addressed"
        if "code_analysis" not in parsed:
            parsed["code_analysis"] = "Code analyzed"
        
        logger.info("✅ AI fix generated")
        
        key_id = f"...{api_key[-8:]}"
        return parsed, key_id
        
    except RateLimitError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ AI error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def call_ai_with_rotation(
    full_code: str,
    vulnerable_section: str,
    vulnerability: Vulnerability,
    model: str,
    rotation_mgr,
    max_retries: int = 5
) -> tuple[dict, str]:
    """Call AI with automatic key rotation on rate limits"""
    
    attempts = 0
    last_error = None
    
    while attempts < max_retries:
        # Get next available key
        api_key = rotation_mgr.get_available_key() if rotation_mgr else None
        
        if not api_key:
            logger.error("❌ No available API keys")
            if rotation_mgr:
                rotation_mgr._log_status()
            raise HTTPException(
                status_code=429,
                detail="All API keys are exhausted or rate limited"
            )
        
        try:
            # Try to call AI with this key
            result, key_id = call_ai_with_key(
                full_code=full_code,
                vulnerable_section=vulnerable_section,
                vulnerability=vulnerability,
                api_key=api_key,
                model=model
            )
            
            # Success! Mark key as used
            if rotation_mgr:
                rotation_mgr.mark_key_used(api_key, success=True)
            
            return result, key_id
            
        except RateLimitError:
            # This key is rate limited, mark it and try next one
            logger.warning(f"⚠️ Key ...{api_key[-8:]} rate limited, trying next key...")
            if rotation_mgr:
                rotation_mgr.mark_key_failed(api_key, rate_limited=True)
            
            attempts += 1
            last_error = "Rate limited"
            continue
            
        except HTTPException as e:
            # Non-rate-limit error, mark as failed but don't retry
            if rotation_mgr:
                rotation_mgr.mark_key_failed(api_key, rate_limited=False)
            raise
        except Exception as e:
            # Unexpected error
            if rotation_mgr:
                rotation_mgr.mark_key_failed(api_key, rate_limited=False)
            raise
    
    # If we get here, all retries failed
    logger.error(f"❌ All {max_retries} retry attempts failed")
    raise HTTPException(
        status_code=429,
        detail=f"Failed after {max_retries} attempts. Last error: {last_error}"
    )

# ============================================================================
# API ENDPOINTS
# ============================================================================

@router.post("/fix-vulnerability", response_model=AIFixResponse)
async def fix_vulnerability_with_ai(request: AIFixRequest):
    """Generate AI-powered security fix"""
    
    logger.info("🔒 AI FIX REQUEST STARTED")
    logger.info(f"Repository: {request.repo_owner}/{request.repo_name}")
    logger.info(f"File: {request.file_path}")
    
    settings = get_settings()
    
    if not settings["github_token"]:
        raise HTTPException(status_code=500, detail="GITHUB_TOKEN not configured")
    
    try:
        # Fetch file
        logger.info("Step 1/3: Fetching file from GitHub...")
        full_code = fetch_full_file_content(
            repo_owner=request.repo_owner,
            repo_name=request.repo_name,
            file_path=request.file_path,
            github_token=settings["github_token"]
        )
        
        # Extract vulnerable section
        logger.info("Step 2/3: Extracting vulnerable code...")
        vulnerable_section = extract_vulnerable_section(
            full_code=full_code,
            start_line=request.vulnerability.location.start_line,
            end_line=request.vulnerability.location.end_line
        )
        
        # Generate fix with rotation
        logger.info("Step 3/3: Generating AI fix...")
        
        # Try rotation manager first
        rotation_mgr = get_rotation_manager()
        
        if rotation_mgr and rotation_mgr.has_available_keys():
            logger.info("✅ Using rotation manager with automatic retry")
            ai_result, key_id = call_ai_with_rotation(
                full_code=full_code,
                vulnerable_section=vulnerable_section,
                vulnerability=request.vulnerability,
                model=settings["model"],
                rotation_mgr=rotation_mgr,
                max_retries=5
            )
        elif settings["single_api_key"]:
            logger.info("⚠️ Using single API key (no rotation)")
            ai_result, key_id = call_ai_with_key(
                full_code=full_code,
                vulnerable_section=vulnerable_section,
                vulnerability=request.vulnerability,
                api_key=settings["single_api_key"],
                model=settings["model"]
            )
        else:
            raise HTTPException(
                status_code=500,
                detail="No OpenRouter API keys configured"
            )
        
        logger.info("✅ AI FIX COMPLETED")
        
        return AIFixResponse(
            success=True,
            vulnerability_analysis=ai_result.get("vulnerability_analysis", ""),
            code_analysis=ai_result.get("code_analysis", ""),
            fix_explanation=ai_result.get("fix_explanation", ""),
            original_code=ai_result.get("original_code", ""),
            fixed_code=ai_result.get("fixed_code", ""),
            changes_made=ai_result.get("changes_made", []),
            security_improvement=ai_result.get("security_improvement", ""),
            api_key_used=key_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    """Health check with API key status"""
    settings = get_settings()
    rotation_mgr = get_rotation_manager()
    
    key_status = {}
    if rotation_mgr:
        key_status = rotation_mgr.get_status()
    
    return {
        "status": "healthy",
        "github_configured": bool(settings["github_token"]),
        "model": settings["model"],
        "rotation_enabled": rotation_mgr is not None,
        "api_keys": {
            "total": len(key_status),
            "available": sum(1 for s in key_status.values() if s["available"]),
            "details": key_status
        } if rotation_mgr else {"single_key": bool(settings["single_api_key"])},
        "version": "3.0.0"
    }

@router.get("/api-status")
async def api_key_status():
    """Detailed API key status"""
    rotation_mgr = get_rotation_manager()
    
    if not rotation_mgr:
        settings = get_settings()
        return {
            "configured": bool(settings["single_api_key"]),
            "mode": "single_key",
            "rotation_enabled": False
        }
    
    status = rotation_mgr.get_status()
    
    return {
        "configured": True,
        "mode": "rotation",
        "rotation_enabled": True,
        "total_keys": len(rotation_mgr.api_keys),
        "available_keys": sum(1 for s in status.values() if s["available"]),
        "has_available": rotation_mgr.has_available_keys(),
        "next_available": rotation_mgr.get_next_available_time(),
        "keys": status
    }