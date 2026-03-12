"""
AI Vulnerability Fix Backend
Uses Mistral Codestral — free tier, purpose-built for code analysis.
Smart: reads only the vulnerable file + its imported dependencies from GitHub.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict
import os
import re
import requests
import base64
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()
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
    global _rotation_manager
    if _rotation_manager is None:
        try:
            from .API_key_rotation import APIKeyRotationManager
            api_keys_str = os.getenv("MISTRAL_API_KEYS") or os.getenv("MISTRAL_API_KEY", "")
            if not api_keys_str:
                logger.warning("No Mistral API keys configured")
                return None
            api_keys = [k.strip() for k in api_keys_str.split(",") if k.strip()]
            if not api_keys:
                return None
            _rotation_manager = APIKeyRotationManager(
                api_keys=api_keys,
                requests_per_day=int(os.getenv("MISTRAL_REQUESTS_PER_DAY", "2000")),
                cooldown_minutes=int(os.getenv("MISTRAL_COOLDOWN_MINUTES", "1")),
            )
            logger.info(f"✅ Mistral Rotation Manager ready ({len(api_keys)} key(s))")
        except ImportError:
            logger.warning("Rotation manager not available — single key mode")
        except Exception as e:
            logger.error(f"Rotation manager init failed: {e}")
    return _rotation_manager

def get_settings() -> dict:
    return {
        "github_token":   os.getenv("GITHUB_TOKEN"),
        "model":          os.getenv("MISTRAL_MODEL", "devstral-2512"),
        "single_api_key": os.getenv("MISTRAL_API_KEY"),
    }

# ============================================================================
# GITHUB HELPERS
# ============================================================================

def normalize_path(file_path: str) -> str:
    if not file_path:
        return ""
    p = file_path.lstrip("./").lstrip(".\\").replace("\\", "/")
    while "//" in p:
        p = p.replace("//", "/")
    return p.strip("/")

def fetch_file_content(repo_owner: str, repo_name: str, file_path: str, token: str) -> Optional[str]:
    path = normalize_path(file_path)
    if not path:
        return None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{path}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return None
        if resp.status_code == 403:
            raise HTTPException(status_code=403, detail="GitHub API access denied — check GITHUB_TOKEN scopes")
        resp.raise_for_status()
        data = resp.json()
        if "content" not in data:
            return None
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"GitHub API error: {e}")

# ============================================================================
# SMART DEPENDENCY RESOLVER
# ============================================================================

_IMPORT_PATTERNS: Dict[str, List[re.Pattern]] = {
    "py": [
        re.compile(r"^\s*from\s+(\.[\w.]*)\s+import", re.MULTILINE),
        re.compile(r"^\s*from\s+([\w.]+)\s+import", re.MULTILINE),
        re.compile(r"^\s*import\s+([\w.]+)", re.MULTILINE),
    ],
    "ts":  [re.compile(r"""(?:import|from)\s+['"]([./][^'"]+)['"]"""),
            re.compile(r"""require\s*\(\s*['"]([./][^'"]+)['"]\s*\)""")],
    "tsx": [re.compile(r"""(?:import|from)\s+['"]([./][^'"]+)['"]""")],
    "js":  [re.compile(r"""(?:import|from)\s+['"]([./][^'"]+)['"]"""),
            re.compile(r"""require\s*\(\s*['"]([./][^'"]+)['"]\s*\)""")],
    "jsx": [re.compile(r"""(?:import|from)\s+['"]([./][^'"]+)['"]""")],
}

_CANDIDATE_EXTS = ["", ".py", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js"]

def _ext(path: str) -> str:
    base = path.split("/")[-1]
    return base.rsplit(".", 1)[-1] if "." in base else ""

def _candidates(base_file: str, ref: str) -> List[str]:
    base_dir = "/".join(base_file.split("/")[:-1])

    # Python relative: ".utils", "..models"
    if re.match(r"^\.+[^./]", ref) or ref == ".":
        dots = len(ref) - len(ref.lstrip("."))
        module = ref.lstrip(".")
        parts = base_dir.split("/") if base_dir else []
        go_up = dots - 1
        if go_up > 0:
            parts = parts[:-go_up] if len(parts) >= go_up else []
        base = "/".join(parts)
        mpath = module.replace(".", "/")
        return [f"{base}/{mpath}{e}".lstrip("/") for e in _CANDIDATE_EXTS]

    # JS/TS relative: "./foo", "../bar/baz"
    if ref.startswith("./") or ref.startswith("../"):
        joined = (base_dir + "/" + ref) if base_dir else ref
        parts = joined.split("/")
        resolved: List[str] = []
        for part in parts:
            if part == "..":
                if resolved:
                    resolved.pop()
            elif part not in (".", ""):
                resolved.append(part)
        path = "/".join(resolved)
        return [f"{path}{e}" for e in _CANDIDATE_EXTS]

    return []

def resolve_dependencies(
    repo_owner: str, repo_name: str,
    main_file: str, main_content: str,
    token: str, max_files: int = 5,
) -> Dict[str, str]:
    patterns = _IMPORT_PATTERNS.get(_ext(main_file), [])
    if not patterns:
        return {}

    refs: List[str] = []
    for p in patterns:
        refs.extend(p.findall(main_content))

    logger.info(f"🔗 Found {len(refs)} import reference(s) in {main_file}")
    fetched: Dict[str, str] = {}

    for ref in refs:
        if len(fetched) >= max_files:
            break
        is_local = ref.startswith(".") or ref.startswith("./") or ref.startswith("../")
        if not is_local:
            continue
        for candidate in _candidates(main_file, ref):
            if not candidate or candidate in fetched:
                continue
            content = fetch_file_content(repo_owner, repo_name, candidate, token)
            if content is not None:
                logger.info(f"  ✅ Resolved: {candidate}")
                fetched[candidate] = content
                break

    logger.info(f"📦 Resolved {len(fetched)} dependency file(s)")
    return fetched

# ============================================================================
# CODE EXTRACTION
# ============================================================================

def extract_vulnerable_section(full_code: str, start_line: int, end_line: int, context: int = 15) -> str:
    lines = full_code.split("\n")
    cs = max(0, start_line - context - 1)
    ce = min(len(lines), end_line + context)
    out = []
    for i in range(cs, ce):
        ln = i + 1
        marker = "→" if start_line <= ln <= end_line else " "
        out.append(f"{marker} {ln:4d} | {lines[i]}")
    return "\n".join(out)

# ============================================================================
# JSON EXTRACTION — robust multi-strategy parser
# ============================================================================

def extract_json(raw: str) -> dict:
    """
    Try multiple strategies to extract valid JSON from AI response.
    Handles: <json> tags, markdown fences, bare JSON, truncated JSON.
    """
    text = raw.strip()

    # Strategy 1: <json>...</json> tags
    m = re.search(r"<json>\s*(.*?)\s*</json>", text, re.DOTALL)
    if m:
        text = m.group(1).strip()

    # Strategy 2: ```json ... ``` or ``` ... ```
    elif "```" in text:
        text = re.sub(r"```(?:json)?\s*", "", text).replace("```", "").strip()

    # Strategy 3: grab first {...} block if text doesn't start with {
    elif not text.startswith("{"):
        m2 = re.search(r"\{.*\}", text, re.DOTALL)
        if m2:
            text = m2.group(0)

    # First parse attempt
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 4: repair truncated JSON
    logger.warning("JSON parse failed — attempting repair")
    repaired = text.rstrip().rstrip(",")

    # Close unclosed string (odd number of unescaped quotes)
    unescaped_quotes = len(re.findall(r'(?<!\\)"', repaired))
    if unescaped_quotes % 2 != 0:
        repaired += '"'

    # Close unclosed arrays
    open_brackets = repaired.count("[") - repaired.count("]")
    if open_brackets > 0:
        repaired += "]" * open_brackets

    # Close unclosed objects
    open_braces = repaired.count("{") - repaired.count("}")
    if open_braces > 0:
        repaired += "}" * open_braces

    try:
        result = json.loads(repaired)
        logger.info("✅ JSON repaired successfully")
        return result
    except json.JSONDecodeError as e:
        logger.error(f"JSON repair failed: {e}\nRaw text (first 600): {text[:600]}")
        raise HTTPException(
            status_code=500,
            detail="Mistral returned malformed JSON — please try again"
        )

# ============================================================================
# MISTRAL CODESTRAL API CALL
# ============================================================================

MISTRAL_API_BASE = "https://api.mistral.ai/v1/chat/completions"

class RateLimitError(Exception):
    pass

def call_gemini_with_key(
    full_code: str,
    vulnerable_section: str,
    vulnerability: Vulnerability,
    dependency_context: Dict[str, str],
    api_key: str,
    model: str,
) -> tuple[dict, str]:

    dep_block = ""
    if dependency_context:
        dep_block = "\n\n**RELATED FILES (resolved from imports):**\n"
        for dep_path, dep_content in dependency_context.items():
            preview = dep_content[:5000] + ("…(truncated)" if len(dep_content) > 5000 else "")
            dep_block += f"\n--- {dep_path} ---\n```\n{preview}\n```\n"

    prompt = (
        "You are a senior security engineer. Analyse and fix this vulnerability.\n\n"
        "**VULNERABILITY**\n"
        f"- Type: {vulnerability.vulnerability_type}\n"
        f"- Severity: {vulnerability.severity}\n"
        f"- Scanner: {vulnerability.scanner} · Rule: {vulnerability.rule_id}\n"
        f"- Message: {vulnerability.message}\n"
        f"- Location: {vulnerability.location.file} "
        f"(Lines {vulnerability.location.start_line}–{vulnerability.location.end_line})\n"
    )
    if vulnerability.cwe:
        prompt += f"- CWE: {', '.join(vulnerability.cwe)}\n"

    prompt += (
        f"\n**COMPLETE VULNERABLE FILE** ({vulnerability.location.file}):\n"
        f"```\n{full_code}\n```\n\n"
        f"**VULNERABLE SECTION WITH CONTEXT:**\n"
        f"```\n{vulnerable_section}\n```\n"
        f"{dep_block}\n\n"
        "Respond with ONLY the JSON object below, wrapped in <json> and </json> tags.\n"
        "Keep all text fields under 400 characters. "
        "For original_code and fixed_code, include ONLY the relevant lines, not the entire file.\n\n"
        "<json>\n"
        "{\n"
        '  "vulnerability_analysis": "Root cause explanation",\n'
        '  "code_analysis": "How this relates to imported dependencies",\n'
        '  "original_code": "The vulnerable lines only",\n'
        '  "fixed_code": "The corrected replacement lines",\n'
        '  "changes_made": ["Change 1", "Change 2"],\n'
        '  "fix_explanation": "Why the fix is secure",\n'
        '  "security_improvement": "Attack vectors this closes"\n'
        "}\n"
        "</json>"
    )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 8192,
    }

    try:
        logger.info(f"🤖 Calling Mistral Devstral ({model}) with {len(dependency_context)} dep file(s)…")
        resp = requests.post(MISTRAL_API_BASE, headers=headers, json=payload, timeout=120)

        if resp.status_code == 429:
            logger.warning(f"⚠️ Key ...{api_key[-8:]} rate limited")
            raise RateLimitError("Rate limited")

        if resp.status_code == 401:
            raise HTTPException(status_code=401, detail="Invalid Mistral API key")

        if resp.status_code == 400:
            err = resp.json().get("message", "Bad request")
            raise HTTPException(status_code=400, detail=f"Mistral request error: {err}")

        if resp.status_code != 200:
            err = resp.json().get("message", "Unknown") if resp.content else "Unknown"
            raise HTTPException(status_code=500, detail=f"Mistral API error ({resp.status_code}): {err}")

        data = resp.json()

        try:
            raw = data["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError):
            logger.error(f"Unexpected Mistral response shape: {data}")
            raise HTTPException(status_code=500, detail="Unexpected Mistral response structure")

        parsed = extract_json(raw)

        # Fill any missing fields with safe defaults
        defaults = {
            "original_code": vulnerable_section,
            "changes_made": ["Security fix applied"],
            "security_improvement": "Vulnerability resolved",
            "code_analysis": "See fix explanation.",
        }
        for k, v in defaults.items():
            parsed.setdefault(k, v)

        logger.info("✅ Mistral fix generated")
        return parsed, f"...{api_key[-8:]}"

    except (RateLimitError, HTTPException):
        raise
    except Exception as e:
        logger.error(f"❌ Mistral call error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def call_gemini_with_rotation(
    full_code: str,
    vulnerable_section: str,
    vulnerability: Vulnerability,
    dependency_context: Dict[str, str],
    model: str,
    rotation_mgr,
    max_retries: int = 5,
) -> tuple[dict, str]:
    for attempt in range(max_retries):
        api_key = rotation_mgr.get_available_key()
        if not api_key:
            rotation_mgr._log_status()
            raise HTTPException(status_code=429, detail="All Mistral keys exhausted or rate limited")
        try:
            result, key_id = call_gemini_with_key(
                full_code, vulnerable_section, vulnerability,
                dependency_context, api_key, model,
            )
            rotation_mgr.mark_key_used(api_key, success=True)
            return result, key_id
        except RateLimitError:
            logger.warning(f"⚠️ Rotating from key ...{api_key[-8:]} (attempt {attempt + 1}/{max_retries})")
            rotation_mgr.mark_key_failed(api_key, rate_limited=True)
        except HTTPException:
            rotation_mgr.mark_key_failed(api_key, rate_limited=False)
            raise
    raise HTTPException(status_code=429, detail=f"All {max_retries} Mistral keys rate limited")

# ============================================================================
# API ENDPOINTS
# ============================================================================

@router.post("/fix-vulnerability", response_model=AIFixResponse)
async def fix_vulnerability_with_ai(request: AIFixRequest):
    logger.info(f"🔒 AI FIX: {request.repo_owner}/{request.repo_name} — {request.file_path}")

    settings = get_settings()
    if not settings["github_token"]:
        raise HTTPException(status_code=500, detail="GITHUB_TOKEN not configured in .env")

    try:
        # Step 1: fetch vulnerable file
        logger.info("Step 1/3: Fetching vulnerable file from GitHub…")
        full_code = fetch_file_content(
            request.repo_owner, request.repo_name,
            request.file_path, settings["github_token"],
        )
        if full_code is None:
            raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")

        # Step 2: resolve imports → fetch connected files
        logger.info("Step 2/3: Resolving imported dependencies…")
        dependency_context = resolve_dependencies(
            repo_owner=request.repo_owner,
            repo_name=request.repo_name,
            main_file=normalize_path(request.file_path),
            main_content=full_code,
            token=settings["github_token"],
            max_files=5,
        )

        vulnerable_section = extract_vulnerable_section(
            full_code,
            request.vulnerability.location.start_line,
            request.vulnerability.location.end_line,
        )

        # Step 3: call Mistral
        logger.info("Step 3/3: Generating fix with AI")
        rotation_mgr = get_rotation_manager()

        if rotation_mgr and rotation_mgr.has_available_keys():
            ai_result, key_id = call_gemini_with_rotation(
                full_code, vulnerable_section, request.vulnerability,
                dependency_context, settings["model"], rotation_mgr,
            )
        elif settings["single_api_key"]:
            logger.info("ℹ️ Using single Mistral API key")
            ai_result, key_id = call_gemini_with_key(
                full_code, vulnerable_section, request.vulnerability,
                dependency_context, settings["single_api_key"], settings["model"],
            )
        else:
            raise HTTPException(
                status_code=500,
                detail="No Mistral API keys configured. Set MISTRAL_API_KEYS or MISTRAL_API_KEY in .env"
            )

        logger.info("✅ AI FIX COMPLETE")
        return AIFixResponse(
            success=True,
            vulnerability_analysis=ai_result.get("vulnerability_analysis", ""),
            code_analysis=ai_result.get("code_analysis", ""),
            fix_explanation=ai_result.get("fix_explanation", ""),
            original_code=ai_result.get("original_code", ""),
            fixed_code=ai_result.get("fixed_code", ""),
            changes_made=ai_result.get("changes_made", []),
            security_improvement=ai_result.get("security_improvement", ""),
            api_key_used=key_id,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    settings = get_settings()
    rotation_mgr = get_rotation_manager()
    key_status = rotation_mgr.get_status() if rotation_mgr else {}
    return {
        "status": "healthy",
        "provider": "Mistral Devstral",
        "github_configured": bool(settings["github_token"]),
        "model": settings["model"],
        "rotation_enabled": rotation_mgr is not None,
        "api_keys": {
            "total": len(key_status),
            "available": sum(1 for s in key_status.values() if s["available"]),
            "details": key_status,
        } if rotation_mgr else {"single_key": bool(settings["single_api_key"])},
        "version": "3.2.0",
    }


@router.get("/api-status")
async def api_key_status():
    rotation_mgr = get_rotation_manager()
    if not rotation_mgr:
        settings = get_settings()
        return {
            "configured": bool(settings["single_api_key"]),
            "mode": "single_key",
            "rotation_enabled": False,
            "provider": "mistral",
        }
    status = rotation_mgr.get_status()
    return {
        "configured": True,
        "mode": "rotation",
        "provider": "mistral",
        "rotation_enabled": True,
        "total_keys": len(rotation_mgr.api_keys),
        "available_keys": sum(1 for s in status.values() if s["available"]),
        "has_available": rotation_mgr.has_available_keys(),
        "next_available": rotation_mgr.get_next_available_time(),
        "keys": status,
    }