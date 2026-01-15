"""
API Key Rotation Manager with Rate Limiting
Handles multiple API keys to avoid hitting rate limits
"""

import time
import logging
from typing import List, Optional, Dict
from datetime import datetime, timedelta
from collections import defaultdict
import random

logger = logging.getLogger(__name__)


class APIKeyRotationManager:
    """
    Manages multiple API keys with intelligent rotation and rate limiting
    """
    
    def __init__(
        self, 
        api_keys: List[str],
        requests_per_day: int = 10,
        cooldown_minutes: int = 60
    ):
        """
        Initialize the rotation manager
        
        Args:
            api_keys: List of API keys to rotate through
            requests_per_day: Maximum requests per key per day
            cooldown_minutes: Cooldown period after hitting limit
        """
        if not api_keys:
            raise ValueError("At least one API key must be provided")
        
        self.api_keys = [key.strip() for key in api_keys if key.strip()]
        self.requests_per_day = requests_per_day
        self.cooldown_minutes = cooldown_minutes
        
        # Track usage per key
        self.usage_count: Dict[str, int] = defaultdict(int)
        self.last_reset: Dict[str, datetime] = {}
        self.cooldown_until: Dict[str, datetime] = {}
        
        # Initialize tracking
        for key in self.api_keys:
            self.last_reset[key] = datetime.now()
        
        logger.info(f"✅ API Key Rotation Manager initialized with {len(self.api_keys)} key(s)")
        logger.info(f"📊 Rate limit: {requests_per_day} requests/day per key")
    
    def _reset_daily_counter(self, api_key: str):
        """Reset counter if 24 hours have passed"""
        now = datetime.now()
        if api_key in self.last_reset:
            time_since_reset = now - self.last_reset[api_key]
            if time_since_reset >= timedelta(days=1):
                logger.info(f"🔄 Daily counter reset for key ending in ...{api_key[-8:]}")
                self.usage_count[api_key] = 0
                self.last_reset[api_key] = now
                # Clear cooldown if it was set
                if api_key in self.cooldown_until:
                    del self.cooldown_until[api_key]
    
    def _is_key_available(self, api_key: str) -> bool:
        """Check if a key is available for use"""
        # Reset counter if needed
        self._reset_daily_counter(api_key)
        
        # Check if in cooldown
        if api_key in self.cooldown_until:
            if datetime.now() < self.cooldown_until[api_key]:
                return False
            else:
                # Cooldown expired
                del self.cooldown_until[api_key]
        
        # Check usage limit
        return self.usage_count[api_key] < self.requests_per_day
    
    def get_available_key(self) -> Optional[str]:
        """
        Get an available API key using intelligent rotation
        
        Returns:
            API key string or None if all keys are exhausted
        """
        # Find all available keys
        available_keys = [
            key for key in self.api_keys 
            if self._is_key_available(key)
        ]
        
        if not available_keys:
            logger.error("❌ All API keys exhausted!")
            self._log_status()
            return None
        
        # Prefer keys with lower usage
        available_keys.sort(key=lambda k: self.usage_count[k])
        
        # Add some randomness to distribute load
        if len(available_keys) > 1:
            # Pick from top 3 least-used keys randomly
            top_keys = available_keys[:min(3, len(available_keys))]
            selected_key = random.choice(top_keys)
        else:
            selected_key = available_keys[0]
        
        logger.info(
            f"🔑 Selected key ending in ...{selected_key[-8:]} "
            f"(used {self.usage_count[selected_key]}/{self.requests_per_day} today)"
        )
        
        return selected_key
    
    def mark_key_used(self, api_key: str, success: bool = True):
        """
        Mark a key as used
        
        Args:
            api_key: The API key that was used
            success: Whether the request was successful
        """
        self.usage_count[api_key] += 1
        
        # If we hit the limit, set cooldown
        if self.usage_count[api_key] >= self.requests_per_day:
            cooldown_until = datetime.now() + timedelta(minutes=self.cooldown_minutes)
            self.cooldown_until[api_key] = cooldown_until
            logger.warning(
                f"⚠️ Key ...{api_key[-8:]} hit rate limit. "
                f"Cooldown until {cooldown_until.strftime('%H:%M:%S')}"
            )
    
    def mark_key_failed(self, api_key: str, rate_limited: bool = False):
        """
        Mark a key as failed
        
        Args:
            api_key: The API key that failed
            rate_limited: If True, put key in immediate cooldown
        """
        if rate_limited:
            # Immediate cooldown for rate limit errors
            cooldown_until = datetime.now() + timedelta(minutes=self.cooldown_minutes)
            self.cooldown_until[api_key] = cooldown_until
            logger.warning(
                f"🚫 Key ...{api_key[-8:]} rate limited by provider. "
                f"Cooldown until {cooldown_until.strftime('%H:%M:%S')}"
            )
        else:
            # Just increment counter for other failures
            self.usage_count[api_key] += 1
    
    def get_status(self) -> Dict:
        """Get current status of all keys"""
        now = datetime.now()
        status = {}
        
        for key in self.api_keys:
            key_id = f"...{key[-8:]}"
            self._reset_daily_counter(key)
            
            is_available = self._is_key_available(key)
            usage = self.usage_count[key]
            
            cooldown_info = None
            if key in self.cooldown_until:
                time_left = self.cooldown_until[key] - now
                if time_left.total_seconds() > 0:
                    cooldown_info = f"{int(time_left.total_seconds() / 60)} min"
            
            status[key_id] = {
                "available": is_available,
                "usage": f"{usage}/{self.requests_per_day}",
                "cooldown": cooldown_info,
                "resets_at": self.last_reset[key] + timedelta(days=1)
            }
        
        return status
    
    def _log_status(self):
        """Log current status of all keys"""
        logger.info("=" * 70)
        logger.info("API KEY STATUS:")
        for key_id, status in self.get_status().items():
            available = "✅" if status["available"] else "❌"
            cooldown = f" (cooldown: {status['cooldown']})" if status['cooldown'] else ""
            logger.info(f"  {available} {key_id}: {status['usage']}{cooldown}")
        logger.info("=" * 70)
    
    def has_available_keys(self) -> bool:
        """Check if any keys are available"""
        return any(self._is_key_available(key) for key in self.api_keys)
    
    def get_next_available_time(self) -> Optional[datetime]:
        """Get the time when the next key will be available"""
        if self.has_available_keys():
            return None
        
        # Find earliest cooldown expiry
        cooldown_times = [
            self.cooldown_until[key] 
            for key in self.api_keys 
            if key in self.cooldown_until
        ]
        
        if not cooldown_times:
            # Check for daily resets
            reset_times = [
                self.last_reset[key] + timedelta(days=1)
                for key in self.api_keys
            ]
            return min(reset_times) if reset_times else None
        
        return min(cooldown_times)