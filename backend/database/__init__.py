# backend/database/__init__.py
from .config import get_db, get_engine, is_db_available, Base
from .models import User, Session, OAuthState  # Keep auth models
from .service import DatabaseService  # Keep auth service

# NEW: Import scan models and service
from .scan_models import (
    Repository, ScanHistory, Vulnerability, 
    ScanStatistics, ScanStatusEnum, SeverityEnum
)
from .scan_service import ScanService

__all__ = [
    'get_db', 'get_engine', 'is_db_available', 'Base',
    'User', 'Session', 'OAuthState',
    'DatabaseService',
    'Repository', 'ScanHistory', 'Vulnerability',
    'ScanStatistics', 'ScanStatusEnum', 'SeverityEnum',
    'ScanService'
]