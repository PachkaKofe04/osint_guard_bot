# username_scanner/models.py
"""Модели данных для Username сканера."""
from datetime import datetime
from typing import List, Optional, Dict
from pydantic import BaseModel

from utils.risk_types import RiskFlag, RiskLevel


class PlatformResult(BaseModel):
    """Результат проверки на одной платформе."""
    platform: str
    url: str
    exists: bool = False
    status: str = "unknown"  # exists, not_found, error, blocked
    error: Optional[str] = None


class UsernameInfo(BaseModel):
    """Информация о username."""
    username: str
    is_valid: bool = True

    # Результаты по платформам
    platforms: List[PlatformResult] = []
    found_count: int = 0
    checked_count: int = 0

    # Дополнительная информация
    common_patterns: List[str] = []  # Паттерны вроде "admin", "support"


class UsernameScanResult(BaseModel):
    """Результат сканирования username."""
    username: str
    info: Optional[UsernameInfo] = None
    risk_level: RiskLevel
    flags: List[RiskFlag] = []
    score: int
    scanned_at: datetime
    from_cache: bool = False
