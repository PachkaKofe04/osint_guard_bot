# email_scanner/models.py
"""Модели данных для Email сканера."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

from utils.risk_types import RiskFlag, RiskLevel


class EmailInfo(BaseModel):
    """Полная информация об email."""
    email: str
    local_part: str  # часть до @
    domain: str  # часть после @

    # Валидация
    is_valid_format: bool = True
    has_mx_records: bool = False
    mx_records: List[str] = []

    # Тип email
    is_disposable: bool = False  # временный email
    is_free_provider: bool = False  # gmail, mail.ru, etc.
    is_corporate: bool = False  # корпоративный домен

    # Провайдер
    provider_name: Optional[str] = None

    # Утечки (HIBP или аналоги)
    breach_count: int = 0
    breaches: List[str] = []

    # Дополнительно
    domain_age_days: Optional[int] = None
    is_catch_all: Optional[bool] = None

    # Gravatar
    gravatar_url: Optional[str] = None


class EmailScanResult(BaseModel):
    """Результат сканирования email."""
    email: str
    info: Optional[EmailInfo] = None
    risk_level: RiskLevel
    flags: List[RiskFlag] = []
    score: int
    scanned_at: datetime
    from_cache: bool = False
