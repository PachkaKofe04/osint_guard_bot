# leak_scanner/models.py
"""Модели данных для Leak сканера."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

from utils.risk_types import RiskFlag, RiskLevel


class BreachInfo(BaseModel):
    """Информация об утечке."""
    name: str
    title: str
    domain: str
    breach_date: Optional[str] = None
    added_date: Optional[str] = None
    pwn_count: int = 0
    description: Optional[str] = None
    data_classes: List[str] = []  # passwords, emails, usernames, etc.
    is_verified: bool = True
    is_sensitive: bool = False


class LeakInfo(BaseModel):
    """Информация о проверке утечек."""
    query: str  # email или другой идентификатор
    query_type: str = "email"  # email, username, phone

    # Результаты
    is_pwned: bool = False
    breach_count: int = 0
    breaches: List[BreachInfo] = []

    # Paste (публичные вставки)
    paste_count: int = 0

    # Была ли проверка выполнена на самом деле.
    # Без этого поля недоступный источник неотличим от чистого адреса.
    check_performed: bool = True
    # Кто отвечал: XposedOrNot (бесплатно) или HIBP (по ключу)
    source: Optional[str] = None

    # Оставлено для совместимости: раньше означало «нет ключа HIBP».
    # Теперь ключ не нужен, проверка идёт через XposedOrNot.
    no_api_key: bool = False


class LeakScanResult(BaseModel):
    """Результат проверки на утечки."""
    query: str
    info: Optional[LeakInfo] = None
    risk_level: RiskLevel
    flags: List[RiskFlag] = []
    score: int
    scanned_at: datetime
    from_cache: bool = False
