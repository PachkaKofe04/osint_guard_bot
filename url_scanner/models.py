# url_scanner/models.py
"""Модели данных для URL сканера."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

from utils.risk_types import RiskFlag, RiskLevel


class UrlExpandResult(BaseModel):
    """Результат разворачивания короткой ссылки."""
    original_url: str
    final_url: str
    redirect_chain: List[str] = []
    redirect_count: int = 0


class VirusTotalResult(BaseModel):
    """Результат проверки через VirusTotal."""
    url: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_scanners: int = 0
    scan_date: Optional[datetime] = None
    permalink: Optional[str] = None


class UrlInfo(BaseModel):
    """Полная информация о URL."""
    original_url: str
    final_url: str
    redirect_chain: List[str] = []
    redirect_count: int = 0

    # Анализ домена
    domain: Optional[str] = None
    is_shortened: bool = False
    shortener_service: Optional[str] = None

    # VirusTotal
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_total: int = 0
    vt_permalink: Optional[str] = None

    # Google Safe Browsing (если будет)
    is_safe_browsing_threat: bool = False
    safe_browsing_threats: List[str] = []

    # HTTP анализ
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    server: Optional[str] = None

    # Подозрительные признаки
    has_ip_address: bool = False
    has_suspicious_tld: bool = False
    has_many_subdomains: bool = False
    url_length: int = 0


class UrlScanResult(BaseModel):
    """Результат сканирования URL."""
    url: str
    info: Optional[UrlInfo] = None
    risk_level: RiskLevel
    flags: List[RiskFlag] = []
    score: int
    scanned_at: datetime
    from_cache: bool = False
