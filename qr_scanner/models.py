# qr_scanner/models.py
"""Модели данных для QR сканера."""
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel

from utils.risk_types import RiskFlag, RiskLevel


class QrContentType(str, Enum):
    """Тип содержимого QR кода."""
    URL = "url"
    EMAIL = "email"
    PHONE = "phone"
    SMS = "sms"
    WIFI = "wifi"
    VCARD = "vcard"
    GEO = "geo"
    CRYPTO = "crypto"
    TEXT = "text"
    UNKNOWN = "unknown"


class WifiInfo(BaseModel):
    """Информация о WiFi из QR."""
    ssid: Optional[str] = None
    password: Optional[str] = None
    security: Optional[str] = None  # WPA, WEP, nopass
    hidden: bool = False


class QrInfo(BaseModel):
    """Информация из QR кода."""
    # Основная информация
    raw_data: str
    content_type: QrContentType
    decoded_count: int = 1  # Количество QR кодов на изображении

    # Специфичные данные
    url: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    wifi: Optional[WifiInfo] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    crypto_address: Optional[str] = None
    crypto_amount: Optional[str] = None

    # Анализ URL (если есть)
    url_domain: Optional[str] = None
    url_is_shortened: bool = False
    url_has_suspicious_tld: bool = False
    url_looks_phishy: bool = False

    # Метаданные
    data_length: int = 0


class QrScanResult(BaseModel):
    """Результат сканирования QR кода."""
    filename: str
    info: Optional[QrInfo] = None
    found_qr: bool = False
    risk_level: RiskLevel
    flags: List[RiskFlag] = []
    score: int
    scanned_at: datetime
