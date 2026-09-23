# ip_scanner/models.py
"""Модели данных для IP сканера."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

from utils.risk_types import RiskFlag, RiskLevel, ThreatVerdict


class OtxInfo(BaseModel):
    """Данные репутации IP из AlienVault OTX."""
    pulse_count: int = 0
    malware_samples: int = 0
    # validation: list of dict или list of str - зависит от OTX API
    # игнорируем её, нам достаточно pulse_count и malware_samples


class IpInfo(BaseModel):
    """Полная информация об IP адресе."""
    ip: str
    version: int = 4  # 4 or 6

    # Валидация
    is_valid: bool = True
    is_private: bool = False
    is_reserved: bool = False

    # Геолокация
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    # Сетевая информация
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    asname: Optional[str] = None

    # Тип подключения
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    is_mobile: bool = False

    # Репутация
    is_blacklisted: bool = False
    abuse_score: Optional[int] = None  # 0-100
    threat_types: List[str] = []
    # Почему данных о репутации нет: ключа нет, ключ отвергнут, кончилась
    # квота или сервис не ответил. Раньше все четыре случая выглядели
    # одинаково, и пользователь не мог понять, надо ли что-то чинить
    reputation_note: Optional[str] = None
    # Откуда взята геолокация: ipwho.is (HTTPS) или ip-api (HTTP)
    geo_source: Optional[str] = None
    # Про прокси ничего не известно: ip-api не ответил
    proxy_unknown: bool = False

    # Проверка по локальным базам угроз: C2-серверы, вредоносные хосты
    threats: Optional[ThreatVerdict] = None


class IpScanResult(BaseModel):
    """Результат сканирования IP."""
    ip: str
    info: Optional[IpInfo] = None
    otx: Optional[OtxInfo] = None
    risk_level: RiskLevel
    flags: List[RiskFlag] = []
    score: int
    scanned_at: datetime
    from_cache: bool = False
