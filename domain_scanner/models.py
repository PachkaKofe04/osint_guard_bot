# domain_scanner/models.py
from datetime import datetime
from typing import List, Optional, Dict

from pydantic import BaseModel
from utils.risk_types import RiskLevel, RiskFlag


class WhoisInfo(BaseModel):
    creation_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    registrar: Optional[str] = None
    country: Optional[str] = None
    is_privacy_protected: bool = False


class DnsInfo(BaseModel):
    a_records: List[str] = []
    ns_records: List[str] = []
    mx_records: List[str] = []
    txt_records: List[str] = []


class SslInfo(BaseModel):
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    issuers: List[str] = []
    san_domains: List[str] = []


class HttpInfo(BaseModel):
    url_checked: Optional[str] = None

    server: Optional[str] = None
    via: Optional[str] = None
    x_powered_by: Optional[str] = None
    cf_ray: Optional[str] = None
    cf_cache_status: Optional[str] = None

    robots_exists: bool = False
    robots_disallow_all: bool = False
    robots_has_sitemap: bool = False
    robots_has_minimal_allow: bool = False
    robots_raw: Optional[str] = None


class OtxInfo(BaseModel):
    """Данные репутации из AlienVault OTX."""
    pulse_count: int = 0  # количество угроз/пульсов
    malware_samples: int = 0  # количество malware образцов
    # validation игнорируем — OTX возвращает list[dict], а нам достаточно счётчиков


class IpProfile(BaseModel):
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    asname: Optional[str] = None
    proxy: Optional[bool] = None
    hosting: Optional[bool] = None


class DomainScanResult(BaseModel):
    domain: str
    normalized_domain: str

    risk_level: RiskLevel
    flags: List[RiskFlag]
    score: int = 0

    whois: Optional[WhoisInfo] = None
    dns: Optional[DnsInfo] = None
    ssl: Optional[SslInfo] = None
    http: Optional[HttpInfo] = None

    ip_profiles: List[IpProfile] = []
    otx: Optional[OtxInfo] = None

    scanned_at: datetime
    from_cache: bool = False
