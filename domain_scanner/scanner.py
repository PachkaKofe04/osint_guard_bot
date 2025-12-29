# domain_scanner/scanner.py
import logging
from datetime import datetime
from typing import Optional, List

from domain_scanner.models import (
    DomainScanResult,
    DnsInfo,
    HttpInfo,
    SslInfo,
    WhoisInfo,
    IpProfile,
)
from domain_scanner.risk_engine import calculate_risk
from domain_scanner.ip_service import fetch_ip_profile
from utils.cache import TTLCache
from utils.domain_normalizer import normalize_domain
from services.whois_service import fetch_whois
from services.dns_service import fetch_dns
from services.ssl_service import fetch_ssl
from services.http_service import fetch_http

log = logging.getLogger(__name__)

_domain_cache: TTLCache[DomainScanResult] = TTLCache(ttl_seconds=600, max_size=1024)


async def scan_domain(raw_domain: str) -> DomainScanResult:
    normalized = normalize_domain(raw_domain)
    if not normalized:
        raise ValueError("Некорректное имя домена")

    cache_key = normalized
    cached = _domain_cache.get(cache_key)
    if cached is not None:
        return cached.copy(update={"from_cache": True})

    whois: Optional[WhoisInfo] = None
    dns: Optional[DnsInfo] = None
    ssl: Optional[SslInfo] = None
    http: Optional[HttpInfo] = None
    ip_profiles: List[IpProfile] = []

    try:
        whois = await fetch_whois(normalized)
    except Exception as e:
        log.warning(f"[scan_domain] WHOIS error for {normalized}: {e}")

    try:
        dns = await fetch_dns(normalized)
    except Exception as e:
        log.warning(f"[scan_domain] DNS error for {normalized}: {e}")

    # IP enrichment (если есть A-записи)
    if dns and dns.a_records:
        unique_ips = []
        for ip in dns.a_records:
            if ip not in unique_ips:
                unique_ips.append(ip)

        for ip in unique_ips[:5]:  # ограничим до 5 IP
            data = fetch_ip_profile(ip)
            if not data:
                continue
            ip_profiles.append(
                IpProfile(
                    ip=ip,
                    country=data.get("country"),
                    country_code=data.get("countryCode"),
                    city=data.get("city"),
                    isp=data.get("isp"),
                    org=data.get("org"),
                    asn=data.get("as"),
                    asname=data.get("asname"),
                    proxy=data.get("proxy"),
                    hosting=data.get("hosting"),
                )
            )

    try:
        ssl = await fetch_ssl(normalized)
    except Exception as e:
        log.warning(f"[scan_domain] SSL error for {normalized}: {e}")

    try:
        http = await fetch_http(normalized)
    except Exception as e:
        log.warning(f"[scan_domain] HTTP error for {normalized}: {e}")

    risk_level, flags, score = calculate_risk(whois, dns, ssl, http, ip_profiles)

    result = DomainScanResult(
        domain=raw_domain,
        normalized_domain=normalized,
        risk_level=risk_level,
        flags=flags,
        score=score,
        whois=whois,
        dns=dns,
        ssl=ssl,
        http=http,
        ip_profiles=ip_profiles,
        scanned_at=datetime.utcnow(),
        from_cache=False,
    )

    _domain_cache.set(cache_key, result)
    return result
