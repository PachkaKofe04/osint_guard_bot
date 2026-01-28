# domain_scanner/scanner.py
import asyncio
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
from ip_scanner.ip_service import fetch_ip_profile_async
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

    # Параллельный запуск всех независимых сервисов
    results = await asyncio.gather(
        fetch_whois(normalized),
        fetch_dns(normalized),
        fetch_ssl(normalized),
        fetch_http(normalized),
        return_exceptions=True,
    )

    whois: Optional[WhoisInfo] = None
    dns: Optional[DnsInfo] = None
    ssl: Optional[SslInfo] = None
    http: Optional[HttpInfo] = None
    ip_profiles: List[IpProfile] = []

    # Обработка результатов
    if isinstance(results[0], Exception):
        log.warning(f"[scan_domain] WHOIS error for {normalized}: {results[0]}")
    else:
        whois = results[0]

    if isinstance(results[1], Exception):
        log.warning(f"[scan_domain] DNS error for {normalized}: {results[1]}")
    else:
        dns = results[1]

    if isinstance(results[2], Exception):
        log.warning(f"[scan_domain] SSL error for {normalized}: {results[2]}")
    else:
        ssl = results[2]

    if isinstance(results[3], Exception):
        log.warning(f"[scan_domain] HTTP error for {normalized}: {results[3]}")
    else:
        http = results[3]

    # IP enrichment (параллельно, если есть A-записи)
    if dns and dns.a_records:
        unique_ips = list(dict.fromkeys(dns.a_records))[:5]  # до 5 уникальных IP
        ip_results = await asyncio.gather(
            *[fetch_ip_profile_async(ip) for ip in unique_ips],
            return_exceptions=True,
        )
        for ip, data in zip(unique_ips, ip_results):
            if isinstance(data, Exception):
                log.warning(f"[scan_domain] IP profile error for {ip}: {data}")
                continue
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
