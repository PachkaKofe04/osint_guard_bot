# ip_scanner/scanner.py
"""Основной модуль сканирования IP адресов."""
import asyncio
import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from ip_scanner.models import IpInfo, IpScanResult, OtxInfo
from ip_scanner.risk_engine import calculate_ip_risk
from ip_scanner.ip_service import fetch_ip_profile_async
from ip_scanner.abuseipdb_service import AbuseIpdbResult, AbuseStatus, check_abuseipdb
from services.otx_service import check_ip_reputation
from config import settings
from services.threat_feeds import feeds, to_verdict
from utils.cache import TTLCache

log = logging.getLogger(__name__)

# Кэш для результатов сканирования IP
_ip_cache: TTLCache[IpScanResult] = TTLCache(ttl_seconds=600, max_size=1024)

# Регулярки для IP адресов
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

IPV6_REGEX = re.compile(
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,7}:$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|"
    r"^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|"
    r"^:(?::[0-9a-fA-F]{1,4}){1,7}$|"
    r"^::$"
)


def validate_ip(ip: str) -> tuple[bool, int]:
    """
    Валидирует IP адрес.

    Returns:
        (is_valid, version) - версия 4 или 6
    """
    ip = ip.strip()

    if IPV4_REGEX.match(ip):
        return True, 4

    if IPV6_REGEX.match(ip):
        return True, 6

    # Fallback через ipaddress модуль
    try:
        addr = ipaddress.ip_address(ip)
        return True, addr.version
    except ValueError:
        return False, 0


def is_private_ip(ip: str) -> bool:
    """Проверяет, является ли IP приватным."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def is_reserved_ip(ip: str) -> bool:
    """Проверяет, является ли IP зарезервированным."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_reserved or addr.is_loopback or addr.is_multicast
    except ValueError:
        return False


async def scan_ip(raw_ip: str) -> IpScanResult:
    """
    Полное сканирование IP адреса.

    Args:
        raw_ip: IP для проверки

    Returns:
        IpScanResult с полной информацией
    """
    ip = raw_ip.strip()

    # Проверяем кэш
    cached = _ip_cache.get(ip)
    if cached is not None:
        return cached

    log.info(f"[IP Scanner] Scanning: {ip}")

    # Валидация формата
    is_valid, version = validate_ip(ip)

    if not is_valid:
        info = IpInfo(
            ip=ip,
            is_valid=False,
        )
        risk_level, flags, score = calculate_ip_risk(info)
        result = IpScanResult(
            ip=ip,
            info=info,
            risk_level=risk_level,
            flags=flags,
            score=score,
            scanned_at=datetime.now(timezone.utc),
        )
        _ip_cache.set(ip, result)
        return result

    # Проверяем приватный/зарезервированный
    is_private = is_private_ip(ip)
    is_reserved = is_reserved_ip(ip)

    # Если приватный - не запрашиваем внешние API
    if is_private or is_reserved:
        info = IpInfo(
            ip=ip,
            version=version,
            is_valid=True,
            is_private=is_private,
            is_reserved=is_reserved,
        )
        risk_level, flags, score = calculate_ip_risk(info)
        result = IpScanResult(
            ip=ip,
            info=info,
            risk_level=risk_level,
            flags=flags,
            score=score,
            scanned_at=datetime.now(timezone.utc),
        )
        _ip_cache.set(ip, result)
        return result

    # Отказ одного провайдера не должен отбрасывать ответы остальных.
    api_data, otx_data, abuse_data = await asyncio.gather(
        fetch_ip_profile_async(ip),
        asyncio.to_thread(check_ip_reputation, ip),
        check_abuseipdb(ip, settings.ABUSEIPDB_API_KEY or ""),
        return_exceptions=True,
    )

    for provider_data in (api_data, otx_data, abuse_data):
        if isinstance(provider_data, asyncio.CancelledError):
            raise provider_data

    geo_note = None
    if isinstance(api_data, Exception):
        log.warning("[IP Scanner] Geo failed for %s: %s", ip, api_data)
        geo_note = f"источник геолокации завершился с ошибкой ({type(api_data).__name__})"
        api_data = None
    elif api_data is None:
        geo_note = "источник геолокации не ответил"

    otx_note = None
    if isinstance(otx_data, Exception):
        log.warning("[IP Scanner] OTX failed for %s: %s", ip, otx_data)
        otx_note = f"AlienVault OTX завершился с ошибкой ({type(otx_data).__name__})"
        otx_data = None
    elif otx_data is None:
        otx_note = "AlienVault OTX не настроен или не ответил"

    abuse_note = None
    if isinstance(abuse_data, Exception):
        log.warning("[IP Scanner] AbuseIPDB failed for %s: %s", ip, abuse_data)
        abuse_note = f"AbuseIPDB завершился с ошибкой ({type(abuse_data).__name__})"
        abuse_data = AbuseIpdbResult(status=AbuseStatus.ERROR)

    # Каждый источник заполняет свою часть результата независимо от геопрофиля.
    otx: Optional[OtxInfo] = None
    if otx_data is not None:
        otx = OtxInfo(
            pulse_count=otx_data.get("pulse_count", 0),
            malware_samples=otx_data.get("malware_samples", 0),
        )

    profile = api_data or {}
    proxy_unknown = (
        api_data is None or bool(profile.get("proxy_unknown"))
        or not isinstance(profile.get("proxy"), bool)
    )
    connection_unknown = proxy_unknown or not all(
        isinstance(profile.get(field), bool) for field in ("proxy", "hosting")
    )
    info = IpInfo(
        ip=ip,
        version=version,
        is_valid=True,
        country=profile.get("country"),
        country_code=profile.get("countryCode"),
        city=profile.get("city"),
        isp=profile.get("isp"),
        org=profile.get("org"),
        asn=profile.get("as"),
        asname=profile.get("asname"),
        is_proxy=profile.get("proxy", False),
        is_hosting=profile.get("hosting", False),
        abuse_score=abuse_data.abuse_score if abuse_data.ok else None,
        is_blacklisted=(abuse_data.abuse_score or 0) >= 75 if abuse_data.ok else False,
        threat_types=[abuse_data.usage_type] if (abuse_data.ok and abuse_data.usage_type) else [],
        reputation_note=abuse_note or abuse_data.explanation,
        geo_source=profile.get("source"),
        geo_note=geo_note,
        proxy_unknown=proxy_unknown,
        connection_unknown=connection_unknown,
    )

    # Положительное доказательство Tor от любого источника сохраняется.
    try:
        tor_known = feeds.is_tor_exit(ip)
    except Exception as exc:
        log.warning("[IP Scanner] Tor list failed for %s: %s", ip, exc)
        tor_known = None
        info.tor_note = f"список Tor недоступен ({type(exc).__name__})"
    info.is_tor = tor_known is True or (abuse_data.ok and abuse_data.is_tor)
    info.tor_unknown = tor_known is None and not abuse_data.ok

    # Проверка по локальным базам: C2-серверы ботнетов, вредоносные хосты
    try:
        info.threats = to_verdict(feeds.lookup_host(ip))
    except Exception as exc:
        log.warning("[IP Scanner] Threat lookup failed for %s: %s", ip, exc)
        info.threat_note = f"локальные базы угроз недоступны ({type(exc).__name__})"

    # Рассчитываем риск
    risk_level, flags, score = calculate_ip_risk(info, otx)

    result = IpScanResult(
        ip=ip,
        info=info,
        otx=otx,
        otx_note=otx_note,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.now(timezone.utc),
        from_cache=False,
    )

    # Сохраняем в кэш
    _ip_cache.set(ip, result)

    log.info(f"[IP Scanner] Result for {ip}: score={score}, country={info.country}, proxy={info.is_proxy}")

    return result
