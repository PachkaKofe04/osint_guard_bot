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
from services.otx_service import check_ip_reputation
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

    # Если приватный — не запрашиваем внешние API
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

    # Получаем данные от ip-api.com и OTX параллельно
    api_data, otx_data = await asyncio.gather(
        fetch_ip_profile_async(ip),
        asyncio.to_thread(check_ip_reputation, ip),
    )

    # Строим OtxInfo если данные получены
    otx: Optional[OtxInfo] = None
    if otx_data is not None:
        otx = OtxInfo(
            pulse_count=otx_data.get("pulse_count", 0),
            malware_samples=otx_data.get("malware_samples", 0),
        )

    if api_data is None:
        info = IpInfo(
            ip=ip,
            version=version,
            is_valid=True,
        )
    else:
        info = IpInfo(
            ip=ip,
            version=version,
            is_valid=True,
            is_private=False,
            is_reserved=False,
            # Геолокация
            country=api_data.get("country"),
            country_code=api_data.get("countryCode"),
            city=api_data.get("city"),
            # Сетевая информация
            isp=api_data.get("isp"),
            org=api_data.get("org"),
            asn=api_data.get("as"),
            asname=api_data.get("asname"),
            # Тип подключения
            is_proxy=api_data.get("proxy", False),
            is_hosting=api_data.get("hosting", False),
        )

    # Рассчитываем риск
    risk_level, flags, score = calculate_ip_risk(info, otx)

    result = IpScanResult(
        ip=ip,
        info=info,
        otx=otx,
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
