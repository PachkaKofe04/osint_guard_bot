# ip_scanner/ip_service.py
"""
Профиль IP-адреса: геолокация, провайдер, ASN, признаки прокси и хостинга.

Источники и почему их два.

`ipwho.is` работает по HTTPS и отдаёт геолокацию, ASN, провайдера и
организацию. Это основной источник: раньше всё шло через `ip-api.com`,
у которого бесплатный тариф доступен только по HTTP, то есть проверяемый
адрес и ответ летели открытым текстом.

`ip-api.com` остался, но вызывается только ради двух полей, которых нет
больше нигде бесплатно: `proxy` и `hosting`. Если он не ответит, потеряются
только эти два флага, а не весь профиль.

Tor определяется отдельно, по списку выходных узлов из services/threat_feeds.py:
это бесплатно и не требует ключа AbuseIPDB.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

import aiohttp

log = logging.getLogger(__name__)

IPWHOIS_URL = "https://ipwho.is/"
IP_API_URL = "http://ip-api.com/json/"

TIMEOUT = aiohttp.ClientTimeout(total=8)
HEADERS = {"User-Agent": "OSINT-Guard-Bot/1.0"}

# Признаки того, что ASN принадлежит хостингу, а не оператору связи.
# Запасной способ определить датацентр, если ip-api не ответил.
HOSTING_KEYWORDS = (
    "hosting", "host", "server", "datacenter", "data center", "cloud",
    "vps", "colocation", "colo", "digitalocean", "linode", "vultr",
    "ovh", "hetzner", "amazon", "aws", "azure", "google cloud",
    "oracle cloud", "scaleway", "leaseweb", "contabo", "netcup",
)


async def _fetch_ipwhois(session: aiohttp.ClientSession, ip: str) -> Optional[Dict[str, Any]]:
    """Геолокация и сеть по HTTPS."""
    try:
        async with session.get(
            f"{IPWHOIS_URL}{ip}", headers=HEADERS, timeout=TIMEOUT
        ) as response:
            if response.status != 200:
                return None
            data = await response.json(content_type=None)
    except Exception as exc:
        log.info("[ip] ipwho.is недоступен для %s: %s", ip, exc)
        return None

    if not data.get("success"):
        return None

    connection = data.get("connection") or {}
    asn = connection.get("asn")

    return {
        "country": data.get("country"),
        "countryCode": data.get("country_code"),
        "city": data.get("city"),
        "isp": connection.get("isp"),
        "org": connection.get("org"),
        "as": f"AS{asn}" if asn else None,
        "asname": connection.get("org") or connection.get("isp"),
        "source": "ipwho.is",
    }


async def _fetch_ipapi(session: aiohttp.ClientSession, ip: str) -> Optional[Dict[str, Any]]:
    """
    Полный профиль от ip-api.

    Используется как источник флагов proxy и hosting, а при недоступности
    ipwho.is - и как запасной источник геолокации.
    """
    try:
        async with session.get(
            f"{IP_API_URL}{ip}",
            params={
                "fields": "status,message,country,countryCode,city,isp,org,"
                          "as,asname,proxy,hosting"
            },
            headers=HEADERS,
            timeout=TIMEOUT,
        ) as response:
            if response.status != 200:
                return None
            data = await response.json(content_type=None)
    except Exception as exc:
        log.info("[ip] ip-api недоступен для %s: %s", ip, exc)
        return None

    if data.get("status") != "success":
        return None

    data["source"] = "ip-api.com"
    return data


def _guess_hosting(profile: Dict[str, Any]) -> bool:
    """Определяет датацентр по названию ASN, если флага от ip-api нет."""
    haystack = " ".join(
        str(profile.get(field) or "").lower()
        for field in ("isp", "org", "asname", "as")
    )
    return any(keyword in haystack for keyword in HOSTING_KEYWORDS)


async def fetch_ip_profile_async(ip: str) -> Optional[Dict[str, Any]]:
    """
    Профиль IP. None означает, что данные получить не удалось.

    Оба источника опрашиваются параллельно: ipwho.is для основного профиля,
    ip-api ради флагов proxy и hosting.
    """
    async with aiohttp.ClientSession() as session:
        secure, legacy = await asyncio.gather(
            _fetch_ipwhois(session, ip),
            _fetch_ipapi(session, ip),
            return_exceptions=True,
        )

    if isinstance(secure, Exception):
        secure = None
    if isinstance(legacy, Exception):
        legacy = None

    if secure is None and legacy is None:
        log.warning("[ip] Профиль для %s получить не удалось", ip)
        return None

    profile: Dict[str, Any] = dict(secure or legacy or {})

    if legacy:
        # Эти два поля есть только у ip-api
        profile["proxy"] = bool(legacy.get("proxy"))
        profile["hosting"] = bool(legacy.get("hosting"))
        # Добираем то, чего не оказалось в основном источнике
        for field in ("country", "countryCode", "city", "isp", "org", "as", "asname"):
            if not profile.get(field) and legacy.get(field):
                profile[field] = legacy[field]
    else:
        # ip-api не ответил: хостинг определяем по названию ASN,
        # про прокси честно ничего не знаем
        profile["proxy"] = False
        profile["hosting"] = _guess_hosting(profile)
        profile["proxy_unknown"] = True

    return profile


def fetch_ip_profile(ip: str) -> Optional[Dict[str, Any]]:
    """Синхронная обёртка для вызова вне event loop."""
    return asyncio.run(fetch_ip_profile_async(ip))
