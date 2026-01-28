# leak_scanner/scanner.py
"""Основной модуль проверки утечек."""
import asyncio
import hashlib
import logging
from datetime import datetime
from typing import Optional, List

import aiohttp

from leak_scanner.models import LeakInfo, LeakScanResult, BreachInfo
from leak_scanner.risk_engine import calculate_leak_risk
from utils.cache import TTLCache

log = logging.getLogger(__name__)

# Кэш для результатов
_leak_cache: TTLCache[LeakScanResult] = TTLCache(ttl_seconds=3600, max_size=512)

# HIBP API (требует API ключ для полноценной работы)
HIBP_API_URL = "https://haveibeenpwned.com/api/v3"

# Известные крупные утечки (для демонстрации без API)
KNOWN_BREACHES_DB = {
    "linkedin": BreachInfo(
        name="LinkedIn",
        title="LinkedIn 2012",
        domain="linkedin.com",
        breach_date="2012-05-05",
        pwn_count=164611595,
        description="В 2012 году LinkedIn подвергся утечке данных",
        data_classes=["Emails", "Passwords"],
    ),
    "adobe": BreachInfo(
        name="Adobe",
        title="Adobe 2013",
        domain="adobe.com",
        breach_date="2013-10-04",
        pwn_count=152445165,
        description="В 2013 году Adobe подвергся масштабной утечке",
        data_classes=["Emails", "Passwords", "Password hints"],
    ),
    "dropbox": BreachInfo(
        name="Dropbox",
        title="Dropbox 2012",
        domain="dropbox.com",
        breach_date="2012-07-01",
        pwn_count=68648009,
        description="В 2012 году Dropbox подвергся утечке данных",
        data_classes=["Emails", "Passwords"],
    ),
}


def _hash_email(email: str) -> str:
    """Хэширует email для демонстрации."""
    return hashlib.sha256(email.lower().encode()).hexdigest()[:16]


async def check_hibp_api(email: str, api_key: Optional[str] = None) -> Optional[List[dict]]:
    """
    Проверяет email через HIBP API.
    Требует API ключ для работы.
    """
    if not api_key:
        return None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{HIBP_API_URL}/breachedaccount/{email}",
                headers={
                    "hibp-api-key": api_key,
                    "User-Agent": "OSINT-Guard-Bot",
                },
                params={"truncateResponse": "false"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 404:
                    return []  # Не найден в утечках
    except Exception as e:
        log.warning(f"[Leak Scanner] HIBP API error: {e}")

    return None


async def check_leaks_demo(email: str) -> LeakInfo:
    """
    Демо-проверка утечек (без API).
    В реальности нужен HIBP API ключ.
    """
    # Для демонстрации — симулируем проверку
    # В реальном проекте здесь был бы вызов HIBP API

    email_lower = email.lower()
    breaches: List[BreachInfo] = []

    # Проверяем домен email на известные утечки
    domain = email_lower.split("@")[-1] if "@" in email_lower else ""

    # Симуляция: если email содержит test/demo — показываем утечки
    if any(x in email_lower for x in ["test", "demo", "example"]):
        breaches = list(KNOWN_BREACHES_DB.values())[:2]

    return LeakInfo(
        query=email,
        query_type="email",
        is_pwned=len(breaches) > 0,
        breach_count=len(breaches),
        breaches=breaches,
    )


async def scan_leaks(query: str, api_key: Optional[str] = None) -> LeakScanResult:
    """
    Проверяет email/username на утечки.

    Args:
        query: Email или username для проверки
        api_key: HIBP API ключ (опционально)

    Returns:
        LeakScanResult
    """
    query = query.strip().lower()

    # Проверяем кэш
    cached = _leak_cache.get(query)
    if cached is not None:
        return cached

    log.info(f"[Leak Scanner] Checking: {query}")

    # Проверяем через HIBP API если есть ключ
    if api_key:
        hibp_result = await check_hibp_api(query, api_key)
        if hibp_result is not None:
            breaches = [
                BreachInfo(
                    name=b.get("Name", "Unknown"),
                    title=b.get("Title", "Unknown"),
                    domain=b.get("Domain", ""),
                    breach_date=b.get("BreachDate"),
                    pwn_count=b.get("PwnCount", 0),
                    description=b.get("Description"),
                    data_classes=b.get("DataClasses", []),
                    is_verified=b.get("IsVerified", True),
                    is_sensitive=b.get("IsSensitive", False),
                )
                for b in hibp_result
            ]
            info = LeakInfo(
                query=query,
                query_type="email",
                is_pwned=len(breaches) > 0,
                breach_count=len(breaches),
                breaches=breaches,
            )
        else:
            info = await check_leaks_demo(query)
    else:
        # Демо-режим без API
        info = await check_leaks_demo(query)

    # Рассчитываем риск
    risk_level, flags, score = calculate_leak_risk(info)

    result = LeakScanResult(
        query=query,
        info=info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.utcnow(),
        from_cache=False,
    )

    # Сохраняем в кэш
    _leak_cache.set(query, result)

    log.info(f"[Leak Scanner] Result for {query}: pwned={info.is_pwned}, breaches={info.breach_count}")

    return result
