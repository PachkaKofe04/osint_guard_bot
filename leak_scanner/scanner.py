# leak_scanner/scanner.py
"""Основной модуль проверки утечек."""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, List

import aiohttp

from leak_scanner.models import LeakInfo, LeakScanResult, BreachInfo
from leak_scanner.risk_engine import calculate_leak_risk
from utils.cache import TTLCache

log = logging.getLogger(__name__)

# Кэш для результатов
_leak_cache: TTLCache[LeakScanResult] = TTLCache(ttl_seconds=3600, max_size=512)

HIBP_API_URL = "https://haveibeenpwned.com/api/v3"


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


def _make_no_api_key_info(query: str) -> LeakInfo:
    """Возвращает LeakInfo-заглушку когда HIBP API ключ не настроен."""
    return LeakInfo(
        query=query,
        query_type="email",
        is_pwned=False,
        breach_count=0,
        breaches=[],
        no_api_key=True,
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
            # API вернул ошибку — не удалось проверить
            info = _make_no_api_key_info(query)
    else:
        # Нет API ключа — честно сообщаем
        info = _make_no_api_key_info(query)

    # Рассчитываем риск
    risk_level, flags, score = calculate_leak_risk(info)

    result = LeakScanResult(
        query=query,
        info=info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.now(timezone.utc),
        from_cache=False,
    )

    # Сохраняем в кэш
    _leak_cache.set(query, result)

    log.info(f"[Leak Scanner] Result for {query}: pwned={info.is_pwned}, breaches={info.breach_count}")

    return result
