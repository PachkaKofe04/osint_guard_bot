# username_scanner/scanner.py
"""Основной модуль сканирования Username."""
import asyncio
import logging
import re
from datetime import datetime
from typing import List, Optional

import aiohttp

from username_scanner.models import UsernameInfo, UsernameScanResult, PlatformResult
from username_scanner.platforms import (
    PLATFORMS, Platform, SUSPICIOUS_PATTERNS, BRAND_PATTERNS
)
from username_scanner.risk_engine import calculate_username_risk
from utils.cache import TTLCache

log = logging.getLogger(__name__)

# Кэш для результатов сканирования
_username_cache: TTLCache[UsernameScanResult] = TTLCache(ttl_seconds=600, max_size=512)

# Регулярка для валидного username
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")

# Таймаут для запросов
REQUEST_TIMEOUT = 10


def validate_username(username: str) -> bool:
    """Проверяет валидность username."""
    return bool(USERNAME_REGEX.match(username))


def detect_suspicious_patterns(username: str) -> List[str]:
    """Определяет подозрительные паттерны в username."""
    found = []
    lower_name = username.lower()

    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in lower_name:
            found.append(pattern)

    for brand in BRAND_PATTERNS:
        if brand in lower_name:
            # Проверяем что это не точное совпадение (официальный аккаунт)
            if lower_name != brand:
                found.append(f"brand:{brand}")

    return found


async def check_platform(
    session: aiohttp.ClientSession,
    platform: Platform,
    username: str
) -> PlatformResult:
    """
    Проверяет существование username на платформе.

    Returns:
        PlatformResult с результатом проверки
    """
    url = platform.url_template.format(username=username)

    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                **platform.headers,
            }
        ) as response:
            status = response.status

            # Проверка по статус-коду
            if platform.error_type == "status_code":
                if status in platform.error_codes:
                    return PlatformResult(
                        platform=platform.name,
                        url=url,
                        exists=False,
                        status="not_found",
                    )
                elif status == 200:
                    return PlatformResult(
                        platform=platform.name,
                        url=url,
                        exists=True,
                        status="exists",
                    )
                else:
                    return PlatformResult(
                        platform=platform.name,
                        url=url,
                        exists=False,
                        status="blocked",
                        error=f"HTTP {status}",
                    )

            # Проверка по сообщению в контенте
            elif platform.error_type == "message":
                if status == 200:
                    content = await response.text()
                    if platform.error_message and platform.error_message in content:
                        return PlatformResult(
                            platform=platform.name,
                            url=url,
                            exists=False,
                            status="not_found",
                        )
                    return PlatformResult(
                        platform=platform.name,
                        url=url,
                        exists=True,
                        status="exists",
                    )
                else:
                    return PlatformResult(
                        platform=platform.name,
                        url=url,
                        exists=False,
                        status="not_found",
                    )

    except asyncio.TimeoutError:
        return PlatformResult(
            platform=platform.name,
            url=url,
            exists=False,
            status="error",
            error="Timeout",
        )
    except aiohttp.ClientError as e:
        return PlatformResult(
            platform=platform.name,
            url=url,
            exists=False,
            status="error",
            error=str(e)[:50],
        )
    except Exception as e:
        log.warning(f"[Username Scanner] Error checking {platform.name}: {e}")
        return PlatformResult(
            platform=platform.name,
            url=url,
            exists=False,
            status="error",
            error=str(e)[:50],
        )


async def scan_username(raw_username: str) -> UsernameScanResult:
    """
    Полное сканирование username по социальным сетям.

    Args:
        raw_username: Username для проверки

    Returns:
        UsernameScanResult с полной информацией
    """
    username = raw_username.strip().lstrip("@")

    # Проверяем кэш
    cached = _username_cache.get(username)
    if cached is not None:
        return cached

    log.info(f"[Username Scanner] Scanning: {username}")

    # Валидация формата
    is_valid = validate_username(username)

    if not is_valid:
        info = UsernameInfo(
            username=username,
            is_valid=False,
        )
        risk_level, flags, score = calculate_username_risk(info)
        result = UsernameScanResult(
            username=username,
            info=info,
            risk_level=risk_level,
            flags=flags,
            score=score,
            scanned_at=datetime.utcnow(),
        )
        _username_cache.set(username, result)
        return result

    # Определяем подозрительные паттерны
    suspicious = detect_suspicious_patterns(username)

    # Проверяем на платформах (параллельно)
    async with aiohttp.ClientSession() as session:
        tasks = [
            check_platform(session, platform, username)
            for platform in PLATFORMS
        ]
        platform_results = await asyncio.gather(*tasks)

    # Подсчитываем результаты
    found_count = sum(1 for r in platform_results if r.exists)
    checked_count = len(platform_results)

    # Собираем информацию
    info = UsernameInfo(
        username=username,
        is_valid=True,
        platforms=platform_results,
        found_count=found_count,
        checked_count=checked_count,
        common_patterns=suspicious,
    )

    # Рассчитываем риск
    risk_level, flags, score = calculate_username_risk(info)

    result = UsernameScanResult(
        username=username,
        info=info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.utcnow(),
        from_cache=False,
    )

    # Сохраняем в кэш
    _username_cache.set(username, result)

    log.info(f"[Username Scanner] Result for {username}: found on {found_count}/{checked_count} platforms")

    return result
