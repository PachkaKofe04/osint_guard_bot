# ip_scanner/abuseipdb_service.py
"""
Репутация IP по базе AbuseIPDB. Бесплатно 1000 проверок в сутки.

Все неуспешные исходы раньше сводились к одному None, и отчёт выглядел
одинаково, когда ключа нет, когда он отвергнут и когда кончилась квота.
Пользователь во всех трёх случаях видел просто отсутствие данных о репутации
и не мог понять, надо ли что-то чинить.

Теперь исход возвращается явно, и форматтер показывает разное сообщение.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import aiohttp

log = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = aiohttp.ClientTimeout(total=8)


class AbuseStatus(str, Enum):
    """Чем закончился запрос к AbuseIPDB."""

    OK = "ok"                    # данные получены
    NO_KEY = "no_key"            # ключ не настроен
    REJECTED = "rejected"        # ключ отвергнут: опечатка или отозван
    RATE_LIMITED = "limited"     # исчерпана суточная квота
    ERROR = "error"              # сеть или сбой сервиса


@dataclass
class AbuseIpdbResult:
    """Ответ AbuseIPDB. При status != OK поля с данными не заполнены."""

    status: AbuseStatus
    abuse_score: Optional[int] = None
    is_tor: bool = False
    total_reports: int = 0
    usage_type: Optional[str] = None
    is_whitelisted: bool = False
    isp: Optional[str] = None
    country_code: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status is AbuseStatus.OK

    @property
    def explanation(self) -> Optional[str]:
        """Что показать пользователю, если данных нет."""
        return {
            AbuseStatus.NO_KEY: "ключ AbuseIPDB не настроен",
            AbuseStatus.REJECTED: "ключ AbuseIPDB отвергнут сервисом",
            AbuseStatus.RATE_LIMITED: "исчерпана суточная квота AbuseIPDB",
            AbuseStatus.ERROR: "AbuseIPDB не ответил",
        }.get(self.status)


async def check_abuseipdb(ip: str, api_key: str) -> AbuseIpdbResult:
    """
    Проверяет IP по базе жалоб.

    Никогда не бросает исключение: любой сбой возвращается как статус,
    чтобы сканер мог отличить «репутация чистая» от «проверить не смогли».
    """
    if not api_key:
        return AbuseIpdbResult(status=AbuseStatus.NO_KEY)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                ABUSEIPDB_URL,
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=TIMEOUT,
            ) as response:
                if response.status == 401:
                    log.warning("[AbuseIPDB] Ключ отвергнут")
                    return AbuseIpdbResult(status=AbuseStatus.REJECTED)
                if response.status == 429:
                    log.warning("[AbuseIPDB] Исчерпана квота (1000/сутки)")
                    return AbuseIpdbResult(status=AbuseStatus.RATE_LIMITED)
                if response.status != 200:
                    log.warning("[AbuseIPDB] HTTP %s для %s", response.status, ip)
                    return AbuseIpdbResult(status=AbuseStatus.ERROR)

                data = await response.json(content_type=None)
    except Exception as exc:
        log.warning("[AbuseIPDB] Сбой для %s: %s", ip, exc)
        return AbuseIpdbResult(status=AbuseStatus.ERROR)

    payload = (data or {}).get("data") or {}
    if not payload:
        return AbuseIpdbResult(status=AbuseStatus.ERROR)

    return AbuseIpdbResult(
        status=AbuseStatus.OK,
        abuse_score=payload.get("abuseConfidenceScore", 0),
        is_tor=bool(payload.get("isTor", False)),
        total_reports=payload.get("totalReports", 0),
        usage_type=payload.get("usageType"),
        is_whitelisted=bool(payload.get("isWhitelisted", False)),
        isp=payload.get("isp"),
        country_code=payload.get("countryCode"),
    )
