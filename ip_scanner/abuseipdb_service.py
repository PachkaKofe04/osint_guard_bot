# ip_scanner/abuseipdb_service.py
"""AbuseIPDB — репутационная проверка IP (1000 req/день на бесплатном плане)."""
import logging
from typing import Optional

import aiohttp

log = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIpdbResult:
    __slots__ = ("abuse_score", "is_tor", "total_reports", "usage_type", "is_whitelisted")

    def __init__(
        self,
        abuse_score: int,
        is_tor: bool,
        total_reports: int,
        usage_type: Optional[str],
        is_whitelisted: bool,
    ) -> None:
        self.abuse_score = abuse_score
        self.is_tor = is_tor
        self.total_reports = total_reports
        self.usage_type = usage_type
        self.is_whitelisted = is_whitelisted


async def check_abuseipdb(ip: str, api_key: str) -> Optional[AbuseIpdbResult]:
    """
    Проверяет IP через AbuseIPDB.
    Возвращает None при ошибке или отсутствии ключа.
    """
    if not api_key:
        return None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                ABUSEIPDB_URL,
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": "90",
                },
                timeout=aiohttp.ClientTimeout(total=8),
            ) as response:
                if response.status == 429:
                    log.warning("[AbuseIPDB] Rate limit exceeded (1000/day free tier)")
                    return None
                if response.status == 401:
                    log.warning("[AbuseIPDB] Invalid API key")
                    return None
                if response.status != 200:
                    log.warning(f"[AbuseIPDB] HTTP {response.status} for {ip}")
                    return None

                data = await response.json()

        payload = data.get("data", {})
        if not payload:
            return None

        return AbuseIpdbResult(
            abuse_score=payload.get("abuseConfidenceScore", 0),
            is_tor=payload.get("isTor", False),
            total_reports=payload.get("totalReports", 0),
            usage_type=payload.get("usageType"),
            is_whitelisted=payload.get("isWhitelisted", False),
        )

    except Exception as e:
        log.warning(f"[AbuseIPDB] Error for {ip}: {e}")
        return None
