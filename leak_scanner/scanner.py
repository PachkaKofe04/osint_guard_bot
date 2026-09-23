# leak_scanner/scanner.py
"""
Проверка email по базам утечек.

Основной источник - XposedOrNot: бесплатно, без ключа, 11.6 млрд записей.
Have I Been Pwned используется только если ключ задан в .env, как апгрейд.

Раньше направление было нерабочим: без платного ключа HIBP сканер возвращал
заглушку, а пользователь видел оценку риска и текст, из которых складывалось
впечатление проверки. Теперь проверка выполняется всегда, а если источник
не ответил - это прямо написано в ответе.
"""
import logging
from datetime import datetime, timezone
from typing import List, Optional

import aiohttp

from leak_scanner.models import BreachInfo, LeakInfo, LeakScanResult
from leak_scanner.risk_engine import calculate_leak_risk
from services.xposedornot_service import BreachReport, check_email_breaches
from utils.cache import TTLCache

log = logging.getLogger(__name__)

_leak_cache: TTLCache[LeakScanResult] = TTLCache(ttl_seconds=3600, max_size=512)

HIBP_API_URL = "https://haveibeenpwned.com/api/v3"


async def check_hibp_api(email: str, api_key: str) -> Optional[List[dict]]:
    """
    Проверка через HIBP. Возвращает None, если ответ получить не удалось.

    Пустой список означает «адрес чист» - это валидный ответ, а не ошибка.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{HIBP_API_URL}/breachedaccount/{email}",
                headers={"hibp-api-key": api_key, "User-Agent": "OSINT-Guard-Bot"},
                params={"truncateResponse": "false"},
                timeout=aiohttp.ClientTimeout(total=12),
            ) as response:
                if response.status == 200:
                    return await response.json()
                if response.status == 404:
                    return []
                # 401 - ключ отвергнут, 429 - лимит. И то и другое не «чисто»
                log.warning("[HIBP] HTTP %s для %s", response.status, email)
    except Exception as exc:
        log.warning("[HIBP] Сбой: %s", exc)

    return None


def _breaches_from_hibp(raw: List[dict]) -> List[BreachInfo]:
    return [
        BreachInfo(
            name=b.get("Name", "Unknown"),
            title=b.get("Title", b.get("Name", "Unknown")),
            domain=b.get("Domain", ""),
            breach_date=b.get("BreachDate"),
            pwn_count=b.get("PwnCount", 0),
            description=b.get("Description"),
            data_classes=b.get("DataClasses", []),
            is_verified=b.get("IsVerified", True),
            is_sensitive=b.get("IsSensitive", False),
        )
        for b in raw
    ]


def _breaches_from_xon(report: BreachReport) -> List[BreachInfo]:
    return [
        BreachInfo(
            name=record.name,
            title=record.name,
            domain=record.domain,
            breach_date=record.year,
            pwn_count=record.records,
            description=record.description,
            data_classes=record.data_classes,
            is_verified=record.verified,
            # XposedOrNot не помечает утечки как «чувствительные» отдельно,
            # но состав данных позволяет судить об этом
            is_sensitive=any(
                "password" in dc.lower() or "financial" in dc.lower()
                for dc in record.data_classes
            ),
        )
        for record in report.breaches
    ]


async def scan_leaks(query: str, api_key: Optional[str] = None) -> LeakScanResult:
    """
    Проверяет email по базам утечек.

    Args:
        query: Email для проверки
        api_key: Ключ HIBP. Необязателен - без него работает XposedOrNot

    Returns:
        LeakScanResult
    """
    email = (query or "").strip().lower()

    cached = _leak_cache.get(email)
    if cached is not None:
        return cached

    log.info("[leak] Проверяю %s", email)

    breaches: List[BreachInfo] = []
    checked = False
    source: Optional[str] = None

    # HIBP только как апгрейд при наличии ключа
    if api_key:
        hibp_raw = await check_hibp_api(email, api_key)
        if hibp_raw is not None:
            breaches = _breaches_from_hibp(hibp_raw)
            checked = True
            source = "Have I Been Pwned"
        else:
            log.info("[leak] HIBP не ответил, перехожу на XposedOrNot")

    # Основной источник: бесплатный, без ключа
    if not checked:
        report = await check_email_breaches(email)
        checked = report.checked
        if checked:
            breaches = _breaches_from_xon(report)
            source = report.source

    info = LeakInfo(
        query=email,
        query_type="email",
        is_pwned=bool(breaches),
        breach_count=len(breaches),
        breaches=breaches,
        check_performed=checked,
        source=source,
    )

    risk_level, flags, score = calculate_leak_risk(info)

    result = LeakScanResult(
        query=email,
        info=info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.now(timezone.utc),
        from_cache=False,
    )

    _leak_cache.set(email, result)

    log.info(
        "[leak] %s: утечек %d, источник %s (проверка выполнена: %s)",
        email, len(breaches), source, checked,
    )
    return result
