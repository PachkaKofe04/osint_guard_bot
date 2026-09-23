# email_scanner/scanner.py
"""Основной модуль сканирования Email."""
import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import List, Optional

import dns.resolver

from email_scanner.models import EmailInfo, EmailScanResult
from email_scanner.disposable import is_disposable_email, is_free_provider, get_provider_name
from email_scanner.risk_engine import calculate_email_risk
from utils.cache import TTLCache
from services.gravatar_service import check_gravatar_exists
from services.holehe_service import check_holehe
from services.whois_service import fetch_whois_sync

log = logging.getLogger(__name__)

# Кэш для результатов сканирования Email
_email_cache: TTLCache[EmailScanResult] = TTLCache(ttl_seconds=600, max_size=1024)

# Регулярка для валидации email
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)


def validate_email_format(email: str) -> bool:
    """Проверяет формат email."""
    return bool(EMAIL_REGEX.match(email))


def parse_email(email: str) -> tuple:
    """Разбирает email на части."""
    if "@" not in email:
        return "", ""
    parts = email.rsplit("@", 1)
    return parts[0], parts[1]


def fetch_mx_records_sync(domain: str) -> List[str]:
    """Получает MX записи домена (синхронно)."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = []
        for rdata in answers:
            mx_records.append(str(rdata.exchange).rstrip("."))
        return sorted(mx_records, key=lambda x: x)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except Exception as e:
        log.warning(f"[Email Scanner] MX lookup failed for {domain}: {e}")
        return []


async def fetch_mx_records(domain: str) -> List[str]:
    """Асинхронная обёртка для получения MX записей."""
    return await asyncio.to_thread(fetch_mx_records_sync, domain)


async def fetch_domain_age(domain: str) -> Optional[int]:
    """Возвращает возраст домена в днях через WHOIS. None если недоступно."""
    try:
        whois_info = await asyncio.wait_for(
            asyncio.to_thread(fetch_whois_sync, domain),
            timeout=5.0,
        )
        if whois_info and whois_info.creation_date:
            cd = whois_info.creation_date
            if cd.tzinfo is None:
                cd = cd.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - cd).days
    except (asyncio.TimeoutError, Exception) as e:
        log.debug(f"[Email Scanner] Domain age lookup failed for {domain}: {e}")
    return None


async def scan_email(raw_email: str, deep: bool = False) -> EmailScanResult:
    """
    Полное сканирование Email.

    Args:
        raw_email: Email для проверки

    Returns:
        EmailScanResult с полной информацией
    """
    email = raw_email.strip().lower()

    # Быстрый и глубокий результаты кэшируются раздельно: иначе быстрый
    # ответ подменял бы собой уже выполненный поиск по платформам
    cache_key = f"{email}:deep" if deep else email
    cached = _email_cache.get(cache_key)
    if cached is not None:
        return cached

    log.info(f"[Email Scanner] Scanning: {email}")

    # Валидация формата
    is_valid = validate_email_format(email)

    if not is_valid:
        info = EmailInfo(
            email=email,
            local_part="",
            domain="",
            is_valid_format=False,
        )
        risk_level, flags, score = calculate_email_risk(info)
        result = EmailScanResult(
            email=email,
            info=info,
            risk_level=risk_level,
            flags=flags,
            score=score,
            scanned_at=datetime.now(timezone.utc),
        )
        _email_cache.set(cache_key, result)
        return result

    # Парсим email
    local_part, domain = parse_email(email)

    # Быстрая часть: укладывается в несколько секунд.
    # Поиск по платформам через holehe занимает до 45 секунд и висел бы
    # молчаливой паузой, поэтому вынесен в отдельный шаг по кнопке.
    tasks = [
        fetch_mx_records(domain),
        check_gravatar_exists(email),
        fetch_domain_age(domain),
    ]
    if deep:
        tasks.append(check_holehe(email))

    results = await asyncio.gather(*tasks)
    mx_records, gravatar_url, domain_age_days = results[0], results[1], results[2]
    holehe_hits = results[3] if deep else []
    has_mx = len(mx_records) > 0

    # Проверяем тип домена
    is_disposable = is_disposable_email(domain)
    is_free = is_free_provider(domain)
    provider = get_provider_name(domain)

    # Корпоративный email - не бесплатный и не одноразовый и имеет MX
    is_corporate = has_mx and not is_free and not is_disposable

    # Собираем информацию
    info = EmailInfo(
        email=email,
        local_part=local_part,
        domain=domain,
        is_valid_format=True,
        has_mx_records=has_mx,
        mx_records=mx_records,
        is_disposable=is_disposable,
        is_free_provider=is_free,
        is_corporate=is_corporate,
        provider_name=provider if provider else None,
        breach_count=0,
        breaches=[],
        domain_age_days=domain_age_days,
        gravatar_url=gravatar_url,
        holehe_hits=holehe_hits,
        deep_check_done=deep,
    )

    # Рассчитываем риск
    risk_level, flags, score = calculate_email_risk(info)

    result = EmailScanResult(
        email=email,
        info=info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.now(timezone.utc),
        from_cache=False,
    )

    # Сохраняем в кэш
    _email_cache.set(cache_key, result)

    log.info(f"[Email Scanner] Result for {email}: score={score}, mx={has_mx}, disposable={is_disposable}")

    return result
