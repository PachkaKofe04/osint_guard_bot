# services/whois_service.py
import asyncio
import logging
from datetime import datetime
from typing import Optional

import whois  # библиотека python-whois

from domain_scanner.models import WhoisInfo
from utils.retry import retry_async

log = logging.getLogger(__name__)


PRIVACY_MARKERS = [
    # Общие маркеры
    "redacted for privacy",
    "redacted for gdpr",
    "data protected",
    "gdpr masked",
    "gdpr redacted",
    "not disclosed",
    "withheld for privacy",
    "registration private",
    "identity protected",
    "private registration",
    "privacy protection",
    "domain privacy",
    "contact privacy",
    "statutory masking",
    "personal data redacted",

    # Популярные провайдеры приватности
    "whoisguard",
    "whois guard",
    "whois privacy",
    "whois protection",
    "whois proxy",
    "domains by proxy",
    "domainsbyproxy",
    "privacy protect",
    "privacyprotect",
    "perfectprivacy",
    "perfect privacy",
    "namecheap privacy",
    "withholdingmydata",
    "contactprivacy",
    "whoisprivacycorp",
    "privacydotlink",
    "super privacy",
    "identity shield",
    "id shield",
    "anonymize",
    "private whois",

    # Регистраторы с приватностью
    "cloudflare, inc",
    "privacy@",
    "@privacy",
    "proxy@",
    "@proxy",
    "abuse@",
]


def _parse_creation_date(raw) -> Optional[datetime]:
    if isinstance(raw, list) and raw:
        raw = min(raw)
    if isinstance(raw, datetime):
        return raw
    return None


def _parse_updated_date(raw) -> Optional[datetime]:
    if isinstance(raw, list) and raw:
        raw = max(raw)
    if isinstance(raw, datetime):
        return raw
    return None


def _detect_privacy(raw_whois: str) -> bool:
    text = (raw_whois or "").lower()
    return any(marker in text for marker in PRIVACY_MARKERS)


def fetch_whois_sync(domain: str) -> Optional[WhoisInfo]:
    """
    Синхронный WHOIS-запрос. Оборачивается в async-обёртку через asyncio.to_thread.
    """
    try:
        data = whois.whois(domain)
    except Exception:
        return None

    creation_date = _parse_creation_date(getattr(data, "creation_date", None))
    updated_date = _parse_updated_date(getattr(data, "updated_date", None))

    registrar = getattr(data, "registrar", None)
    country = getattr(data, "country", None)

    raw_text = str(getattr(data, "text", "")) or str(data)
    is_privacy = _detect_privacy(raw_text)

    return WhoisInfo(
        creation_date=creation_date,
        updated_date=updated_date,
        registrar=registrar,
        country=country,
        is_privacy_protected=is_privacy,
    )


@retry_async(max_attempts=3, backoff=2, exceptions=(Exception,))
async def fetch_whois(domain: str) -> Optional[WhoisInfo]:
    """
    Async-обёртка вокруг sync WHOIS. Запуск в отдельном потоке с retry.
    """
    log.debug(f"[WHOIS] Fetching WHOIS for {domain}")
    result = await asyncio.to_thread(fetch_whois_sync, domain)

    if result:
        log.info(f"[WHOIS] Successfully fetched WHOIS for {domain}")
    else:
        log.warning(f"[WHOIS] Failed to fetch WHOIS for {domain}")

    return result
