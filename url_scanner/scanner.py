# url_scanner/scanner.py
"""Основной модуль сканирования URL."""
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from url_scanner.models import UrlInfo, UrlScanResult
from url_scanner.expander import expand_url, is_shortened_url
from url_scanner.risk_engine import calculate_url_risk, analyze_url_structure
from utils.cache import TTLCache

log = logging.getLogger(__name__)

# Кэш для результатов сканирования URL
_url_cache: TTLCache[UrlScanResult] = TTLCache(ttl_seconds=600, max_size=1024)


def normalize_url(raw_url: str) -> str:
    """Нормализует URL для использования."""
    url = raw_url.strip()

    # Добавляем схему если нет
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


async def scan_url(raw_url: str) -> UrlScanResult:
    """
    Полное сканирование URL.

    Args:
        raw_url: URL для проверки

    Returns:
        UrlScanResult с полной информацией
    """
    normalized = normalize_url(raw_url)

    # Проверяем кэш
    cached = _url_cache.get(normalized)
    if cached is not None:
        return cached

    log.info(f"[URL Scanner] Scanning: {normalized}")

    # Проверяем, сокращённая ли ссылка
    is_short, shortener = is_shortened_url(normalized)

    # Разворачиваем URL
    try:
        final_url, redirect_chain = await expand_url(normalized)
    except Exception as e:
        log.error(f"[URL Scanner] Failed to expand URL: {e}")
        final_url = normalized
        redirect_chain = []

    # Анализируем структуру конечного URL
    structure = analyze_url_structure(final_url)

    # Получаем домен
    try:
        parsed = urlparse(final_url)
        domain = parsed.netloc
    except Exception:
        domain = None

    # Собираем информацию
    info = UrlInfo(
        original_url=raw_url,
        final_url=final_url,
        redirect_chain=redirect_chain,
        redirect_count=len(redirect_chain),
        domain=domain,
        is_shortened=is_short,
        shortener_service=shortener if shortener else None,
        has_ip_address=structure["has_ip_address"],
        has_suspicious_tld=structure["has_suspicious_tld"],
        has_many_subdomains=structure["has_many_subdomains"],
        url_length=structure["url_length"],
        # VirusTotal пока не интегрирован — добавим позже
        vt_malicious=0,
        vt_suspicious=0,
        vt_total=0,
    )

    # Рассчитываем риск
    risk_level, flags, score = calculate_url_risk(info)

    result = UrlScanResult(
        url=raw_url,
        info=info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.now(timezone.utc),
        from_cache=False,
    )

    # Сохраняем в кэш
    _url_cache.set(normalized, result)

    log.info(f"[URL Scanner] Result for {raw_url}: score={score}, redirects={len(redirect_chain)}")

    return result
