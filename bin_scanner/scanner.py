# bin_scanner/scanner.py
import logging
from datetime import datetime, timezone
from typing import Optional

import requests

from bin_scanner.models import BinInfo, BinScanResult
from bin_scanner.risk_engine import calculate_bin_risk
from bin_scanner.trusted_bins import is_trusted_bank
from utils.cache import TTLCache
from utils.retry import retry_sync

log = logging.getLogger(__name__)

BINLIST_URL = "https://lookup.binlist.net/"

# Кэш для результатов сканирования BIN
_bin_cache: TTLCache[BinScanResult] = TTLCache(ttl_seconds=600, max_size=1024)


def _normalize_bin(raw: str) -> str:
    """Извлечь только цифры из BIN"""
    digits = "".join(ch for ch in raw if ch.isdigit())
    return digits


@retry_sync(max_attempts=3, backoff=2, exceptions=(requests.exceptions.RequestException,))
def _fetch_bin_info(bin_code: str) -> Optional[BinInfo]:
    """
    Получить информацию о BIN из binlist.net API с retry механизмом.

    Args:
        bin_code: Нормализованный BIN (только цифры)

    Returns:
        BinInfo или None если не удалось получить данные
    """
    try:
        log.debug(f"[BIN] Fetching BIN info for {bin_code}")
        resp = requests.get(f"{BINLIST_URL}{bin_code}", timeout=5)
    except Exception as e:
        log.warning(f"[BIN] HTTP error for {bin_code}: {e}")
        return None

    if resp.status_code != 200:
        log.info(f"[BIN] binlist response {resp.status_code} for {bin_code}")
        return None

    try:
        data = resp.json()
    except ValueError:
        log.warning(f"[BIN] Invalid JSON response for {bin_code}")
        return None

    scheme = data.get("scheme")
    brand = data.get("brand")
    card_type = data.get("type")
    country = data.get("country") or {}
    bank = data.get("bank") or {}

    country_name = country.get("name")
    country_code = country.get("alpha2")
    bank_name = bank.get("name")
    prepaid = data.get("prepaid", None)

    # Проверяем доверенный банк
    is_trusted = is_trusted_bank(bank_name) if bank_name else False

    log.info(f"[BIN] Successfully fetched BIN info for {bin_code}: bank={bank_name}, country={country_code}")

    return BinInfo(
        raw_input=bin_code,
        bin=bin_code,
        scheme=scheme,
        brand=brand,
        card_type=card_type,
        bank_name=bank_name,
        country_name=country_name,
        country_code=country_code,
        prepaid=prepaid,
        is_trusted=is_trusted,
    )


def scan_bin(raw_bin: str) -> BinScanResult:
    """
    Основная функция сканирования BIN.

    Args:
        raw_bin: BIN в любом формате

    Returns:
        BinScanResult с полной информацией и оценкой риска
    """
    raw = raw_bin.strip()
    if not raw:
        raise ValueError("Пустой BIN")

    digits = _normalize_bin(raw)
    if not digits:
        raise ValueError("Не удалось выделить цифры из BIN")

    if len(digits) < 6 or len(digits) > 8:
        raise ValueError("BIN должен содержать 6–8 цифр")

    # Проверяем кэш
    cached = _bin_cache.get(digits)
    if cached is not None:
        return cached

    info = _fetch_bin_info(digits)

    risk_level, flags, score = calculate_bin_risk(info)

    result = BinScanResult(
        bin=digits,
        info=info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.now(timezone.utc),
    )

    # Сохраняем в кэш
    _bin_cache.set(digits, result)

    log.info(
        f"[BIN] {raw_bin} → bank={info.bank_name if info else 'N/A'}, "
        f"country={info.country_code if info else 'N/A'}, "
        f"score={score}, trusted={info.is_trusted if info else False}"
    )

    return result
