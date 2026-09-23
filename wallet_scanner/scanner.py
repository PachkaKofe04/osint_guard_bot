# wallet_scanner/scanner.py
"""
Сканирование криптокошельков.

Данные блокчейна берутся из wallet_scanner/providers.py - по провайдеру на
сеть, все без ключей. Скам-проверка идёт по локальному кэшу ScamSniffer
(services/threat_feeds.py).

Про честность вердикта. Раньше и недоступный источник, и реальное отсутствие
адреса в базе давали один результат - «скам не обнаружен». База скама при этом
была мертва больше года, то есть бот всегда отвечал «чисто», ни разу ничего не
проверив. Теперь состояние проверки хранится отдельно в scam_check_performed,
и форматтер обязан его показывать.
"""
import asyncio
import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

import aiohttp

from services.threat_feeds import feeds
from utils.cache import TTLCache
from wallet_scanner.models import WalletInfo, WalletScanResult
from wallet_scanner.providers import (
    PRIVACY_COINS,
    balance_available,
    fetch_chain_data,
)
from wallet_scanner.risk_engine import calculate_wallet_risk
from wallet_scanner.validators import validate_address

log = logging.getLogger(__name__)

_wallet_cache: TTLCache[WalletScanResult] = TTLCache(ttl_seconds=300, max_size=512)

# CoinGecko - курсы к USD, без ключа
COINGECKO_PRICE_URL = "https://api.coingecko.com/api/v3/simple/price"
COINGECKO_IDS = {
    "BTC": "bitcoin",
    "ETH": "ethereum",
    "LTC": "litecoin",
    "DOGE": "dogecoin",
    "TRX": "tron",
    "XRP": "ripple",
    "SOL": "solana",
    "XMR": "monero",
    "BCH": "bitcoin-cash",
    "DASH": "dash",
}


async def fetch_coin_price_usd(currency: str) -> Optional[Decimal]:
    """Курс монеты к доллару. None, если получить не удалось."""
    coin_id = COINGECKO_IDS.get(currency)
    if not coin_id:
        return None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                COINGECKO_PRICE_URL,
                params={"ids": coin_id, "vs_currencies": "usd"},
                timeout=aiohttp.ClientTimeout(total=8),
                headers={"User-Agent": "OSINT-Guard-Bot/1.0"},
            ) as response:
                if response.status != 200:
                    return None
                data = await response.json()
    except Exception as exc:
        log.debug("[wallet] CoinGecko недоступен для %s: %s", currency, exc)
        return None

    price = (data.get(coin_id) or {}).get("usd")
    return Decimal(str(price)) if price is not None else None


def _invalid_result(address: str) -> WalletScanResult:
    info = WalletInfo(address=address, currency="UNKNOWN", is_valid=False)
    risk_level, flags, score = calculate_wallet_risk(info)
    return WalletScanResult(
        address=address,
        currency="UNKNOWN",
        info=info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.now(timezone.utc),
    )


async def scan_wallet(raw_address: str) -> WalletScanResult:
    """
    Полное сканирование криптокошелька.

    Args:
        raw_address: Адрес кошелька

    Returns:
        WalletScanResult
    """
    address = raw_address.strip()

    cached = _wallet_cache.get(address)
    if cached is not None:
        return cached

    is_valid, currency = validate_address(address)
    if not is_valid or not currency:
        result = _invalid_result(address)
        _wallet_cache.set(address, result)
        return result

    log.info("[wallet] Сканирую %s:%s", currency, address)

    # Скам-проверка идёт по памяти, в сеть не ходит - делаем её сразу
    scam_result = feeds.lookup_crypto_address(address)

    chain_data, price_usd = await asyncio.gather(
        fetch_chain_data(address, currency),
        fetch_coin_price_usd(currency),
    )

    balance = chain_data.balance if chain_data else None
    balance_usd = None
    if balance is not None and price_usd is not None:
        balance_usd = (balance * price_usd).quantize(Decimal("0.01"))

    scam_labels = []
    if scam_result.is_hit:
        for hit in scam_result.hits:
            label = hit.threat_type or "scam"
            if hit.source:
                label = f"{label} ({hit.source})"
            scam_labels.append(label)

    info = WalletInfo(
        address=address,
        currency=currency,
        is_valid=True,
        balance=balance,
        balance_usd=balance_usd,
        tx_count=chain_data.tx_count if chain_data else None,
        first_seen=chain_data.first_seen if chain_data else None,
        last_seen=chain_data.last_seen if chain_data else None,
        is_contract=chain_data.is_contract if chain_data else False,
        is_smart_account=chain_data.is_smart_account if chain_data else False,
        contract_name=chain_data.contract_name if chain_data else None,
        is_scam=scam_result.is_hit,
        scam_labels=scam_labels,
        # Ключевое отличие от прежней версии: отсутствие находки и
        # невыполненная проверка - разные вещи
        scam_check_performed=scam_result.is_checked,
        balance_available=balance_available(currency),
        data_source=chain_data.source if chain_data else None,
    )

    risk_level, flags, score = calculate_wallet_risk(info)

    result = WalletScanResult(
        address=address,
        currency=currency,
        info=info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.now(timezone.utc),
        from_cache=False,
    )

    _wallet_cache.set(address, result)

    log.info(
        "[wallet] %s:%s - баланс=%s источник=%s скам=%s (проверка выполнена: %s)",
        currency, address, balance, info.data_source,
        info.is_scam, info.scam_check_performed,
    )
    return result


__all__ = ["scan_wallet", "fetch_coin_price_usd", "PRIVACY_COINS"]
