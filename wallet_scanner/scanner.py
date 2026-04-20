# wallet_scanner/scanner.py
"""Основной модуль сканирования Crypto Wallet."""
import asyncio
import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

import aiohttp

from wallet_scanner.models import WalletInfo, WalletScanResult
from wallet_scanner.validators import validate_address, detect_currency
from wallet_scanner.risk_engine import calculate_wallet_risk
from utils.cache import TTLCache

log = logging.getLogger(__name__)

# Кэш для результатов сканирования
_wallet_cache: TTLCache[WalletScanResult] = TTLCache(ttl_seconds=300, max_size=512)

# Blockchair — универсальный API для 20+ блокчейнов (1500 req/день бесплатно)
BLOCKCHAIR_API = "https://api.blockchair.com/{chain}/dashboards/address/{address}"

# CryptoScamDB — база скам-адресов (бесплатно, без ключа)
CRYPTOSCAMDB_API = "https://api.cryptoscamdb.org/v1/check/{address}"

# Маппинг валюта → название цепочки в Blockchair
BLOCKCHAIR_CHAINS = {
    "BTC":  "bitcoin",
    "ETH":  "ethereum",
    "LTC":  "litecoin",
    "DOGE": "dogecoin",
    "TRX":  "tron",
    "XRP":  "ripple",
    "SOL":  "solana",
    "XMR":  "monero",
    "BCH":  "bitcoin-cash",
}

# Делители для перевода минимальных единиц в основную валюту
BALANCE_DIVISORS = {
    "BTC":  Decimal(10 ** 8),   # satoshi
    "ETH":  Decimal(10 ** 18),  # wei
    "LTC":  Decimal(10 ** 8),   # litoshi
    "DOGE": Decimal(10 ** 8),   # koinu
    "TRX":  Decimal(10 ** 6),   # sun
    "XRP":  Decimal(10 ** 6),   # drop
    "SOL":  Decimal(10 ** 9),   # lamport
    "XMR":  Decimal(10 ** 12),  # piconero
    "BCH":  Decimal(10 ** 8),   # satoshi
}

# Известные скам-адреса
KNOWN_SCAM_ADDRESSES = {
    "1Ai52Uw6usjhpcDrwSmkUvjuqLpcznUuyF": ["phishing", "fake_giveaway"],
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": ["scam", "twitter_hack"],
    "0x000000000000000000000000000000000000dead": ["burn_address"],
}

# Известные биржевые адреса
KNOWN_EXCHANGES = {
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": "Satoshi (Genesis Block)",
    "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5": "Bitfinex",
}


async def fetch_blockchair_info(address: str, currency: str) -> Optional[dict]:
    """
    Получает информацию об адресе через Blockchair API.

    Returns dict с полями: balance, tx_count, first_seen, last_seen, is_contract
    или None при ошибке.
    """
    chain = BLOCKCHAIR_CHAINS.get(currency)
    if not chain:
        return None

    url = BLOCKCHAIR_API.format(chain=chain, address=address)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                headers={"User-Agent": "OSINT-Bot/1.0"},
            ) as response:
                if response.status != 200:
                    log.warning(f"[Wallet] Blockchair HTTP {response.status} for {currency}:{address}")
                    return None

                data = await response.json()

    except Exception as e:
        log.warning(f"[Wallet] Blockchair error for {currency}:{address}: {e}")
        return None

    try:
        addr_data = data.get("data", {}).get(address, {}).get("address", {})
        if not addr_data:
            # Blockchair иногда возвращает ключ в другом регистре (ETH — lowercase)
            addr_key = address.lower()
            addr_data = data.get("data", {}).get(addr_key, {}).get("address", {})

        if not addr_data:
            log.warning(f"[Wallet] Blockchair: нет данных для {address}")
            return None

        divisor = BALANCE_DIVISORS.get(currency, Decimal(1))
        raw_balance = addr_data.get("balance", 0)
        balance = Decimal(str(raw_balance)) / divisor if raw_balance is not None else None

        tx_count = addr_data.get("transaction_count")

        # Даты (формат: "2021-01-01 00:00:00")
        first_seen = None
        last_seen = None
        fs_str = addr_data.get("first_seen_receiving")
        ls_str = addr_data.get("last_seen_receiving")
        if fs_str:
            try:
                first_seen = datetime.strptime(fs_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        if ls_str:
            try:
                last_seen = datetime.strptime(ls_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass

        # Смарт-контракт (только для ETH)
        is_contract = addr_data.get("type") == "contract"

        return {
            "balance": balance,
            "tx_count": tx_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "is_contract": is_contract,
        }

    except Exception as e:
        log.warning(f"[Wallet] Blockchair parse error for {address}: {e}")
        return None


async def fetch_cryptoscamdb(address: str) -> list:
    """
    Проверяет адрес в базе CryptoScamDB.

    Returns:
        Список меток скама (пустой если чисто)
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                CRYPTOSCAMDB_API.format(address=address),
                timeout=aiohttp.ClientTimeout(total=8),
                headers={"User-Agent": "OSINT-Bot/1.0"},
            ) as response:
                if response.status != 200:
                    return []
                data = await response.json()

        entries = data.get("entries", [])
        labels = []
        for entry in entries:
            entry_type = entry.get("type", "")
            name = entry.get("name", "")
            if entry_type:
                labels.append(entry_type if not name else f"{entry_type}: {name}")
        return labels

    except Exception as e:
        log.debug(f"[Wallet] CryptoScamDB error for {address}: {e}")
        return []


async def scan_wallet(raw_address: str) -> WalletScanResult:
    """
    Полное сканирование криптокошелька.

    Args:
        raw_address: Адрес кошелька

    Returns:
        WalletScanResult с полной информацией
    """
    address = raw_address.strip()

    # Проверяем кэш
    cached = _wallet_cache.get(address)
    if cached is not None:
        return cached

    log.info(f"[Wallet Scanner] Scanning: {address}")

    # Валидация и определение валюты
    is_valid, currency = validate_address(address)

    if not is_valid or not currency:
        info = WalletInfo(address=address, currency="UNKNOWN", is_valid=False)
        risk_level, flags, score = calculate_wallet_risk(info)
        result = WalletScanResult(
            address=address,
            currency="UNKNOWN",
            info=info,
            risk_level=risk_level,
            flags=flags,
            score=score,
            scanned_at=datetime.now(timezone.utc),
        )
        _wallet_cache.set(address, result)
        return result

    # Проверяем на известные скам-адреса
    is_scam = address in KNOWN_SCAM_ADDRESSES
    scam_labels = KNOWN_SCAM_ADDRESSES.get(address, [])

    # Проверяем на известные биржи
    exchange_name = KNOWN_EXCHANGES.get(address)

    # Параллельно: данные из блокчейна + проверка скама
    bc_data, scamdb_labels = await asyncio.gather(
        fetch_blockchair_info(address, currency),
        fetch_cryptoscamdb(address),
    )

    balance = None
    tx_count = None
    first_seen = None
    last_seen = None
    is_contract = False

    if bc_data:
        balance = bc_data.get("balance")
        tx_count = bc_data.get("tx_count")
        first_seen = bc_data.get("first_seen")
        last_seen = bc_data.get("last_seen")
        is_contract = bc_data.get("is_contract", False)

    # Объединяем скам-метки из локального списка и CryptoScamDB
    if scamdb_labels:
        is_scam = True
        scam_labels = list(set(scam_labels + scamdb_labels))

    # Собираем информацию
    info = WalletInfo(
        address=address,
        currency=currency,
        is_valid=True,
        balance=balance,
        tx_count=tx_count,
        first_seen=first_seen,
        last_seen=last_seen,
        is_scam=is_scam,
        scam_labels=scam_labels,
        exchange_name=exchange_name,
        is_contract=is_contract,
    )

    # Рассчитываем риск
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

    log.info(f"[Wallet Scanner] Result for {address}: {currency}, balance={balance}, tx={tx_count}, scam={is_scam}")
    return result
