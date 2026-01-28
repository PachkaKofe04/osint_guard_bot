# wallet_scanner/scanner.py
"""Основной модуль сканирования Crypto Wallet."""
import asyncio
import logging
from datetime import datetime
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

# API для получения информации о кошельках (бесплатные)
BLOCKCHAIN_INFO_API = "https://blockchain.info/rawaddr/{address}?limit=0"
ETHERSCAN_API = "https://api.etherscan.io/api"

# Известные скам-адреса (примеры)
KNOWN_SCAM_ADDRESSES = {
    # Bitcoin scam addresses (примеры)
    "1Ai52Uw6usjhpcDrwSmkUvjuqLpcznUuyF": ["phishing", "fake_giveaway"],
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": ["scam", "twitter_hack"],

    # Ethereum scam addresses (примеры)
    "0x000000000000000000000000000000000000dead": ["burn_address"],
}

# Известные биржевые адреса
KNOWN_EXCHANGES = {
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": "Satoshi (Genesis Block)",
    "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5": "Bitfinex",
}


async def fetch_btc_info(address: str) -> Optional[dict]:
    """Получает информацию о Bitcoin адресе."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                BLOCKCHAIN_INFO_API.format(address=address),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status == 200:
                    return await response.json()
    except Exception as e:
        log.warning(f"[Wallet Scanner] BTC API error for {address}: {e}")
    return None


async def fetch_eth_info(address: str) -> Optional[dict]:
    """Получает информацию о Ethereum адресе."""
    try:
        async with aiohttp.ClientSession() as session:
            # Баланс
            async with session.get(
                ETHERSCAN_API,
                params={
                    "module": "account",
                    "action": "balance",
                    "address": address,
                    "tag": "latest",
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "1":
                        balance_wei = int(data.get("result", "0"))
                        balance_eth = Decimal(balance_wei) / Decimal(10**18)
                        return {"balance": balance_eth}
    except Exception as e:
        log.warning(f"[Wallet Scanner] ETH API error for {address}: {e}")
    return None


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
        info = WalletInfo(
            address=address,
            currency="UNKNOWN",
            is_valid=False,
        )
        risk_level, flags, score = calculate_wallet_risk(info)
        result = WalletScanResult(
            address=address,
            currency="UNKNOWN",
            info=info,
            risk_level=risk_level,
            flags=flags,
            score=score,
            scanned_at=datetime.utcnow(),
        )
        _wallet_cache.set(address, result)
        return result

    # Проверяем на известные скам-адреса
    is_scam = address in KNOWN_SCAM_ADDRESSES
    scam_labels = KNOWN_SCAM_ADDRESSES.get(address, [])

    # Проверяем на известные биржи
    exchange_name = KNOWN_EXCHANGES.get(address)

    # Получаем данные из блокчейна
    balance = None
    tx_count = None

    if currency == "BTC":
        btc_data = await fetch_btc_info(address)
        if btc_data:
            balance = Decimal(btc_data.get("final_balance", 0)) / Decimal(100_000_000)
            tx_count = btc_data.get("n_tx", 0)

    elif currency == "ETH":
        eth_data = await fetch_eth_info(address)
        if eth_data:
            balance = eth_data.get("balance")

    # Собираем информацию
    info = WalletInfo(
        address=address,
        currency=currency,
        is_valid=True,
        balance=balance,
        tx_count=tx_count,
        is_scam=is_scam,
        scam_labels=scam_labels,
        exchange_name=exchange_name,
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
        scanned_at=datetime.utcnow(),
        from_cache=False,
    )

    # Сохраняем в кэш
    _wallet_cache.set(address, result)

    log.info(f"[Wallet Scanner] Result for {address}: {currency}, balance={balance}, scam={is_scam}")

    return result
