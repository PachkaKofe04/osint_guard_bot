# wallet_scanner/validators.py
"""Валидаторы для криптовалютных адресов."""
import re
from typing import Optional, Tuple


# Bitcoin адреса
BTC_LEGACY_REGEX = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")  # Legacy (1... или 3...)
BTC_BECH32_REGEX = re.compile(r"^bc1[a-zA-HJ-NP-Z0-9]{25,89}$")     # Segwit (bc1...)

# Ethereum адреса
ETH_REGEX = re.compile(r"^0x[a-fA-F0-9]{40}$")

# Litecoin адреса
LTC_LEGACY_REGEX = re.compile(r"^[LM][a-km-zA-HJ-NP-Z1-9]{26,33}$")
LTC_BECH32_REGEX = re.compile(r"^ltc1[a-zA-HJ-NP-Z0-9]{25,89}$")

# TRON адреса
TRX_REGEX = re.compile(r"^T[a-zA-HJ-NP-Z1-9]{33}$")

# Solana адреса
SOL_REGEX = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

# Ripple (XRP) адреса
XRP_REGEX = re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{24,34}$")

# Dogecoin адреса
DOGE_REGEX = re.compile(r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$")

# Monero адреса (очень длинные)
XMR_REGEX = re.compile(r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")


def detect_currency(address: str) -> Optional[str]:
    """
    Определяет валюту по формату адреса.

    Returns:
        Код валюты или None если не распознан
    """
    address = address.strip()

    # Bitcoin
    if BTC_LEGACY_REGEX.match(address) or BTC_BECH32_REGEX.match(address):
        return "BTC"

    # Ethereum (и совместимые EVM сети)
    if ETH_REGEX.match(address):
        return "ETH"

    # Litecoin
    if LTC_LEGACY_REGEX.match(address) or LTC_BECH32_REGEX.match(address):
        return "LTC"

    # TRON
    if TRX_REGEX.match(address):
        return "TRX"

    # Ripple
    if XRP_REGEX.match(address):
        return "XRP"

    # Dogecoin
    if DOGE_REGEX.match(address):
        return "DOGE"

    # Monero
    if XMR_REGEX.match(address):
        return "XMR"

    # Solana (последний — более общий паттерн)
    if SOL_REGEX.match(address) and len(address) >= 32:
        # Дополнительная проверка на Solana
        if not any([
            address.startswith("1"),
            address.startswith("3"),
            address.startswith("bc1"),
            address.startswith("0x"),
        ]):
            return "SOL"

    return None


def validate_btc_address(address: str) -> bool:
    """Валидирует Bitcoin адрес."""
    return bool(BTC_LEGACY_REGEX.match(address) or BTC_BECH32_REGEX.match(address))


def validate_eth_address(address: str) -> bool:
    """Валидирует Ethereum адрес."""
    return bool(ETH_REGEX.match(address))


def validate_address(address: str, currency: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Валидирует криптоадрес.

    Args:
        address: Адрес для проверки
        currency: Ожидаемая валюта (опционально)

    Returns:
        (is_valid, detected_currency)
    """
    address = address.strip()

    if currency:
        currency = currency.upper()
        if currency == "BTC":
            return validate_btc_address(address), "BTC"
        elif currency == "ETH":
            return validate_eth_address(address), "ETH"
        # Для остальных — просто определяем валюту
        detected = detect_currency(address)
        if detected == currency:
            return True, currency
        return False, None

    # Авто-определение
    detected = detect_currency(address)
    if detected:
        return True, detected

    return False, None
