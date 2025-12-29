# bin_scanner/trusted_bins.py
"""
Список доверенных банков для понижения risk score.
"""

# Доверенные банки России
TRUSTED_BANKS_RU = {
    "sberbank",
    "сбербанк",
    "vtb",
    "втб",
    "tinkoff",
    "тинькофф",
    "alfabank",
    "альфа-банк",
    "alpha-bank",
    "gazprombank",
    "газпромбанк",
    "raiffeisen",
    "райффайзен",
    "rosbank",
    "росбанк",
    "otkritie",
    "открытие",
    "uralsib",
    "уралсиб",
    "promsvyazbank",
    "промсвязьбанк",
    "sovcombank",
    "совкомбанк",
    "mkb",
    "мкб",
    "moscow credit bank",
}

# Доверенные банки международные
TRUSTED_BANKS_INTERNATIONAL = {
    "visa",
    "mastercard",
    "american express",
    "amex",
    "citibank",
    "hsbc",
    "jpmorgan",
    "bank of america",
    "wells fargo",
    "deutsche bank",
    "barclays",
    "bnp paribas",
    "ing bank",
    "santander",
    "unicredit",
}


def is_trusted_bank(bank_name: str) -> bool:
    """
    Проверить, является ли банк доверенным.

    Args:
        bank_name: Название банка

    Returns:
        True если банк в списке доверенных
    """
    if not bank_name:
        return False

    bank_lower = bank_name.lower()

    # Проверяем российские банки
    if any(trusted in bank_lower for trusted in TRUSTED_BANKS_RU):
        return True

    # Проверяем международные банки
    if any(trusted in bank_lower for trusted in TRUSTED_BANKS_INTERNATIONAL):
        return True

    return False
