# wallet_scanner/risk_engine.py
"""Движок оценки рисков для Crypto Wallet."""
from typing import List, Optional, Tuple
from decimal import Decimal

from wallet_scanner.models import WalletInfo
from utils.risk_types import RiskFlag, RiskLevel
from utils.risk_scoring import add_risk_flag, calculate_risk_score


class WalletRiskWeight:
    """Веса рисков для кошельков."""
    # Высокие риски
    KNOWN_SCAM = 6                # Известный скам-адрес
    INVALID_FORMAT = 3            # Невалидный формат

    # Средние риски
    EMPTY_WALLET = 1              # Пустой кошелёк
    NEW_WALLET = 2                # Новый кошелёк (мало транзакций)

    # Низкие риски
    HIGH_ACTIVITY = 0             # Высокая активность

    # Доверие
    KNOWN_EXCHANGE = -2           # Известная биржа
    ESTABLISHED_WALLET = -1       # Старый кошелёк с историей


def calculate_wallet_risk(info: Optional[WalletInfo]) -> Tuple[RiskLevel, List[RiskFlag], int]:
    """
    Расчёт риска для криптокошелька.

    Returns:
        Tuple[RiskLevel, List[RiskFlag], score]
    """
    flags: List[RiskFlag] = []

    if info is None:
        add_risk_flag(
            flags,
            "WALLET_ANALYSIS_FAILED",
            RiskLevel.MEDIUM,
            "Не удалось проанализировать кошелёк",
            2,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Невалидный формат
    if not info.is_valid:
        add_risk_flag(
            flags,
            "INVALID_WALLET",
            RiskLevel.MEDIUM,
            "Невалидный формат адреса кошелька",
            WalletRiskWeight.INVALID_FORMAT,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Валюта определена
    add_risk_flag(
        flags,
        "CURRENCY_DETECTED",
        RiskLevel.LOW,
        f"Криптовалюта: {info.currency}",
        0,
    )

    # Известный скам-адрес — высочайший риск
    if info.is_scam:
        labels = ", ".join(info.scam_labels) if info.scam_labels else "scam"
        add_risk_flag(
            flags,
            "KNOWN_SCAM_ADDRESS",
            RiskLevel.HIGH,
            f"⚠️ ИЗВЕСТНЫЙ СКАМ-АДРЕС! Метки: {labels}",
            WalletRiskWeight.KNOWN_SCAM,
        )

    # Известная биржа — доверие
    if info.exchange_name:
        add_risk_flag(
            flags,
            "KNOWN_EXCHANGE",
            RiskLevel.LOW,
            f"Известный адрес: {info.exchange_name}",
            WalletRiskWeight.KNOWN_EXCHANGE,
        )

    # Анализ баланса
    if info.balance is not None:
        if info.balance == Decimal(0):
            add_risk_flag(
                flags,
                "EMPTY_WALLET",
                RiskLevel.MEDIUM,
                "Пустой кошелёк (баланс = 0)",
                WalletRiskWeight.EMPTY_WALLET,
            )
        elif info.balance > Decimal(0):
            # Форматируем баланс
            if info.currency == "BTC":
                balance_str = f"{info.balance:.8f} BTC"
            elif info.currency == "ETH":
                balance_str = f"{info.balance:.6f} ETH"
            else:
                balance_str = f"{info.balance} {info.currency}"

            add_risk_flag(
                flags,
                "HAS_BALANCE",
                RiskLevel.LOW,
                f"Баланс: {balance_str}",
                0,
            )

    # Анализ активности
    if info.tx_count is not None:
        if info.tx_count == 0:
            add_risk_flag(
                flags,
                "NO_TRANSACTIONS",
                RiskLevel.MEDIUM,
                "Нет транзакций",
                WalletRiskWeight.NEW_WALLET,
            )
        elif info.tx_count < 5:
            add_risk_flag(
                flags,
                "FEW_TRANSACTIONS",
                RiskLevel.LOW,
                f"Мало транзакций: {info.tx_count}",
                1,
            )
        elif info.tx_count < 50:
            add_risk_flag(
                flags,
                "MODERATE_ACTIVITY",
                RiskLevel.LOW,
                f"Умеренная активность: {info.tx_count} транзакций",
                0,
            )
        else:
            add_risk_flag(
                flags,
                "HIGH_ACTIVITY",
                RiskLevel.LOW,
                f"Высокая активность: {info.tx_count}+ транзакций",
                WalletRiskWeight.ESTABLISHED_WALLET,
            )

    # Смарт-контракт (ETH)
    if info.is_contract:
        add_risk_flag(
            flags,
            "SMART_CONTRACT",
            RiskLevel.LOW,
            "Это смарт-контракт",
            0,
        )

    # Рассчитываем итоговый риск
    risk_score = calculate_risk_score(flags)

    return risk_score.level, flags, risk_score.score
