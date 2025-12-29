# bin_scanner/risk_engine.py
from typing import List, Tuple, Optional

from utils.risk_types import RiskFlag, RiskLevel, RiskWeight
from utils.risk_scoring import add_risk_flag, calculate_risk_score
from bin_scanner.models import BinInfo


def calculate_bin_risk(info: Optional[BinInfo]) -> Tuple[RiskLevel, List[RiskFlag], int]:
    """
    Расчёт риска для BIN с использованием unified scoring system.

    Returns:
        Tuple[RiskLevel, List[RiskFlag], score]
    """
    flags: List[RiskFlag] = []

    if info is None:
        add_risk_flag(
            flags,
            "BIN_NOT_FOUND",
            RiskLevel.HIGH,
            "BIN не найден в открытой базе (binlist.net)",
            RiskWeight.BIN_NOT_FOUND,
        )
    else:
        # Prepaid detection - улучшенная логика
        is_prepaid = False

        # Проверка через card_type
        if info.card_type:
            t = info.card_type.lower()
            if "prepaid" in t:
                is_prepaid = True

        # Проверка через флаг prepaid
        if info.prepaid is True:
            is_prepaid = True

        if is_prepaid:
            add_risk_flag(
                flags,
                "BIN_PREPAID",
                RiskLevel.MEDIUM,
                "Prepaid карта — часто используется для анонимных/одноразовых платежей",
                RiskWeight.BIN_PREPAID,
            )

        # Неизвестный банк
        if not info.bank_name:
            add_risk_flag(
                flags,
                "BIN_BANK_UNKNOWN",
                RiskLevel.LOW,
                "Не указано название банка-эмитента",
                RiskWeight.BIN_BANK_UNKNOWN,
            )

        # Неизвестная страна
        if not info.country_name:
            add_risk_flag(
                flags,
                "BIN_COUNTRY_UNKNOWN",
                RiskLevel.LOW,
                "Не указана страна эмитента BIN",
                RiskWeight.BIN_COUNTRY_UNKNOWN,
            )

        # Trust signal - доверенный банк (понижает риск)
        if info.is_trusted:
            add_risk_flag(
                flags,
                "BIN_TRUSTED_BANK",
                RiskLevel.LOW,
                f"Карта выпущена доверенным банком: {info.bank_name}",
                RiskWeight.TRUSTED_BANK,
            )

    # Рассчитываем итоговый риск через unified систему
    risk_score = calculate_risk_score(flags)

    return risk_score.level, flags, risk_score.score
