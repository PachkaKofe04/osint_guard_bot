# phone_scanner/risk_engine.py
from typing import List, Tuple

from utils.risk_types import RiskFlag, RiskLevel, RiskWeight
from utils.risk_scoring import add_risk_flag, calculate_risk_score
from phone_scanner.models import PhoneInfo


def calculate_phone_risk(info: PhoneInfo) -> Tuple[RiskLevel, List[RiskFlag], int, int]:
    """
    Расчёт риска для телефонного номера с использованием unified scoring system.

    Returns:
        Tuple[RiskLevel, List[RiskFlag], score, confidence]
    """
    flags: List[RiskFlag] = []

    length = info.length
    digits = info.normalized

    # Валидация длины
    if length < 10 or length > 15:
        add_risk_flag(
            flags,
            "PHONE_LENGTH_INVALID",
            RiskLevel.HIGH,
            f"Неверная длина номера: {length} цифр (ожидалось 10–15)",
            RiskWeight.PHONE_LENGTH_INVALID,
        )

    # Все цифры одинаковые
    if len(set(digits)) == 1:
        add_risk_flag(
            flags,
            "PHONE_ALL_SAME_DIGITS",
            RiskLevel.HIGH,
            "Все цифры номера одинаковые — тестовый/поддельный номер",
            RiskWeight.PHONE_ALL_SAME_DIGITS,
        )

    # Слишком однообразные первые цифры
    if length >= 6:
        first6 = digits[:6]
        unique_in_first6 = len(set(first6))
        if unique_in_first6 <= 2:
            add_risk_flag(
                flags,
                "PHONE_LOW_VARIETY",
                RiskLevel.MEDIUM,
                "Первые цифры номера сильно повторяются — подозрительный паттерн",
                RiskWeight.PHONE_LOW_VARIETY,
            )

    # Страна / оператор / регион
    if info.country_code == "UNKNOWN":
        add_risk_flag(
            flags,
            "PHONE_COUNTRY_UNKNOWN",
            RiskLevel.LOW,
            "Не удалось однозначно определить страну по номеру",
            RiskWeight.PHONE_COUNTRY_UNKNOWN,
        )
    elif info.country_code == "RU":
        if info.operator is None:
            add_risk_flag(
                flags,
                "PHONE_OPERATOR_UNKNOWN",
                RiskLevel.LOW,
                "Для российского номера не удалось определить оператора по префиксу",
                RiskWeight.PHONE_OPERATOR_UNKNOWN,
            )
        if info.region is None:
            add_risk_flag(
                flags,
                "PHONE_REGION_UNKNOWN",
                RiskLevel.LOW,
                "Для российского номера не удалось определить регион по префиксу",
                RiskWeight.PHONE_REGION_UNKNOWN,
            )

    # MNP-флаг (виртуальный оператор)
    if info.is_virtual:
        add_risk_flag(
            flags,
            "PHONE_VIRTUAL_OPERATOR",
            RiskLevel.LOW,
            f"Виртуальный оператор ({info.operator}) — возможен MNP (перенос номера)",
            RiskWeight.PHONE_VIRTUAL_OPERATOR,
        )

    # Низкая уверенность определения
    if info.confidence < 70:
        add_risk_flag(
            flags,
            "PHONE_LOW_CONFIDENCE",
            RiskLevel.LOW,
            f"Низкая уверенность определения оператора ({info.confidence}%)",
            RiskWeight.PHONE_LOW_CONFIDENCE,
        )

    # Рассчитываем итоговый риск через unified систему
    risk_score = calculate_risk_score(flags, confidence=info.confidence)

    return risk_score.level, flags, risk_score.score, info.confidence
