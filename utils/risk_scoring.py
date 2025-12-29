# utils/risk_scoring.py
"""
Единая система подсчёта риска 0-10 с explainability.
"""
from typing import List, Tuple
from utils.risk_types import (
    RiskFlag,
    RiskScore,
    RiskLevel,
    get_risk_emoji,
    get_risk_level,
    get_risk_label,
    get_risk_description,
)


def calculate_risk_score(flags: List[RiskFlag], confidence: int = 100) -> RiskScore:
    """
    Подсчитать итоговый risk score на основе флагов.

    Args:
        flags: Список флагов риска с весами
        confidence: Уровень уверенности в определении (0-100%)

    Returns:
        RiskScore с детальной разбивкой
    """
    # Суммируем веса всех флагов
    raw_score = sum(flag.weight for flag in flags)

    # Нормализуем в диапазон 0-10
    score = max(0, min(10, raw_score))

    # Определяем уровень и метаданные
    level = get_risk_level(score)
    emoji = get_risk_emoji(score)
    label = get_risk_label(level)
    description = get_risk_description(score, level)

    return RiskScore(
        score=score,
        level=level,
        emoji=emoji,
        label=label,
        description=description,
        flags=flags,
        confidence=confidence,
    )


def add_risk_flag(
    flags: List[RiskFlag],
    code: str,
    level: RiskLevel,
    message: str,
    weight: int,
) -> int:
    """
    Добавить флаг риска в список и вернуть его вес.

    Args:
        flags: Список для добавления
        code: Код флага
        level: Уровень серьёзности
        message: Описание
        weight: Вес флага

    Returns:
        Вес добавленного флага
    """
    flags.append(
        RiskFlag(
            code=code,
            level=level,
            message=message,
            weight=weight,
        )
    )
    return weight


def format_risk_explanation(flags: List[RiskFlag]) -> str:
    """
    Форматировать список флагов в человекочитаемый текст с весами.

    Example:
        +2: домен создан 15 дней назад
        +3: prepaid карта
        +1: неизвестный оператор
        -2: известный российский банк

    Args:
        flags: Список флагов

    Returns:
        Форматированная строка
    """
    if not flags:
        return "Флагов риска не обнаружено."

    lines = []
    for flag in flags:
        sign = "+" if flag.weight >= 0 else ""
        lines.append(f"{sign}{flag.weight}: {flag.message}")

    return "\n".join(lines)
