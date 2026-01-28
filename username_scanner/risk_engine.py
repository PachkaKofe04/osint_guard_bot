# username_scanner/risk_engine.py
"""Движок оценки рисков для Username."""
from typing import List, Optional, Tuple

from username_scanner.models import UsernameInfo
from utils.risk_types import RiskFlag, RiskLevel
from utils.risk_scoring import add_risk_flag, calculate_risk_score


class UsernameRiskWeight:
    """Веса рисков для Username."""
    # Высокие риски
    IMPERSONATION_PATTERN = 4     # Паттерны вроде "support", "admin"
    BRAND_IMPERSONATION = 4       # Имитация бренда
    INVALID_FORMAT = 3            # Невалидный формат

    # Средние риски
    NOT_FOUND_ANYWHERE = 2        # Не найден ни на одной платформе
    FOUND_FEW = 1                 # Найден на 1-2 платформах

    # Доверие
    FOUND_MANY = -2               # Найден на многих платформах
    ESTABLISHED_PRESENCE = -1     # Устоявшееся присутствие


def calculate_username_risk(info: Optional[UsernameInfo]) -> Tuple[RiskLevel, List[RiskFlag], int]:
    """
    Расчёт риска для Username.

    Returns:
        Tuple[RiskLevel, List[RiskFlag], score]
    """
    flags: List[RiskFlag] = []

    if info is None:
        add_risk_flag(
            flags,
            "USERNAME_ANALYSIS_FAILED",
            RiskLevel.MEDIUM,
            "Не удалось проанализировать username",
            2,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Невалидный формат
    if not info.is_valid:
        add_risk_flag(
            flags,
            "INVALID_USERNAME",
            RiskLevel.MEDIUM,
            "Невалидный формат username",
            UsernameRiskWeight.INVALID_FORMAT,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Подозрительные паттерны (admin, support, etc.)
    impersonation_patterns = [p for p in info.common_patterns if not p.startswith("brand:")]
    brand_patterns = [p.replace("brand:", "") for p in info.common_patterns if p.startswith("brand:")]

    if impersonation_patterns:
        patterns_str = ", ".join(impersonation_patterns[:3])
        add_risk_flag(
            flags,
            "IMPERSONATION_PATTERN",
            RiskLevel.HIGH,
            f"Подозрительные паттерны: {patterns_str}",
            UsernameRiskWeight.IMPERSONATION_PATTERN,
        )

    if brand_patterns:
        brands_str = ", ".join(brand_patterns[:3])
        add_risk_flag(
            flags,
            "BRAND_IMPERSONATION",
            RiskLevel.HIGH,
            f"Возможная имитация бренда: {brands_str}",
            UsernameRiskWeight.BRAND_IMPERSONATION,
        )

    # Анализ присутствия на платформах
    if info.found_count == 0 and info.checked_count > 0:
        add_risk_flag(
            flags,
            "NOT_FOUND_ANYWHERE",
            RiskLevel.MEDIUM,
            f"Не найден ни на одной из {info.checked_count} платформ",
            UsernameRiskWeight.NOT_FOUND_ANYWHERE,
        )
    elif info.found_count == 1:
        platform_name = next(
            (p.platform for p in info.platforms if p.exists),
            "неизвестно"
        )
        add_risk_flag(
            flags,
            "FOUND_SINGLE",
            RiskLevel.LOW,
            f"Найден только на 1 платформе: {platform_name}",
            UsernameRiskWeight.FOUND_FEW,
        )
    elif 1 < info.found_count <= 3:
        found_platforms = [p.platform for p in info.platforms if p.exists]
        add_risk_flag(
            flags,
            "FOUND_FEW",
            RiskLevel.LOW,
            f"Найден на {info.found_count} платформах: {', '.join(found_platforms)}",
            0,  # Нейтральный вес
        )
    elif info.found_count > 3:
        found_platforms = [p.platform for p in info.platforms if p.exists]
        add_risk_flag(
            flags,
            "FOUND_MANY",
            RiskLevel.LOW,
            f"Найден на {info.found_count} платформах: {', '.join(found_platforms[:5])}{'...' if len(found_platforms) > 5 else ''}",
            UsernameRiskWeight.FOUND_MANY,
        )
        # Устоявшееся присутствие
        add_risk_flag(
            flags,
            "ESTABLISHED_PRESENCE",
            RiskLevel.LOW,
            "Устоявшееся присутствие в интернете",
            UsernameRiskWeight.ESTABLISHED_PRESENCE,
        )

    # Рассчитываем итоговый риск
    risk_score = calculate_risk_score(flags)

    return risk_score.level, flags, risk_score.score
