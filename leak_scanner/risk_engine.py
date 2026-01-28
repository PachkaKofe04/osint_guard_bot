# leak_scanner/risk_engine.py
"""Движок оценки рисков для Leak сканера."""
from typing import List, Optional, Tuple

from leak_scanner.models import LeakInfo
from utils.risk_types import RiskFlag, RiskLevel
from utils.risk_scoring import add_risk_flag, calculate_risk_score


class LeakRiskWeight:
    """Веса рисков для утечек."""
    # Высокие риски
    MANY_BREACHES = 5         # Много утечек (5+)
    PASSWORD_LEAKED = 4       # Утечка паролей
    SENSITIVE_BREACH = 4      # Чувствительные данные

    # Средние риски
    FEW_BREACHES = 3          # Несколько утечек (1-4)
    RECENT_BREACH = 2         # Недавняя утечка

    # Доверие
    NO_BREACHES = -2          # Нет утечек


def calculate_leak_risk(info: Optional[LeakInfo]) -> Tuple[RiskLevel, List[RiskFlag], int]:
    """
    Расчёт риска по утечкам.

    Returns:
        Tuple[RiskLevel, List[RiskFlag], score]
    """
    flags: List[RiskFlag] = []

    if info is None:
        add_risk_flag(
            flags,
            "LEAK_CHECK_FAILED",
            RiskLevel.MEDIUM,
            "Не удалось проверить на утечки",
            2,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Нет утечек — отлично
    if not info.is_pwned:
        add_risk_flag(
            flags,
            "NO_BREACHES_FOUND",
            RiskLevel.LOW,
            "Не найден в известных утечках данных",
            LeakRiskWeight.NO_BREACHES,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Есть утечки
    if info.breach_count >= 5:
        add_risk_flag(
            flags,
            "MANY_BREACHES",
            RiskLevel.HIGH,
            f"Найден в {info.breach_count} утечках данных!",
            LeakRiskWeight.MANY_BREACHES,
        )
    elif info.breach_count >= 1:
        add_risk_flag(
            flags,
            "FEW_BREACHES",
            RiskLevel.MEDIUM,
            f"Найден в {info.breach_count} утечке(ах) данных",
            LeakRiskWeight.FEW_BREACHES,
        )

    # Проверяем типы утечек
    all_data_classes = set()
    has_sensitive = False

    for breach in info.breaches:
        all_data_classes.update(breach.data_classes)
        if breach.is_sensitive:
            has_sensitive = True

    # Утечка паролей — высокий риск
    password_keywords = ["Passwords", "Password", "Hashed passwords"]
    if any(kw in all_data_classes for kw in password_keywords):
        add_risk_flag(
            flags,
            "PASSWORD_LEAKED",
            RiskLevel.HIGH,
            "⚠️ Пароли были в утечке! Рекомендуется сменить пароли",
            LeakRiskWeight.PASSWORD_LEAKED,
        )

    # Чувствительные данные
    if has_sensitive:
        add_risk_flag(
            flags,
            "SENSITIVE_DATA",
            RiskLevel.HIGH,
            "Чувствительные данные в утечке",
            LeakRiskWeight.SENSITIVE_BREACH,
        )

    # Информация о типах данных
    if all_data_classes:
        data_str = ", ".join(list(all_data_classes)[:5])
        add_risk_flag(
            flags,
            "DATA_TYPES",
            RiskLevel.MEDIUM,
            f"Утекшие данные: {data_str}",
            0,
        )

    # Список утечек
    if info.breaches:
        breach_names = [b.title or b.name for b in info.breaches[:5]]
        add_risk_flag(
            flags,
            "BREACH_LIST",
            RiskLevel.MEDIUM,
            f"Утечки: {', '.join(breach_names)}",
            0,
        )

    # Рассчитываем итоговый риск
    risk_score = calculate_risk_score(flags)

    return risk_score.level, flags, risk_score.score
