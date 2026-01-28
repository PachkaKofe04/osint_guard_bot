# email_scanner/risk_engine.py
"""Движок оценки рисков для Email."""
from typing import List, Optional, Tuple

from email_scanner.models import EmailInfo
from utils.risk_types import RiskFlag, RiskLevel
from utils.risk_scoring import add_risk_flag, calculate_risk_score


class EmailRiskWeight:
    """Веса рисков для Email."""
    # Высокие риски
    DISPOSABLE_EMAIL = 4      # Одноразовый email
    NO_MX_RECORDS = 3         # Нет MX записей
    INVALID_FORMAT = 5        # Невалидный формат
    MANY_BREACHES = 3         # Много утечек (>5)

    # Средние риски
    FEW_BREACHES = 2          # Несколько утечек (1-5)
    SUSPICIOUS_DOMAIN = 2     # Подозрительный домен
    NEW_DOMAIN = 2            # Новый домен (<30 дней)

    # Низкие риски
    FREE_PROVIDER = 1         # Бесплатный провайдер

    # Доверие
    CORPORATE_EMAIL = -2      # Корпоративный email
    KNOWN_PROVIDER = -1       # Известный провайдер
    NO_BREACHES = -1          # Нет утечек


def calculate_email_risk(info: Optional[EmailInfo]) -> Tuple[RiskLevel, List[RiskFlag], int]:
    """
    Расчёт риска для Email.

    Returns:
        Tuple[RiskLevel, List[RiskFlag], score]
    """
    flags: List[RiskFlag] = []

    if info is None:
        add_risk_flag(
            flags,
            "EMAIL_ANALYSIS_FAILED",
            RiskLevel.MEDIUM,
            "Не удалось проанализировать email",
            2,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Невалидный формат
    if not info.is_valid_format:
        add_risk_flag(
            flags,
            "INVALID_FORMAT",
            RiskLevel.HIGH,
            "Невалидный формат email",
            EmailRiskWeight.INVALID_FORMAT,
        )

    # Одноразовый email — высокий риск
    if info.is_disposable:
        add_risk_flag(
            flags,
            "DISPOSABLE_EMAIL",
            RiskLevel.HIGH,
            "Одноразовый (временный) email — часто используется для мошенничества",
            EmailRiskWeight.DISPOSABLE_EMAIL,
        )

    # Нет MX записей — домен не принимает почту
    if not info.has_mx_records:
        add_risk_flag(
            flags,
            "NO_MX_RECORDS",
            RiskLevel.HIGH,
            "Домен не имеет MX записей — не может принимать почту",
            EmailRiskWeight.NO_MX_RECORDS,
        )

    # Утечки данных
    if info.breach_count > 5:
        breaches_str = ", ".join(info.breaches[:3])
        if len(info.breaches) > 3:
            breaches_str += f" и ещё {len(info.breaches) - 3}"
        add_risk_flag(
            flags,
            "MANY_BREACHES",
            RiskLevel.HIGH,
            f"Email найден в {info.breach_count} утечках: {breaches_str}",
            EmailRiskWeight.MANY_BREACHES,
        )
    elif info.breach_count > 0:
        breaches_str = ", ".join(info.breaches[:3])
        add_risk_flag(
            flags,
            "FEW_BREACHES",
            RiskLevel.MEDIUM,
            f"Email найден в {info.breach_count} утечках: {breaches_str}",
            EmailRiskWeight.FEW_BREACHES,
        )
    else:
        add_risk_flag(
            flags,
            "NO_BREACHES",
            RiskLevel.LOW,
            "Email не найден в известных утечках",
            EmailRiskWeight.NO_BREACHES,
        )

    # Возраст домена
    if info.domain_age_days is not None and info.domain_age_days < 30:
        add_risk_flag(
            flags,
            "NEW_DOMAIN",
            RiskLevel.MEDIUM,
            f"Домен создан недавно ({info.domain_age_days} дней назад)",
            EmailRiskWeight.NEW_DOMAIN,
        )

    # Бесплатный провайдер
    if info.is_free_provider and not info.is_disposable:
        add_risk_flag(
            flags,
            "FREE_PROVIDER",
            RiskLevel.LOW,
            f"Бесплатный email провайдер: {info.provider_name or info.domain}",
            EmailRiskWeight.FREE_PROVIDER,
        )

    # Корпоративный email — доверие
    if info.is_corporate:
        add_risk_flag(
            flags,
            "CORPORATE_EMAIL",
            RiskLevel.LOW,
            "Корпоративный email",
            EmailRiskWeight.CORPORATE_EMAIL,
        )

    # Известный провайдер
    if info.provider_name and not info.is_disposable and info.has_mx_records:
        add_risk_flag(
            flags,
            "KNOWN_PROVIDER",
            RiskLevel.LOW,
            f"Известный провайдер: {info.provider_name}",
            EmailRiskWeight.KNOWN_PROVIDER,
        )

    # Рассчитываем итоговый риск
    risk_score = calculate_risk_score(flags)

    return risk_score.level, flags, risk_score.score
