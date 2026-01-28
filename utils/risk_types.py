# utils/risk_types.py
"""
Единые типы и константы для системы оценки рисков.
"""
from enum import Enum
from typing import List
from pydantic import BaseModel


class RiskLevel(str, Enum):
    """Уровень риска"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RiskWeight:
    """Весовые коэффициенты для различных факторов риска"""

    # Domain risks
    DOMAIN_AGE_VERY_NEW = 2      # < 30 дней
    DOMAIN_AGE_NEW = 1           # < 90 дней
    WHOIS_PRIVACY = 2
    NO_MX_RECORDS = 1
    MINIMAL_ROBOTS = 1
    NO_SITEMAP = 1
    FRESH_SSL_CERT = 1           # < 30 дней
    SINGLE_SAN_DOMAIN = 2        # SAN = 1 домен (фишинг паттерн)
    CLOUDFLARE_ONLY = 1
    NON_STANDARD_NS = 1
    PROXY_DETECTED = 2
    HIGH_RISK_COUNTRY = 2
    WHOIS_MISSING = 1
    DNS_MISSING = 1
    BRAND_IMPERSONATION = 4      # Попытка имитации бренда (фишинг)

    # Phone risks
    PHONE_LENGTH_INVALID = 4
    PHONE_ALL_SAME_DIGITS = 4
    PHONE_LOW_VARIETY = 2
    PHONE_COUNTRY_UNKNOWN = 1
    PHONE_OPERATOR_UNKNOWN = 1
    PHONE_REGION_UNKNOWN = 1
    PHONE_VIRTUAL_OPERATOR = 1   # MNP/виртуальный оператор
    PHONE_LOW_CONFIDENCE = 1     # низкая уверенность определения

    # BIN risks
    BIN_NOT_FOUND = 4
    BIN_PREPAID = 3
    BIN_BANK_UNKNOWN = 1
    BIN_COUNTRY_UNKNOWN = 1

    # Trust signals (negative weights, reduce risk)
    DOMAIN_AGE_VERY_OLD = -4     # > 10 лет
    DOMAIN_AGE_OLD = -3          # > 5 лет
    DOMAIN_AGE_MATURE = -1       # > 1 года
    TRUSTED_ASN = -3
    TRUSTED_BRAND = -3
    MULTI_SAN_SSL = -2           # >= 5 доменов в SAN
    TRUSTED_BANK = -2


class RiskFlag(BaseModel):
    """Флаг риска с детальной информацией"""
    code: str                    # Код флага (например, "NEW_DOMAIN")
    level: RiskLevel             # Уровень серьёзности
    message: str                 # Человекочитаемое описание
    weight: int = 0              # Вес в итоговом score (+2, +3, -2, и т.д.)


class RiskScore(BaseModel):
    """Унифицированная оценка риска"""
    score: int                   # 0-10
    level: RiskLevel             # LOW/MEDIUM/HIGH
    emoji: str                   # 🟢/🟡/🔴
    label: str                   # "Низкий риск" / "Средний риск" / "Высокий риск"
    description: str             # Детальное описание
    flags: List[RiskFlag] = []   # Список всех флагов
    confidence: int = 100        # Уровень уверенности 0-100%


def get_risk_emoji(score: int) -> str:
    """Получить эмодзи по score"""
    if score <= 3:
        return "🟢"
    elif score <= 6:
        return "🟡"
    else:
        return "🔴"


def get_risk_level(score: int) -> RiskLevel:
    """Получить уровень риска по score"""
    if score <= 3:
        return RiskLevel.LOW
    elif score <= 6:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.HIGH


def get_risk_label(level: RiskLevel) -> str:
    """Получить текстовую метку уровня риска"""
    labels = {
        RiskLevel.LOW: "Низкий риск",
        RiskLevel.MEDIUM: "Средний риск",
        RiskLevel.HIGH: "Высокий риск",
    }
    return labels[level]


def get_risk_description(score: int, level: RiskLevel) -> str:
    """Получить детальное описание риска"""
    if level == RiskLevel.LOW:
        return f"{score}/10 — низкий уровень риска. Явных признаков недобросовестности не обнаружено."
    elif level == RiskLevel.MEDIUM:
        return f"{score}/10 — средний уровень риска. Обнаружены подозрительные признаки. Требуется осторожность."
    else:
        return f"{score}/10 — высокий уровень риска. Обнаружены серьёзные признаки недобросовестности. Требуется повышенная осторожность."
