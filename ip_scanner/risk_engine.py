# ip_scanner/risk_engine.py
"""Движок оценки рисков для IP."""
from typing import List, Optional, Tuple

from ip_scanner.models import IpInfo
from utils.risk_types import RiskFlag, RiskLevel
from utils.risk_scoring import add_risk_flag, calculate_risk_score


# Страны повышенного риска (по фишингу и мошенничеству)
HIGH_RISK_COUNTRIES = {
    "NG",  # Nigeria
    "CN",  # China
    "RU",  # Russia (для некоторых контекстов)
    "IN",  # India
    "PK",  # Pakistan
    "BD",  # Bangladesh
    "VN",  # Vietnam
    "PH",  # Philippines
    "ID",  # Indonesia
    "UA",  # Ukraine
    "RO",  # Romania
    "BG",  # Bulgaria
}

# Доверенные облачные провайдеры
TRUSTED_PROVIDERS = {
    "google", "amazon", "microsoft", "cloudflare",
    "akamai", "fastly", "digitalocean", "linode",
    "ovh", "hetzner", "vultr",
}


class IpRiskWeight:
    """Веса рисков для IP."""
    # Высокие риски
    TOR_EXIT = 5              # TOR exit node
    VPN_PROXY = 3             # VPN или Proxy
    HIGH_ABUSE_SCORE = 4      # Высокий abuse score (>75)
    BLACKLISTED = 5           # В чёрном списке
    HIGH_RISK_COUNTRY = 2     # Страна повышенного риска

    # Средние риски
    HOSTING_IP = 2            # Хостинг провайдер (не резиденциальный)
    MEDIUM_ABUSE_SCORE = 2    # Средний abuse score (25-75)

    # Низкие риски
    PRIVATE_IP = 1            # Приватный IP

    # Доверие
    TRUSTED_PROVIDER = -2     # Доверенный провайдер
    CLEAN_IP = -1             # Чистый IP


def calculate_ip_risk(info: Optional[IpInfo]) -> Tuple[RiskLevel, List[RiskFlag], int]:
    """
    Расчёт риска для IP адреса.

    Returns:
        Tuple[RiskLevel, List[RiskFlag], score]
    """
    flags: List[RiskFlag] = []

    if info is None:
        add_risk_flag(
            flags,
            "IP_ANALYSIS_FAILED",
            RiskLevel.MEDIUM,
            "Не удалось проанализировать IP адрес",
            2,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Невалидный IP
    if not info.is_valid:
        add_risk_flag(
            flags,
            "INVALID_IP",
            RiskLevel.HIGH,
            "Невалидный формат IP адреса",
            5,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Приватный IP
    if info.is_private:
        add_risk_flag(
            flags,
            "PRIVATE_IP",
            RiskLevel.LOW,
            "Приватный (локальный) IP адрес",
            IpRiskWeight.PRIVATE_IP,
        )

    # Зарезервированный IP
    if info.is_reserved:
        add_risk_flag(
            flags,
            "RESERVED_IP",
            RiskLevel.LOW,
            "Зарезервированный IP адрес",
            0,
        )

    # TOR exit node — очень высокий риск
    if info.is_tor:
        add_risk_flag(
            flags,
            "TOR_EXIT_NODE",
            RiskLevel.HIGH,
            "TOR exit node — часто используется для анонимизации злоумышленников",
            IpRiskWeight.TOR_EXIT,
        )

    # VPN/Proxy — высокий риск
    if info.is_vpn or info.is_proxy:
        proxy_type = "VPN" if info.is_vpn else "Proxy"
        add_risk_flag(
            flags,
            "VPN_PROXY",
            RiskLevel.MEDIUM,
            f"{proxy_type} обнаружен — IP может скрывать реальное местоположение",
            IpRiskWeight.VPN_PROXY,
        )

    # Чёрный список
    if info.is_blacklisted:
        add_risk_flag(
            flags,
            "IP_BLACKLISTED",
            RiskLevel.HIGH,
            "IP в чёрном списке (спам, атаки)",
            IpRiskWeight.BLACKLISTED,
        )

    # Abuse score
    if info.abuse_score is not None:
        if info.abuse_score > 75:
            add_risk_flag(
                flags,
                "HIGH_ABUSE_SCORE",
                RiskLevel.HIGH,
                f"Высокий abuse score: {info.abuse_score}% — много жалоб на этот IP",
                IpRiskWeight.HIGH_ABUSE_SCORE,
            )
        elif info.abuse_score > 25:
            add_risk_flag(
                flags,
                "MEDIUM_ABUSE_SCORE",
                RiskLevel.MEDIUM,
                f"Средний abuse score: {info.abuse_score}%",
                IpRiskWeight.MEDIUM_ABUSE_SCORE,
            )

    # Хостинг провайдер
    if info.is_hosting and not info.is_private:
        add_risk_flag(
            flags,
            "HOSTING_IP",
            RiskLevel.MEDIUM,
            "Хостинг/датацентр — не резиденциальный IP",
            IpRiskWeight.HOSTING_IP,
        )

    # Страна повышенного риска
    if info.country_code and info.country_code.upper() in HIGH_RISK_COUNTRIES:
        add_risk_flag(
            flags,
            "HIGH_RISK_COUNTRY",
            RiskLevel.MEDIUM,
            f"Страна повышенного риска: {info.country}",
            IpRiskWeight.HIGH_RISK_COUNTRY,
        )

    # Доверенный провайдер
    if info.asname or info.org:
        provider_name = (info.asname or info.org or "").lower()
        for trusted in TRUSTED_PROVIDERS:
            if trusted in provider_name:
                add_risk_flag(
                    flags,
                    "TRUSTED_PROVIDER",
                    RiskLevel.LOW,
                    f"Доверенный провайдер: {info.asname or info.org}",
                    IpRiskWeight.TRUSTED_PROVIDER,
                )
                break

    # Чистый IP (нет VPN, не proxy, не TOR, низкий abuse)
    if (not info.is_vpn and not info.is_proxy and not info.is_tor and
        not info.is_blacklisted and (info.abuse_score is None or info.abuse_score < 25)):
        add_risk_flag(
            flags,
            "CLEAN_IP",
            RiskLevel.LOW,
            "Чистый IP без признаков proxy/VPN",
            IpRiskWeight.CLEAN_IP,
        )

    # Геолокация успешна
    if info.country and info.city:
        add_risk_flag(
            flags,
            "GEO_RESOLVED",
            RiskLevel.LOW,
            f"Геолокация: {info.city}, {info.country}",
            0,
        )

    # Рассчитываем итоговый риск
    risk_score = calculate_risk_score(flags)

    return risk_score.level, flags, risk_score.score
