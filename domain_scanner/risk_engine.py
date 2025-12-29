# domain_scanner/risk_engine.py
from datetime import datetime
from typing import List, Optional, Tuple

from domain_scanner.models import (
    DnsInfo,
    HttpInfo,
    SslInfo,
    WhoisInfo,
    IpProfile,
)
from utils.risk_types import RiskFlag, RiskLevel, RiskWeight
from utils.risk_scoring import add_risk_flag, calculate_risk_score

HIGH_RISK_COUNTRIES = {"NG", "PK", "GH", "IR", "KP", "SY"}

TRUSTED_ASN_KEYWORDS = {
    "google",
    "cloudflare",
    "amazon",
    "aws",
    "microsoft",
    "azure",
    "akamai",
    "fastly",
}

TRUSTED_BRAND_KEYWORDS = {
    "facebook",
    "instagram",
    "whatsapp",
    "telegram",
    "vk",
    "vkontakte",
    "twitter",
    "x.com",
    "tiktok",
    "youtube",
    "linkedin",
    "reddit",
    "discord",
    "google",
    "gmail",
    "amazon",
    "apple",
    "icloud",
    "netflix",
    "spotify",
    "yandex",
    "bing",
}


# Удалена старая функция _add_flag, используем новую из utils.risk_scoring


def calculate_risk(
    whois: Optional[WhoisInfo],
    dns: Optional[DnsInfo],
    ssl: Optional[SslInfo],
    http: Optional[HttpInfo],
    ip_profiles: Optional[List[IpProfile]] = None,
) -> Tuple[RiskLevel, List[RiskFlag], int]:

    flags: List[RiskFlag] = []
    now = datetime.utcnow()
    ip_profiles = ip_profiles or []

    # --------------------
    # RISK SIGNALS
    # --------------------

    # WHOIS
    if whois:
        if whois.creation_date:
            age_days = (now - whois.creation_date).days

            # Возраст домена - улучшенная логика
            if age_days < 30:
                add_risk_flag(
                    flags,
                    "DOMAIN_VERY_NEW",
                    RiskLevel.HIGH,
                    f"Домен создан {age_days} дней назад (< 30 дней)",
                    RiskWeight.DOMAIN_AGE_VERY_NEW,
                )
            elif age_days < 90:
                add_risk_flag(
                    flags,
                    "DOMAIN_NEW",
                    RiskLevel.MEDIUM,
                    f"Домен создан {age_days} дней назад (< 90 дней)",
                    RiskWeight.DOMAIN_AGE_NEW,
                )
            # Trust signals - старые домены
            elif age_days > 3650:  # > 10 лет
                add_risk_flag(
                    flags,
                    "DOMAIN_VERY_OLD",
                    RiskLevel.LOW,
                    f"Домен существует {age_days // 365} лет (высокое доверие)",
                    RiskWeight.DOMAIN_AGE_VERY_OLD,
                )
            elif age_days > 1825:  # > 5 лет
                add_risk_flag(
                    flags,
                    "DOMAIN_OLD",
                    RiskLevel.LOW,
                    f"Домен существует {age_days // 365} лет (доверие)",
                    RiskWeight.DOMAIN_AGE_OLD,
                )
            elif age_days > 365:  # > 1 года
                add_risk_flag(
                    flags,
                    "DOMAIN_MATURE",
                    RiskLevel.LOW,
                    f"Домен существует {age_days // 365} год(а)",
                    RiskWeight.DOMAIN_AGE_MATURE,
                )

        if whois.is_privacy_protected:
            add_risk_flag(
                flags,
                "WHOIS_PRIVACY",
                RiskLevel.MEDIUM,
                "Включена защита приватности WHOIS",
                RiskWeight.WHOIS_PRIVACY,
            )
    else:
        add_risk_flag(
            flags,
            "WHOIS_MISSING",
            RiskLevel.LOW,
            "WHOIS-данные недоступны",
            RiskWeight.WHOIS_MISSING,
        )

    # DNS
    if dns:
        if not dns.mx_records:
            add_risk_flag(
                flags,
                "NO_MAIL_INFRA",
                RiskLevel.MEDIUM,
                "Отсутствуют MX-записи",
                RiskWeight.NO_MX_RECORDS,
            )

        # DNS логика - Cloudflare-only detection
        if dns.ns_records:
            cloudflare_ns = [ns for ns in dns.ns_records if "cloudflare" in ns.lower()]
            if cloudflare_ns and len(cloudflare_ns) == len(dns.ns_records):
                add_risk_flag(
                    flags,
                    "CLOUDFLARE_ONLY",
                    RiskLevel.LOW,
                    "Используются только Cloudflare NS (возможно скрытие реального хостинга)",
                    RiskWeight.CLOUDFLARE_ONLY,
                )

            # Нестандартные NS (не популярные провайдеры)
            well_known_ns = ["cloudflare", "google", "amazon", "azure", "route53", "ns-", "dns"]
            unknown_ns = [
                ns for ns in dns.ns_records
                if not any(known in ns.lower() for known in well_known_ns)
            ]
            if unknown_ns:
                add_risk_flag(
                    flags,
                    "NON_STANDARD_NS",
                    RiskLevel.LOW,
                    f"Нестандартные NS-серверы: {', '.join(unknown_ns[:2])}",
                    RiskWeight.NON_STANDARD_NS,
                )
    else:
        add_risk_flag(
            flags,
            "DNS_MISSING",
            RiskLevel.LOW,
            "DNS-записи недоступны",
            RiskWeight.DNS_MISSING,
        )

    # SSL анализ - улучшенная логика
    if ssl:
        # SSL сертификат как индикатор возраста домена
        if ssl.first_seen:
            ssl_age_days = (now - ssl.first_seen).days

            # Свежий сертификат (< 30 дней)
            if ssl_age_days < 30:
                add_risk_flag(
                    flags,
                    "FRESH_SSL_CERT",
                    RiskLevel.LOW,
                    f"SSL сертификат выдан {ssl_age_days} дней назад (< 30 дней)",
                    RiskWeight.FRESH_SSL_CERT,
                )
            # Trust signal - очень старый SSL (если WHOIS недоступен)
            elif ssl_age_days > 3650 and not whois:  # > 10 лет и нет WHOIS
                add_risk_flag(
                    flags,
                    "SSL_VERY_OLD",
                    RiskLevel.LOW,
                    f"SSL сертификат существует {ssl_age_days // 365} лет (высокое доверие)",
                    RiskWeight.DOMAIN_AGE_VERY_OLD,  # -4 как у старого домена
                )
            elif ssl_age_days > 1825 and not whois:  # > 5 лет и нет WHOIS
                add_risk_flag(
                    flags,
                    "SSL_OLD",
                    RiskLevel.LOW,
                    f"SSL сертификат существует {ssl_age_days // 365} лет (доверие)",
                    RiskWeight.DOMAIN_AGE_OLD,  # -3
                )

        # SAN = 1 домен (часто фишинг)
        if ssl.san_domains:
            unique_sans = set(ssl.san_domains)
            if len(unique_sans) == 1:
                add_risk_flag(
                    flags,
                    "SINGLE_SAN_DOMAIN",
                    RiskLevel.MEDIUM,
                    "SSL сертификат выдан только на 1 домен (фишинг паттерн)",
                    RiskWeight.SINGLE_SAN_DOMAIN,
                )
            elif len(unique_sans) >= 5:
                # Trust signal - мультидоменный сертификат
                add_risk_flag(
                    flags,
                    "MULTI_SAN_SSL",
                    RiskLevel.LOW,
                    f"SSL сертификат покрывает {len(unique_sans)} доменов (доверие)",
                    RiskWeight.MULTI_SAN_SSL,
                )

    # HTTP / robots
    if http:
        if http.robots_exists and http.robots_disallow_all:
            add_risk_flag(
                flags,
                "MINIMAL_ROBOTS",
                RiskLevel.MEDIUM,
                "robots.txt содержит Disallow: /",
                RiskWeight.MINIMAL_ROBOTS,
            )

        if http.robots_exists and not http.robots_has_sitemap:
            add_risk_flag(
                flags,
                "NO_SITEMAP",
                RiskLevel.LOW,
                "Отсутствует sitemap в robots.txt",
                RiskWeight.NO_SITEMAP,
            )

    # IP / Hosting
    for ip in ip_profiles:
        if ip.proxy:
            add_risk_flag(
                flags,
                "PROXY_DETECTED",
                RiskLevel.MEDIUM,
                "Обнаружен proxy/VPN хостинг",
                RiskWeight.PROXY_DETECTED,
            )
            break

    for ip in ip_profiles:
        if ip.country_code and ip.country_code.upper() in HIGH_RISK_COUNTRIES:
            add_risk_flag(
                flags,
                "HIGH_RISK_COUNTRY",
                RiskLevel.MEDIUM,
                f"Хостинг в стране повышенного риска: {ip.country}",
                RiskWeight.HIGH_RISK_COUNTRY,
            )
            break

    # --------------------
    # TRUST SIGNALS
    # --------------------

    # ASN / ISP trust
    for ip in ip_profiles:
        if ip.asname:
            asname_lower = ip.asname.lower()
            if any(k in asname_lower for k in TRUSTED_ASN_KEYWORDS):
                add_risk_flag(
                    flags,
                    "TRUSTED_ASN",
                    RiskLevel.LOW,
                    f"Хостинг у доверенного провайдера: {ip.asname}",
                    RiskWeight.TRUSTED_ASN,
                )
                break

    # Trusted brand in domain name
    domain_candidates = []
    if ssl and ssl.san_domains:
        domain_candidates.extend(ssl.san_domains)

    for d in domain_candidates:
        d_low = d.lower()
        if any(b in d_low for b in TRUSTED_BRAND_KEYWORDS):
            add_risk_flag(
                flags,
                "TRUSTED_BRAND",
                RiskLevel.LOW,
                "Домен совпадает с известным брендом/соцсетью",
                RiskWeight.TRUSTED_BRAND,
            )
            break

    # --------------------
    # FINAL SCORE
    # --------------------

    # Используем новую unified систему подсчёта
    risk_score = calculate_risk_score(flags)

    return risk_score.level, flags, risk_score.score
