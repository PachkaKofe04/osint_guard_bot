# url_scanner/risk_engine.py
"""Движок оценки рисков для URL."""
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from url_scanner.models import UrlInfo
from utils.risk_types import RiskFlag, RiskLevel, RiskWeight
from utils.risk_scoring import add_risk_flag, calculate_risk_score


# Подозрительные TLD
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",  # Бесплатные домены
    "xyz", "top", "work", "click", "link",
    "buzz", "monster", "rest", "cam",
}

# Подозрительные слова в URL (фишинг-паттерны)
SUSPICIOUS_URL_PATTERNS = [
    r"login", r"signin", r"sign-in",
    r"account", r"verify", r"verification",
    r"secure", r"security", r"update",
    r"confirm", r"password", r"credential",
    r"banking", r"wallet", r"paypal",
    r"apple.*id", r"icloud",
    r"microsoft.*login", r"outlook",
    r"facebook.*login", r"instagram",
    r"google.*sign", r"gmail",
]

# Паттерны обхода (URL encoding, homoglyphs)
OBFUSCATION_PATTERNS = [
    r"%[0-9a-fA-F]{2}",  # URL encoding
    r"@",  # user@domain обман
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP вместо домена
]


class UrlRiskWeight:
    """Веса рисков для URL."""
    # Риски
    VT_MALICIOUS = 5           # VirusTotal: malicious
    VT_SUSPICIOUS = 3          # VirusTotal: suspicious
    MANY_REDIRECTS = 2         # > 3 редиректов
    SHORTENED_URL = 1          # Сокращённая ссылка
    SUSPICIOUS_TLD = 2         # Подозрительный TLD
    SUSPICIOUS_PATTERN = 2     # Фишинг-паттерн в URL
    IP_IN_URL = 3              # IP-адрес вместо домена
    LONG_URL = 1               # Очень длинный URL
    MANY_SUBDOMAINS = 2        # Много поддоменов
    URL_OBFUSCATION = 3        # Обфускация URL
    HTTP_NOT_HTTPS = 1         # HTTP вместо HTTPS

    # Доверие
    KNOWN_SHORTENER = -1       # Известный сокращатель
    VT_CLEAN = -2              # VirusTotal: чисто


def calculate_url_risk(info: Optional[UrlInfo]) -> Tuple[RiskLevel, List[RiskFlag], int]:
    """
    Расчёт риска для URL.

    Returns:
        Tuple[RiskLevel, List[RiskFlag], score]
    """
    flags: List[RiskFlag] = []

    if info is None:
        add_risk_flag(
            flags,
            "URL_UNREACHABLE",
            RiskLevel.MEDIUM,
            "Не удалось получить информацию о URL",
            2,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # VirusTotal результаты
    if info.vt_malicious > 0:
        add_risk_flag(
            flags,
            "VT_MALICIOUS",
            RiskLevel.HIGH,
            f"VirusTotal: {info.vt_malicious} антивирусов считают URL вредоносным",
            UrlRiskWeight.VT_MALICIOUS,
        )
    elif info.vt_suspicious > 0:
        add_risk_flag(
            flags,
            "VT_SUSPICIOUS",
            RiskLevel.MEDIUM,
            f"VirusTotal: {info.vt_suspicious} антивирусов считают URL подозрительным",
            UrlRiskWeight.VT_SUSPICIOUS,
        )
    elif info.vt_total > 0 and info.vt_malicious == 0 and info.vt_suspicious == 0:
        add_risk_flag(
            flags,
            "VT_CLEAN",
            RiskLevel.LOW,
            f"VirusTotal: чисто ({info.vt_total} сканеров)",
            UrlRiskWeight.VT_CLEAN,
        )

    # Сокращённая ссылка
    if info.is_shortened:
        if info.shortener_service:
            add_risk_flag(
                flags,
                "SHORTENED_URL",
                RiskLevel.LOW,
                f"Сокращённая ссылка ({info.shortener_service})",
                UrlRiskWeight.SHORTENED_URL,
            )
        else:
            add_risk_flag(
                flags,
                "SHORTENED_URL_UNKNOWN",
                RiskLevel.MEDIUM,
                "Сокращённая ссылка через неизвестный сервис",
                UrlRiskWeight.SHORTENED_URL + 1,
            )

    # Много редиректов
    if info.redirect_count > 3:
        add_risk_flag(
            flags,
            "MANY_REDIRECTS",
            RiskLevel.MEDIUM,
            f"Много редиректов: {info.redirect_count}",
            UrlRiskWeight.MANY_REDIRECTS,
        )

    # IP-адрес в URL
    if info.has_ip_address:
        add_risk_flag(
            flags,
            "IP_IN_URL",
            RiskLevel.HIGH,
            "URL содержит IP-адрес вместо домена",
            UrlRiskWeight.IP_IN_URL,
        )

    # Подозрительный TLD
    if info.has_suspicious_tld:
        add_risk_flag(
            flags,
            "SUSPICIOUS_TLD",
            RiskLevel.MEDIUM,
            "Подозрительный домен верхнего уровня",
            UrlRiskWeight.SUSPICIOUS_TLD,
        )

    # Много поддоменов
    if info.has_many_subdomains:
        add_risk_flag(
            flags,
            "MANY_SUBDOMAINS",
            RiskLevel.MEDIUM,
            "Много поддоменов (возможная маскировка)",
            UrlRiskWeight.MANY_SUBDOMAINS,
        )

    # Длинный URL
    if info.url_length > 200:
        add_risk_flag(
            flags,
            "LONG_URL",
            RiskLevel.LOW,
            f"Очень длинный URL ({info.url_length} символов)",
            UrlRiskWeight.LONG_URL,
        )

    # HTTP без SSL
    if info.final_url and info.final_url.startswith("http://"):
        add_risk_flag(
            flags,
            "NO_HTTPS",
            RiskLevel.LOW,
            "URL использует HTTP вместо HTTPS",
            UrlRiskWeight.HTTP_NOT_HTTPS,
        )

    # Проверка на фишинг-паттерны в URL
    url_lower = (info.final_url or info.original_url).lower()
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url_lower):
            add_risk_flag(
                flags,
                "PHISHING_PATTERN",
                RiskLevel.MEDIUM,
                f"URL содержит подозрительный паттерн",
                UrlRiskWeight.SUSPICIOUS_PATTERN,
            )
            break

    # Проверка на обфускацию
    if "@" in url_lower.split("://")[-1].split("/")[0]:
        add_risk_flag(
            flags,
            "URL_OBFUSCATION",
            RiskLevel.HIGH,
            "URL содержит символ @ (возможная обфускация)",
            UrlRiskWeight.URL_OBFUSCATION,
        )

    # Рассчитываем итоговый риск
    risk_score = calculate_risk_score(flags)

    return risk_score.level, flags, risk_score.score


def analyze_url_structure(url: str) -> dict:
    """Анализирует структуру URL и возвращает признаки."""
    result = {
        "has_ip_address": False,
        "has_suspicious_tld": False,
        "has_many_subdomains": False,
        "url_length": len(url),
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Убираем порт
        if ":" in domain:
            domain = domain.split(":")[0]

        # IP-адрес?
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, domain):
            result["has_ip_address"] = True

        # TLD
        parts = domain.split(".")
        if parts:
            tld = parts[-1]
            if tld in SUSPICIOUS_TLDS:
                result["has_suspicious_tld"] = True

        # Много поддоменов (> 3 уровня)
        if len(parts) > 4:
            result["has_many_subdomains"] = True

    except Exception:
        pass

    return result
