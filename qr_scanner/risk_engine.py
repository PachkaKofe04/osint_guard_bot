# qr_scanner/risk_engine.py
"""Движок оценки рисков для QR сканера."""
from typing import List, Optional, Tuple

from qr_scanner.models import QrInfo, QrContentType
from utils.risk_types import RiskFlag, RiskLevel
from utils.risk_scoring import add_risk_flag, calculate_risk_score


class QrRiskWeight:
    """Веса рисков для QR кодов."""
    # Высокие риски
    PHISHING_URL = 6          # Фишинговый URL
    SUSPICIOUS_TLD = 4        # Подозрительный TLD
    SHORTENED_URL = 3         # Сокращённая ссылка

    # Средние риски
    CRYPTO_PAYMENT = 3        # Запрос крипто-платежа
    WIFI_WITH_PASSWORD = 2    # WiFi с паролем
    UNKNOWN_URL = 2           # Неизвестный URL

    # Низкие риски
    SAFE_CONTENT = -1         # Безопасный контент


def calculate_qr_risk(
    info: Optional[QrInfo],
    no_qr_found: bool = False,
    library_error: bool = False,
) -> Tuple[RiskLevel, List[RiskFlag], int]:
    """
    Расчёт риска по содержимому QR кода.

    Returns:
        Tuple[RiskLevel, List[RiskFlag], score]
    """
    flags: List[RiskFlag] = []

    # Ошибка библиотеки
    if library_error:
        add_risk_flag(
            flags,
            "QR_LIBRARY_ERROR",
            RiskLevel.MEDIUM,
            "Библиотека pyzbar недоступна",
            2,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # QR код не найден
    if no_qr_found or info is None:
        add_risk_flag(
            flags,
            "NO_QR_FOUND",
            RiskLevel.LOW,
            "QR код не найден на изображении",
            0,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Несколько QR кодов
    if info.decoded_count > 1:
        add_risk_flag(
            flags,
            "MULTIPLE_QR",
            RiskLevel.LOW,
            f"Найдено {info.decoded_count} QR кода(ов)",
            0,
        )

    # Анализ по типу контента
    if info.content_type == QrContentType.URL:
        _analyze_url_risk(info, flags)

    elif info.content_type == QrContentType.WIFI:
        _analyze_wifi_risk(info, flags)

    elif info.content_type == QrContentType.CRYPTO:
        _analyze_crypto_risk(info, flags)

    elif info.content_type == QrContentType.EMAIL:
        add_risk_flag(
            flags,
            "EMAIL_CONTENT",
            RiskLevel.LOW,
            f"Email адрес: {info.email}",
            QrRiskWeight.SAFE_CONTENT,
        )

    elif info.content_type == QrContentType.PHONE:
        add_risk_flag(
            flags,
            "PHONE_CONTENT",
            RiskLevel.LOW,
            f"Телефон: {info.phone}",
            0,
        )

    elif info.content_type == QrContentType.GEO:
        add_risk_flag(
            flags,
            "GEO_CONTENT",
            RiskLevel.LOW,
            f"Координаты: {info.geo_lat}, {info.geo_lon}",
            0,
        )

    elif info.content_type == QrContentType.VCARD:
        add_risk_flag(
            flags,
            "VCARD_CONTENT",
            RiskLevel.LOW,
            "Контактная карточка (vCard)",
            QrRiskWeight.SAFE_CONTENT,
        )

    elif info.content_type == QrContentType.SMS:
        add_risk_flag(
            flags,
            "SMS_CONTENT",
            RiskLevel.MEDIUM,
            "SMS сообщение — проверьте номер получателя",
            1,
        )

    else:  # TEXT или UNKNOWN
        add_risk_flag(
            flags,
            "TEXT_CONTENT",
            RiskLevel.LOW,
            f"Текст ({info.data_length} символов)",
            0,
        )

    # Информация о типе контента
    add_risk_flag(
        flags,
        "CONTENT_TYPE",
        RiskLevel.LOW,
        f"Тип: {info.content_type.value}",
        0,
    )

    # Рассчитываем итоговый риск
    risk_score = calculate_risk_score(flags)

    return risk_score.level, flags, risk_score.score


def _analyze_url_risk(info: QrInfo, flags: List[RiskFlag]) -> None:
    """Анализ рисков URL."""

    # Фишинговый URL
    if info.url_looks_phishy:
        add_risk_flag(
            flags,
            "PHISHING_URL",
            RiskLevel.HIGH,
            "⚠️ URL имеет признаки фишинга!",
            QrRiskWeight.PHISHING_URL,
        )

    # Подозрительный TLD
    if info.url_has_suspicious_tld:
        add_risk_flag(
            flags,
            "SUSPICIOUS_TLD",
            RiskLevel.HIGH,
            "Подозрительный домен верхнего уровня",
            QrRiskWeight.SUSPICIOUS_TLD,
        )

    # Сокращённая ссылка
    if info.url_is_shortened:
        add_risk_flag(
            flags,
            "SHORTENED_URL",
            RiskLevel.MEDIUM,
            "Сокращённая ссылка — конечный URL скрыт",
            QrRiskWeight.SHORTENED_URL,
        )
    else:
        add_risk_flag(
            flags,
            "URL_CONTENT",
            RiskLevel.LOW,
            f"URL: {info.url_domain or info.url}",
            QrRiskWeight.UNKNOWN_URL if not info.url_domain else 0,
        )


def _analyze_wifi_risk(info: QrInfo, flags: List[RiskFlag]) -> None:
    """Анализ рисков WiFi."""
    wifi = info.wifi

    if wifi:
        if wifi.ssid:
            add_risk_flag(
                flags,
                "WIFI_SSID",
                RiskLevel.LOW,
                f"WiFi сеть: {wifi.ssid}",
                0,
            )

        if wifi.password:
            add_risk_flag(
                flags,
                "WIFI_PASSWORD",
                RiskLevel.MEDIUM,
                "⚠️ Содержит пароль WiFi",
                QrRiskWeight.WIFI_WITH_PASSWORD,
            )

        if wifi.security:
            security_label = wifi.security.upper()
            if security_label == "NOPASS":
                add_risk_flag(
                    flags,
                    "WIFI_OPEN",
                    RiskLevel.MEDIUM,
                    "Открытая сеть без пароля",
                    1,
                )
            else:
                add_risk_flag(
                    flags,
                    "WIFI_SECURITY",
                    RiskLevel.LOW,
                    f"Защита: {security_label}",
                    0,
                )


def _analyze_crypto_risk(info: QrInfo, flags: List[RiskFlag]) -> None:
    """Анализ рисков крипто-адреса."""

    if info.crypto_address:
        # Определяем тип криптовалюты
        addr = info.crypto_address
        if addr.startswith("0x"):
            crypto_type = "Ethereum"
        elif addr.startswith("bc1"):
            crypto_type = "Bitcoin (SegWit)"
        elif addr.startswith("3"):
            crypto_type = "Bitcoin (P2SH)"
        elif addr.startswith("1"):
            crypto_type = "Bitcoin (Legacy)"
        else:
            crypto_type = "Криптовалюта"

        add_risk_flag(
            flags,
            "CRYPTO_ADDRESS",
            RiskLevel.MEDIUM,
            f"{crypto_type}: {addr[:16]}...",
            QrRiskWeight.CRYPTO_PAYMENT,
        )

    if info.crypto_amount:
        add_risk_flag(
            flags,
            "CRYPTO_AMOUNT",
            RiskLevel.HIGH,
            f"⚠️ Запрос на сумму: {info.crypto_amount}",
            2,
        )
