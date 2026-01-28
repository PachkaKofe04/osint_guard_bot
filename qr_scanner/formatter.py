# qr_scanner/formatter.py
"""Форматирование результатов QR сканера для Telegram."""
from qr_scanner.models import QrScanResult, QrContentType
from utils.risk_types import get_risk_emoji, get_risk_label, RiskLevel


def format_qr_result(result: QrScanResult) -> str:
    """
    Форматирует результат сканирования QR для Telegram.

    Args:
        result: Результат сканирования

    Returns:
        Отформатированная строка с HTML разметкой
    """
    emoji = get_risk_emoji(result.score)
    level_label = get_risk_label(result.risk_level)

    lines = []
    lines.append("📱 <b>Анализ QR кода</b>")
    lines.append("")

    # Риск
    lines.append(f"{emoji} <b>{level_label}</b> (оценка: {result.score}/10)")
    lines.append("")

    if not result.found_qr:
        lines.append("ℹ️ QR код не найден на изображении.")
        lines.append("")
        lines.append("💡 <i>Убедитесь, что:")
        lines.append("• QR код чёткий и не размытый")
        lines.append("• Изображение достаточного качества")
        lines.append("• QR код полностью виден на фото</i>")

    elif result.info:
        info = result.info

        # Тип контента
        type_labels = {
            QrContentType.URL: "🔗 Ссылка (URL)",
            QrContentType.EMAIL: "📧 Email",
            QrContentType.PHONE: "📞 Телефон",
            QrContentType.SMS: "💬 SMS",
            QrContentType.WIFI: "📶 WiFi",
            QrContentType.VCARD: "👤 Контакт",
            QrContentType.GEO: "📍 Геолокация",
            QrContentType.CRYPTO: "💰 Криптовалюта",
            QrContentType.TEXT: "📝 Текст",
            QrContentType.UNKNOWN: "❓ Неизвестно",
        }
        type_label = type_labels.get(info.content_type, "Данные")
        lines.append(f"<b>Тип:</b> {type_label}")
        lines.append("")

        # Содержимое по типу
        if info.content_type == QrContentType.URL:
            _format_url_content(info, lines)

        elif info.content_type == QrContentType.WIFI:
            _format_wifi_content(info, lines)

        elif info.content_type == QrContentType.CRYPTO:
            _format_crypto_content(info, lines)

        elif info.content_type == QrContentType.EMAIL:
            lines.append(f"<b>Email:</b> <code>{info.email}</code>")

        elif info.content_type == QrContentType.PHONE:
            lines.append(f"<b>Телефон:</b> <code>{info.phone}</code>")

        elif info.content_type == QrContentType.GEO:
            lines.append(f"<b>Координаты:</b>")
            lines.append(f"  Широта: {info.geo_lat}")
            lines.append(f"  Долгота: {info.geo_lon}")
            if info.geo_lat and info.geo_lon:
                maps_url = f"https://www.google.com/maps?q={info.geo_lat},{info.geo_lon}"
                lines.append(f"  <a href=\"{maps_url}\">📍 Открыть в Google Maps</a>")

        elif info.content_type == QrContentType.VCARD:
            lines.append("<b>Контактная карточка (vCard)</b>")
            lines.append("")
            # Показываем часть данных
            if len(info.raw_data) > 200:
                lines.append(f"<code>{info.raw_data[:200]}...</code>")
            else:
                lines.append(f"<code>{info.raw_data}</code>")

        else:  # TEXT и другие
            lines.append("<b>Содержимое:</b>")
            # Ограничиваем длину
            content = info.raw_data
            if len(content) > 500:
                content = content[:500] + "..."
            lines.append(f"<code>{content}</code>")

        lines.append("")

        # Количество QR кодов
        if info.decoded_count > 1:
            lines.append(f"ℹ️ <i>Найдено QR кодов: {info.decoded_count}</i>")
            lines.append("")

    # Флаги
    if result.flags:
        lines.append("📋 <b>Детали анализа:</b>")
        for flag in result.flags:
            if flag.code in ("CONTENT_TYPE", "NO_QR_FOUND"):
                continue  # Пропускаем дублирующую информацию
            if flag.level == RiskLevel.HIGH:
                flag_emoji = "🔴"
            elif flag.level == RiskLevel.MEDIUM:
                flag_emoji = "🟡"
            else:
                flag_emoji = "🟢"
            lines.append(f"  {flag_emoji} {flag.message}")

    return "\n".join(lines)


def _format_url_content(info, lines: list) -> None:
    """Форматирование URL контента."""
    lines.append(f"<b>Ссылка:</b>")
    lines.append(f"<code>{info.url}</code>")
    lines.append("")

    if info.url_domain:
        lines.append(f"<b>Домен:</b> {info.url_domain}")

    # Предупреждения
    warnings = []
    if info.url_looks_phishy:
        warnings.append("🚨 <b>Признаки фишинга!</b>")
    if info.url_has_suspicious_tld:
        warnings.append("⚠️ Подозрительный домен")
    if info.url_is_shortened:
        warnings.append("⚠️ Сокращённая ссылка")

    if warnings:
        lines.append("")
        for w in warnings:
            lines.append(w)
        lines.append("")
        lines.append("💡 <i>Рекомендуется проверить ссылку перед переходом</i>")


def _format_wifi_content(info, lines: list) -> None:
    """Форматирование WiFi контента."""
    wifi = info.wifi
    if wifi:
        if wifi.ssid:
            lines.append(f"<b>Сеть:</b> {wifi.ssid}")
        if wifi.security:
            lines.append(f"<b>Защита:</b> {wifi.security.upper()}")
        if wifi.password:
            lines.append(f"<b>Пароль:</b> <tg-spoiler>{wifi.password}</tg-spoiler>")
        if wifi.hidden:
            lines.append("<i>Скрытая сеть</i>")
    else:
        lines.append("<code>" + info.raw_data + "</code>")


def _format_crypto_content(info, lines: list) -> None:
    """Форматирование крипто контента."""
    if info.crypto_address:
        # Определяем тип
        addr = info.crypto_address
        if addr.startswith("0x"):
            crypto_type = "Ethereum"
            explorer = f"https://etherscan.io/address/{addr}"
        elif addr.startswith(("1", "3", "bc1")):
            crypto_type = "Bitcoin"
            explorer = f"https://www.blockchain.com/btc/address/{addr}"
        else:
            crypto_type = "Криптовалюта"
            explorer = None

        lines.append(f"<b>Тип:</b> {crypto_type}")
        lines.append(f"<b>Адрес:</b>")
        lines.append(f"<code>{addr}</code>")

        if info.crypto_amount:
            lines.append(f"<b>Сумма:</b> {info.crypto_amount}")
            lines.append("")
            lines.append("⚠️ <b>Внимание!</b> QR код запрашивает перевод средств.")
            lines.append("Убедитесь, что вы знаете получателя!")

        if explorer:
            lines.append("")
            lines.append(f"🔍 <a href=\"{explorer}\">Проверить адрес</a>")
