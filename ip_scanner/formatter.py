# ip_scanner/formatter.py
"""Форматирование результатов сканирования IP для Telegram."""
from ip_scanner.models import IpScanResult
from utils.risk_types import get_risk_emoji, get_risk_label, RiskLevel


def format_ip_result(result: IpScanResult) -> str:
    """
    Форматирует результат сканирования IP для отправки в Telegram.

    Args:
        result: Результат сканирования

    Returns:
        Отформатированная строка с HTML разметкой
    """
    info = result.info
    emoji = get_risk_emoji(result.score)
    level_label = get_risk_label(result.risk_level)

    lines = []
    lines.append(f"🔍 <b>Анализ IP адреса</b>")
    lines.append(f"<code>{result.ip}</code>")
    lines.append("")

    # Риск
    lines.append(f"{emoji} <b>{level_label}</b> (оценка: {result.score}/10)")
    lines.append("")

    if info:
        # Статус валидности
        if not info.is_valid:
            lines.append("❌ <b>Невалидный IP адрес</b>")
            lines.append("")
        elif info.is_private:
            lines.append("🏠 <b>Приватный IP адрес</b>")
            lines.append("Локальный IP, не виден в интернете")
            lines.append("")
        elif info.is_reserved:
            lines.append("⚙️ <b>Зарезервированный IP</b>")
            lines.append("")
        else:
            # Геолокация
            lines.append("📍 <b>Геолокация:</b>")
            if info.country:
                location_parts = []
                if info.city:
                    location_parts.append(info.city)
                location_parts.append(info.country)
                if info.country_code:
                    location_parts.append(f"({info.country_code})")
                lines.append(f"    {' '.join(location_parts)}")
            else:
                lines.append("    Не определено")
            lines.append("")

            # Сетевая информация
            lines.append("🌐 <b>Сетевая информация:</b>")
            if info.isp:
                lines.append(f"    ISP: {info.isp}")
            if info.org:
                lines.append(f"    Организация: {info.org}")
            if info.asn:
                lines.append(f"    ASN: {info.asn}")
            if info.asname:
                lines.append(f"    AS Name: {info.asname}")
            lines.append("")

            # Тип подключения
            connection_types = []
            if info.is_tor:
                connection_types.append("🧅 TOR")
            if info.is_vpn:
                connection_types.append("🔐 VPN")
            if info.is_proxy:
                connection_types.append("🔄 Proxy")
            if info.is_hosting:
                connection_types.append("🖥️ Хостинг/Датацентр")
            if info.is_mobile:
                connection_types.append("📱 Мобильный")

            if connection_types:
                lines.append("🔌 <b>Тип подключения:</b>")
                lines.append(f"    {', '.join(connection_types)}")
                lines.append("")
            elif not info.is_private:
                lines.append("🔌 <b>Тип:</b> Резиденциальный IP")
                lines.append("")

            # Репутация
            if info.abuse_score is not None or info.is_blacklisted:
                lines.append("⚡ <b>Репутация:</b>")
                if info.abuse_score is not None:
                    abuse_emoji = "🔴" if info.abuse_score > 50 else "🟡" if info.abuse_score > 25 else "🟢"
                    lines.append(f"    {abuse_emoji} Abuse Score: {info.abuse_score}%")
                if info.is_blacklisted:
                    lines.append("    🚫 IP в чёрном списке")
                lines.append("")

    # OTX репутация
    if result.otx is not None:
        otx = result.otx
        if otx.pulse_count > 0 or otx.malware_samples > 0:
            lines.append("🛡 <b>AlienVault OTX:</b>")
            pulse_emoji = "🔴" if otx.pulse_count > 5 else "🟡" if otx.pulse_count > 0 else "🟢"
            lines.append(f"    {pulse_emoji} Threat-пульсов: {otx.pulse_count}")
            if otx.malware_samples > 0:
                lines.append(f"    🔴 Malware-образцов: {otx.malware_samples}")
            lines.append("")

    # Флаги рисков
    if result.flags:
        lines.append("📋 <b>Детали анализа:</b>")
        for flag in result.flags:
            if flag.level == RiskLevel.HIGH:
                flag_emoji = "🔴"
            elif flag.level == RiskLevel.MEDIUM:
                flag_emoji = "🟡"
            else:
                flag_emoji = "🟢"
            lines.append(f"    {flag_emoji} {flag.message}")

    return "\n".join(lines)
