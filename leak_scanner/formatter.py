# leak_scanner/formatter.py
"""Форматирование результатов проверки утечек для Telegram."""
from leak_scanner.models import LeakScanResult
from utils.risk_types import get_risk_emoji, get_risk_label, RiskLevel


def format_leak_result(result: LeakScanResult) -> str:
    """
    Форматирует результат проверки утечек для Telegram.

    Args:
        result: Результат проверки

    Returns:
        Отформатированная строка с HTML разметкой
    """
    info = result.info
    emoji = get_risk_emoji(result.score)
    level_label = get_risk_label(result.risk_level)

    lines = []
    lines.append("🔓 <b>Проверка на утечки данных</b>")
    lines.append(f"<code>{result.query}</code>")
    lines.append("")

    # Риск
    lines.append(f"{emoji} <b>{level_label}</b> (оценка: {result.score}/10)")
    lines.append("")

    if info:
        if not info.is_pwned:
            lines.append("✅ <b>Отлично!</b>")
            lines.append("Не найден в известных утечках данных.")
            lines.append("")
            lines.append("💡 <i>Это не гарантирует полную безопасность,")
            lines.append("но email не встречался в крупных утечках.</i>")
        else:
            lines.append(f"🚨 <b>Внимание! Найден в {info.breach_count} утечке(ах)</b>")
            lines.append("")

            # Список утечек
            if info.breaches:
                lines.append("📋 <b>Утечки:</b>")
                for breach in info.breaches[:5]:
                    lines.append(f"    • <b>{breach.title or breach.name}</b>")
                    if breach.breach_date:
                        lines.append(f"      Дата: {breach.breach_date}")
                    if breach.pwn_count:
                        count_str = f"{breach.pwn_count:,}".replace(",", " ")
                        lines.append(f"      Затронуто: {count_str} аккаунтов")
                    if breach.data_classes:
                        lines.append(f"      Данные: {', '.join(breach.data_classes[:4])}")
                    lines.append("")

                if len(info.breaches) > 5:
                    lines.append(f"    ... и ещё {len(info.breaches) - 5} утечек")
                    lines.append("")

            # Рекомендации
            lines.append("⚠️ <b>Рекомендации:</b>")
            lines.append("    1. Смените пароли на затронутых сервисах")
            lines.append("    2. Включите двухфакторную аутентификацию")
            lines.append("    3. Не используйте одинаковые пароли")
            lines.append("")

    # Флаги
    if result.flags:
        lines.append("📋 <b>Детали:</b>")
        for flag in result.flags:
            if flag.level == RiskLevel.HIGH:
                flag_emoji = "🔴"
            elif flag.level == RiskLevel.MEDIUM:
                flag_emoji = "🟡"
            else:
                flag_emoji = "🟢"
            lines.append(f"    {flag_emoji} {flag.message}")

    # Источник
    lines.append("")
    lines.append("🔗 <i>Проверьте на <a href=\"https://haveibeenpwned.com\">haveibeenpwned.com</a></i>")

    return "\n".join(lines)
