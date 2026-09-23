# leak_scanner/formatter.py
"""Форматирование результатов проверки утечек для Telegram."""
from utils.safe_html import esc
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
    lines.append(f"<code>{esc(result.query)}</code>")
    lines.append("")

    # Риск
    lines.append(f"{emoji} <b>{level_label}</b> (оценка: {result.score}/10)")
    lines.append("")

    if info:
        if not info.check_performed:
            lines.append("⚠️ <b>Проверка не выполнена</b>")
            lines.append("")
            lines.append("Базы утечек сейчас не отвечают.")
            lines.append("Отсутствие результата не значит, что адрес не засвечен.")
            lines.append("")
            lines.append("Попробуй через пару минут или проверь вручную:")
            lines.append(
                f"🔗 <a href=\"https://xposedornot.com/\">xposedornot.com</a>"
            )
        elif not info.is_pwned:
            lines.append("✅ <b>Не найден в известных утечках</b>")
            lines.append("")
            lines.append("💡 <i>Это не гарантия безопасности: публичные базы")
            lines.append("охватывают далеко не все утечки, а часть данных")
            lines.append("продаётся, а не выкладывается.</i>")
        else:
            lines.append(f"🚨 <b>Внимание! Найден в {info.breach_count} утечке(ах)</b>")
            lines.append("")

            # Список утечек
            if info.breaches:
                lines.append("📋 <b>Утечки:</b>")
                for breach in info.breaches[:5]:
                    lines.append(f"    • <b>{esc(breach.title or breach.name)}</b>")
                    if breach.breach_date:
                        lines.append(f"      Дата: {esc(breach.breach_date)}")
                    if breach.pwn_count:
                        count_str = f"{breach.pwn_count:,}".replace(",", " ")
                        lines.append(f"      Затронуто: {esc(count_str)} аккаунтов")
                    if breach.data_classes:
                        lines.append(f"      Данные: {esc(', '.join(breach.data_classes[:4]))}")
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
            lines.append(f"    {flag_emoji} {esc(flag.message)}")

    # Источник данных: пользователю полезно знать, чем именно проверяли
    if info and info.check_performed and info.source:
        lines.append("")
        lines.append(f"<i>Источник: {esc(info.source)}</i>")

    return "\n".join(lines)
