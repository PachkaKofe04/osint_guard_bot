# username_scanner/formatter.py
"""Форматирование результатов сканирования Username для Telegram."""
from username_scanner.models import UsernameScanResult
from utils.risk_types import get_risk_emoji, get_risk_label, RiskLevel


def format_username_result(result: UsernameScanResult) -> str:
    """
    Форматирует результат сканирования Username для отправки в Telegram.

    Args:
        result: Результат сканирования

    Returns:
        Отформатированная строка с HTML разметкой
    """
    info = result.info
    emoji = get_risk_emoji(result.score)
    level_label = get_risk_label(result.risk_level)

    lines = []
    lines.append(f"👤 <b>Анализ Username</b>")
    lines.append(f"<code>@{result.username}</code>")
    lines.append("")

    # Риск
    lines.append(f"{emoji} <b>{level_label}</b> (оценка: {result.score}/10)")
    lines.append("")

    if info:
        if not info.is_valid:
            lines.append("❌ <b>Невалидный username</b>")
            lines.append("Допустимы: a-z, 0-9, _, -, . (3-32 символа)")
            lines.append("")
        else:
            # Статистика поиска
            lines.append(f"🔍 <b>Результаты поиска:</b>")
            lines.append(f"    Найден на {info.found_count} из {info.checked_count} платформ")
            lines.append("")

            # Где найден
            found = [p for p in info.platforms if p.exists]
            if found:
                lines.append("✅ <b>Найден на:</b>")
                for p in found[:10]:  # Макс 10
                    lines.append(f"    • <a href=\"{p.url}\">{p.platform}</a>")
                if len(found) > 10:
                    lines.append(f"    ... и ещё {len(found) - 10}")
                lines.append("")

            # Где не найден
            not_found = [p for p in info.platforms if p.status == "not_found"]
            if not_found and len(not_found) < 10:
                lines.append("❌ <b>Не найден на:</b>")
                for p in not_found[:5]:
                    lines.append(f"    • {p.platform}")
                if len(not_found) > 5:
                    lines.append(f"    ... и ещё {len(not_found) - 5}")
                lines.append("")

            # Ошибки (если были)
            errors = [p for p in info.platforms if p.status == "error"]
            if errors and len(errors) < len(info.platforms) // 2:
                lines.append("⚠️ <b>Ошибки проверки:</b>")
                for p in errors[:3]:
                    lines.append(f"    • {p.platform}: {p.error or 'недоступен'}")
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
