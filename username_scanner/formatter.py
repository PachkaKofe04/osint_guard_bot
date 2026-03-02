# username_scanner/formatter.py
"""Форматирование результатов сканирования Username для Telegram."""
from typing import List, Tuple

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
                lines.append("<i>⚠️ Совпадение username не означает что это тот же человек</i>")
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


def format_maigret_result(
    username: str,
    hits: List[Tuple[str, str]],
    total_checked: int,
) -> str:
    """
    Форматирует результат углублённого поиска Maigret для Telegram.

    Args:
        username:      Искомый никнейм
        hits:          Список (site_name, profile_url) где найден
        total_checked: Сколько сайтов проверено
    """
    lines = []
    lines.append("🔬 <b>Углублённый поиск Maigret</b>")
    lines.append(f"<code>@{username}</code>")
    lines.append("")

    if total_checked == 0:
        lines.append("⚠️ Maigret недоступен или произошла ошибка.")
        return "\n".join(lines)

    lines.append(f"🔍 Проверено платформ: <b>{total_checked}</b>")
    lines.append(f"✅ Найден на: <b>{len(hits)}</b>")
    lines.append("")

    if hits:
        lines.append("📋 <b>Найденные профили:</b>")
        for site_name, url in hits[:30]:
            if url:
                lines.append(f"  • <a href=\"{url}\">{site_name}</a>")
            else:
                lines.append(f"  • {site_name}")
        if len(hits) > 30:
            lines.append(f"  ... и ещё {len(hits) - 30}")
    else:
        lines.append("❌ Профили не найдены в проверенных платформах.")

    return "\n".join(lines)
