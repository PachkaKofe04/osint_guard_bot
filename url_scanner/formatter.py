# url_scanner/formatter.py
"""Форматирование результатов сканирования URL для Telegram."""
from url_scanner.models import UrlScanResult
from utils.risk_types import get_risk_emoji, RiskLevel


def _escape_html(text: str) -> str:
    """Экранирует HTML-символы."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def format_url_result(result: UrlScanResult) -> str:
    """Форматирует результат сканирования URL для Telegram."""
    emoji = get_risk_emoji(result.score)
    info = result.info

    lines = [
        f"{emoji} <b>Проверка URL</b>",
        "",
    ]

    if info:
        # Оригинальный URL
        lines.append(f"<b>URL:</b> <code>{_escape_html(info.original_url)}</code>")

        # Если была переадресация — показываем конечный URL
        if info.original_url != info.final_url:
            lines.append(f"<b>Конечный URL:</b> <code>{_escape_html(info.final_url)}</code>")

        # Информация о редиректах
        if info.redirect_count > 0:
            lines.append(f"<b>Редиректов:</b> {info.redirect_count}")

        # Сокращённая ссылка?
        if info.is_shortened:
            shortener = info.shortener_service or "неизвестный"
            lines.append(f"<b>Сокращатель:</b> {shortener}")

        # Домен
        if info.domain:
            lines.append(f"<b>Домен:</b> {_escape_html(info.domain)}")

        lines.append("")

    # Оценка риска
    risk_labels = {
        RiskLevel.LOW: "Низкий риск",
        RiskLevel.MEDIUM: "Средний риск",
        RiskLevel.HIGH: "Высокий риск",
    }
    risk_label = risk_labels.get(result.risk_level, "Неизвестно")

    lines.append(f"<b>Оценка:</b> {emoji} {result.score}/10 — {risk_label}")

    # Флаги рисков
    if result.flags:
        lines.append("")
        lines.append("<b>Обнаружено:</b>")

        for flag in result.flags:
            flag_emoji = "🔴" if flag.level == RiskLevel.HIGH else (
                "🟡" if flag.level == RiskLevel.MEDIUM else "🟢"
            )
            weight_str = f"+{flag.weight}" if flag.weight > 0 else str(flag.weight)
            lines.append(f"  {flag_emoji} {flag.message} ({weight_str})")

    # Цепочка редиректов (если есть и не слишком длинная)
    if info and info.redirect_chain and len(info.redirect_chain) <= 5:
        lines.append("")
        lines.append("<b>Цепочка редиректов:</b>")
        for i, url in enumerate(info.redirect_chain, 1):
            short_url = url[:60] + "..." if len(url) > 60 else url
            lines.append(f"  {i}. {_escape_html(short_url)}")
        if info.final_url and info.final_url not in info.redirect_chain:
            lines.append(f"  → {_escape_html(info.final_url[:60])}")

    # Предупреждения
    if result.score >= 7:
        lines.append("")
        lines.append("⚠️ <b>Не рекомендуется переходить по этой ссылке!</b>")
    elif result.score >= 4:
        lines.append("")
        lines.append("⚠️ <b>Будьте осторожны с этой ссылкой.</b>")

    return "\n".join(lines)
