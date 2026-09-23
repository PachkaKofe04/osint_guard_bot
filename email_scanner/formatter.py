# email_scanner/formatter.py
"""Форматирование результатов сканирования Email для Telegram."""
from utils.safe_html import esc
from email_scanner.models import EmailScanResult
from utils.risk_types import get_risk_emoji, RiskLevel


def format_email_result(result: EmailScanResult) -> str:
    """Форматирует результат сканирования Email для Telegram."""
    emoji = get_risk_emoji(result.score)
    info = result.info

    lines = [
        f"{emoji} <b>Проверка Email</b>",
        "",
    ]

    if info:
        # Email
        lines.append(f"<b>Email:</b> <code>{esc(info.email)}</code>")

        # Домен
        if info.domain:
            lines.append(f"<b>Домен:</b> {esc(info.domain)}")

        # Провайдер
        if info.provider_name:
            lines.append(f"<b>Провайдер:</b> {esc(info.provider_name)}")

        # Тип
        if info.is_disposable:
            lines.append(f"<b>Тип:</b> Одноразовый (временный)")
        elif info.is_corporate:
            lines.append(f"<b>Тип:</b> Корпоративный")
        elif info.is_free_provider:
            lines.append(f"<b>Тип:</b> Бесплатный провайдер")

        # MX записи
        if info.has_mx_records:
            lines.append(f"<b>MX записи:</b> ✅ Есть ({len(info.mx_records)})")
        else:
            lines.append(f"<b>MX записи:</b> ❌ Отсутствуют")

        # Утечки
        if info.breach_count > 0:
            lines.append(f"<b>Утечки:</b> ⚠️ Найден в {info.breach_count} утечках")
            if info.breaches:
                breaches_str = ", ".join(info.breaches[:5])
                lines.append(f"  └ {breaches_str}")
        else:
            # Утечки проверяет отдельное направление «Утечки» в меню.
            # Прежний текст ссылался на неподключённый ключ HIBP, который
            # с переходом на XposedOrNot больше не нужен
            lines.append(
                "<b>Утечки:</b> ℹ️ проверяются отдельно - раздел «Утечки» в меню"
            )

        # Gravatar
        if info.gravatar_url:
            lines.append(f"<b>Gravatar:</b> <a href=\"{info.gravatar_url}\">Аватар найден</a>")

        # Holehe - регистрации на платформах
        if info.holehe_hits:
            lines.append(f"<b>Платформы ({len(info.holehe_hits)} найдено):</b>")
            for domain in info.holehe_hits[:15]:
                lines.append(f"  • {esc(domain)}")
            if len(info.holehe_hits) > 15:
                lines.append(f"  ... и ещё {len(info.holehe_hits) - 15}")
        elif info.deep_check_done:
            lines.append("<b>Платформы:</b> адрес нигде не найден (проверено 250+ сервисов)")
        elif info.is_valid_format and info.has_mx_records:
            # Пустой список без этой оговорки читался бы как «нигде не найден»,
            # хотя поиск ещё не запускался
            lines.append(
                "<b>Платформы:</b> поиск не запускался, он идёт отдельной кнопкой"
            )

        lines.append("")

    # Оценка риска
    risk_labels = {
        RiskLevel.LOW: "Низкий риск",
        RiskLevel.MEDIUM: "Средний риск",
        RiskLevel.HIGH: "Высокий риск",
    }
    risk_label = risk_labels.get(result.risk_level, "Неизвестно")

    lines.append(f"<b>Оценка:</b> {emoji} {result.score}/10 - {risk_label}")

    # Флаги рисков
    if result.flags:
        lines.append("")
        lines.append("<b>Детали:</b>")

        for flag in result.flags:
            flag_emoji = "🔴" if flag.level == RiskLevel.HIGH else (
                "🟡" if flag.level == RiskLevel.MEDIUM else "🟢"
            )
            weight_str = f"+{flag.weight}" if flag.weight > 0 else str(flag.weight)
            lines.append(f"  {flag_emoji} {esc(flag.message)} ({weight_str})")

    # Предупреждения
    if info and info.is_disposable:
        lines.append("")
        lines.append("⚠️ <b>Одноразовые email часто используются для мошенничества!</b>")
    elif info and not info.has_mx_records:
        lines.append("")
        lines.append("⚠️ <b>Домен не может принимать почту - email невалиден!</b>")

    return "\n".join(lines)
