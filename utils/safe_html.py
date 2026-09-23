# utils/safe_html.py
"""
Экранирование пользовательских данных для parse_mode=HTML.

Telegram принимает ограниченный набор тегов и требует, чтобы `<`, `>` и `&`
внутри текста были экранированы. Любое незакрытое или неизвестное `<...>`
в тексте приводит к TelegramBadRequest, и пользователь не получает ответа.

Правило проекта: разметку пишет форматтер, данные всегда проходят через esc().
"""
from typing import Any


def esc(value: Any) -> str:
    """
    Экранирует значение для вставки в HTML-текст сообщения.

    None превращается в пустую строку — чтобы не печатать "None" в отчётах.

    >>> esc('<b>evil</b> & "x"')
    '&lt;b&gt;evil&lt;/b&gt; &amp; "x"'
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def esc_attr(value: Any) -> str:
    """
    Экранирует значение для вставки в атрибут тега, например href="...".
    Дополнительно закрывает кавычки, иначе ссылка «разрывает» атрибут.
    """
    return esc(value).replace('"', "&quot;")


def strip_tags(text: str) -> str:
    """
    Грубо убирает HTML-теги — для аварийного отката на plain text,
    когда Telegram отверг разметку. Сущности разворачиваются обратно.
    """
    out: list[str] = []
    inside = False
    for ch in text:
        if ch == "<":
            inside = True
        elif ch == ">":
            inside = False
        elif not inside:
            out.append(ch)
    plain = "".join(out)
    return (
        plain.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&amp;", "&")
    )
