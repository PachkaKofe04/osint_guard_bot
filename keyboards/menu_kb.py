# keyboards/menu_kb.py
"""
Клавиатуры навигации. Строятся из scan_registry, поэтому меню не может
разойтись с тем, что бот реально умеет.

Схема callback_data:
    menu:main          - главное меню
    menu:cat:<key>     - раздел
    menu:monitor       - мониторинг
    menu:more          - раздел "Ещё"
    menu:sources       - статус источников данных
    menu:howto         - как это работает
    scan:<key>         - начать проверку по направлению
    again:<key>        - ещё одна проверка того же типа
    cancel             - отмена ввода, возврат в меню
"""
from typing import List, Optional

from aiogram.types import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
)

from scan_registry import CATEGORIES, Direction, directions_of, get_category

# Текст постоянной кнопки внизу экрана
MENU_BUTTON_TEXT = "☰ Меню"

# Навигация по экранам меню: перерисовывает сообщение на месте
BACK_TO_MAIN = InlineKeyboardButton(text="☰ В меню", callback_data="menu:main")

# То же самое, но новым сообщением. Ставится под карточки результата:
# обычная кнопка заменяла бы текст отчёта меню, и отчёт исчезал навсегда.
BACK_TO_MAIN_KEEP = InlineKeyboardButton(text="☰ В меню", callback_data="menu:fresh")


def get_persistent_menu() -> ReplyKeyboardMarkup:
    """
    Постоянная клавиатура под полем ввода.

    Нужна, чтобы пользователь не терялся: инлайн-меню уезжает вверх по истории
    чата, а эта кнопка всегда под рукой.
    """
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=MENU_BUTTON_TEXT)]],
        resize_keyboard=True,
        is_persistent=True,
        input_field_placeholder="Пришли данные для проверки или нажми «Меню»",
    )


def get_main_menu() -> InlineKeyboardMarkup:
    """Главное меню: разделы по категориям."""
    rows: List[List[InlineKeyboardButton]] = []

    buttons = [
        InlineKeyboardButton(text=c.button, callback_data=f"menu:cat:{c.key}")
        for c in CATEGORIES
    ]
    # По два в ряд, последний может остаться один
    for i in range(0, len(buttons), 2):
        rows.append(buttons[i:i + 2])

    rows.append([
        InlineKeyboardButton(text="📡 Мониторинг", callback_data="menu:monitor"),
        InlineKeyboardButton(text="⚙️ Ещё", callback_data="menu:more"),
    ])

    return InlineKeyboardMarkup(inline_keyboard=rows)


def get_category_menu(category_key: str) -> InlineKeyboardMarkup:
    """Подменю раздела: направления проверки внутри него."""
    category = get_category(category_key)
    rows: List[List[InlineKeyboardButton]] = []

    if category:
        for direction in directions_of(category):
            rows.append([
                InlineKeyboardButton(
                    text=direction.button,
                    callback_data=f"scan:{direction.key}",
                )
            ])

    rows.append([BACK_TO_MAIN])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def get_cancel_menu() -> InlineKeyboardMarkup:
    """Показывается, пока бот ждёт ввод."""
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✖️ Отмена", callback_data="cancel"),
    ]])


def get_result_menu(
    direction: Direction,
    value: Optional[str] = None,
    extra_rows: Optional[List[List[InlineKeyboardButton]]] = None,
) -> InlineKeyboardMarkup:
    """
    Кнопки под карточкой результата.

    Карточка не должна быть тупиком: с неё всегда есть куда пойти дальше.
    """
    rows: List[List[InlineKeyboardButton]] = list(extra_rows or [])

    if direction.monitorable and value:
        payload = f"mon:add:{direction.key}:{value}"
        # Telegram отвергает callback_data длиннее 64 байт, а обрезка исказила бы
        # объект мониторинга. Для слишком длинных целей кнопку просто не показываем.
        if len(payload.encode("utf-8")) <= 64:
            rows.append([
                InlineKeyboardButton(text="📡 Следить за объектом", callback_data=payload)
            ])

    rows.append([
        InlineKeyboardButton(text="🔄 Ещё проверка", callback_data=f"again:{direction.key}"),
        BACK_TO_MAIN_KEEP,
    ])

    return InlineKeyboardMarkup(inline_keyboard=rows)


def get_back_menu() -> InlineKeyboardMarkup:
    """
    Одна кнопка возврата в меню под сообщением с результатом.

    Меню открывается новым сообщением, а не поверх отчёта.
    """
    return InlineKeyboardMarkup(inline_keyboard=[[BACK_TO_MAIN_KEEP]])


def get_more_menu() -> InlineKeyboardMarkup:
    """Раздел «Ещё»."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❓ Как это работает", callback_data="menu:howto")],
        [InlineKeyboardButton(text="📊 Статус источников", callback_data="menu:sources")],
        [BACK_TO_MAIN],
    ])


def get_monitor_menu(has_entries: bool) -> InlineKeyboardMarkup:
    """Раздел мониторинга."""
    rows: List[List[InlineKeyboardButton]] = [
        [InlineKeyboardButton(text="➕ Добавить объект", callback_data="mon:new")],
    ]
    if has_entries:
        rows.append([
            InlineKeyboardButton(text="🗑 Удалить объект", callback_data="mon:del_list")
        ])
    rows.append([BACK_TO_MAIN])
    return InlineKeyboardMarkup(inline_keyboard=rows)
