# keyboards/username_kb.py
"""Inline-клавиатура для username scanner."""
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton


def get_username_keyboard(username: str) -> InlineKeyboardMarkup:
    """Клавиатура с кнопкой углублённого поиска через Maigret."""
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(
            text="🔬 Углублённый поиск (Maigret ~500 сайтов)",
            callback_data=f"maigret:{username}",
        ),
    ]])
