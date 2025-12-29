# keyboards/domain_kb.py
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


DETAILS_PREFIX = "domain_detail:"


def domain_details_keyboard(domain: str) -> InlineKeyboardMarkup:
    """
    Инлайн-кнопка для запроса детального отчёта по домену.
    В callback_data шьём домен.
    """
    cb_data = f"{DETAILS_PREFIX}{domain}"
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="📄 Подробнее", callback_data=cb_data)]
        ]
    )
    return kb
