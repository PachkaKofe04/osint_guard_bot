# handlers/menu.py
"""Обработчики навигации и меню."""
from aiogram import Router, types, F
from aiogram.filters import Command

from keyboards.main_menu import (
    get_main_menu,
    get_scanner_help,
    SCANNER_HELP,
)

router = Router()


@router.callback_query(F.data == "menu:main")
async def callback_main_menu(callback: types.CallbackQuery) -> None:
    """Возврат в главное меню."""
    text = (
        "🛡 <b>OSINT Guard Bot</b>\n\n"
        "Выбери тип проверки или просто отправь данные — "
        "бот автоматически определит тип.\n\n"
        "📸 <i>Для анализа фото — просто отправь изображение</i>"
    )
    await callback.message.edit_text(
        text,
        reply_markup=get_main_menu(),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("menu:"))
async def callback_scanner_help(callback: types.CallbackQuery) -> None:
    """Показ справки по конкретному сканеру."""
    scanner = callback.data.split(":")[1]

    if scanner in SCANNER_HELP:
        await callback.message.edit_text(
            SCANNER_HELP[scanner],
            reply_markup=get_scanner_help(scanner),
        )
    else:
        await callback.answer("Неизвестный раздел", show_alert=True)
        return

    await callback.answer()


@router.message(Command("menu"))
async def cmd_menu(message: types.Message) -> None:
    """Команда /menu — показать главное меню."""
    text = (
        "🛡 <b>OSINT Guard Bot</b>\n\n"
        "Выбери тип проверки или просто отправь данные — "
        "бот автоматически определит тип.\n\n"
        "📸 <i>Для анализа фото — просто отправь изображение</i>"
    )
    await message.answer(text, reply_markup=get_main_menu())
