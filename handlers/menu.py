# handlers/menu.py
"""Обработчики навигации и меню."""
from aiogram import Router, types, F
from aiogram.filters import Command

from keyboards.main_menu import (
    get_main_menu,
    get_back_button,
    SECTION_HELP,
)

router = Router()

# Текст главного меню
MAIN_MENU_TEXT = (
    "<b>OSINT Guard Bot</b>\n"
    "Проверка безопасности данных\n\n"
    "С чего начнём проверку?"
)


@router.message(Command("start"))
async def cmd_start(message: types.Message) -> None:
    """Команда /start — показать главное меню."""
    await message.answer(MAIN_MENU_TEXT, reply_markup=get_main_menu())


@router.message(Command("menu"))
async def cmd_menu(message: types.Message) -> None:
    """Команда /menu — показать главное меню."""
    await message.answer(MAIN_MENU_TEXT, reply_markup=get_main_menu())


@router.message(Command("help"))
async def cmd_help(message: types.Message) -> None:
    """Команда /help — показать главное меню."""
    await message.answer(MAIN_MENU_TEXT, reply_markup=get_main_menu())


@router.callback_query(F.data == "menu:main")
async def callback_main_menu(callback: types.CallbackQuery) -> None:
    """Возврат в главное меню."""
    await callback.message.edit_text(
        MAIN_MENU_TEXT,
        reply_markup=get_main_menu(),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("help:"))
async def callback_section_help(callback: types.CallbackQuery) -> None:
    """Показ справки по конкретному разделу."""
    section = callback.data.split(":")[1]

    if section in SECTION_HELP:
        await callback.message.edit_text(
            SECTION_HELP[section],
            reply_markup=get_back_button(),
        )
    else:
        await callback.answer("Раздел не найден", show_alert=True)
        return

    await callback.answer()
