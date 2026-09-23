# handlers/menu.py
"""Навигация по меню: главный экран, разделы, справка, статус источников."""
import logging

from aiogram import F, Router, types
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext

from keyboards.menu_kb import (
    MENU_BUTTON_TEXT,
    get_back_menu,
    get_category_menu,
    get_main_menu,
    get_more_menu,
    get_persistent_menu,
)
from scan_registry import (
    CATEGORIES,
    DIRECTIONS,
    STATUS_LIMITED,
    directions_of,
    get_category,
    limited_directions,
)
from utils.safe_html import esc
from utils.telegram_io import safe_answer, safe_edit

log = logging.getLogger(__name__)

router = Router()

MAIN_MENU_TEXT = (
    "<b>OSINT Guard</b>\n"
    "Проверка данных на признаки мошенничества\n\n"
    "Выбери раздел или просто пришли данные - я сам определю тип."
)

WELCOME_TEXT = (
    "<b>OSINT Guard</b>\n"
    "Проверяю сайты, почту, телефоны, карты, кошельки и фотографии "
    "на признаки мошенничества и утечки данных.\n\n"
    "Можно работать двумя способами:\n"
    "• выбрать раздел кнопками ниже;\n"
    "• просто прислать данные - я сам пойму, что это.\n\n"
    "Кнопка «☰ Меню» под полем ввода всегда вернёт сюда."
)

HOWTO_TEXT = (
    "<b>Как это работает</b>\n\n"
    "По каждому объекту бот собирает данные из открытых источников "
    "и считает оценку риска от 0 до 10.\n\n"
    "🟢 <b>0-3</b> - явных признаков обмана нет\n"
    "🟡 <b>4-6</b> - есть подозрительные признаки, нужна осторожность\n"
    "🔴 <b>7-10</b> - серьёзные признаки недобросовестности\n\n"
    "Оценка складывается из факторов с весами: возраст домена, скрытие "
    "владельца, репутация IP, свежесть сертификата и десятки других. "
    "В отчёте видно, какой фактор сколько добавил.\n\n"
    "<b>Важно:</b> оценка - это повод проверить внимательнее, "
    "а не приговор. Низкий риск не гарантирует добросовестность, "
    "а высокий не всегда означает мошенничество."
)

ABOUT_LIMITS_HEADER = "<b>Статус источников данных</b>\n"


@router.message(Command("start"))
async def cmd_start(message: types.Message, state: FSMContext) -> None:
    """Приветствие, постоянная клавиатура и главное меню."""
    await state.clear()
    await safe_answer(message, WELCOME_TEXT, reply_markup=get_persistent_menu())
    await safe_answer(message, MAIN_MENU_TEXT, reply_markup=get_main_menu())


@router.message(Command("menu", "help"))
async def cmd_menu(message: types.Message, state: FSMContext) -> None:
    """Главное меню по команде. Заодно сбрасывает застрявшее состояние."""
    await state.clear()
    await safe_answer(message, MAIN_MENU_TEXT, reply_markup=get_main_menu())


@router.message(F.text == MENU_BUTTON_TEXT)
async def reply_menu_button(message: types.Message, state: FSMContext) -> None:
    """Постоянная кнопка «Меню» под полем ввода."""
    await state.clear()
    await safe_answer(message, MAIN_MENU_TEXT, reply_markup=get_main_menu())


@router.callback_query(F.data == "menu:main")
async def cb_main_menu(callback: types.CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.answer()
    await safe_edit(callback.message, MAIN_MENU_TEXT, reply_markup=get_main_menu())


@router.callback_query(F.data.startswith("menu:cat:"))
async def cb_category(callback: types.CallbackQuery, state: FSMContext) -> None:
    """Подменю раздела."""
    await state.clear()
    key = (callback.data or "").split(":")[2]
    category = get_category(key)

    if category is None:
        await callback.answer("Раздел не найден", show_alert=True)
        return

    await callback.answer()

    lines = [f"<b>{esc(category.button)}</b>", ""]
    for direction in directions_of(category):
        mark = " ⚠️" if direction.status == STATUS_LIMITED else ""
        lines.append(f"{direction.label}{mark}")

    if any(d.status == STATUS_LIMITED for d in directions_of(category)):
        lines += ["", "⚠️ - работает частично, подробности внутри"]

    lines += ["", "Что проверяем?"]

    await safe_edit(
        callback.message,
        "\n".join(lines),
        reply_markup=get_category_menu(key),
    )


@router.callback_query(F.data == "menu:more")
async def cb_more(callback: types.CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.answer()
    await safe_edit(
        callback.message,
        "<b>⚙️ Ещё</b>\n\nСправка и техническая информация.",
        reply_markup=get_more_menu(),
    )


@router.callback_query(F.data == "menu:howto")
async def cb_howto(callback: types.CallbackQuery) -> None:
    await callback.answer()
    await safe_edit(callback.message, HOWTO_TEXT, reply_markup=get_more_menu())


@router.callback_query(F.data == "menu:sources")
async def cb_sources(callback: types.CallbackQuery) -> None:
    """
    Честный экран о том, что сейчас работает не полностью.

    Нужен, чтобы бот не выдавал молчаливую деградацию за нормальный результат:
    «скам не обнаружен» при недоступной базе скама вводит в заблуждение.
    """
    await callback.answer()

    limited = limited_directions()
    lines = [ABOUT_LIMITS_HEADER]

    if not limited:
        lines.append("✅ Все источники данных доступны.")
    else:
        working = len(DIRECTIONS) - len(limited)
        lines.append(f"✅ Полностью работают: {working} из {len(DIRECTIONS)}\n")
        lines.append("⚠️ <b>Работают частично:</b>\n")
        for direction in limited:
            lines.append(f"<b>{esc(direction.label)}</b>")
            lines.append(f"{esc(direction.status_note)}\n")

    lines.append(
        "<i>Направления с пометкой ⚠️ отвечают, но часть проверок в них "
        "сейчас не выполняется. Учитывай это при чтении отчёта.</i>"
    )

    await safe_edit(callback.message, "\n".join(lines), reply_markup=get_more_menu())
