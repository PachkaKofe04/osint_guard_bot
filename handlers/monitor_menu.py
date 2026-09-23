# handlers/monitor_menu.py
"""
Мониторинг через кнопки.

Команды /monitor, /monitors и /unmonitor остаются рабочими (handlers/monitor.py),
но основной путь теперь кнопочный: раздел меню, добавление с карточки
результата, удаление из списка.

Схема callback_data:
    menu:monitor            - раздел мониторинга
    mon:new                 - выбрать тип нового объекта
    mon:new:<type>          - ждём ввод объекта этого типа
    mon:add:<type>:<target> - добавить прямо с карточки результата
    mon:del_list            - список объектов с кнопками удаления
    mon:del:<idx>           - удалить объект по номеру в списке
"""
from __future__ import annotations

import logging
from typing import List

from aiogram import F, Router, types
from aiogram.fsm.context import FSMContext
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from handlers.monitor import SUPPORTED_TYPES, get_storage
from keyboards.menu_kb import get_back_menu, get_main_menu, get_monitor_menu
from monitoring.models import MonitorEntry
from monitoring.storage import MAX_MONITORS_PER_USER
from scan_registry import get_direction, monitorable_directions
from states.scan_states import MonitorStates
from utils.safe_html import esc
from utils.telegram_io import safe_answer, safe_edit

log = logging.getLogger(__name__)

router = Router()

LEVEL_EMOJI = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "🚨"}

NOT_READY = "⚠️ Система мониторинга не инициализирована."


def _render_list(entries: List[MonitorEntry]) -> str:
    """Текст раздела мониторинга."""
    if not entries:
        return (
            "<b>📡 Мониторинг</b>\n\n"
            "Бот раз в сутки перепроверяет выбранные объекты и пишет, "
            "если уровень риска изменился.\n\n"
            "Следить можно за доменом, IP-адресом или email.\n\n"
            "Сейчас список пуст."
        )

    lines = [
        f"<b>📡 Мониторинг</b>\n",
        f"Объектов под наблюдением: {len(entries)} из {MAX_MONITORS_PER_USER}\n",
    ]
    for i, entry in enumerate(entries, 1):
        state = ""
        if entry.last_risk_level:
            emoji = LEVEL_EMOJI.get(entry.last_risk_level, "⚪")
            state = f" - {emoji} {entry.last_risk_level}"
            if entry.last_score is not None:
                state += f" ({entry.last_score}/10)"
        else:
            state = " - ещё не проверялся"
        lines.append(f"{i}. <code>{esc(entry.target)}</code> [{entry.scan_type}]{state}")

    return "\n".join(lines)


@router.callback_query(F.data == "menu:monitor")
async def cb_monitor_section(callback: types.CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    storage = get_storage()
    if storage is None:
        await callback.answer()
        await safe_edit(callback.message, NOT_READY, reply_markup=get_main_menu())
        return

    await callback.answer()
    entries = storage.list_for_user(callback.from_user.id)
    await safe_edit(
        callback.message,
        _render_list(entries),
        reply_markup=get_monitor_menu(has_entries=bool(entries)),
    )


@router.callback_query(F.data == "mon:new")
async def cb_monitor_new(callback: types.CallbackQuery, state: FSMContext) -> None:
    """Выбор типа объекта для наблюдения."""
    await state.clear()
    await callback.answer()

    rows = [
        [InlineKeyboardButton(text=d.label, callback_data=f"mon:new:{d.key}")]
        for d in monitorable_directions()
    ]
    rows.append([InlineKeyboardButton(text="⬅️ Назад", callback_data="menu:monitor")])

    await safe_edit(
        callback.message,
        "<b>➕ Добавить объект</b>\n\nЗа чем следить?",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows),
    )


@router.callback_query(F.data.startswith("mon:new:"))
async def cb_monitor_new_type(callback: types.CallbackQuery, state: FSMContext) -> None:
    """Переход в режим ожидания объекта."""
    key = (callback.data or "").split(":")[2]
    direction = get_direction(key)

    if direction is None or not direction.monitorable:
        await callback.answer("За этим типом следить нельзя", show_alert=True)
        return

    await callback.answer()
    await state.set_state(MonitorStates.waiting_target)
    await state.update_data(scan_type=key)

    examples = ""
    if direction.examples:
        examples = "\n\n<b>Пример:</b>\n" + "\n".join(
            f"<code>{esc(e)}</code>" for e in direction.examples
        )

    await safe_edit(
        callback.message,
        f"<b>📡 Слежение: {esc(direction.title)}</b>\n\n"
        f"Пришли объект, за которым следить. Буду проверять раз в сутки "
        f"и напишу, если уровень риска изменится.{examples}",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="✖️ Отмена", callback_data="menu:monitor"),
        ]]),
    )


@router.message(MonitorStates.waiting_target, F.text & ~F.text.startswith("/"))
async def on_monitor_target(message: types.Message, state: FSMContext) -> None:
    """Пользователь прислал объект для наблюдения."""
    data = await state.get_data()
    scan_type = data.get("scan_type", "")
    await state.clear()

    if scan_type not in SUPPORTED_TYPES:
        await safe_answer(
            message, "Не понял тип объекта.", reply_markup=get_main_menu()
        )
        return

    await _add_monitor(message, message.from_user.id, scan_type,
                       (message.text or "").strip().lower())


@router.callback_query(F.data.startswith("mon:add:"))
async def cb_monitor_add(callback: types.CallbackQuery, state: FSMContext) -> None:
    """Кнопка «Следить за объектом» под карточкой результата."""
    await state.clear()
    parts = (callback.data or "").split(":", 3)
    if len(parts) < 4:
        await callback.answer("Некорректные данные", show_alert=True)
        return

    scan_type, target = parts[2], parts[3].strip().lower()
    if scan_type not in SUPPORTED_TYPES:
        await callback.answer("За этим типом следить нельзя", show_alert=True)
        return

    await callback.answer()
    await _add_monitor(callback.message, callback.from_user.id, scan_type, target)


async def _add_monitor(
    message: types.Message, user_id: int, scan_type: str, target: str
) -> None:
    """Общая часть добавления: и с карточки, и из раздела мониторинга."""
    storage = get_storage()
    if storage is None:
        await safe_answer(message, NOT_READY, reply_markup=get_main_menu())
        return

    if not target:
        await safe_answer(
            message, "Пустой объект - нечего добавлять.", reply_markup=get_main_menu()
        )
        return

    if storage.get(user_id, scan_type, target) is not None:
        await safe_answer(
            message,
            f"ℹ️ <code>{esc(target)}</code> уже под наблюдением.",
            reply_markup=get_monitor_menu(has_entries=True),
        )
        return

    if not storage.add(MonitorEntry(user_id=user_id, target=target, scan_type=scan_type)):
        await safe_answer(
            message,
            f"❌ Достигнут лимит: {MAX_MONITORS_PER_USER} объектов.\n"
            "Удали один, чтобы добавить новый.",
            reply_markup=get_monitor_menu(has_entries=True),
        )
        return

    await safe_answer(
        message,
        f"✅ <b>Слежение включено</b>\n\n"
        f"Объект: <code>{esc(target)}</code>\n"
        f"Тип: {esc(scan_type)}\n\n"
        f"Первая проверка пройдёт в течение 5 минут. "
        f"Дальше - раз в сутки, напишу только если риск изменится.",
        reply_markup=get_monitor_menu(has_entries=True),
    )


@router.callback_query(F.data == "mon:del_list")
async def cb_monitor_delete_list(callback: types.CallbackQuery) -> None:
    """Список объектов с кнопками удаления."""
    storage = get_storage()
    if storage is None:
        await callback.answer()
        await safe_edit(callback.message, NOT_READY, reply_markup=get_main_menu())
        return

    entries = storage.list_for_user(callback.from_user.id)
    await callback.answer()

    if not entries:
        await safe_edit(
            callback.message,
            _render_list(entries),
            reply_markup=get_monitor_menu(has_entries=False),
        )
        return

    # Индекс вместо самой цели: домен может не влезть в 64 байта callback_data
    rows = [
        [InlineKeyboardButton(
            text=f"🗑 {entry.target[:40]}",
            callback_data=f"mon:del:{i}",
        )]
        for i, entry in enumerate(entries)
    ]
    rows.append([InlineKeyboardButton(text="⬅️ Назад", callback_data="menu:monitor")])

    await safe_edit(
        callback.message,
        "<b>🗑 Удаление</b>\n\nВыбери объект, за которым больше не следить:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows),
    )


@router.callback_query(F.data.startswith("mon:del:"))
async def cb_monitor_delete(callback: types.CallbackQuery) -> None:
    """Удаление объекта по номеру в списке."""
    storage = get_storage()
    if storage is None:
        await callback.answer()
        await safe_edit(callback.message, NOT_READY, reply_markup=get_main_menu())
        return

    try:
        index = int((callback.data or "").split(":")[2])
    except (IndexError, ValueError):
        await callback.answer("Некорректные данные", show_alert=True)
        return

    entries = storage.list_for_user(callback.from_user.id)
    if not 0 <= index < len(entries):
        await callback.answer("Объект уже удалён", show_alert=True)
        return

    entry = entries[index]
    storage.remove(entry.user_id, entry.scan_type, entry.target)
    await callback.answer("Удалено")

    remaining = storage.list_for_user(callback.from_user.id)
    await safe_edit(
        callback.message,
        _render_list(remaining),
        reply_markup=get_monitor_menu(has_entries=bool(remaining)),
    )
