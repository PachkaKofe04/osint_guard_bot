# handlers/scan_flow.py
"""
Универсальный сценарий проверки: кнопка -> ввод -> карточка результата.

Один набор хендлеров обслуживает все направления из scan_registry.
Раньше на каждое направление был свой почти идентичный хендлер - двенадцать
копий одного и того же кода, которые расходились при каждой правке.

Роутер подключается ДО auto_detect: пока пользователь в состоянии ожидания
ввода, его сообщение должно уйти в выбранное направление, а не в авто-детект.
"""
from __future__ import annotations

import logging
from typing import Optional

from aiogram import F, Router, types
from aiogram.fsm.context import FSMContext
from aiogram.types import InlineKeyboardButton

from keyboards.menu_kb import (
    get_back_menu,
    get_cancel_menu,
    get_main_menu,
    get_result_menu,
)
from scan_registry import (
    INPUT_IMAGE,
    STATUS_LIMITED,
    Direction,
    get_direction,
)
from states.scan_states import ScanStates
from utils.safe_html import esc
from utils.telegram_io import safe_answer, safe_edit

log = logging.getLogger(__name__)

router = Router()

IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".tif", ".bmp",
    ".heic", ".heif", ".avif",
    ".nef", ".nrw", ".cr2", ".cr3", ".crw", ".arw", ".dng", ".orf",
    ".raf", ".rw2", ".pef", ".srw",
}


def _is_image_document(document: types.Document) -> bool:
    if document.mime_type and document.mime_type.startswith("image/"):
        return True
    if document.file_name and "." in document.file_name:
        ext = "." + document.file_name.rsplit(".", 1)[-1].lower()
        return ext in IMAGE_EXTENSIONS
    return False


def build_prompt(direction: Direction) -> str:
    """Экран ожидания ввода: что прислать и что бот с этим сделает."""
    lines = [f"<b>{esc(direction.label)}</b>", "", direction.prompt]

    if direction.status == STATUS_LIMITED and direction.status_note:
        lines += ["", f"⚠️ <b>Работает частично.</b> {esc(direction.status_note)}"]

    if direction.examples:
        lines += ["", "<b>Пример:</b>"]
        lines += [f"<code>{esc(example)}</code>" for example in direction.examples]

    return "\n".join(lines)


async def start_direction(
    message: types.Message,
    direction: Direction,
    state: FSMContext,
    edit: bool = False,
) -> None:
    """Переводит пользователя в режим ожидания ввода для направления."""
    await state.set_state(ScanStates.waiting_input)
    await state.update_data(direction=direction.key)

    text = build_prompt(direction)
    if edit:
        await safe_edit(message, text, reply_markup=get_cancel_menu())
    else:
        await safe_answer(message, text, reply_markup=get_cancel_menu())


@router.callback_query(F.data.startswith("scan:"))
async def cb_start_scan(callback: types.CallbackQuery, state: FSMContext) -> None:
    """Нажата кнопка направления в подменю."""
    key = (callback.data or "").split(":", 1)[1]
    direction = get_direction(key)

    if direction is None:
        await callback.answer("Это направление недоступно", show_alert=True)
        return

    await callback.answer()
    await start_direction(callback.message, direction, state, edit=True)


@router.callback_query(F.data.startswith("again:"))
async def cb_scan_again(callback: types.CallbackQuery, state: FSMContext) -> None:
    """Кнопка «Ещё проверка» под карточкой результата."""
    key = (callback.data or "").split(":", 1)[1]
    direction = get_direction(key)

    if direction is None:
        await callback.answer("Это направление недоступно", show_alert=True)
        return

    await callback.answer()
    # Новым сообщением, а не правкой: карточку результата стоит сохранить
    await start_direction(callback.message, direction, state, edit=False)


@router.callback_query(F.data == "cancel")
async def cb_cancel(callback: types.CallbackQuery, state: FSMContext) -> None:
    """Отмена ожидания ввода."""
    await state.clear()
    await callback.answer("Отменено")
    await safe_edit(
        callback.message,
        "Проверка отменена. Выбери раздел:",
        reply_markup=get_main_menu(),
    )


async def _download_image(message: types.Message) -> Optional[tuple]:
    """Возвращает (bytes, filename) для фото или документа-изображения."""
    if message.photo:
        photo = message.photo[-1]
        file = await message.bot.get_file(photo.file_id)
        data = await message.bot.download_file(file.file_path)
        name = file.file_path.split("/")[-1] if file.file_path else "photo.jpg"
        return data.read(), name

    if message.document and _is_image_document(message.document):
        file = await message.bot.get_file(message.document.file_id)
        data = await message.bot.download_file(file.file_path)
        return data.read(), message.document.file_name or "image"

    return None


async def run_direction(
    message: types.Message,
    direction: Direction,
    value: str,
    payload: Optional[tuple],
) -> None:
    """
    Выполняет скан и показывает карточку результата.

    Публичная: этим же путём идут команды-алиасы (handlers/commands.py),
    чтобы `/ip 8.8.8.8` и кнопка «IP-адрес» вели себя одинаково.
    """
    waiting_msg = await safe_answer(message, direction.waiting)

    try:
        if payload is not None:
            result = await direction.scan(payload[0], payload[1])
        else:
            result = await direction.scan(value)
        text = direction.format(result)
    except ValueError as exc:
        log.info("[scan_flow] Некорректный ввод для %s: %s", direction.key, exc)
        await safe_edit(
            waiting_msg,
            f"❌ Не получилось разобрать ввод.\n\n{esc(exc)}",
            reply_markup=get_result_menu(direction),
        )
        return
    except Exception as exc:
        log.error("[scan_flow] Ошибка скана %s: %s", direction.key, exc, exc_info=True)
        await safe_edit(
            waiting_msg,
            "⚠️ Не удалось выполнить проверку - источник данных не ответил.\n"
            "Попробуй ещё раз через минуту.",
            reply_markup=get_result_menu(direction),
        )
        return

    extra_rows = _extra_actions(direction, result, value)
    await safe_edit(
        waiting_msg,
        text,
        reply_markup=get_result_menu(direction, value=value, extra_rows=extra_rows),
        disable_web_page_preview=True,
    )


def _extra_actions(direction: Direction, result, value: str) -> list:
    """Кнопки, специфичные для конкретного направления."""
    rows = []

    if direction.key == "domain":
        normalized = getattr(result, "normalized_domain", "") or value
        rows.append([
            InlineKeyboardButton(
                text="📄 Подробный отчёт",
                callback_data=f"domain_detail:{normalized}",
            )
        ])

    if direction.key == "username":
        info = getattr(result, "info", None)
        if info is not None and getattr(info, "is_valid", False):
            username = getattr(result, "username", value)
            payload = f"maigret:{username}"
            if len(payload.encode("utf-8")) <= 64:
                rows.append([
                    InlineKeyboardButton(
                        text="🔬 Углублённый поиск (~500 сайтов)",
                        callback_data=payload,
                    )
                ])

    return rows


@router.message(ScanStates.waiting_input, F.text & ~F.text.startswith("/"))
async def on_text_input(message: types.Message, state: FSMContext) -> None:
    """Пользователь прислал текст в режиме ожидания ввода."""
    data = await state.get_data()
    direction = get_direction(data.get("direction", ""))

    if direction is None:
        await state.clear()
        await safe_answer(
            message,
            "Не понял, что проверяем. Выбери раздел:",
            reply_markup=get_main_menu(),
        )
        return

    if direction.input_kind == INPUT_IMAGE:
        await safe_answer(
            message,
            "Здесь нужно изображение, а не текст.\n\n" + direction.prompt,
            reply_markup=get_cancel_menu(),
        )
        return

    await state.clear()
    await run_direction(message, direction, (message.text or "").strip(), None)


@router.message(ScanStates.waiting_input, F.photo | F.document)
async def on_image_input(message: types.Message, state: FSMContext) -> None:
    """Пользователь прислал изображение в режиме ожидания ввода."""
    data = await state.get_data()
    direction = get_direction(data.get("direction", ""))

    if direction is None or direction.input_kind != INPUT_IMAGE:
        await state.clear()
        await safe_answer(
            message,
            "Не ждал здесь картинку. Выбери раздел:",
            reply_markup=get_main_menu(),
        )
        return

    try:
        payload = await _download_image(message)
    except Exception as exc:
        log.error("[scan_flow] Не удалось скачать файл: %s", exc)
        payload = None

    if payload is None:
        await safe_answer(
            message,
            "📎 Это не изображение.\n\n" + direction.prompt,
            reply_markup=get_cancel_menu(),
        )
        return

    await state.clear()
    filename = payload[1]
    await run_direction(message, direction, filename, payload)


@router.message(ScanStates.waiting_input, ~F.text.startswith("/"))
async def on_wrong_input(message: types.Message, state: FSMContext) -> None:
    """
    Стикер, голосовое и прочее, пока бот ждёт данные.

    Команды сознательно исключены: без этого условия хендлер ловил и их,
    и пользователь застревал в режиме ввода - «/ip 8.8.8.8» получал ответ
    «с таким типом сообщений я не работаю» вместо запуска проверки.
    """
    data = await state.get_data()
    direction = get_direction(data.get("direction", ""))

    if direction is None:
        await state.clear()
        await safe_answer(
            message, "Выбери раздел:", reply_markup=get_main_menu()
        )
        return

    await safe_answer(
        message,
        "С таким типом сообщений я не работаю.\n\n" + direction.prompt,
        reply_markup=get_cancel_menu(),
    )
