# handlers/media.py
"""
Изображение, присланное без захода в меню.

Быстрый путь для тех, кто просто кидает фото в чат:
  - подпись «/qr» или ответ командой /qr на фото -> распознаём QR-код;
  - всё остальное -> читаем EXIF.

Сценарий через меню (кнопки «EXIF фотографии» и «QR-код») живёт в scan_flow,
этот роутер подключается после него и ловит только то, что прошло мимо.
"""
from __future__ import annotations

import logging

from aiogram import F, Router, types

from handlers.scan_flow import run_direction
from keyboards.menu_kb import get_main_menu
from scan_registry import get_direction
from utils.safe_html import esc
from utils.telegram_io import safe_answer

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


async def _download(message: types.Message) -> tuple | None:
    """Скачивает изображение из сообщения. Возвращает (bytes, filename)."""
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


async def _handle(message: types.Message, source: types.Message, key: str) -> None:
    """Скачивает изображение из source и прогоняет через направление key."""
    direction = get_direction(key)
    if direction is None:
        return

    try:
        payload = await _download(source)
    except Exception as exc:
        log.error("[media] Не удалось скачать файл: %s", exc)
        payload = None

    if payload is None:
        await safe_answer(
            message,
            "⚠️ Не получилось прочитать изображение.",
            reply_markup=get_main_menu(),
        )
        return

    await run_direction(message, direction, payload[1], payload)


@router.message(F.reply_to_message.photo, F.text.startswith("/qr"))
async def qr_by_reply(message: types.Message) -> None:
    """Команда /qr в ответ на сообщение с фото."""
    await _handle(message, message.reply_to_message, "qr")


@router.message((F.photo | F.document) & F.caption.startswith("/qr"))
async def qr_by_caption(message: types.Message) -> None:
    """Фото или документ с подписью /qr."""
    await _handle(message, message, "qr")


@router.message(F.photo)
async def photo_to_exif(message: types.Message) -> None:
    """
    Фото без подписи. Разбираем метаданные.

    Telegram при обычной отправке пересжимает картинку и вырезает EXIF,
    поэтому сразу подсказываем, как прислать правильно.
    """
    await _handle(message, message, "exif")


@router.message(F.document)
async def document_to_exif(message: types.Message) -> None:
    """Документ: если изображение - EXIF, иначе объясняем, что умеем."""
    document = message.document

    if not _is_image_document(document):
        await safe_answer(
            message,
            f"📎 <code>{esc(document.file_name or 'файл')}</code> - это не изображение.\n\n"
            "Я читаю метаданные фотографий: JPEG, PNG, HEIC, WebP, TIFF "
            "и RAW-форматы камер.",
            reply_markup=get_main_menu(),
        )
        return

    await _handle(message, message, "exif")
