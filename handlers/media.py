# handlers/media.py
"""
Изображение, присланное без захода в меню.

Быстрый путь для тех, кто просто кидает фото в чат:
  - подпись «/qr» или ответ командой /qr на фото -> сразу распознаём QR-код;
  - без подписи -> сначала ищем QR-код, и только если его нет, читаем EXIF.

Порядок важен. Раньше всё без подписи безусловно уходило в EXIF, и человек,
приславший очевидную картинку с QR-кодом, получал в ответ разбор метаданных
и сообщение «GPS координаты отсутствуют».

Сценарий через меню (кнопки «EXIF фотографии» и «QR-код») живёт в scan_flow,
этот роутер подключается после него и ловит только то, что прошло мимо.
"""
from __future__ import annotations

import logging

from aiogram import F, Router, types

from exif_scanner.scanner import scan_exif
from handlers.scan_flow import run_direction
from keyboards.menu_kb import get_main_menu, get_result_menu
from qr_scanner.formatter import format_qr_result
from qr_scanner.scanner import scan_qr
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


async def _handle_auto(message: types.Message, source: types.Message) -> None:
    """
    Изображение прислали без указания, что с ним делать.

    Сначала ищем QR-код и только потом читаем метаданные. Раньше всё
    безусловно уходило в EXIF: пользователь присылал явную картинку с
    QR-кодом, а в ответ получал «GPS координаты отсутствуют».

    Файл скачивается один раз и прогоняется обоими сканерами, так что
    лишнего обращения к Telegram не происходит.
    """
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

    data, filename = payload

    qr_result = None
    try:
        qr_result = await scan_qr(data, filename)
    except Exception as exc:
        log.warning("[media] Проверка на QR не удалась: %s", exc)

    if qr_result is not None and qr_result.found_qr:
        exif_hint = await _exif_hint(data, filename)
        text = format_qr_result(qr_result)
        if exif_hint:
            text += f"\n\n🖼 <i>{exif_hint}</i>"

        direction = get_direction("qr")
        await safe_answer(
            message, text,
            reply_markup=get_result_menu(direction) if direction else get_main_menu(),
            disable_web_page_preview=True,
        )
        return

    await _handle(message, source, "exif")


async def _exif_hint(data: bytes, filename: str) -> str:
    """Короткая сводка по метаданным, чтобы они не потерялись за QR-ответом."""
    try:
        result = await scan_exif(data, filename)
    except Exception:
        return ""

    info = result.info
    if info is None or not info.has_exif:
        return ""

    parts = []
    if info.camera_model:
        parts.append(f"снято на {info.camera_model}")
    if info.has_gps:
        parts.append("есть GPS-координаты")
    if info.date_taken:
        parts.append(f"дата {info.date_taken}")

    if not parts:
        return ""
    return "В файле также нашлись метаданные: " + ", ".join(parts) + "."


@router.message(F.reply_to_message.photo, F.text.startswith("/qr"))
async def qr_by_reply(message: types.Message) -> None:
    """Команда /qr в ответ на сообщение с фото."""
    await _handle(message, message.reply_to_message, "qr")


@router.message((F.photo | F.document) & F.caption.startswith("/qr"))
async def qr_by_caption(message: types.Message) -> None:
    """Фото или документ с подписью /qr."""
    await _handle(message, message, "qr")


@router.message(F.photo)
async def photo_without_caption(message: types.Message) -> None:
    """Фото без подписи: сначала ищем QR-код, потом читаем метаданные."""
    await _handle_auto(message, message)


@router.message(F.document)
async def document_without_caption(message: types.Message) -> None:
    """Документ: если изображение - разбираем, иначе объясняем, что умеем."""
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

    await _handle_auto(message, message)
