# handlers/exif_scan.py
"""Обработчик для извлечения EXIF из изображений."""
import logging

from aiogram import Router, types, F

from exif_scanner.scanner import scan_exif
from exif_scanner.formatter import format_exif_result
from keyboards.main_menu import get_main_menu
from utils.safe_html import esc
from utils.telegram_io import safe_answer, safe_edit

log = logging.getLogger(__name__)

router = Router()

IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".tiff", ".tif", ".bmp",
    ".heic", ".heif", ".avif",  # iPhone / Apple formats
    ".nef", ".cr2", ".cr3", ".arw", ".dng", ".orf", ".raf",  # RAW
}


def _is_image_document(document: types.Document) -> bool:
    """Определяет, является ли документ изображением - по MIME или расширению файла."""
    if document.mime_type and document.mime_type.startswith("image/"):
        return True
    if document.file_name and "." in document.file_name:
        ext = "." + document.file_name.rsplit(".", 1)[-1].lower()
        return ext in IMAGE_EXTENSIONS
    return False


@router.message(F.photo)
async def handle_photo(message: types.Message) -> None:
    """
    Обработка отправленных фотографий.
    Извлекает и анализирует EXIF данные.
    """
    # Берём фото максимального размера
    photo = message.photo[-1]

    waiting_msg = await safe_answer(message, "📷 Анализирую метаданные изображения...")

    try:
        # Скачиваем файл
        file = await message.bot.get_file(photo.file_id)
        file_data = await message.bot.download_file(file.file_path)

        # Читаем байты
        image_bytes = file_data.read()

        # Получаем имя файла
        filename = file.file_path.split("/")[-1] if file.file_path else "photo.jpg"

        # Анализируем
        result = await scan_exif(image_bytes, filename)

    except Exception as e:
        log.error(f"[EXIF] Error scanning photo: {e}")
        await safe_edit(waiting_msg,
            "⚠️ Ошибка при анализе изображения.\n"
            "Убедитесь, что файл - это изображение (JPEG, PNG)."
        )
        return

    result_text = format_exif_result(result)
    await safe_edit(waiting_msg, result_text, disable_web_page_preview=True)


@router.message(F.document)
async def handle_document_image(message: types.Message) -> None:
    """
    Обработка изображений отправленных как документы (JPEG, PNG, HEIC, RAW и др.).
    Определяет тип по MIME или расширению файла - для поддержки iPhone HEIC.
    """
    document = message.document

    if not _is_image_document(document):
        # Раньше здесь был молчаливый return, и присланный, например, PDF
        # оставался без ответа - пользователь считал, что бот сломался.
        await safe_answer(
            message,
            f"📎 <code>{esc(document.file_name or 'файл')}</code> - это не изображение.\n\n"
            "Я разбираю метаданные фото: JPEG, PNG, HEIC, WebP, TIFF и RAW-форматы камер.\n"
            "Отправь картинку <b>файлом</b> (без сжатия) - иначе Telegram вырежет EXIF.",
            reply_markup=get_main_menu(),
        )
        return

    waiting_msg = await safe_answer(message, "📷 Анализирую метаданные изображения...")

    try:
        file = await message.bot.get_file(document.file_id)
        file_data = await message.bot.download_file(file.file_path)
        image_bytes = file_data.read()
        filename = document.file_name or "image"
        result = await scan_exif(image_bytes, filename)

    except Exception as e:
        log.error(f"[EXIF] Error scanning document image: {e}")
        await safe_edit(waiting_msg,
            "⚠️ Ошибка при анализе изображения.\n"
            "Убедитесь, что файл - это изображение."
        )
        return

    result_text = format_exif_result(result)
    await safe_edit(waiting_msg, result_text, disable_web_page_preview=True)
