# handlers/exif_scan.py
"""Обработчик для извлечения EXIF из изображений."""
import logging

from aiogram import Router, types, F

from exif_scanner.scanner import scan_exif
from exif_scanner.formatter import format_exif_result

log = logging.getLogger(__name__)

router = Router()


@router.message(F.photo)
async def handle_photo(message: types.Message) -> None:
    """
    Обработка отправленных фотографий.
    Извлекает и анализирует EXIF данные.
    """
    # Берём фото максимального размера
    photo = message.photo[-1]

    waiting_msg = await message.answer("📷 Анализирую метаданные изображения...")

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
        await waiting_msg.edit_text(
            "⚠️ Ошибка при анализе изображения.\n"
            "Убедитесь, что файл — это изображение (JPEG, PNG)."
        )
        return

    result_text = format_exif_result(result)
    await waiting_msg.edit_text(result_text, disable_web_page_preview=True)


@router.message(F.document & F.document.mime_type.startswith("image/"))
async def handle_document_image(message: types.Message) -> None:
    """
    Обработка изображений отправленных как документы.
    Сохраняет оригинальное качество и EXIF.
    """
    document = message.document

    waiting_msg = await message.answer("📷 Анализирую метаданные изображения...")

    try:
        # Скачиваем файл
        file = await message.bot.get_file(document.file_id)
        file_data = await message.bot.download_file(file.file_path)

        # Читаем байты
        image_bytes = file_data.read()

        # Имя файла
        filename = document.file_name or "image"

        # Анализируем
        result = await scan_exif(image_bytes, filename)

    except Exception as e:
        log.error(f"[EXIF] Error scanning document image: {e}")
        await waiting_msg.edit_text(
            "⚠️ Ошибка при анализе изображения.\n"
            "Убедитесь, что файл — это изображение (JPEG, PNG)."
        )
        return

    result_text = format_exif_result(result)
    await waiting_msg.edit_text(result_text, disable_web_page_preview=True)
