# handlers/qr_scan.py
"""Обработчик для декодирования QR кодов."""
import logging

from aiogram import Router, types, F
from aiogram.filters import Command, StateFilter
from aiogram.fsm.context import FSMContext

from qr_scanner.scanner import scan_qr
from qr_scanner.formatter import format_qr_result
from states.qr_states import QRScanStates
from utils.telegram_io import safe_answer, safe_edit

log = logging.getLogger(__name__)

router = Router()

IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".tiff", ".tif", ".bmp",
    ".heic", ".heif", ".avif",
    ".nef", ".cr2", ".cr3", ".arw", ".dng", ".orf", ".raf",
}


def _is_image_document(document: types.Document) -> bool:
    if document.mime_type and document.mime_type.startswith("image/"):
        return True
    if document.file_name and "." in document.file_name:
        ext = "." + document.file_name.rsplit(".", 1)[-1].lower()
        return ext in IMAGE_EXTENSIONS
    return False


@router.message(Command("qr"), ~F.reply_to_message.photo)
async def cmd_qr_help(message: types.Message, state: FSMContext) -> None:
    """
    Справка по команде /qr и активация режима ожидания QR.
    Срабатывает, только если /qr отправлен НЕ в ответ на фото -
    иначе обработку забирает cmd_qr_reply_to_photo.
    """
    # Устанавливаем состояние - ждём фото с QR кодом
    await state.set_state(QRScanStates.waiting_for_photo)

    await safe_answer(message,
        "📱 <b>Декодирование QR кодов</b>\n\n"
        "Отправьте фото с QR кодом для анализа.\n\n"
        "<b>Что анализируется:</b>\n"
        "• 🔗 URL - проверка на фишинг\n"
        "• 📶 WiFi - сеть и пароль\n"
        "• 💰 Криптовалюта - адрес и сумма\n"
        "• 📧 Email, 📞 телефон\n"
        "• 📍 Геолокация\n"
        "• 📝 Текст\n\n"
        "💡 <i>Просто отправьте изображение с QR кодом!</i>"
    )


@router.message(QRScanStates.waiting_for_photo, F.photo)
async def handle_qr_photo_in_state(message: types.Message, state: FSMContext) -> None:
    """
    Обработка фото, когда пользователь в режиме ожидания QR.
    """
    photo = message.photo[-1]
    waiting_msg = await safe_answer(message, "📱 Сканирую QR код...")

    try:
        file = await message.bot.get_file(photo.file_id)
        file_data = await message.bot.download_file(file.file_path)
        image_bytes = file_data.read()
        filename = file.file_path.split("/")[-1] if file.file_path else "photo.jpg"

        result = await scan_qr(image_bytes, filename)

    except Exception as e:
        log.error(f"[QR] Error scanning photo: {e}")
        await safe_edit(waiting_msg,
            "⚠️ Ошибка при сканировании QR кода.\n"
            "Убедитесь, что изображение содержит QR код."
        )
        await state.clear()
        return

    result_text = format_qr_result(result)
    await safe_edit(waiting_msg, result_text, disable_web_page_preview=True)

    # Очищаем состояние после обработки
    await state.clear()


@router.message(QRScanStates.waiting_for_photo, F.document)
async def handle_qr_document_in_state(message: types.Message, state: FSMContext) -> None:
    """
    Обработка документов-изображений, когда пользователь в режиме ожидания QR.
    """
    document = message.document
    if not _is_image_document(document):
        return
    waiting_msg = await safe_answer(message, "📱 Сканирую QR код...")

    try:
        file = await message.bot.get_file(document.file_id)
        file_data = await message.bot.download_file(file.file_path)
        image_bytes = file_data.read()
        filename = document.file_name or "image"

        result = await scan_qr(image_bytes, filename)

    except Exception as e:
        log.error(f"[QR] Error scanning document: {e}")
        await safe_edit(waiting_msg,
            "⚠️ Ошибка при сканировании QR кода.\n"
            "Убедитесь, что файл - это изображение с QR кодом."
        )
        await state.clear()
        return

    result_text = format_qr_result(result)
    await safe_edit(waiting_msg, result_text, disable_web_page_preview=True)

    # Очищаем состояние после обработки
    await state.clear()


# Примечание: обработка фото с QR кодами происходит в exif_scan.py
# Если нужен отдельный обработчик, можно добавить фильтр по caption "/qr"
# Но для удобства пользователя - любое фото сначала проверяется на EXIF,
# а для QR можно сделать inline кнопку или отдельную команду

@router.message(Command("qr"), F.reply_to_message.photo)
async def cmd_qr_reply_to_photo(message: types.Message) -> None:
    """
    Обработка /qr в ответ на сообщение с фото.
    """
    reply = message.reply_to_message
    if not reply or not reply.photo:
        await safe_answer(message, "Ответьте на сообщение с фото командой /qr")
        return

    photo = reply.photo[-1]
    waiting_msg = await safe_answer(message, "📱 Сканирую QR код...")

    try:
        file = await message.bot.get_file(photo.file_id)
        file_data = await message.bot.download_file(file.file_path)
        image_bytes = file_data.read()
        filename = file.file_path.split("/")[-1] if file.file_path else "photo.jpg"

        result = await scan_qr(image_bytes, filename)

    except Exception as e:
        log.error(f"[QR] Error scanning photo: {e}")
        await safe_edit(waiting_msg,
            "⚠️ Ошибка при сканировании QR кода.\n"
            "Убедитесь, что изображение содержит QR код."
        )
        return

    result_text = format_qr_result(result)
    await safe_edit(waiting_msg, result_text, disable_web_page_preview=True)


@router.message(F.photo, F.caption.startswith("/qr"))
async def handle_photo_with_qr_caption(message: types.Message) -> None:
    """
    Обработка фото с подписью /qr.
    """
    photo = message.photo[-1]
    waiting_msg = await safe_answer(message, "📱 Сканирую QR код...")

    try:
        file = await message.bot.get_file(photo.file_id)
        file_data = await message.bot.download_file(file.file_path)
        image_bytes = file_data.read()
        filename = file.file_path.split("/")[-1] if file.file_path else "photo.jpg"

        result = await scan_qr(image_bytes, filename)

    except Exception as e:
        log.error(f"[QR] Error scanning photo: {e}")
        await safe_edit(waiting_msg,
            "⚠️ Ошибка при сканировании QR кода.\n"
            "Убедитесь, что изображение содержит QR код."
        )
        return

    result_text = format_qr_result(result)
    await safe_edit(waiting_msg, result_text, disable_web_page_preview=True)


@router.message(F.document, F.caption.startswith("/qr"))
async def handle_document_with_qr_caption(message: types.Message) -> None:
    """
    Обработка изображений-документов с подписью /qr.
    """
    document = message.document
    if not _is_image_document(document):
        return
    waiting_msg = await safe_answer(message, "📱 Сканирую QR код...")

    try:
        file = await message.bot.get_file(document.file_id)
        file_data = await message.bot.download_file(file.file_path)
        image_bytes = file_data.read()
        filename = document.file_name or "image"

        result = await scan_qr(image_bytes, filename)

    except Exception as e:
        log.error(f"[QR] Error scanning document: {e}")
        await safe_edit(waiting_msg,
            "⚠️ Ошибка при сканировании QR кода.\n"
            "Убедитесь, что файл - это изображение с QR кодом."
        )
        return

    result_text = format_qr_result(result)
    await safe_edit(waiting_msg, result_text, disable_web_page_preview=True)
