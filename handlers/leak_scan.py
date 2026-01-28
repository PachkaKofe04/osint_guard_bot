# handlers/leak_scan.py
"""Обработчик команды /leak для проверки утечек."""
import logging
import os

from aiogram import Router, types
from aiogram.filters import Command

from leak_scanner.scanner import scan_leaks
from leak_scanner.formatter import format_leak_result

log = logging.getLogger(__name__)

router = Router()

# HIBP API ключ из переменных окружения (опционально)
HIBP_API_KEY = os.getenv("HIBP_API_KEY")


@router.message(Command("leak"))
async def cmd_leak(message: types.Message) -> None:
    """
    Обработка команды /leak <email>.
    Проверяет email на утечки данных.
    """
    text = message.text or ""
    parts = text.split(maxsplit=1)

    if len(parts) < 2:
        await message.answer(
            "Укажи email для проверки на утечки.\n\n"
            "Пример:\n"
            "<code>/leak user@example.com</code>\n\n"
            "⚠️ Проверка происходит по базам известных утечек."
        )
        return

    query = parts[1].strip()

    # Проверяем что это похоже на email
    if "@" not in query or "." not in query:
        await message.answer(
            "⚠️ Введите корректный email адрес.\n"
            "Пример: <code>/leak user@example.com</code>"
        )
        return

    waiting_msg = await message.answer("🔍 Проверяю на утечки...")

    try:
        result = await scan_leaks(query, api_key=HIBP_API_KEY)
    except Exception as e:
        log.error(f"[/leak] Error checking leaks: {e}")
        await waiting_msg.edit_text(
            "⚠️ Ошибка при проверке. Попробуй позже."
        )
        return

    result_text = format_leak_result(result)
    await waiting_msg.edit_text(result_text, disable_web_page_preview=True)
