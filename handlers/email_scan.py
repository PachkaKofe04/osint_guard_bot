# handlers/email_scan.py
"""Обработчик команды /email для проверки email адресов."""
import logging

from aiogram import Router, types
from aiogram.filters import Command

from email_scanner.scanner import scan_email
from email_scanner.formatter import format_email_result

log = logging.getLogger(__name__)

router = Router()


@router.message(Command("email"))
async def cmd_email(message: types.Message) -> None:
    """
    Обработка команды /email <адрес>.
    Проверяет email на валидность, утечки, одноразовость.
    """
    text = message.text or ""
    parts = text.split(maxsplit=1)

    if len(parts) < 2:
        await message.answer(
            "Укажи email для проверки.\n\n"
            "Пример:\n"
            "<code>/email user@example.com</code>"
        )
        return

    raw_email = parts[1].strip()

    waiting_msg = await message.answer("📧 Проверяю email...")

    try:
        result = await scan_email(raw_email)
    except Exception as e:
        log.error(f"[/email] Error scanning email: {e}")
        await waiting_msg.edit_text(
            "⚠️ Произошла ошибка при проверке email. Попробуй позже."
        )
        return

    result_text = format_email_result(result)
    await waiting_msg.edit_text(result_text)
