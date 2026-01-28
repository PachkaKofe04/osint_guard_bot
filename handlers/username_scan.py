# handlers/username_scan.py
"""Обработчик команды /username для OSINT поиска."""
import logging

from aiogram import Router, types
from aiogram.filters import Command

from username_scanner.scanner import scan_username
from username_scanner.formatter import format_username_result

log = logging.getLogger(__name__)

router = Router()


@router.message(Command("username"))
async def cmd_username(message: types.Message) -> None:
    """
    Обработка команды /username <ник>.
    Проверяет наличие username на различных платформах.
    """
    text = message.text or ""
    parts = text.split(maxsplit=1)

    if len(parts) < 2:
        await message.answer(
            "Укажи username для проверки.\n\n"
            "Пример:\n"
            "<code>/username john_doe</code>\n"
            "<code>/username @telegram_user</code>"
        )
        return

    raw_username = parts[1].strip()

    waiting_msg = await message.answer(
        "👤 Ищу username на платформах...\n"
        "Это может занять до 30 секунд."
    )

    try:
        result = await scan_username(raw_username)
    except Exception as e:
        log.error(f"[/username] Error scanning username: {e}")
        await waiting_msg.edit_text(
            "⚠️ Произошла ошибка при поиске username. Попробуй позже."
        )
        return

    result_text = format_username_result(result)
    await waiting_msg.edit_text(result_text, disable_web_page_preview=True)
