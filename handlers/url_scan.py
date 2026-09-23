# handlers/url_scan.py
"""Обработчик команды /url для проверки ссылок."""
import logging

from aiogram import Router, types
from aiogram.filters import Command

from url_scanner.scanner import scan_url
from url_scanner.formatter import format_url_result
from utils.telegram_io import safe_answer, safe_edit

log = logging.getLogger(__name__)

router = Router()


@router.message(Command("url"))
async def cmd_url(message: types.Message) -> None:
    """
    Обработка команды /url <ссылка>.
    Проверяет URL на фишинг, разворачивает короткие ссылки.
    """
    text = message.text or ""
    parts = text.split(maxsplit=1)

    if len(parts) < 2:
        await safe_answer(message,
            "Укажи URL для проверки.\n\n"
            "Примеры:\n"
            "<code>/url bit.ly/abc123</code>\n"
            "<code>/url https://example.com</code>"
        )
        return

    raw_url = parts[1].strip()

    waiting_msg = await safe_answer(message, "🔍 Проверяю ссылку...")

    try:
        result = await scan_url(raw_url)
    except ValueError as e:
        await safe_edit(waiting_msg, f"❌ Ошибка: {e}")
        return
    except Exception as e:
        log.error(f"[/url] Error scanning URL: {e}")
        await safe_edit(waiting_msg,
            "⚠️ Произошла ошибка при проверке ссылки. Попробуй позже."
        )
        return

    result_text = format_url_result(result)
    await safe_edit(waiting_msg, result_text)
