# handlers/ip_scan.py
"""Обработчик команды /ip для проверки IP адресов."""
import logging

from aiogram import Router, types
from aiogram.filters import Command

from ip_scanner.scanner import scan_ip
from ip_scanner.formatter import format_ip_result
from utils.telegram_io import safe_answer, safe_edit

log = logging.getLogger(__name__)

router = Router()


@router.message(Command("ip"))
async def cmd_ip(message: types.Message) -> None:
    """
    Обработка команды /ip <адрес>.
    Проверяет IP адрес на геолокацию, VPN/proxy, репутацию.
    """
    text = message.text or ""
    parts = text.split(maxsplit=1)

    if len(parts) < 2:
        await safe_answer(message,
            "Укажи IP адрес для проверки.\n\n"
            "Пример:\n"
            "<code>/ip 8.8.8.8</code>\n"
            "<code>/ip 2001:4860:4860::8888</code>"
        )
        return

    raw_ip = parts[1].strip()

    waiting_msg = await safe_answer(message, "🔍 Проверяю IP адрес...")

    try:
        result = await scan_ip(raw_ip)
    except Exception as e:
        log.error(f"[/ip] Error scanning IP: {e}")
        await safe_edit(waiting_msg,
            "⚠️ Произошла ошибка при проверке IP. Попробуй позже."
        )
        return

    result_text = format_ip_result(result)
    await safe_edit(waiting_msg, result_text)
