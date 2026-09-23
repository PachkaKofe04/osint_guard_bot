import re
from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from phone_scanner.scanner import scan_phone
from phone_scanner.formatter import format_phone_summary
from utils.telegram_io import safe_answer

router = Router()

PHONE_RE = re.compile(r"^[\d\+\-\s\(\)]{7,20}$")  # простой фильтр: цифры/плюс/скобки/пробелы


@router.message(Command("phone"))
async def phone_cmd(message: Message):
    text = (message.text or "").strip()
    parts = text.split(maxsplit=1)

    if len(parts) < 2:
        await safe_answer(message, "❌ Формат: /phone +79991234567")
        return

    raw_phone = parts[1].strip()

    if not PHONE_RE.match(raw_phone):
        await safe_answer(message, "❌ Похоже, это не номер. Формат: /phone +79991234567")
        return

    try:
        result = await scan_phone(raw_phone)
    except Exception as e:
        await safe_answer(message, f"❌ Ошибка при сканировании телефона: {e}")
        return

    # Используем единый formatter
    formatted_message = format_phone_summary(result)
    await safe_answer(message, formatted_message)
