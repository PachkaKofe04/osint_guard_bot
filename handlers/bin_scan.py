# handlers/bin_scan.py
from aiogram import Router, types
from aiogram.filters import Command

from bin_scanner.scanner import scan_bin
from bin_scanner.formatter import format_bin_summary

router = Router()


@router.message(Command("bin"))
async def cmd_bin(message: types.Message) -> None:
    text = message.text or ""
    parts = text.split(maxsplit=1)

    if len(parts) < 2:
        await message.answer(
            "Укажи BIN для проверки (первые 6–8 цифр карты).\n\n"
            "Пример:\n"
            "<code>/bin 45717360</code>"
        )
        return

    raw_bin = parts[1].strip()

    try:
        result = scan_bin(raw_bin)
    except ValueError as e:
        await message.answer(f"❌ {e}")
        return
    except Exception:
        await message.answer("⚠️ Произошла ошибка при проверке BIN.")
        return

    summary = format_bin_summary(result)
    await message.answer(summary)
