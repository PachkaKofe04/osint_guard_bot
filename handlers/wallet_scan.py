# handlers/wallet_scan.py
"""Обработчик команды /wallet для проверки криптокошельков."""
import logging

from aiogram import Router, types
from aiogram.filters import Command

from wallet_scanner.scanner import scan_wallet
from wallet_scanner.formatter import format_wallet_result
from utils.telegram_io import safe_answer, safe_edit

log = logging.getLogger(__name__)

router = Router()


@router.message(Command("wallet"))
async def cmd_wallet(message: types.Message) -> None:
    """
    Обработка команды /wallet <адрес>.
    Проверяет криптокошелёк на баланс, активность и скам.
    """
    text = message.text or ""
    parts = text.split(maxsplit=1)

    if len(parts) < 2:
        await safe_answer(message,
            "Укажи адрес криптокошелька для проверки.\n\n"
            "Поддерживаются: BTC, ETH, LTC, TRX, XRP, DOGE, SOL\n\n"
            "Примеры:\n"
            "<code>/wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</code>\n"
            "<code>/wallet 0x742d35Cc6634C0532925a3b844Bc9e7595f...</code>"
        )
        return

    raw_address = parts[1].strip()

    waiting_msg = await safe_answer(message, "💰 Проверяю криптокошелёк...")

    try:
        result = await scan_wallet(raw_address)
    except Exception as e:
        log.error(f"[/wallet] Error scanning wallet: {e}")
        await safe_edit(waiting_msg,
            "⚠️ Произошла ошибка при проверке кошелька. Попробуй позже."
        )
        return

    result_text = format_wallet_result(result)
    await safe_edit(waiting_msg, result_text, disable_web_page_preview=True)
