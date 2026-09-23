# handlers/scan_domain.py
import logging

from aiogram import Router, types, F
from aiogram.filters import Command

from domain_scanner.scanner import scan_domain
from domain_scanner.formatter import format_summary, format_details
from keyboards.domain_kb import domain_details_keyboard, DETAILS_PREFIX
from keyboards.main_menu import get_main_menu
from utils.safe_html import esc
from utils.telegram_io import safe_edit, safe_answer

log = logging.getLogger(__name__)

router = Router()


@router.message(Command("scan", "domain"))
async def cmd_scan(message: types.Message) -> None:
    """
    Обработка команды /scan <домен>.
    """
    text = message.text or ""
    parts = text.split(maxsplit=1)

    if len(parts) < 2:
        await message.answer(
            "Укажи домен для сканирования.\n\n"
            "Пример:\n"
            "<code>/scan example.com</code>",
            reply_markup=get_main_menu(),
        )
        return

    raw_domain = parts[1].strip()

    waiting_msg = await message.answer("⏳ Сканирую домен, это может занять несколько секунд…")

    try:
        result = await scan_domain(raw_domain)
    except ValueError:
        await safe_edit(
            waiting_msg,
            f"❌ <code>{esc(raw_domain[:100])}</code> не похоже на корректный домен.\n\n"
            "Пример: <code>/scan example.com</code>",
            reply_markup=get_main_menu(),
        )
        return
    except Exception as exc:
        log.error("[/scan] Ошибка сканирования %s: %s", raw_domain, exc, exc_info=True)
        await safe_edit(
            waiting_msg,
            "⚠️ Произошла ошибка при сканировании домена. Попробуй позже.",
            reply_markup=get_main_menu(),
        )
        return

    await safe_edit(
        waiting_msg,
        format_summary(result),
        reply_markup=domain_details_keyboard(result.normalized_domain),
    )


@router.callback_query(F.data.startswith(DETAILS_PREFIX))
async def cb_domain_details(callback: types.CallbackQuery) -> None:
    """
    Обработка нажатия на кнопку «Подробнее». В callback_data зашит домен.
    Отчёт может быть длиннее лимита Telegram — отправляем через safe_answer,
    он разобьёт текст на части.
    """
    data = callback.data or ""
    domain = data[len(DETAILS_PREFIX):].strip()

    if not domain:
        await callback.answer("Некорректные данные для отчёта", show_alert=True)
        return

    await callback.answer()  # убираем «часики»

    # Повторно сканируем домен — сработает кэш, поэтому быстро
    try:
        result = await scan_domain(domain)
    except Exception as exc:
        log.error("[domain details] Ошибка для %s: %s", domain, exc, exc_info=True)
        await safe_answer(
            callback.message,
            "⚠️ Не удалось получить детальный отчёт. Попробуй позже.",
            reply_markup=get_main_menu(),
        )
        return

    await safe_answer(
        callback.message,
        format_details(result),
        disable_web_page_preview=True,
    )
