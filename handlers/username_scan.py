# handlers/username_scan.py
"""Обработчик команды /username для OSINT поиска."""
import logging

from aiogram import Router, types, F
from aiogram.filters import Command

from username_scanner.scanner import scan_username
from username_scanner.formatter import format_username_result, format_maigret_result
from keyboards.username_kb import get_username_keyboard
from services.maigret_service import maigret_search

log = logging.getLogger(__name__)

router = Router()


@router.message(Command("username", "user"))
async def cmd_username(message: types.Message) -> None:
    """
    Обработка команды /username <ник>.
    Проверяет наличие username на 20 платформах, затем предлагает
    углублённый поиск через Maigret (inline-кнопка).
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

    # Показываем результат с кнопкой углублённого поиска (только для валидных username)
    if result.info and result.info.is_valid:
        username_clean = result.username
        keyboard = get_username_keyboard(username_clean)
        await waiting_msg.edit_text(
            result_text,
            reply_markup=keyboard,
            disable_web_page_preview=True,
        )
    else:
        await waiting_msg.edit_text(result_text, disable_web_page_preview=True)


@router.callback_query(F.data.startswith("maigret:"))
async def callback_maigret(callback: types.CallbackQuery) -> None:
    """
    Callback для кнопки 'Углублённый поиск (Maigret)'.
    Запускает maigret по ~500 платформам и возвращает результат.
    """
    username = callback.data.split(":", 1)[1]

    await callback.answer("🔬 Запускаю углублённый поиск...")

    # Убираем кнопку (запрос уже принят)
    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        pass

    waiting_msg = await callback.message.answer(
        f"🔬 Запускаю Maigret для <code>@{username}</code>...\n"
        "Проверяю ~500 платформ, это займёт до 90 секунд."
    )

    try:
        hits, total_checked = await maigret_search(username)
    except Exception as e:
        log.error(f"[Maigret callback] Error for {username}: {e}")
        await waiting_msg.edit_text("⚠️ Ошибка при запуске Maigret. Попробуй позже.")
        return

    result_text = format_maigret_result(username, hits, total_checked)
    await waiting_msg.edit_text(result_text, disable_web_page_preview=True)
