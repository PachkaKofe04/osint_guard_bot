# handlers/auto_detect.py
"""Автоматическое определение типа ввода и перенаправление на нужный сканер."""
import logging

from aiogram import Router, types, F
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from url_scanner.scanner import scan_url
from url_scanner.formatter import format_url_result
from email_scanner.scanner import scan_email
from email_scanner.formatter import format_email_result
from ip_scanner.scanner import scan_ip
from ip_scanner.formatter import format_ip_result
from username_scanner.scanner import scan_username
from username_scanner.formatter import format_username_result
from wallet_scanner.scanner import scan_wallet
from wallet_scanner.formatter import format_wallet_result
from domain_scanner.scanner import scan_domain
from domain_scanner.formatter import format_summary as format_domain_result
from phone_scanner.scanner import scan_phone
from phone_scanner.formatter import format_phone_summary
from bin_scanner.scanner import scan_bin_async
from bin_scanner.formatter import format_bin_summary

from keyboards.main_menu import get_main_menu
from utils.input_detect import detect_input_type
from utils.safe_html import esc
from utils.telegram_io import safe_edit, safe_answer

log = logging.getLogger(__name__)

router = Router()

# Человекочитаемые названия типов для сообщения «определён …»
TYPE_NAMES = {
    "url": "🔗 ссылка",
    "email": "📧 email",
    "ip": "🌐 IP-адрес",
    "phone": "📞 телефон",
    "bin": "💳 BIN карты",
    "wallet": "💰 криптокошелёк",
    "domain": "🌍 домен",
    "username": "👤 никнейм",
}


async def _run_scan(input_type: str, value: str) -> str:
    """Запускает нужный сканер и возвращает готовый текст отчёта."""
    if input_type == "url":
        return format_url_result(await scan_url(value))
    if input_type == "email":
        return format_email_result(await scan_email(value))
    if input_type == "ip":
        return format_ip_result(await scan_ip(value))
    if input_type == "phone":
        return format_phone_summary(await scan_phone(value))
    if input_type == "bin":
        return format_bin_summary(await scan_bin_async(value))
    if input_type == "wallet":
        return format_wallet_result(await scan_wallet(value))
    if input_type == "domain":
        return format_domain_result(await scan_domain(value))
    if input_type == "username":
        return format_username_result(await scan_username(value))
    raise ValueError(f"Неизвестный тип скана: {input_type}")


def _ambiguous_keyboard(value: str) -> InlineKeyboardMarkup:
    """Кнопки для случая, когда ввод похож и на слово, и на никнейм."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👤 Искать как никнейм", callback_data=f"asname:{value}")],
        [InlineKeyboardButton(text="☰ Открыть меню", callback_data="menu:main")],
    ])


UNKNOWN_TEXT = (
    "🤔 Не понял, что это за данные.\n\n"
    "Пришли что-то из этого:\n"
    "• домен или ссылку — <code>example.com</code>\n"
    "• email — <code>user@mail.ru</code>\n"
    "• телефон — <code>+79991234567</code>\n"
    "• IP-адрес — <code>8.8.8.8</code>\n"
    "• никнейм — <code>@johndoe</code>\n"
    "• BIN карты — <code>427229</code>\n"
    "• адрес криптокошелька\n"
    "• фото файлом — разберу EXIF или QR\n\n"
    "Или выбери раздел в меню 👇"
)


@router.message(F.text & ~F.text.startswith("/"))
async def auto_detect_handler(message: types.Message) -> None:
    """
    Определяет тип ввода и вызывает нужный сканер.
    Срабатывает на любой текст без команды — это последний роутер в цепочке.
    """
    text = message.text or ""
    input_type, value = detect_input_type(text)

    log.info("[Auto-detect] %r → %s", text[:50], input_type)

    if input_type == "ambiguous":
        await message.answer(
            f"🤔 <code>{esc(value)}</code> — это никнейм?\n\n"
            "Если да, проверю по 20 платформам.",
            reply_markup=_ambiguous_keyboard(value),
        )
        return

    if input_type == "unknown":
        await message.answer(UNKNOWN_TEXT, reply_markup=get_main_menu())
        return

    type_name = TYPE_NAMES.get(input_type, input_type)
    waiting_msg = await message.answer(f"🔍 Определил {type_name}, анализирую…")

    try:
        result_text = await _run_scan(input_type, value)
    except ValueError as exc:
        log.info("[Auto-detect] Некорректный ввод для %s: %s", input_type, exc)
        await safe_edit(
            waiting_msg,
            f"❌ Не получилось разобрать: <code>{esc(text[:100])}</code>\n\n{esc(exc)}",
            reply_markup=get_main_menu(),
        )
        return
    except Exception as exc:
        log.error("[Auto-detect] Ошибка скана %s: %s", input_type, exc, exc_info=True)
        await safe_edit(
            waiting_msg,
            "⚠️ Не удалось выполнить проверку. Источник данных не ответил.\n"
            "Попробуй ещё раз через минуту.",
            reply_markup=get_main_menu(),
        )
        return

    await safe_edit(waiting_msg, result_text, disable_web_page_preview=True)


@router.callback_query(F.data.startswith("asname:"))
async def callback_scan_as_username(callback: types.CallbackQuery) -> None:
    """Пользователь подтвердил, что введённое слово — никнейм."""
    username = (callback.data or "").split(":", 1)[1]
    await callback.answer()

    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        log.debug("[Auto-detect] Не удалось убрать клавиатуру подтверждения")

    waiting_msg = await callback.message.answer(
        f"👤 Ищу <code>{esc(username)}</code> на платформах…"
    )

    try:
        result_text = format_username_result(await scan_username(username))
    except Exception as exc:
        log.error("[Auto-detect] Ошибка поиска username %s: %s", username, exc)
        await safe_edit(
            waiting_msg,
            "⚠️ Не удалось выполнить поиск. Попробуй позже.",
            reply_markup=get_main_menu(),
        )
        return

    await safe_edit(waiting_msg, result_text, disable_web_page_preview=True)


@router.message(F.text.startswith("/"))
async def unknown_command(message: types.Message) -> None:
    """
    Ловит команды, для которых нет обработчика.
    Раньше бот на них просто молчал, и выглядело это как поломка.
    """
    command = (message.text or "").split()[0]
    log.info("[Auto-detect] Неизвестная команда: %s", command)
    await safe_answer(
        message,
        f"❓ Команда <code>{esc(command)}</code> мне неизвестна.\n\n"
        "Всё, что я умею, — в меню 👇",
        reply_markup=get_main_menu(),
    )


@router.message()
async def unsupported_content(message: types.Message) -> None:
    """Стикеры, голосовые, геопозиция и прочее, с чем бот не работает."""
    await safe_answer(
        message,
        "🤷 С таким типом сообщений я не работаю.\n\n"
        "Пришли текст или изображение файлом — или выбери раздел в меню 👇",
        reply_markup=get_main_menu(),
    )
