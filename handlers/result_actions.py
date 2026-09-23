# handlers/result_actions.py
"""
Действия с карточки результата, специфичные для отдельных направлений.

    domain_detail:<домен>  - развёрнутый отчёт по домену
    maigret:<ник>          - углублённый поиск по ~500 платформам

Общие действия (повторить, следить, в меню) живут в scan_flow и monitor_menu.
"""
from __future__ import annotations

import logging

from aiogram import F, Router, types
from aiogram.types import BufferedInputFile

from domain_scanner.formatter import format_details
from domain_scanner.scanner import scan_domain
from email_scanner.formatter import format_email_result
from email_scanner.scanner import scan_email
from keyboards.menu_kb import get_back_menu
from services.maigret_service import maigret_search
from username_scanner.formatter import format_maigret_result
from utils.safe_html import esc
from utils.telegram_io import safe_answer, safe_edit

log = logging.getLogger(__name__)

router = Router()

DETAILS_PREFIX = "domain_detail:"

# Начиная с этого числа найденных профилей список уходит отдельным файлом:
# в сообщение он не влезает даже после разбиения на части
MAIGRET_FILE_THRESHOLD = 50


@router.callback_query(F.data.startswith(DETAILS_PREFIX))
async def cb_domain_details(callback: types.CallbackQuery) -> None:
    """
    Развёрнутый отчёт по домену.

    Отчёт бывает длиннее лимита Telegram, поэтому идёт через safe_answer:
    он разобьёт текст на части.
    """
    domain = (callback.data or "")[len(DETAILS_PREFIX):].strip()

    if not domain:
        await callback.answer("Некорректные данные для отчёта", show_alert=True)
        return

    await callback.answer()

    try:
        # Повторный скан попадёт в кэш, поэтому отвечает быстро
        result = await scan_domain(domain)
    except Exception as exc:
        log.error("[result_actions] Отчёт по %s не собрался: %s", domain, exc)
        await safe_answer(
            callback.message,
            "⚠️ Не удалось собрать детальный отчёт. Попробуй позже.",
            reply_markup=get_back_menu(),
        )
        return

    await safe_answer(
        callback.message,
        format_details(result),
        reply_markup=get_back_menu(),
        disable_web_page_preview=True,
    )


@router.callback_query(F.data.startswith("maigret:"))
async def cb_maigret(callback: types.CallbackQuery) -> None:
    """Углублённый поиск ника по ~500 платформам."""
    username = (callback.data or "").split(":", 1)[1]

    await callback.answer("Запускаю углублённый поиск")

    # Кнопку убираем: повторный запуск того же поиска смысла не имеет
    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        log.debug("[result_actions] Клавиатура уже снята")

    waiting_msg = await safe_answer(
        callback.message,
        f"🔬 Ищу <code>{esc(username)}</code> по ~500 платформам.\n"
        f"Это займёт до 90 секунд.",
    )

    try:
        hits, total_checked = await maigret_search(username)
    except Exception as exc:
        log.error("[result_actions] Maigret для %s упал: %s", username, exc)
        await safe_edit(
            waiting_msg,
            "⚠️ Углублённый поиск не удался. Попробуй позже.",
            reply_markup=get_back_menu(),
        )
        return

    await safe_edit(
        waiting_msg,
        format_maigret_result(username, hits, total_checked),
        reply_markup=get_back_menu(),
        disable_web_page_preview=True,
    )

    if len(hits) > MAIGRET_FILE_THRESHOLD:
        lines = [
            f"Maigret: @{username}",
            f"Проверено: {total_checked} | Найдено: {len(hits)}",
            "",
        ]
        for i, (site_name, url) in enumerate(hits, 1):
            lines.append(f"{i}. {site_name}" + (f" - {url}" if url else ""))

        await callback.message.answer_document(
            BufferedInputFile(
                "\n".join(lines).encode("utf-8"),
                filename=f"maigret_{username}.txt",
            ),
            caption=f"Полный список: {len(hits)} профилей",
        )


@router.callback_query(F.data.startswith("emaildeep:"))
async def cb_email_deep(callback: types.CallbackQuery) -> None:
    """
    Углублённая проверка email: поиск по платформам через holehe.

    Вынесена из основной проверки, потому что занимает до 45 секунд.
    Раньше столько длился любой запрос /email, и всё это время бот молчал.
    """
    email = (callback.data or "").split(":", 1)[1]

    await callback.answer("Запускаю поиск по платформам")

    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        log.debug("[result_actions] Клавиатура уже снята")

    waiting_msg = await safe_answer(
        callback.message,
        f"🔬 Ищу <code>{esc(email)}</code> по сервисам.\n"
        f"Это займёт до 45 секунд.",
    )

    try:
        result = await scan_email(email, deep=True)
    except Exception as exc:
        log.error("[result_actions] Глубокая проверка %s не удалась: %s", email, exc)
        await safe_edit(
            waiting_msg,
            "⚠️ Поиск по платформам не удался. Попробуй позже.",
            reply_markup=get_back_menu(),
        )
        return

    await safe_edit(
        waiting_msg,
        format_email_result(result),
        reply_markup=get_back_menu(),
        disable_web_page_preview=True,
    )
