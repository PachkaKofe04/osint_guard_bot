# handlers/scan_domain.py
from aiogram import Router, types, F
from aiogram.filters import Command

from domain_scanner.scanner import scan_domain
from domain_scanner.formatter import format_summary, format_details   # ← вот так
from keyboards.domain_kb import domain_details_keyboard, DETAILS_PREFIX


router = Router()


@router.message(Command("scan"))
async def cmd_scan(message: types.Message) -> None:
    """
    Обработка команды /scan <домен>.
    """
    # текст после /scan
    # в aiogram 3 message.text уже целиком, парсим сами
    text = message.text or ""
    parts = text.split(maxsplit=1)

    if len(parts) < 2:
        await message.answer(
            "Укажи домен для сканирования.\n\n"
            "Пример:\n"
            "<code>/scan baodex.cc</code>"
        )
        return

    raw_domain = parts[1].strip()

    waiting_msg = await message.answer("⏳ Сканирую домен, это может занять несколько секунд...")

    try:
        result = await scan_domain(raw_domain)
    except ValueError:
        await waiting_msg.edit_text(
            "❌ Похоже, это не похоже на корректный домен.\n"
            "Пример корректного ввода:\n"
            "<code>/scan example.com</code>"
        )
        return
    except Exception as e:
        await waiting_msg.edit_text(
            "⚠️ Произошла ошибка при сканировании домена. Попробуй позже."
        )
        return

    summary_text = format_summary(result)
    kb = domain_details_keyboard(result.normalized_domain)

    await waiting_msg.edit_text(summary_text, reply_markup=kb)


@router.callback_query(F.data.startswith(DETAILS_PREFIX))
async def cb_domain_details(callback: types.CallbackQuery) -> None:
    """
    Обработка нажатия на кнопку 'Подробнее'.
    В callback_data зашит домен.
    """
    data = callback.data or ""
    domain = data[len(DETAILS_PREFIX):].strip()

    if not domain:
        await callback.answer("Некорректные данные для отчёта", show_alert=True)
        return

    await callback.answer()  # убираем "часики"

    # повторно сканируем домен — сработает кэш, поэтому быстро
    try:
        result = await scan_domain(domain)
    except Exception:
        await callback.message.answer(
            "⚠️ Не удалось получить детальный отчёт. Попробуй позже."
        )
        return

    details_text = format_details(result)
    await callback.message.answer(details_text)
