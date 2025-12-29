# handlers/common.py
from aiogram import Router, types
from aiogram.filters import CommandStart, Command

router = Router()


@router.message(CommandStart())
async def cmd_start(message: types.Message) -> None:
    text = (
        "Привет 👋\n\n"
        "Я OSINT-бот для быстрой оценки рисков.\n\n"
        "<b>Что я умею сейчас:</b>\n"
        "• Сканировать домен: WHOIS, DNS, SSL (crt.sh), HTTP/robots — команда: <code>/scan &lt;домен&gt;</code>\n"
        "• Проверять номер телефона по базовым признакам подозрительности — команда: <code>/phone &lt;номер&gt;</code>\n"
        "• Проверять BIN банковской карты через открытую базу (binlist) — команда: <code>/bin &lt;BIN&gt;</code>\n\n"
        "<b>Примеры:</b>\n"
        "<code>/scan baodex.cc</code>\n"
        "<code>/phone +7 999 123-45-67</code>\n"
        "<code>/bin 45717360</code>"
    )
    await message.answer(text)


@router.message(Command("help"))
async def cmd_help(message: types.Message) -> None:
    text = (
        "<b>Доступные команды:</b>\n"
        "• <code>/start</code> — информация о боте\n"
        "• <code>/help</code> — эта справка\n"
        "• <code>/scan &lt;домен&gt;</code> — проверка домена (WHOIS/DNS/SSL/HTTP)\n"
        "• <code>/phone &lt;номер&gt;</code> — проверка телефона\n"
        "• <code>/bin &lt;BIN&gt;</code> — проверка BIN банковской карты\n\n"
        "<b>Примеры:</b>\n"
        "<code>/scan example.com</code>\n"
        "<code>/phone +7 999 123-45-67</code>\n"
        "<code>/bin 45717360</code>"
    )
    await message.answer(text)
