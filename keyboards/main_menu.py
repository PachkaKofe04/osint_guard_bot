# keyboards/main_menu.py
"""Главное меню и навигация бота."""
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder


def get_main_menu() -> InlineKeyboardMarkup:
    """Главное меню с категориями сканеров."""
    builder = InlineKeyboardBuilder()

    # Ряд 1: Основные проверки
    builder.row(
        InlineKeyboardButton(text="🌐 Домен", callback_data="menu:domain"),
        InlineKeyboardButton(text="🔗 URL", callback_data="menu:url"),
        InlineKeyboardButton(text="📧 Email", callback_data="menu:email"),
    )

    # Ряд 2: Сетевые проверки
    builder.row(
        InlineKeyboardButton(text="📱 Телефон", callback_data="menu:phone"),
        InlineKeyboardButton(text="🌍 IP", callback_data="menu:ip"),
        InlineKeyboardButton(text="👤 Username", callback_data="menu:user"),
    )

    # Ряд 3: Финансы и медиа
    builder.row(
        InlineKeyboardButton(text="💳 BIN карты", callback_data="menu:bin"),
        InlineKeyboardButton(text="💰 Криптокошелёк", callback_data="menu:wallet"),
    )

    # Ряд 4: Медиа и утечки
    builder.row(
        InlineKeyboardButton(text="🖼 EXIF фото", callback_data="menu:exif"),
        InlineKeyboardButton(text="📱 QR код", callback_data="menu:qr"),
        InlineKeyboardButton(text="🔓 Утечки", callback_data="menu:leak"),
    )

    # Ряд 5: Справка
    builder.row(
        InlineKeyboardButton(text="❓ Справка", callback_data="menu:help"),
    )

    return builder.as_markup()


def get_back_to_menu() -> InlineKeyboardMarkup:
    """Кнопка возврата в главное меню."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text="◀️ Главное меню", callback_data="menu:main"),
    )
    return builder.as_markup()


def get_scanner_help(scanner: str) -> InlineKeyboardMarkup:
    """Кнопки под справкой сканера."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text="◀️ Назад", callback_data="menu:main"),
    )
    return builder.as_markup()


# Тексты справки для каждого сканера
SCANNER_HELP = {
    "domain": (
        "🌐 <b>Сканер доменов</b>\n\n"
        "<b>Команда:</b> <code>/scan example.com</code>\n\n"
        "<b>Что проверяется:</b>\n"
        "• Возраст домена (WHOIS)\n"
        "• DNS конфигурация\n"
        "• SSL сертификат\n"
        "• Хостинг-провайдер\n"
        "• Privacy protection\n\n"
        "<b>Или просто отправь домен</b> — бот определит автоматически."
    ),
    "url": (
        "🔗 <b>Сканер URL</b>\n\n"
        "<b>Команда:</b> <code>/url https://example.com/page</code>\n\n"
        "<b>Что проверяется:</b>\n"
        "• Разворот сокращённых ссылок\n"
        "• Проверка на фишинг\n"
        "• Подозрительные TLD\n"
        "• Редиректы\n\n"
        "<b>Или просто отправь ссылку</b> — бот определит автоматически."
    ),
    "email": (
        "📧 <b>Сканер Email</b>\n\n"
        "<b>Команда:</b> <code>/email user@example.com</code>\n\n"
        "<b>Что проверяется:</b>\n"
        "• Валидность формата\n"
        "• Disposable (одноразовые) email\n"
        "• Возраст домена\n"
        "• MX записи\n\n"
        "<b>Или просто отправь email</b> — бот определит автоматически."
    ),
    "phone": (
        "📱 <b>Сканер телефонов</b>\n\n"
        "<b>Команда:</b> <code>/phone +79991234567</code>\n\n"
        "<b>Что проверяется:</b>\n"
        "• Страна и оператор\n"
        "• Тип номера (mobile/VoIP)\n"
        "• Валидность формата\n\n"
        "<b>Форматы:</b> +79991234567, 89991234567, 9991234567"
    ),
    "ip": (
        "🌍 <b>Сканер IP адресов</b>\n\n"
        "<b>Команда:</b> <code>/ip 8.8.8.8</code>\n\n"
        "<b>Что проверяется:</b>\n"
        "• Геолокация (страна, город)\n"
        "• VPN/Proxy/Tor детекция\n"
        "• ASN и провайдер\n"
        "• Репутация в blacklists\n\n"
        "<b>Или просто отправь IP</b> — бот определит автоматически."
    ),
    "user": (
        "👤 <b>Username OSINT</b>\n\n"
        "<b>Команда:</b> <code>/user johndoe</code>\n\n"
        "<b>Что проверяется:</b>\n"
        "• Поиск по 20+ платформам\n"
        "• Социальные сети\n"
        "• Профессиональные сети\n"
        "• Форумы и сервисы\n\n"
        "<b>Отправь username</b> для поиска."
    ),
    "bin": (
        "💳 <b>Сканер BIN карт</b>\n\n"
        "<b>Команда:</b> <code>/bin 427229</code>\n\n"
        "<b>Что проверяется:</b>\n"
        "• Платёжная система\n"
        "• Банк-эмитент\n"
        "• Страна выпуска\n"
        "• Тип карты (debit/credit/prepaid)\n\n"
        "<b>BIN:</b> первые 6-8 цифр карты."
    ),
    "wallet": (
        "💰 <b>Сканер криптокошельков</b>\n\n"
        "<b>Команда:</b> <code>/wallet 0x...</code> или <code>/wallet 1A...</code>\n\n"
        "<b>Что проверяется:</b>\n"
        "• Bitcoin, Ethereum, USDT, Solana\n"
        "• Баланс кошелька\n"
        "• Проверка в scam-базах\n"
        "• История транзакций\n\n"
        "<b>Или просто отправь адрес</b> — бот определит автоматически."
    ),
    "exif": (
        "🖼 <b>EXIF анализ фото</b>\n\n"
        "<b>Как использовать:</b>\n"
        "Просто отправь фотографию боту.\n\n"
        "<b>Что извлекается:</b>\n"
        "• GPS координаты (если есть)\n"
        "• Модель камеры/телефона\n"
        "• Дата и время съёмки\n"
        "• Автор и ПО\n\n"
        "⚠️ <i>Предупреждает о рисках приватности</i>"
    ),
    "qr": (
        "📱 <b>Декодер QR кодов</b>\n\n"
        "<b>Как использовать:</b>\n"
        "Отправь фото с QR кодом и подпись <code>/qr</code>\n"
        "Или ответь на фото командой <code>/qr</code>\n\n"
        "<b>Что проверяется:</b>\n"
        "• URL — на фишинг\n"
        "• WiFi — сеть и пароль\n"
        "• Криптоадреса — проверка\n"
        "• Email, телефон, геолокация"
    ),
    "leak": (
        "🔓 <b>Проверка утечек</b>\n\n"
        "<b>Команда:</b> <code>/leak user@example.com</code>\n\n"
        "<b>Что проверяется:</b>\n"
        "• Email в базах утечек\n"
        "• Телефон в базах утечек\n"
        "• Какие данные скомпрометированы\n\n"
        "⚠️ <i>Используется для проверки собственных данных</i>"
    ),
    "help": (
        "❓ <b>Справка по боту</b>\n\n"
        "<b>OSINT Guard Bot</b> — бот для анализа безопасности.\n\n"
        "<b>Автоматическое определение:</b>\n"
        "Просто отправь данные — бот сам определит тип:\n"
        "• Домен, URL, Email, IP, телефон, криптоадрес\n\n"
        "<b>Все команды:</b>\n"
        "/scan — домен\n"
        "/url — ссылка\n"
        "/email — email\n"
        "/phone — телефон\n"
        "/ip — IP адрес\n"
        "/user — username\n"
        "/bin — BIN карты\n"
        "/wallet — криптокошелёк\n"
        "/leak — утечки данных\n"
        "/qr — QR код (отправь фото)\n\n"
        "<b>Фото:</b> EXIF анализ автоматически"
    ),
}
