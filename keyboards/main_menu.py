# keyboards/main_menu.py
"""Главное меню и навигация бота."""
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder


def get_main_menu() -> InlineKeyboardMarkup:
    """Главное меню с категориями сканеров."""
    builder = InlineKeyboardBuilder()

    # 2 столбика, аккуратно
    builder.row(
        InlineKeyboardButton(text="Сайт/ссылка", callback_data="help:site"),
        InlineKeyboardButton(text="Email", callback_data="help:email"),
    )
    builder.row(
        InlineKeyboardButton(text="Телефон", callback_data="help:phone"),
        InlineKeyboardButton(text="IP адрес", callback_data="help:ip"),
    )
    builder.row(
        InlineKeyboardButton(text="Никнейм", callback_data="help:user"),
        InlineKeyboardButton(text="Карта (BIN)", callback_data="help:bin"),
    )
    builder.row(
        InlineKeyboardButton(text="Криптокошелек", callback_data="help:wallet"),
        InlineKeyboardButton(text="Утечки", callback_data="help:leak"),
    )
    builder.row(
        InlineKeyboardButton(text="Фото", callback_data="help:photo"),
    )

    return builder.as_markup()


def get_back_button() -> InlineKeyboardMarkup:
    """Кнопка возврата в меню."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text="Назад", callback_data="menu:main"),
    )
    return builder.as_markup()


# Тексты справки для каждого раздела
SECTION_HELP = {
    "site": (
        "<b>Проверка сайта или ссылки</b>\n\n"
        "Отправьте адрес сайта или ссылку:\n"
        "<code>google.com</code>\n"
        "<code>https://example.ru/page</code>\n"
        "<code>https://bit.ly/abc123</code>\n\n"
        "Что проверяется:\n"
        "- Возраст домена и владелец\n"
        "- DNS записи и SSL сертификат\n"
        "- Разворот сокращенных ссылок\n"
        "- Проверка на фишинг\n"
        "- Оценка риска 0-10"
    ),
    "email": (
        "<b>Проверка Email</b>\n\n"
        "Отправьте email адрес:\n"
        "<code>user@example.com</code>\n\n"
        "Что проверяется:\n"
        "- Валидность формата\n"
        "- Одноразовый ли email\n"
        "- Возраст домена почты\n"
        "- MX записи\n"
        "- Оценка риска 0-10"
    ),
    "phone": (
        "<b>Проверка телефона</b>\n\n"
        "Отправьте номер телефона:\n"
        "<code>+79991234567</code>\n"
        "<code>89991234567</code>\n\n"
        "Что проверяется:\n"
        "- Страна и оператор\n"
        "- Тип номера (мобильный/VoIP)\n"
        "- Валидность формата\n"
        "- Оценка риска 0-10"
    ),
    "ip": (
        "<b>Проверка IP адреса</b>\n\n"
        "Отправьте IP адрес:\n"
        "<code>8.8.8.8</code>\n"
        "<code>2001:4860:4860::8888</code>\n\n"
        "Что проверяется:\n"
        "- Геолокация (страна, город)\n"
        "- VPN/Proxy/Tor детекция\n"
        "- Провайдер и ASN\n"
        "- Репутация в blacklists\n"
        "- Оценка риска 0-10"
    ),
    "user": (
        "<b>Проверка никнейма</b>\n\n"
        "Отправьте никнейм:\n"
        "<code>/user johndoe</code>\n\n"
        "Что проверяется:\n"
        "- Поиск по 20+ платформам\n"
        "- Социальные сети\n"
        "- Профессиональные сети\n"
        "- Форумы и сервисы"
    ),
    "bin": (
        "<b>Проверка карты (BIN)</b>\n\n"
        "Отправьте первые 6-8 цифр карты:\n"
        "<code>/bin 427229</code>\n\n"
        "Что проверяется:\n"
        "- Платежная система\n"
        "- Банк-эмитент\n"
        "- Страна выпуска\n"
        "- Тип карты (дебетовая/кредитная)"
    ),
    "wallet": (
        "<b>Проверка криптокошелька</b>\n\n"
        "Отправьте адрес кошелька:\n"
        "<code>0x742d35Cc6634C0532925a3b844Bc9e7595f8fE01</code>\n"
        "<code>1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2</code>\n\n"
        "Поддерживаются:\n"
        "- Bitcoin, Ethereum, USDT, Solana\n\n"
        "Что проверяется:\n"
        "- Баланс кошелька\n"
        "- Проверка в scam-базах\n"
        "- Оценка риска 0-10"
    ),
    "leak": (
        "<b>Проверка утечек данных</b>\n\n"
        "Отправьте email или телефон:\n"
        "<code>/leak user@example.com</code>\n"
        "<code>/leak +79991234567</code>\n\n"
        "Что проверяется:\n"
        "- Наличие в базах утечек\n"
        "- Какие данные скомпрометированы\n"
        "- Дата утечки\n"
        "- Оценка риска 0-10"
    ),
    "photo": (
        "<b>Анализ фотографии</b>\n\n"
        "Просто отправьте фото.\n\n"
        "Что извлекается:\n"
        "- GPS координаты (если есть)\n"
        "- Модель камеры/телефона\n"
        "- Дата и время съемки\n"
        "- Оценка риска приватности\n\n"
        "Для проверки QR кода:\n"
        "Отправьте фото с подписью <code>/qr</code>"
    ),
}
