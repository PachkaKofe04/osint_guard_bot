# handlers/auto_detect.py
"""Автоматическое определение типа ввода и перенаправление на нужный сканер."""
import logging
import re
from typing import Optional, Tuple

from aiogram import Router, types, F

from url_scanner.scanner import scan_url
from url_scanner.formatter import format_url_result
from email_scanner.scanner import scan_email
from email_scanner.formatter import format_email_result
from ip_scanner.scanner import scan_ip, validate_ip
from ip_scanner.formatter import format_ip_result
from username_scanner.scanner import scan_username
from username_scanner.formatter import format_username_result
from wallet_scanner.scanner import scan_wallet
from wallet_scanner.validators import detect_currency
from wallet_scanner.formatter import format_wallet_result
from domain_scanner.scanner import scan_domain
from domain_scanner.formatter import format_summary as format_domain_result

log = logging.getLogger(__name__)

router = Router()


# Паттерны для детекции
URL_PATTERN = re.compile(
    r"^(https?://)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    r"(/[^\s]*)?$"
)
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
DOMAIN_PATTERN = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
USERNAME_PATTERN = re.compile(r"^@?[a-zA-Z0-9_.-]{3,32}$")


def detect_input_type(text: str) -> Tuple[str, str]:
    """
    Определяет тип ввода.

    Returns:
        (input_type, normalized_value)
        input_type: url, email, ip, wallet, domain, username, unknown
    """
    text = text.strip()

    # URL (с протоколом)
    if text.startswith(("http://", "https://")):
        return "url", text

    # Email
    if "@" in text and "." in text:
        if EMAIL_PATTERN.match(text):
            return "email", text

    # IP адрес
    is_valid_ip, ip_version = validate_ip(text)
    if is_valid_ip:
        return "ip", text

    # Криптокошелёк
    currency = detect_currency(text)
    if currency:
        return "wallet", text

    # Домен (без протокола)
    if DOMAIN_PATTERN.match(text):
        return "domain", text

    # Username (@ в начале или просто ник)
    if text.startswith("@"):
        return "username", text.lstrip("@")
    if USERNAME_PATTERN.match(text) and len(text) >= 3:
        # Проверяем что это не похоже на домен
        if "." not in text:
            return "username", text

    return "unknown", text


@router.message(F.text & ~F.text.startswith("/"))
async def auto_detect_handler(message: types.Message) -> None:
    """
    Автоматический обработчик — определяет тип ввода и вызывает нужный сканер.
    Срабатывает только на текст без команд.
    """
    text = message.text or ""

    # Пропускаем слишком короткие сообщения
    if len(text) < 3:
        return

    # Определяем тип ввода
    input_type, value = detect_input_type(text)

    log.info(f"[Auto-detect] Input: '{text[:50]}...' → Type: {input_type}")

    if input_type == "unknown":
        # Не отвечаем на неизвестный ввод чтобы не спамить
        return

    # Уведомляем что определили тип
    type_names = {
        "url": "🔗 URL",
        "email": "📧 Email",
        "ip": "🌐 IP адрес",
        "wallet": "💰 Криптокошелёк",
        "domain": "🌍 Домен",
        "username": "👤 Username",
    }
    type_name = type_names.get(input_type, input_type)

    waiting_msg = await message.answer(f"🔍 Определён {type_name}, анализирую...")

    try:
        if input_type == "url":
            result = await scan_url(value)
            result_text = format_url_result(result)

        elif input_type == "email":
            result = await scan_email(value)
            result_text = format_email_result(result)

        elif input_type == "ip":
            result = await scan_ip(value)
            result_text = format_ip_result(result)

        elif input_type == "wallet":
            result = await scan_wallet(value)
            result_text = format_wallet_result(result)

        elif input_type == "domain":
            result = await scan_domain(value)
            result_text = format_domain_result(result)

        elif input_type == "username":
            result = await scan_username(value)
            result_text = format_username_result(result)

        else:
            await waiting_msg.delete()
            return

        await waiting_msg.edit_text(result_text, disable_web_page_preview=True)

    except Exception as e:
        log.error(f"[Auto-detect] Error scanning {input_type}: {e}")
        await waiting_msg.edit_text(
            f"⚠️ Ошибка при анализе. Попробуй использовать команду:\n"
            f"/{input_type} {value}"
        )
