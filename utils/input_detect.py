# utils/input_detect.py
"""
Определение типа пользовательского ввода.

Живёт в utils, а не в handlers, потому что нужен двум потребителям:
  - handlers/auto_detect.py — чтобы выбрать сканер;
  - middlewares/rate_limit.py — чтобы понять, породит ли сообщение
    реальный скан (и только тогда тратить квоту пользователя).

Типы: url, email, ip, phone, bin, wallet, domain, username, ambiguous, unknown

`ambiguous` — голое слово, которое технически подходит под username, но с тем же
успехом может быть обычным словом («help», «проверь»). Такое не сканируем молча:
хендлер переспрашивает кнопками.
"""
from __future__ import annotations

import re
from typing import Tuple

from ip_scanner.scanner import validate_ip
from wallet_scanner.validators import detect_currency

EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
DOMAIN_PATTERN = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
USERNAME_PATTERN = re.compile(r"^@?[a-zA-Z0-9_.-]{3,32}$")

# Телефон: цифры, разделители, необязательный +. Проверку длины делаем отдельно.
PHONE_CHARS_PATTERN = re.compile(r"^\+?[\d\s\-().]{7,25}$")

# Расширения файлов, которые НЕ являются доменами верхнего уровня.
# Сознательно не включены .sh .io .me .tv .cc .ai .co .zip .mov — это реальные TLD,
# и «readme.io» вполне может быть настоящим сайтом.
FILE_EXTENSIONS = {
    "txt", "md", "js", "mjs", "cjs", "py", "pyc", "json", "csv", "xml",
    "html", "htm", "css", "scss", "less", "jpg", "jpeg", "png", "gif",
    "bmp", "webp", "svg", "psd", "pdf", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "rar", "7z", "tar", "gz", "iso", "deb", "rpm",
    "exe", "dll", "bat", "cmd", "log", "yml", "yaml", "toml", "ini",
    "cfg", "conf", "env", "lock", "ts", "tsx", "jsx", "java", "class",
    "cpp", "hpp", "php", "sql", "bak", "tmp", "mp3", "wav", "flac",
    "mp4", "avi", "mkv", "webm", "ttf", "otf", "woff", "woff2",
}

# Обычные слова и служебные термины: сканировать их как никнейм бессмысленно.
# Раньше «help» запускал 20 HTTP-запросов по платформам.
COMMON_WORDS = {
    "help", "menu", "start", "stop", "test", "tests", "testing", "hello",
    "hi", "hey", "admin", "administrator", "root", "user", "users",
    "password", "passwd", "pass", "login", "logout", "signin", "signup",
    "info", "about", "settings", "config", "cancel", "back", "exit",
    "quit", "yes", "no", "yep", "nope", "ok", "okay", "thanks", "thank",
    "please", "search", "find", "check", "scan", "status", "version",
    "update", "upgrade", "bot", "spam", "none", "null", "nil", "undefined",
    "localhost", "example", "sample", "demo", "todo", "readme", "main",
    "index", "home", "data", "file", "files", "error", "errors", "debug",
    "log", "logs", "true", "false", "default", "custom", "new", "old",
}


def _digits_only(text: str) -> str:
    return "".join(ch for ch in text if ch.isdigit())


def _looks_like_filename(text: str) -> bool:
    """Отсекает `readme.md`, `script.js` — их незачем гнать в скан домена."""
    if "." not in text:
        return False
    return text.rsplit(".", 1)[-1].lower() in FILE_EXTENSIONS


def detect_input_type(text: str) -> Tuple[str, str]:
    """
    Определяет тип ввода.

    Returns:
        (input_type, normalized_value)
    """
    text = text.strip()

    if not text:
        return "unknown", text

    # URL (с явным протоколом)
    if text.startswith(("http://", "https://")):
        return "url", text

    # Email
    if "@" in text and "." in text and EMAIL_PATTERN.match(text):
        return "email", text

    # IP — строго до телефона, иначе 8.8.8.8 уедет в телефоны
    is_valid_ip, _version = validate_ip(text)
    if is_valid_ip:
        return "ip", text

    # Числовой ввод: телефон или BIN карты.
    # Разбирается до проверки на пробелы, чтобы «+7 999 585 20 48» дошёл сюда.
    # Ветки телефона раньше не было вообще — /phone был недостижим без команды.
    if PHONE_CHARS_PATTERN.match(text):
        digits = _digits_only(text)
        if 10 <= len(digits) <= 15:
            return "phone", text
        if 6 <= len(digits) <= 8 and not text.startswith("+"):
            return "bin", digits
        return "unknown", text

    # Короткий числовой ввод (6–8 цифр) — BIN карты
    if text.isdigit() and 6 <= len(text) <= 8:
        return "bin", text

    # Пробелы внутри — это фраза, а не идентификатор
    if " " in text:
        return "unknown", text

    # Криптокошелёк
    if detect_currency(text):
        return "wallet", text

    # Домен — но не имя файла
    if DOMAIN_PATTERN.match(text) and not _looks_like_filename(text):
        return "domain", text

    # Username с явным @ — намерение однозначное
    if text.startswith("@"):
        stripped = text.lstrip("@")
        if USERNAME_PATTERN.match(text):
            return "username", stripped
        return "unknown", text

    # Голое слово: похоже на username, но может быть обычным словом
    if USERNAME_PATTERN.match(text) and "." not in text:
        if text.lower() in COMMON_WORDS:
            return "unknown", text
        # Только буквы, без цифр/подчёркиваний — скорее слово, чем ник.
        # Не сканируем молча: хендлер переспросит кнопками.
        if text.isalpha():
            return "ambiguous", text
        return "username", text

    return "unknown", text


# Типы, ради которых реально запускается внешний скан.
# Используется rate limiter'ом: usage-подсказки и болтовня квоту не тратят.
SCANNABLE_TYPES = frozenset(
    {"url", "email", "ip", "phone", "bin", "wallet", "domain", "username"}
)


def triggers_scan(text: str) -> bool:
    """Породит ли этот текст реальное обращение к внешним API."""
    input_type, _ = detect_input_type(text)
    return input_type in SCANNABLE_TYPES
