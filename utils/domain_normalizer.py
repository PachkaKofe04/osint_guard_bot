# utils/domain_normalizer.py
import re
from typing import Optional
from urllib.parse import urlparse


# Жёсткая, но адекватная проверка домена (ASCII/punycode)
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _extract_host(raw: str) -> str:
    """
    Забирает host из строки:
    - обрабатывает варианты с http/https
    - обрабатывает просто 'example.com' / 'example.com/path'
    """
    raw = raw.strip()

    # Если нет схемы, подставляем http:// для корректного парсинга
    if "://" not in raw:
        candidate = "http://" + raw
    else:
        candidate = raw

    parsed = urlparse(candidate)

    host = parsed.netloc or parsed.path or ""
    # срезаем юзер/пароль если вдруг: user:pass@host
    if "@" in host:
        host = host.split("@", 1)[-1]

    # срезаем порт
    if ":" in host:
        host = host.split(":", 1)[0]

    return host


def normalize_domain(raw: str) -> Optional[str]:
    """
    Преобразует произвольный ввод в нормализованный домен (punycode, lower).
    Если домен некорректен — возвращает None.
    """
    if not raw:
        return None

    host = _extract_host(raw)
    host = host.strip().lower().rstrip(".")

    if not host:
        return None

    # Убираем префикс www. (чтобы /scan www.example.com и /scan example.com были эквивалентны)
    if host.startswith("www."):
        host = host[4:]

    # IDN → punycode через стандартный codec 'idna'
    try:
        ascii_domain = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    # Валидация домена
    if not DOMAIN_REGEX.match(ascii_domain):
        return None

    return ascii_domain
