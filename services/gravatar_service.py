# services/gravatar_service.py
"""Сервис для работы с Gravatar API."""
import hashlib
import logging
from typing import Optional

import aiohttp

log = logging.getLogger(__name__)

GRAVATAR_BASE_URL = "https://www.gravatar.com/avatar"
GRAVATAR_TIMEOUT = 5.0


def get_gravatar_hash(email: str) -> str:
    """
    Вычисляет MD5 хеш email для Gravatar.

    Gravatar требует lowercase email без пробелов.
    """
    normalized = email.strip().lower()
    return hashlib.md5(normalized.encode("utf-8")).hexdigest()


def get_gravatar_url(email: str, size: int = 200) -> str:
    """
    Возвращает URL аватара Gravatar.

    Args:
        email: Email адрес
        size: Размер изображения (по умолчанию 200px)

    Returns:
        URL аватара
    """
    email_hash = get_gravatar_hash(email)
    return f"{GRAVATAR_BASE_URL}/{email_hash}?s={size}&d=404"


async def check_gravatar_exists(email: str) -> Optional[str]:
    """
    Проверяет наличие Gravatar для email.

    Args:
        email: Email адрес для проверки

    Returns:
        URL аватара если существует, иначе None
    """
    url = get_gravatar_url(email)

    try:
        timeout = aiohttp.ClientTimeout(total=GRAVATAR_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.head(url, allow_redirects=True) as response:
                if response.status == 200:
                    log.debug("[Gravatar] Found avatar for email hash")
                    return url
                elif response.status == 404:
                    log.debug("[Gravatar] No avatar found for email hash")
                    return None
                else:
                    log.warning(f"[Gravatar] Unexpected status code: {response.status}")
                    return None

    except aiohttp.ClientError as e:
        log.warning(f"[Gravatar] Request failed: {e}")
        return None
    except Exception as e:
        log.warning(f"[Gravatar] Unexpected error: {e}")
        return None
