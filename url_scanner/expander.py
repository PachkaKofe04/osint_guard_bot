# url_scanner/expander.py
"""Сервис для разворачивания коротких ссылок."""
import asyncio
import logging
from typing import List, Tuple
from urllib.parse import urlparse

import requests

from utils.retry import retry_sync

log = logging.getLogger(__name__)

# Известные сервисы сокращения ссылок
SHORTENER_DOMAINS = {
    "bit.ly", "bitly.com",
    "t.co",
    "goo.gl",
    "tinyurl.com",
    "ow.ly",
    "is.gd", "v.gd",
    "buff.ly",
    "j.mp",
    "soo.gd",
    "s.id",
    "clck.ru",
    "qps.ru",
    "vk.cc", "vk.com/away.php",
    "t.me", "telegram.me",
    "youtu.be",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "trib.al",
    "x.co",
    "lnkd.in",
    "fb.me",
    "amp.gs",
}


def is_shortened_url(url: str) -> Tuple[bool, str]:
    """
    Проверяет, является ли URL сокращённой ссылкой.

    Returns:
        Tuple[is_shortened, shortener_service]
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Убираем www.
        if domain.startswith("www."):
            domain = domain[4:]

        for shortener in SHORTENER_DOMAINS:
            if domain == shortener or domain.endswith("." + shortener):
                return True, shortener

        # Проверка на короткий путь (bit.ly/abc123)
        if len(parsed.path) > 0 and len(parsed.path) <= 15:
            if domain in SHORTENER_DOMAINS:
                return True, domain

        return False, ""
    except Exception:
        return False, ""


@retry_sync(max_attempts=2, backoff=1.0, exceptions=(requests.RequestException,))
def expand_url_sync(url: str, max_redirects: int = 10) -> Tuple[str, List[str]]:
    """
    Разворачивает URL, следуя редиректам.

    Returns:
        Tuple[final_url, redirect_chain]
    """
    redirect_chain = []
    current_url = url

    if not current_url.startswith(("http://", "https://")):
        current_url = "https://" + current_url

    session = requests.Session()
    session.max_redirects = max_redirects

    try:
        # Делаем HEAD запрос с отслеживанием редиректов
        resp = session.head(
            current_url,
            allow_redirects=True,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (compatible; OSINTBot/1.0)"}
        )

        # Собираем цепочку редиректов
        for r in resp.history:
            redirect_chain.append(r.url)

        final_url = resp.url

    except requests.exceptions.TooManyRedirects:
        log.warning(f"[URL Expander] Too many redirects for {url}")
        final_url = current_url
    except requests.RequestException as e:
        log.warning(f"[URL Expander] HEAD failed for {url}: {e}, trying GET")
        # Пробуем GET если HEAD не работает
        try:
            resp = session.get(
                current_url,
                allow_redirects=True,
                timeout=10,
                stream=True,  # Не скачиваем тело
                headers={"User-Agent": "Mozilla/5.0 (compatible; OSINTBot/1.0)"}
            )
            for r in resp.history:
                redirect_chain.append(r.url)
            final_url = resp.url
            resp.close()
        except Exception as e2:
            log.error(f"[URL Expander] GET also failed for {url}: {e2}")
            final_url = current_url

    return final_url, redirect_chain


async def expand_url(url: str, max_redirects: int = 10) -> Tuple[str, List[str]]:
    """Асинхронная обёртка."""
    return await asyncio.to_thread(expand_url_sync, url, max_redirects)
