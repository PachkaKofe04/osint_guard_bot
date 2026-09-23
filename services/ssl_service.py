# services/ssl_service.py
"""
История SSL-сертификатов домена по Certificate Transparency.

crt.sh - основной источник, но он регулярно отдаёт 502 и уходит в таймаут.
При прежних настройках (5 секунд, без повторов) данные пропадали молча, и
факторы риска, завязанные на сертификаты, просто переставали срабатывать -
оценка домена тихо деградировала, а пользователь об этом не знал.

Теперь: увеличенный таймаут, два повтора и резервный источник certspotter.
Если данных нет совсем, возвращается None, и вызывающий код обязан отразить
это в отчёте, а не делать вид, что сертификатов не существует.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import List, Optional

import aiohttp

from domain_scanner.models import SslInfo

log = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"

# crt.sh медленный даже когда жив: 500 КБ JSON на популярный домен
REQUEST_TIMEOUT = 20
RETRY_ATTEMPTS = 2
RETRY_PAUSE_SECONDS = 2

HEADERS = {"User-Agent": "OSINT-Guard-Bot/1.0"}


def _parse_dt(value: str) -> Optional[datetime]:
    """Разбирает дату из CT-лога. Форматы у источников слегка разные."""
    if not value:
        return None
    base = value.split(".")[0].replace("Z", "").replace("+00:00", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(base, fmt)
        except ValueError:
            continue
    return None


def _build(
    not_befores: List[datetime],
    not_afters: List[datetime],
    issuers: List[str],
    sans: List[str],
    history_complete: bool,
    source: str,
) -> Optional[SslInfo]:
    if not not_befores and not not_afters and not sans:
        return None
    return SslInfo(
        first_seen=min(not_befores) if not_befores else None,
        last_seen=max(not_afters) if not_afters else None,
        issuers=sorted(set(issuers)),
        san_domains=sorted(set(sans)),
        history_complete=history_complete,
        source=source,
    )


async def _fetch_crtsh(session: aiohttp.ClientSession, domain: str) -> Optional[SslInfo]:
    async with session.get(
        CRT_SH_URL,
        params={"q": domain, "output": "json"},
        headers=HEADERS,
        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
    ) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        data = await response.json(content_type=None)

    if not isinstance(data, list) or not data:
        return None

    not_befores: List[datetime] = []
    not_afters: List[datetime] = []
    issuers: List[str] = []
    sans: List[str] = []

    for item in data:
        before = _parse_dt(item.get("not_before", ""))
        after = _parse_dt(item.get("not_after", ""))
        if before:
            not_befores.append(before)
        if after:
            not_afters.append(after)

        issuer = (item.get("issuer_name") or "").strip()
        if issuer:
            issuers.append(issuer)

        for part in (item.get("name_value") or "").splitlines():
            part = part.strip().lower()
            if part:
                sans.append(part)

    # crt.sh хранит весь Certificate Transparency: возраст по нему считать можно
    return _build(not_befores, not_afters, issuers, sans,
                  history_complete=True, source="crt.sh")


async def _fetch_certspotter(
    session: aiohttp.ClientSession, domain: str
) -> Optional[SslInfo]:
    """Резерв: тот же Certificate Transparency, другой оператор."""
    # expand передаётся списком пар: в словаре повторный ключ затирает предыдущий,
    # из-за чего разворачивалось только одно из двух полей
    async with session.get(
        CERTSPOTTER_URL,
        params=[
            ("domain", domain),
            ("include_subdomains", "false"),
            ("expand", "dns_names"),
            ("expand", "issuer"),
        ],
        headers=HEADERS,
        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
    ) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        data = await response.json(content_type=None)

    if not isinstance(data, list) or not data:
        return None

    not_befores: List[datetime] = []
    not_afters: List[datetime] = []
    issuers: List[str] = []
    sans: List[str] = []

    for item in data:
        before = _parse_dt(item.get("not_before", ""))
        after = _parse_dt(item.get("not_after", ""))
        if before:
            not_befores.append(before)
        if after:
            not_afters.append(after)

        issuer = ((item.get("issuer") or {}).get("name") or "").strip()
        if issuer:
            issuers.append(issuer)

        for name in item.get("dns_names") or []:
            name = str(name).strip().lower()
            if name:
                sans.append(name)

    # certspotter бесплатно отдаёт только последние выпуски, не всю историю
    return _build(not_befores, not_afters, issuers, sans,
                  history_complete=False, source="certspotter")


async def fetch_ssl(domain: str) -> Optional[SslInfo]:
    """
    История сертификатов домена.

    None означает «данные получить не удалось» - это не то же самое, что
    «сертификатов нет». Отчёт должен различать эти случаи.
    """
    async with aiohttp.ClientSession() as session:
        # certspotter первым по результатам замеров: 1.7 с против 15-23 с у
        # crt.sh, и данных отдаёт больше (518 SAN против 399 по одному домену).
        # crt.sh при этом регулярно отвечает 502.
        try:
            result = await _fetch_certspotter(session, domain)
            if result is not None:
                return result
            log.info("[SSL] certspotter: для %s сертификатов нет", domain)
        except Exception as exc:
            log.info("[SSL] certspotter недоступен для %s: %s", domain, exc)

        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                return await _fetch_crtsh(session, domain)
            except Exception as exc:
                log.info(
                    "[SSL] crt.sh попытка %d/%d для %s: %s",
                    attempt, RETRY_ATTEMPTS, domain, exc,
                )
                if attempt < RETRY_ATTEMPTS:
                    await asyncio.sleep(RETRY_PAUSE_SECONDS)

        log.warning("[SSL] Данные о сертификатах для %s получить не удалось", domain)
        return None
