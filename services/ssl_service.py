# services/ssl_service.py
import asyncio
from datetime import datetime
from typing import List, Optional

import requests

from domain_scanner.models import SslInfo


CRT_SH_URL = "https://crt.sh/"


def _parse_dt(value: str) -> Optional[datetime]:
    if not value:
        return None
    # Примитивный парсер: режем по '.' / 'Z' и парсим как ISO без зоны
    try:
        base = value.split(".")[0].replace("Z", "")
        return datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


def fetch_ssl_sync(domain: str) -> Optional[SslInfo]:
    params = {"q": domain, "output": "json"}

    try:
        resp = requests.get(CRT_SH_URL, params=params, timeout=5)
        resp.raise_for_status()
    except Exception:
        return None

    try:
        data = resp.json()
    except ValueError:
        return None

    if not isinstance(data, list) or not data:
        return None

    not_befores: List[datetime] = []
    not_afters: List[datetime] = []
    issuers: List[str] = []
    san_domains: List[str] = []

    for item in data:
        nb = _parse_dt(item.get("not_before", ""))
        na = _parse_dt(item.get("not_after", ""))
        if nb:
            not_befores.append(nb)
        if na:
            not_afters.append(na)

        issuer = item.get("issuer_name") or ""
        if issuer:
            issuers.append(issuer.strip())

        san_raw = item.get("name_value") or ""
        # SAN-список может быть через переносы строк
        for part in san_raw.splitlines():
            part = part.strip()
            if part:
                san_domains.append(part.lower())

    if not not_befores and not not_afters and not san_domains:
        # Ничего полезного не нашли
        return None

    first_seen = min(not_befores) if not_befores else None
    last_seen = max(not_afters) if not_afters else None

    unique_issuers = sorted(set(issuers))
    unique_san = sorted(set(san_domains))

    return SslInfo(
        first_seen=first_seen,
        last_seen=last_seen,
        issuers=unique_issuers,
        san_domains=unique_san,
    )


async def fetch_ssl(domain: str) -> Optional[SslInfo]:
    return await asyncio.to_thread(fetch_ssl_sync, domain)
