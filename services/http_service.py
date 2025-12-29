# services/http_service.py
import asyncio
from typing import Optional

import requests

from domain_scanner.models import HttpInfo


def _head_request(url: str, timeout: float = 5.0) -> Optional[requests.Response]:
    try:
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        return resp
    except Exception:
        return None


def _get_request(url: str, timeout: float = 5.0) -> Optional[requests.Response]:
    try:
        resp = requests.get(url, allow_redirects=True, timeout=timeout)
        return resp
    except Exception:
        return None


def fetch_http_sync(domain: str) -> Optional[HttpInfo]:
    checked_url = None

    # Пытаемся HTTPS, если не получилось — HTTP
    for scheme in ("https", "http"):
        base_url = f"{scheme}://{domain}"
        resp_head = _head_request(base_url + "/", timeout=5.0)
        if resp_head is None:
            continue

        checked_url = resp_head.url  # финальный URL после редиректов
        headers = {k.lower(): v for k, v in resp_head.headers.items()}
        break

    if checked_url is None:
        # сайт вообще не отвечает
        return None

    server = headers.get("server")
    via = headers.get("via")
    x_powered_by = headers.get("x-powered-by")
    cf_ray = headers.get("cf-ray")
    cf_cache_status = headers.get("cf-cache-status")

    # robots.txt
    robots_exists = False
    robots_disallow_all = False
    robots_has_sitemap = False
    robots_has_minimal_allow = False
    robots_raw: Optional[str] = None

    robots_url = checked_url.rstrip("/") + "/robots.txt"
    resp_robots = _get_request(robots_url, timeout=5.0)
    if resp_robots and resp_robots.status_code == 200:
        robots_exists = True
        text = resp_robots.text or ""
        robots_raw = text

        lowered = text.lower()
        if "disallow: /" in lowered:
            robots_disallow_all = True

        if "sitemap:" in lowered:
            robots_has_sitemap = True

        # минимальные Allow
        if "allow: /index.html" in lowered or "allow: /index_2.html" in lowered:
            robots_has_minimal_allow = True

    return HttpInfo(
        url_checked=checked_url,
        server=server,
        via=via,
        x_powered_by=x_powered_by,
        cf_ray=cf_ray,
        cf_cache_status=cf_cache_status,
        robots_exists=robots_exists,
        robots_disallow_all=robots_disallow_all,
        robots_has_sitemap=robots_has_sitemap,
        robots_has_minimal_allow=robots_has_minimal_allow,
        robots_raw=robots_raw,
    )


async def fetch_http(domain: str) -> Optional[HttpInfo]:
    return await asyncio.to_thread(fetch_http_sync, domain)
