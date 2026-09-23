"""
Проверка ключа abuse.ch и того, какие данные он отдаёт.

Запуск после получения ключа:

    # положить ключ в .env:  ABUSECH_API_KEY=твой_ключ
    PYTHONIOENCODING=utf-8 python tools/check_abusech.py

    # или разово, без .env:
    ABUSECH_API_KEY=твой_ключ PYTHONIOENCODING=utf-8 python tools/check_abusech.py

Проверяет три базы, которые открывает один ключ:
    URLhaus   - вредоносные URL и хосты
    ThreatFox - IOC: домены, IP и URL, связанные с малварью и C2
    MalwareBazaar - хеши файлов (боту не нужен, проверяем только доступность)
"""
import asyncio
import json
import os
import sys

import aiohttp
from dotenv import load_dotenv

load_dotenv()

KEY = os.environ.get("ABUSECH_API_KEY", "").strip()

URLHAUS = "https://urlhaus-api.abuse.ch/v1"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
BAZAAR = "https://mb-api.abuse.ch/api/v1/"

# Заведомо вредоносный хост из публичных примеров abuse.ch.
# Если база ответит по нему - значит ключ работает и данные приходят.
KNOWN_BAD_HOST = "vgoodcheck.xyz"
CLEAN_HOST = "google.com"


def headers() -> dict:
    return {"Auth-Key": KEY, "User-Agent": "OSINT-Guard/1.0"}


async def urlhaus_host(session, host: str) -> dict:
    async with session.post(
        f"{URLHAUS}/host/", data={"host": host}, headers=headers(),
        timeout=aiohttp.ClientTimeout(total=20),
    ) as r:
        return r.status, await r.json(content_type=None)


async def urlhaus_url(session, url: str) -> dict:
    async with session.post(
        f"{URLHAUS}/url/", data={"url": url}, headers=headers(),
        timeout=aiohttp.ClientTimeout(total=20),
    ) as r:
        return r.status, await r.json(content_type=None)


async def threatfox_search(session, term: str) -> dict:
    async with session.post(
        THREATFOX, json={"query": "search_ioc", "search_term": term, "exact_match": True},
        headers=headers(), timeout=aiohttp.ClientTimeout(total=20),
    ) as r:
        return r.status, await r.json(content_type=None)


async def bazaar_ping(session) -> dict:
    async with session.post(
        BAZAAR, data={"query": "get_recent", "selector": "time"},
        headers=headers(), timeout=aiohttp.ClientTimeout(total=20),
    ) as r:
        return r.status, await r.json(content_type=None)


def show(title: str, status: int, payload) -> None:
    print(f"\n--- {title} ---")
    print(f"HTTP {status}")
    if isinstance(payload, dict):
        qs = payload.get("query_status", "?")
        print(f"query_status: {qs}")
        if qs == "ok":
            data = payload.get("data") or payload.get("urls") or []
            if isinstance(data, list):
                print(f"записей: {len(data)}")
                for item in data[:2]:
                    trimmed = {
                        k: v for k, v in item.items()
                        if k in ("url", "ioc", "threat", "threat_type", "malware",
                                 "malware_printable", "url_status", "tags",
                                 "date_added", "first_seen", "confidence_level")
                    }
                    print("  " + json.dumps(trimmed, ensure_ascii=False)[:200])
            else:
                print("  " + json.dumps(payload, ensure_ascii=False)[:250])
        elif qs in ("no_results", "ok_no_results"):
            print("  чисто: объект в базе не числится")
        else:
            print("  " + json.dumps(payload, ensure_ascii=False)[:250])
    else:
        print(str(payload)[:250])


async def main() -> int:
    if not KEY:
        print("ABUSECH_API_KEY не задан.")
        print("Положи ключ в .env:  ABUSECH_API_KEY=твой_ключ")
        print("Получить: https://auth.abuse.ch/ -> вход через Google/GitHub -> Optional -> Auth-Key")
        return 1

    # Сам ключ не печатаем: вывод скрипта может уйти в лог или в переписку
    print(f"Ключ найден, длина {len(KEY)} символов.")

    async with aiohttp.ClientSession() as s:
        try:
            show("URLhaus: заведомо вредоносный хост", *await urlhaus_host(s, KNOWN_BAD_HOST))
            show("URLhaus: чистый хост", *await urlhaus_host(s, CLEAN_HOST))
            show("URLhaus: конкретный URL", *await urlhaus_url(s, "http://example.com/"))
            show("ThreatFox: поиск IOC", *await threatfox_search(s, KNOWN_BAD_HOST))
            show("MalwareBazaar: доступность", *await bazaar_ping(s))
        except Exception as exc:
            print(f"\nОшибка запроса: {type(exc).__name__}: {exc}")
            return 1

    print("\n" + "=" * 60)
    print("Если выше нет HTTP 401 - ключ рабочий и покрывает все три базы.")
    return 0


sys.exit(asyncio.run(main()))
