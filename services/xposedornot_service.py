# services/xposedornot_service.py
"""
Проверка email по базам утечек через XposedOrNot.

Бесплатно и без ключа, 11.6 млрд записей. Заменяет Have I Been Pwned,
за который просят 4.39 USD в месяц: набор полей практически тот же -
название утечки, домен, год, число записей, состав украденных данных.

Два эндпоинта:
    /v1/check-email/{email}  - быстрый ответ «есть или нет»
    /v1/breach-analytics     - подробности по каждой утечке

Используем второй: одним запросом получаем и факт, и детали.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

import aiohttp

log = logging.getLogger(__name__)

API_BASE = "https://api.xposedornot.com/v1"
TIMEOUT = aiohttp.ClientTimeout(total=15)
HEADERS = {"User-Agent": "OSINT-Guard-Bot/1.0"}


@dataclass
class BreachRecord:
    """Одна утечка, в которой засветился адрес."""

    name: str
    domain: str = ""
    year: Optional[str] = None
    records: int = 0
    description: str = ""
    data_classes: List[str] = field(default_factory=list)
    industry: Optional[str] = None
    password_risk: Optional[str] = None
    verified: bool = True


@dataclass
class BreachReport:
    """
    Результат проверки.

    `checked` отделяет «база ответила, утечек нет» от «проверить не удалось».
    Без этого разделения недоступный сервис выглядел бы как чистый адрес.
    """

    checked: bool
    breaches: List[BreachRecord] = field(default_factory=list)
    source: str = "XposedOrNot"
    error: Optional[str] = None

    @property
    def is_pwned(self) -> bool:
        return bool(self.breaches)


def _split_data_classes(raw) -> List[str]:
    """
    Состав украденных данных.

    XposedOrNot отдаёт его по-разному: строкой через точку с запятой,
    вложенными списками или списком строк. Разбираем все формы.
    """
    if not raw:
        return []

    if isinstance(raw, str):
        return [p.strip() for p in raw.replace(",", ";").split(";") if p.strip()]

    result: List[str] = []
    if isinstance(raw, (list, tuple)):
        for item in raw:
            if isinstance(item, str):
                result.extend(_split_data_classes(item))
            elif isinstance(item, (list, tuple)):
                result.extend(_split_data_classes(list(item)))
    return result


def _parse_analytics(payload: dict) -> List[BreachRecord]:
    exposed = payload.get("ExposedBreaches") or {}
    details = exposed.get("breaches_details") or []

    records: List[BreachRecord] = []
    for item in details:
        if not isinstance(item, dict):
            continue
        try:
            count = int(item.get("xposed_records") or 0)
        except (TypeError, ValueError):
            count = 0

        records.append(BreachRecord(
            name=str(item.get("breach") or "Неизвестная утечка"),
            domain=str(item.get("domain") or ""),
            year=str(item.get("xposed_date")) if item.get("xposed_date") else None,
            records=count,
            description=str(item.get("details") or ""),
            data_classes=_split_data_classes(item.get("xposed_data")),
            industry=item.get("industry") or None,
            password_risk=item.get("password_risk") or None,
            verified=bool(item.get("verified", True)),
        ))

    # Самые крупные утечки вперёд: они важнее для пользователя
    records.sort(key=lambda r: r.records, reverse=True)
    return records


async def check_email_breaches(email: str) -> BreachReport:
    """
    Проверяет email по базам утечек.

    Никогда не бросает исключение: сбой сети возвращается как checked=False,
    чтобы вызывающий код мог честно сказать «проверить не удалось» вместо
    «утечек не найдено».
    """
    address = (email or "").strip().lower()
    if not address:
        return BreachReport(checked=False, error="пустой адрес")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{API_BASE}/breach-analytics",
                params={"email": address},
                headers=HEADERS,
                timeout=TIMEOUT,
            ) as response:
                if response.status == 404:
                    # Адрес не найден ни в одной утечке - это валидный ответ
                    return BreachReport(checked=True, breaches=[])
                if response.status != 200:
                    return BreachReport(
                        checked=False, error=f"HTTP {response.status}"
                    )
                payload = await response.json(content_type=None)
    except Exception as exc:
        log.warning("[XposedOrNot] Сбой для %s: %s", address, exc)
        return BreachReport(checked=False, error=str(exc)[:80])

    # Сервис отвечает 200 с полем Error, когда адрес чист
    if isinstance(payload, dict) and payload.get("Error"):
        return BreachReport(checked=True, breaches=[])

    if not isinstance(payload, dict):
        return BreachReport(checked=False, error="неожиданный формат ответа")

    breaches = _parse_analytics(payload)
    log.info("[XposedOrNot] %s: утечек найдено %d", address, len(breaches))
    return BreachReport(checked=True, breaches=breaches)
