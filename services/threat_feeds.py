# services/threat_feeds.py
"""
Локальный кэш публичных баз угроз.

Источники раздаются файлами, а не поисковым API, поэтому качаем их по
расписанию и ищем в памяти. Что это даёт:

  - ноль сетевой задержки на запрос пользователя;
  - нет зависимости от лимитов: abuse.ch с сентября 2026 блокирует за
    превышение Fair Use на срок до 72 часов;
  - работает, когда источник недоступен - берём последнюю выгрузку с диска;
  - ключи не нужны ни для одного из фидов.

Главное правило модуля: **никогда не выдавать «не найдено» за «чисто»**.
Каждый поиск возвращает одно из трёх состояний, и вызывающий код обязан
различать HIT, CLEAN и UNAVAILABLE. Именно смешение двух последних приводило
к тому, что бот писал «скам не обнаружен» при недоступной базе скама.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import aiohttp

log = logging.getLogger(__name__)

CACHE_DIR = "data/feeds"
# Фиды обновляются часто, но и стареют небыстро. 6 часов - компромисс между
# свежестью и нагрузкой на источники.
REFRESH_INTERVAL_SECONDS = 6 * 3600
# Данные старше суток считаем протухшими: лучше честно сказать «не знаю»,
# чем отвечать по позавчерашней выгрузке.
STALE_AFTER_SECONDS = 24 * 3600
DOWNLOAD_TIMEOUT = 90

USER_AGENT = "OSINT-Guard-Bot/1.0"


class Verdict(str, Enum):
    """Результат поиска по базе."""

    HIT = "hit"                  # объект найден в базе угроз
    CLEAN = "clean"              # база доступна, объекта в ней нет
    UNAVAILABLE = "unavailable"  # база не загружена, проверка не выполнялась


@dataclass(frozen=True)
class ThreatInfo:
    """Что известно про найденный объект."""

    source: str                       # URLhaus, ThreatFox, ScamSniffer
    threat_type: Optional[str] = None  # malware_download, payload_delivery, ...
    malware: Optional[str] = None      # Cobalt Strike, ClearFake, ...
    confidence: Optional[int] = None   # 0-100
    tags: tuple = ()
    first_seen: Optional[str] = None


@dataclass
class LookupResult:
    """Трёхзначный ответ: найдено, чисто или проверить не смогли."""

    verdict: Verdict
    hits: List[ThreatInfo] = field(default_factory=list)

    @property
    def is_hit(self) -> bool:
        return self.verdict is Verdict.HIT

    @property
    def is_checked(self) -> bool:
        """Была ли проверка выполнена вообще."""
        return self.verdict is not Verdict.UNAVAILABLE


@dataclass
class FeedSpec:
    """Описание одного фида."""

    name: str
    url: str
    filename: str
    parser: str          # имя метода-парсера
    required: bool = False


FEEDS: tuple = (
    FeedSpec(
        name="URLhaus",
        url="https://urlhaus.abuse.ch/downloads/csv_online/",
        filename="urlhaus_online.csv",
        parser="_parse_urlhaus",
    ),
    FeedSpec(
        name="ThreatFox",
        url="https://threatfox.abuse.ch/export/json/recent/",
        filename="threatfox_recent.json",
        parser="_parse_threatfox",
    ),
    FeedSpec(
        name="ScamSniffer-адреса",
        url="https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json",
        filename="scamsniffer_addresses.json",
        parser="_parse_scam_addresses",
    ),
    FeedSpec(
        name="ScamSniffer-домены",
        url="https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
        filename="scamsniffer_domains.json",
        parser="_parse_scam_domains",
    ),
    FeedSpec(
        name="Tor",
        url="https://check.torproject.org/torbulkexitlist",
        filename="tor_exit_nodes.txt",
        parser="_parse_tor",
    ),
    FeedSpec(
        name="Feodo Tracker",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        filename="feodo_c2.json",
        parser="_parse_feodo",
    ),
)


def _clean_tags(raw: Optional[str]) -> tuple:
    """
    Разбирает поле тегов фида.

    URLhaus пишет в CSV литеральную строку None вместо пустого значения,
    из-за чего в отчёт попадал тег «None».
    """
    if not raw:
        return ()
    return tuple(
        tag for tag in (t.strip() for t in raw.split(","))
        if tag and tag.lower() not in ("none", "null", "-")
    )


def _normalize_host(value: str) -> str:
    """Приводит хост к виду для сравнения: нижний регистр, без www и порта."""
    host = (value or "").strip().lower()
    if "://" in host:
        host = urlparse(host).hostname or ""
    host = host.split("/")[0].split("?")[0]
    if ":" in host and not host.count(":") > 1:  # отсекаем порт, но не IPv6
        host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host.rstrip(".")


def _normalize_url(value: str) -> str:
    return (value or "").strip().rstrip("/").lower()


class ThreatFeeds:
    """
    Кэш баз угроз. Один экземпляр на процесс.

    Поиск идёт по структурам в памяти, поэтому синхронный и мгновенный.
    Скачивание и разбор - асинхронные, вызываются планировщиком.
    """

    def __init__(self, cache_dir: str = CACHE_DIR) -> None:
        self._cache_dir = cache_dir
        self._loaded_at: Dict[str, float] = {}

        # Вредоносные URL и хосты
        self._bad_urls: Dict[str, ThreatInfo] = {}
        self._bad_hosts: Dict[str, ThreatInfo] = {}
        # Скам-адреса криптокошельков
        self._scam_addresses: Dict[str, ThreatInfo] = {}
        # Фишинговые домены
        self._phishing_domains: Set[str] = set()
        # C2-серверы ботнетов
        self._c2_ips: Dict[str, ThreatInfo] = {}
        # Выходные узлы Tor. Определяются без ключа, в отличие от AbuseIPDB
        self._tor_exits: Set[str] = set()
        # Сколько вредоносных URL размещено на хосте. Не обвинение хоста:
        # на крупных площадках такие ссылки есть всегда
        self._urlhaus_host_counts: Dict[str, int] = {}

    # --- состояние -------------------------------------------------------

    def _is_fresh(self, feed_name: str) -> bool:
        loaded = self._loaded_at.get(feed_name)
        return loaded is not None and (time.time() - loaded) < STALE_AFTER_SECONDS

    @property
    def stats(self) -> Dict[str, object]:
        """Для экрана «Статус источников» и админ-панели."""
        return {
            "urls": len(self._bad_urls),
            "hosts": len(self._bad_hosts),
            "scam_addresses": len(self._scam_addresses),
            "phishing_domains": len(self._phishing_domains),
            "c2_ips": len(self._c2_ips),
            "hosts_with_bad_urls": len(self._urlhaus_host_counts),
            "tor_exits": len(self._tor_exits),
            "feeds": {
                name: {
                    "fresh": self._is_fresh(name),
                    "age_hours": round((time.time() - ts) / 3600, 1),
                }
                for name, ts in self._loaded_at.items()
            },
        }

    def feed_ready(self, *names: str) -> bool:
        """Загружен ли хотя бы один из перечисленных фидов и не протух ли он."""
        return any(self._is_fresh(n) for n in names)

    # --- поиск -----------------------------------------------------------

    def lookup_url(self, url: str) -> LookupResult:
        """Числится ли URL или его хост среди вредоносных."""
        if not self.feed_ready("URLhaus", "ThreatFox"):
            return LookupResult(Verdict.UNAVAILABLE)

        hits: List[ThreatInfo] = []

        direct = self._bad_urls.get(_normalize_url(url))
        if direct:
            hits.append(direct)

        # Хост проверяем по доменным индикаторам (ThreatFox, ScamSniffer, Feodo),
        # но не по факту «на этом хосте когда-то лежал вредоносный файл»
        host = urlparse(url if "://" in url else f"http://{url}").hostname or url
        host_result = self.lookup_host(host)
        if host_result.is_hit:
            hits.extend(host_result.hits)

        return LookupResult(Verdict.HIT if hits else Verdict.CLEAN, hits)

    def is_tor_exit(self, ip: str) -> Optional[bool]:
        """
        Выходной ли это узел Tor.

        None означает «список не загружен»: вызывающий код не должен
        выдавать это за «не Tor».
        """
        if not self.feed_ready("Tor"):
            return None
        return (ip or "").strip() in self._tor_exits

    def malicious_urls_on_host(self, host: str) -> int:
        """
        Сколько вредоносных URL зафиксировано на хосте.

        Справочный показатель для отчёта. Сам по себе не делает хост
        вредоносным: у GitHub и Google Drive он всегда ненулевой.
        """
        return self._urlhaus_host_counts.get(_normalize_host(host), 0)

    def lookup_host(self, host: str) -> LookupResult:
        """Числится ли домен или IP среди вредоносных."""
        if not self.feed_ready("URLhaus", "ThreatFox", "ScamSniffer-домены", "Feodo Tracker"):
            return LookupResult(Verdict.UNAVAILABLE)

        normalized = _normalize_host(host)
        if not normalized:
            return LookupResult(Verdict.CLEAN)

        hits: List[ThreatInfo] = []

        known = self._bad_hosts.get(normalized)
        if known:
            hits.append(known)

        c2 = self._c2_ips.get(normalized)
        if c2:
            hits.append(c2)

        if normalized in self._phishing_domains:
            hits.append(ThreatInfo(source="ScamSniffer", threat_type="phishing"))

        return LookupResult(Verdict.HIT if hits else Verdict.CLEAN, hits)

    def lookup_crypto_address(self, address: str) -> LookupResult:
        """
        Числится ли адрес кошелька среди скамерских.

        Раньше при недоступной базе бот писал «скам не обнаружен».
        Теперь неготовая база честно возвращает UNAVAILABLE.
        """
        if not self.feed_ready("ScamSniffer-адреса"):
            return LookupResult(Verdict.UNAVAILABLE)

        hit = self._scam_addresses.get((address or "").strip().lower())
        return LookupResult(Verdict.HIT, [hit]) if hit else LookupResult(Verdict.CLEAN)

    # --- загрузка --------------------------------------------------------

    def _cache_path(self, spec: FeedSpec) -> str:
        return os.path.join(self._cache_dir, spec.filename)

    def _write_cache(self, spec: FeedSpec, payload: bytes) -> None:
        """Атомарная запись: временный файл рядом, потом переименование."""
        os.makedirs(self._cache_dir, exist_ok=True)
        path = self._cache_path(spec)
        tmp = f"{path}.tmp"
        try:
            with open(tmp, "wb") as f:
                f.write(payload)
            os.replace(tmp, path)
        except OSError as exc:
            log.warning("[feeds] Не удалось сохранить %s: %s", spec.name, exc)
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def _read_cache(self, spec: FeedSpec) -> Optional[bytes]:
        path = self._cache_path(spec)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError as exc:
            log.warning("[feeds] Не удалось прочитать кэш %s: %s", spec.name, exc)
            return None

    async def _download(self, session: aiohttp.ClientSession, spec: FeedSpec) -> Optional[bytes]:
        try:
            async with session.get(
                spec.url,
                headers={"User-Agent": USER_AGENT},
                timeout=aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT),
            ) as response:
                if response.status != 200:
                    log.warning("[feeds] %s: HTTP %s", spec.name, response.status)
                    return None
                return await response.read()
        except Exception as exc:
            log.warning("[feeds] %s: %s", spec.name, exc)
            return None

    async def refresh(self, use_cache_on_failure: bool = True) -> Dict[str, bool]:
        """
        Скачивает и разбирает все фиды. Возвращает {название: успешно}.

        Разбор - в отдельном потоке: распаковка 6 МБ JSON занимает заметное
        время и заморозила бы event loop.
        """
        results: Dict[str, bool] = {}

        async with aiohttp.ClientSession() as session:
            payloads = await asyncio.gather(
                *[self._download(session, spec) for spec in FEEDS]
            )

        for spec, payload in zip(FEEDS, payloads):
            if payload is None and use_cache_on_failure:
                payload = self._read_cache(spec)
                if payload is not None:
                    log.info("[feeds] %s: источник недоступен, беру кэш с диска", spec.name)
            elif payload is not None:
                self._write_cache(spec, payload)

            if payload is None:
                results[spec.name] = False
                continue

            try:
                parser = getattr(self, spec.parser)
                await asyncio.to_thread(parser, payload)
                self._loaded_at[spec.name] = time.time()
                results[spec.name] = True
            except Exception as exc:
                log.warning("[feeds] %s: ошибка разбора: %s", spec.name, exc)
                results[spec.name] = False

        ok = sum(1 for v in results.values() if v)
        log.info(
            "[feeds] Обновлено %d из %d. Вредоносных URL: %d, хостов: %d, "
            "скам-адресов: %d, фишинг-доменов: %d, C2: %d",
            ok, len(FEEDS), len(self._bad_urls), len(self._bad_hosts),
            len(self._scam_addresses), len(self._phishing_domains), len(self._c2_ips),
        )
        return results

    def load_from_disk(self) -> int:
        """
        Поднимает фиды из кэша на старте, не дожидаясь скачивания.

        Возвращает число загруженных. Свежесть проверяется по времени
        изменения файла: протухший кэш не поднимаем.
        """
        loaded = 0
        for spec in FEEDS:
            path = self._cache_path(spec)
            if not os.path.exists(path):
                continue
            age = time.time() - os.path.getmtime(path)
            if age > STALE_AFTER_SECONDS:
                log.info("[feeds] %s: кэш протух (%.1f ч), пропускаю", spec.name, age / 3600)
                continue
            payload = self._read_cache(spec)
            if payload is None:
                continue
            try:
                getattr(self, spec.parser)(payload)
                self._loaded_at[spec.name] = time.time() - age
                loaded += 1
            except Exception as exc:
                log.warning("[feeds] %s: кэш не разобрался: %s", spec.name, exc)
        if loaded:
            log.info("[feeds] С диска поднято фидов: %d", loaded)
        return loaded

    # --- парсеры ---------------------------------------------------------

    def _parse_urlhaus(self, payload: bytes) -> None:
        """
        CSV: id,dateadded,url,url_status,last_online,threat,tags,link,reporter.

        Хосты из URLhaus намеренно НЕ попадают в список вредоносных.
        В базе полно ссылок вида github.com/user/repo/releases/malware.exe
        или drive.google.com/..., и пометка хоста целиком превращала
        github.com, Google Drive, Dropbox и Discord во «вредоносные».
        Проверено: до этой правки github.com получал 10/10 «Высокий риск».

        Вместо этого считаем, сколько вредоносных URL размещено на хосте.
        Это честный контекст («на площадке зафиксировано N вредоносных ссылок»),
        а не обвинение самой площадки.
        """
        text = payload.decode("utf-8", "ignore")
        rows = [line for line in text.splitlines() if line and not line.startswith("#")]

        urls: Dict[str, ThreatInfo] = {}
        host_counts: Dict[str, int] = {}

        for row in csv.reader(rows):
            if len(row) < 7:
                continue
            _id, date_added, url, _status, _last, threat, tags = row[:7]
            urls[_normalize_url(url)] = ThreatInfo(
                source="URLhaus",
                threat_type=threat or None,
                tags=_clean_tags(tags),
                first_seen=date_added or None,
            )
            host = _normalize_host(url)
            if host:
                host_counts[host] = host_counts.get(host, 0) + 1

        self._bad_urls = urls
        self._urlhaus_host_counts = host_counts

    def _parse_threatfox(self, payload: bytes) -> None:
        """JSON: {id: [ {ioc_value, ioc_type, threat_type, malware_printable, ...} ]}."""
        data = json.loads(payload.decode("utf-8", "ignore"))

        hosts: Dict[str, ThreatInfo] = {}
        urls: Dict[str, ThreatInfo] = {}

        for entries in data.values():
            if not entries:
                continue
            item = entries[0]
            value = (item.get("ioc_value") or "").strip()
            if not value:
                continue

            info = ThreatInfo(
                source="ThreatFox",
                threat_type=item.get("threat_type"),
                malware=item.get("malware_printable"),
                confidence=item.get("confidence_level"),
                tags=_clean_tags(item.get("tags")),
                first_seen=item.get("first_seen_utc"),
            )

            ioc_type = item.get("ioc_type")
            if ioc_type == "url":
                urls[_normalize_url(value)] = info
                host = _normalize_host(value)
                if host:
                    hosts.setdefault(host, info)
            elif ioc_type in ("domain", "ip:port"):
                host = _normalize_host(value.split(":")[0] if ioc_type == "ip:port" else value)
                if host:
                    hosts[host] = info

        self._bad_urls.update(urls)
        self._bad_hosts.update(hosts)

    def _parse_scam_addresses(self, payload: bytes) -> None:
        """JSON-массив адресов кошельков."""
        data = json.loads(payload.decode("utf-8", "ignore"))
        info = ThreatInfo(source="ScamSniffer", threat_type="scam")
        self._scam_addresses = {
            str(addr).strip().lower(): info for addr in data if addr
        }

    def _parse_scam_domains(self, payload: bytes) -> None:
        """JSON-массив фишинговых доменов."""
        data = json.loads(payload.decode("utf-8", "ignore"))
        self._phishing_domains = {
            _normalize_host(str(d)) for d in data if d
        }
        self._phishing_domains.discard("")

    def _parse_tor(self, payload: bytes) -> None:
        """Текстовый список: по одному IP в строке."""
        self._tor_exits = {
            line.strip()
            for line in payload.decode("utf-8", "ignore").splitlines()
            if line.strip() and not line.startswith("#")
        }

    def _parse_feodo(self, payload: bytes) -> None:
        """JSON-массив C2-серверов ботнетов."""
        data = json.loads(payload.decode("utf-8", "ignore"))
        c2: Dict[str, ThreatInfo] = {}
        for item in data:
            ip = (item.get("ip_address") or "").strip()
            if not ip:
                continue
            c2[ip] = ThreatInfo(
                source="Feodo Tracker",
                threat_type="botnet_c2",
                malware=item.get("malware"),
                first_seen=item.get("first_seen"),
            )
        self._c2_ips = c2


# Единственный экземпляр на процесс
feeds = ThreatFeeds()


async def feeds_loop(store: Optional[ThreatFeeds] = None) -> None:
    """Фоновое обновление фидов. Запускается из main.py рядом с monitor_loop."""
    store = store or feeds

    # На старте поднимаем кэш с диска, чтобы бот отвечал сразу,
    # и только потом идём в сеть за свежими данными.
    await asyncio.to_thread(store.load_from_disk)

    while True:
        try:
            await store.refresh()
        except Exception as exc:
            log.error("[feeds] Обновление сорвалось: %s", exc, exc_info=True)
        await asyncio.sleep(REFRESH_INTERVAL_SECONDS)


def to_verdict(result: LookupResult) -> "ThreatVerdict":
    """
    Переводит внутренний LookupResult в модель для отчётов сканеров.

    Держится здесь, а не в каждом сканере, чтобы трёхзначность вердикта
    не потерялась при переносе: checked обязан доехать до форматтера.
    """
    from utils.risk_types import ThreatVerdict

    if result.verdict is Verdict.UNAVAILABLE:
        return ThreatVerdict(checked=False, found=False)

    if not result.hits:
        return ThreatVerdict(checked=True, found=False)

    # Берём самую содержательную находку: с названием малвари информативнее
    best = max(result.hits, key=lambda h: (bool(h.malware), h.confidence or 0))
    tags: List[str] = []
    for hit in result.hits:
        tags.extend(hit.tags)

    return ThreatVerdict(
        checked=True,
        found=True,
        sources=sorted({h.source for h in result.hits}),
        threat_type=best.threat_type,
        malware=best.malware,
        confidence=best.confidence,
        tags=sorted(set(tags))[:8],
    )
