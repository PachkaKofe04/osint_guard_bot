"""Контракт обновления фидов: ошибки не уничтожают проверенные данные."""

import os
import time
from pathlib import Path

import pytest

import services.threat_feeds as threat_feeds
from services.threat_feeds import FEEDS, ThreatFeeds, Verdict


URLHAUS = next(spec for spec in FEEDS if spec.name == "URLhaus")
SCAM_ADDRESSES = next(spec for spec in FEEDS if spec.parser == "_parse_scam_addresses")
KNOWN_URL = "https://known-malware.example/payload"
NEW_URL = "https://new-malware.example/payload"
KNOWN_ADDRESS = "0x1111111111111111111111111111111111111111"
NEW_ADDRESS = "0x2222222222222222222222222222222222222222"
GOOD_ADDRESSES = f'["{KNOWN_ADDRESS}"]'.encode()


def _urlhaus_payload(url):
    return (
        "# id,dateadded,url,url_status,last_online,threat,tags,link,reporter\n"
        f'"1","2026-10-08","{url}","online","2026-10-08",'
        '"malware_download","exe","https://urlhaus.abuse.ch/url/1/","tester"\n'
    ).encode()


class _Response:
    def __init__(self, payload, content_type, status=200):
        self.status = status
        self.headers = {"Content-Type": content_type}
        self.content_type = content_type
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def read(self):
        return self._payload


class _Session:
    def __init__(self, spec, response):
        self._spec = spec
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def get(self, url, **kwargs):
        if url != self._spec.url:
            raise RuntimeError("Unexpected request in an isolated feed test")
        return self._response


def _mock_http(monkeypatch, spec, payload, content_type, status=200):
    # Единственный разрешенный запрос получает синтетический ответ.
    monkeypatch.setattr(threat_feeds, "FEEDS", (spec,))
    monkeypatch.setattr(
        threat_feeds.aiohttp,
        "ClientSession",
        lambda: _Session(spec, _Response(payload, content_type, status)),
    )


def _seed_cache(monkeypatch, tmp_path, spec, payload, age_seconds=3600):
    monkeypatch.setattr(threat_feeds, "FEEDS", (spec,))
    store = ThreatFeeds(cache_dir=str(tmp_path))
    store._write_cache(spec, payload)
    path = tmp_path / spec.filename
    timestamp = time.time() - age_seconds
    os.utime(path, (timestamp, timestamp))
    return store, path


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="TW-02: HTML200 must preserve the last valid URLhaus snapshot",
)
async def test_html200_preserves_urlhaus_memory_and_disk(monkeypatch, tmp_path):
    good_payload = _urlhaus_payload(KNOWN_URL)
    store, path = _seed_cache(monkeypatch, tmp_path, URLHAUS, good_payload)
    assert store.load_from_disk() == 1
    assert store.lookup_url(KNOWN_URL).verdict is Verdict.HIT
    old_urls = store._bad_urls.copy()
    old_host_counts = store._urlhaus_host_counts.copy()
    old_loaded_at = store._loaded_at.copy()
    old_mtime = path.stat().st_mtime
    _mock_http(monkeypatch, URLHAUS, b"<html>access denied</html>", "text/html")

    results = await store.refresh(use_cache_on_failure=False)

    assert results[URLHAUS.name] is False
    assert store._bad_urls == old_urls
    assert store._urlhaus_host_counts == old_host_counts
    assert store._loaded_at == old_loaded_at
    assert path.read_bytes() == good_payload
    assert path.stat().st_mtime == old_mtime
    assert store.lookup_url(KNOWN_URL).verdict is Verdict.HIT
    restarted = ThreatFeeds(cache_dir=str(tmp_path))
    assert restarted.load_from_disk() == 1
    assert restarted.lookup_url(KNOWN_URL).verdict is Verdict.HIT


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="TW-02: invalid JSON responses must preserve the last valid snapshot",
)
@pytest.mark.parametrize(
    "payload,content_type",
    [
        pytest.param(b"<html>upstream unavailable</html>", "text/html", id="html200"),
        pytest.param(b'["unterminated', "application/json", id="malformed-json"),
        pytest.param(b'{"error":"unavailable"}', "application/json", id="wrong-schema"),
    ],
)
async def test_invalid_json_preserves_memory_and_disk(
    monkeypatch, tmp_path, payload, content_type
):
    store, path = _seed_cache(monkeypatch, tmp_path, SCAM_ADDRESSES, GOOD_ADDRESSES)
    assert store.load_from_disk() == 1
    assert store.lookup_crypto_address(KNOWN_ADDRESS).verdict is Verdict.HIT
    old_addresses = store._scam_addresses.copy()
    old_loaded_at = store._loaded_at.copy()
    old_mtime = path.stat().st_mtime
    _mock_http(monkeypatch, SCAM_ADDRESSES, payload, content_type)

    results = await store.refresh(use_cache_on_failure=False)

    assert results[SCAM_ADDRESSES.name] is False
    assert store._scam_addresses == old_addresses
    assert store._loaded_at == old_loaded_at
    assert path.read_bytes() == GOOD_ADDRESSES
    assert path.stat().st_mtime == old_mtime
    assert store.lookup_crypto_address(KNOWN_ADDRESS).verdict is Verdict.HIT
    restarted = ThreatFeeds(cache_dir=str(tmp_path))
    assert restarted.load_from_disk() == 1
    assert restarted.lookup_crypto_address(KNOWN_ADDRESS).verdict is Verdict.HIT


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="TW-03: network failure must not make a seven-day cache fresh",
)
async def test_network_failure_does_not_rejuvenate_stale_cache(monkeypatch, tmp_path):
    store, path = _seed_cache(
        monkeypatch, tmp_path, SCAM_ADDRESSES, GOOD_ADDRESSES, age_seconds=7 * 24 * 3600
    )
    assert store.load_from_disk() == 0
    assert store.lookup_crypto_address(NEW_ADDRESS).verdict is Verdict.UNAVAILABLE
    old_mtime = path.stat().st_mtime
    _mock_http(monkeypatch, SCAM_ADDRESSES, b"service unavailable", "text/plain", status=503)

    await store.refresh()

    assert not store.feed_ready(SCAM_ADDRESSES.name)
    assert store.lookup_crypto_address(NEW_ADDRESS).verdict is Verdict.UNAVAILABLE
    assert path.read_bytes() == GOOD_ADDRESSES
    assert path.stat().st_mtime == old_mtime
    timestamp = store._loaded_at.get(SCAM_ADDRESSES.name)
    assert timestamp is None or timestamp <= old_mtime
    restarted = ThreatFeeds(cache_dir=str(tmp_path))
    assert restarted.load_from_disk() == 0
    assert restarted.lookup_crypto_address(NEW_ADDRESS).verdict is Verdict.UNAVAILABLE


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="TW-03: fallback must retain the original fresh cache timestamp",
)
async def test_network_failure_retains_fresh_cache_timestamp(monkeypatch, tmp_path):
    store, path = _seed_cache(monkeypatch, tmp_path, SCAM_ADDRESSES, GOOD_ADDRESSES)
    assert store.load_from_disk() == 1
    old_loaded_at = store._loaded_at[SCAM_ADDRESSES.name]
    old_mtime = path.stat().st_mtime
    _mock_http(monkeypatch, SCAM_ADDRESSES, b"service unavailable", "text/plain", status=503)

    await store.refresh()

    assert store._loaded_at[SCAM_ADDRESSES.name] == pytest.approx(old_loaded_at, abs=0.001, rel=0)
    assert store.lookup_crypto_address(KNOWN_ADDRESS).verdict is Verdict.HIT
    assert path.read_bytes() == GOOD_ADDRESSES
    assert path.stat().st_mtime == old_mtime


async def test_valid_urlhaus_refresh_publishes_new_snapshot(monkeypatch, tmp_path):
    store, path = _seed_cache(monkeypatch, tmp_path, URLHAUS, _urlhaus_payload(KNOWN_URL))
    assert store.load_from_disk() == 1
    old_loaded_at = store._loaded_at[URLHAUS.name]
    new_payload = _urlhaus_payload(NEW_URL)
    _mock_http(monkeypatch, URLHAUS, new_payload, "text/csv")

    results = await store.refresh(use_cache_on_failure=False)

    assert results[URLHAUS.name] is True
    assert store._loaded_at[URLHAUS.name] > old_loaded_at
    assert store.lookup_url(NEW_URL).verdict is Verdict.HIT
    assert store.lookup_url(KNOWN_URL).verdict is Verdict.CLEAN
    assert path.read_bytes() == new_payload
    restarted = ThreatFeeds(cache_dir=str(tmp_path))
    assert restarted.load_from_disk() == 1
    assert restarted.lookup_url(NEW_URL).verdict is Verdict.HIT


async def test_valid_json_refresh_publishes_new_snapshot(monkeypatch, tmp_path):
    store, path = _seed_cache(monkeypatch, tmp_path, SCAM_ADDRESSES, GOOD_ADDRESSES)
    assert store.load_from_disk() == 1
    old_loaded_at = store._loaded_at[SCAM_ADDRESSES.name]
    new_payload = f'["{NEW_ADDRESS}"]'.encode()
    _mock_http(monkeypatch, SCAM_ADDRESSES, new_payload, "application/json")

    results = await store.refresh(use_cache_on_failure=False)

    assert results[SCAM_ADDRESSES.name] is True
    assert store._loaded_at[SCAM_ADDRESSES.name] > old_loaded_at
    assert store.lookup_crypto_address(NEW_ADDRESS).verdict is Verdict.HIT
    assert store.lookup_crypto_address(KNOWN_ADDRESS).verdict is Verdict.CLEAN
    assert path.read_bytes() == new_payload
    restarted = ThreatFeeds(cache_dir=str(tmp_path))
    assert restarted.load_from_disk() == 1
    assert restarted.lookup_crypto_address(NEW_ADDRESS).verdict is Verdict.HIT


@pytest.mark.parametrize("spec", [URLHAUS, SCAM_ADDRESSES], ids=["csv", "json"])
async def test_network_failure_without_cache_is_unavailable(monkeypatch, tmp_path, spec):
    store = ThreatFeeds(cache_dir=str(tmp_path))
    _mock_http(monkeypatch, spec, b"service unavailable", "text/plain", status=503)

    results = await store.refresh()

    assert results[spec.name] is False
    assert not store.feed_ready(spec.name)
    assert store.lookup_url(KNOWN_URL).verdict is Verdict.UNAVAILABLE
    assert store.lookup_crypto_address(KNOWN_ADDRESS).verdict is Verdict.UNAVAILABLE
    assert not Path(store._cache_path(spec)).exists()
