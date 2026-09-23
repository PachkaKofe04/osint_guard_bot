# tests/test_threat_feeds.py
"""
Локальный кэш баз угроз.

Главное, что здесь проверяется: незагруженная база отвечает UNAVAILABLE,
а не CLEAN. Раньше мёртвый источник молча превращался в вердикт
«скам не обнаружен» - ложноотрицательный ответ в боте по безопасности.

Сеть не используется: парсеры кормятся синтетическими выгрузками.
"""
import json
import time

import pytest

from services.threat_feeds import ThreatFeeds, Verdict, _clean_tags, _normalize_host

URLHAUS_CSV = b"""# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-09-23 05:32:14","http://evil.example/bin.sh","online","2026-09-23","malware_download","Mozi","https://urlhaus.abuse.ch/url/1/","tester"
"2","2026-09-23 05:33:00","http://bad.test/payload","online","2026-09-23","malware_download","None","https://urlhaus.abuse.ch/url/2/","tester"
"""

THREATFOX_JSON = json.dumps({
    "100": [{
        "ioc_value": "c2.example",
        "ioc_type": "domain",
        "threat_type": "botnet_cc",
        "malware_printable": "Cobalt Strike",
        "confidence_level": 90,
        "tags": "cs,beacon",
        "first_seen_utc": "2026-09-23 05:44:56",
    }],
    "101": [{
        "ioc_value": "203.0.113.7:4444",
        "ioc_type": "ip:port",
        "threat_type": "botnet_cc",
        "malware_printable": "AsyncRAT",
        "confidence_level": 75,
        "tags": None,
        "first_seen_utc": "2026-09-23 05:45:00",
    }],
}).encode()

SCAM_ADDRESSES = json.dumps([
    "0x101ce0cedd142f199c9ef61739ae59b6611a0fc0",
    "1BadBitcoinAddressExample",
]).encode()

SCAM_DOMAINS = json.dumps(["phish.example", "www.drainer.test"]).encode()

FEODO = json.dumps([
    {"ip_address": "198.51.100.5", "malware": "Emotet", "first_seen": "2026-09-01"},
]).encode()


@pytest.fixture
def loaded_feeds(tmp_path) -> ThreatFeeds:
    """Кэш с разобранными синтетическими выгрузками."""
    store = ThreatFeeds(cache_dir=str(tmp_path))
    store._parse_urlhaus(URLHAUS_CSV)
    store._parse_threatfox(THREATFOX_JSON)
    store._parse_scam_addresses(SCAM_ADDRESSES)
    store._parse_scam_domains(SCAM_DOMAINS)
    store._parse_feodo(FEODO)
    now = time.time()
    for name in ("URLhaus", "ThreatFox", "ScamSniffer-адреса",
                 "ScamSniffer-домены", "Feodo Tracker"):
        store._loaded_at[name] = now
    return store


@pytest.fixture
def empty_feeds(tmp_path) -> ThreatFeeds:
    return ThreatFeeds(cache_dir=str(tmp_path))


class TestUnavailableIsNotClean:
    """Ядро дефекта C-06: незагруженная база не должна означать «чисто»."""

    def test_address_lookup_without_feeds(self, empty_feeds):
        result = empty_feeds.lookup_crypto_address("0xanything")
        assert result.verdict is Verdict.UNAVAILABLE
        assert result.is_checked is False
        assert result.is_hit is False

    def test_host_lookup_without_feeds(self, empty_feeds):
        assert empty_feeds.lookup_host("example.com").verdict is Verdict.UNAVAILABLE

    def test_url_lookup_without_feeds(self, empty_feeds):
        assert empty_feeds.lookup_url("http://example.com/").verdict is Verdict.UNAVAILABLE

    def test_clean_is_distinguishable_from_unavailable(self, loaded_feeds, empty_feeds):
        """Два разных состояния нельзя перепутать по is_checked."""
        clean = loaded_feeds.lookup_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        unavailable = empty_feeds.lookup_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

        assert clean.verdict is Verdict.CLEAN
        assert clean.is_checked is True
        assert unavailable.is_checked is False

    def test_stale_feed_counts_as_unavailable(self, loaded_feeds):
        """Позавчерашняя выгрузка - не основание говорить «чисто»."""
        loaded_feeds._loaded_at["ScamSniffer-адреса"] = time.time() - 48 * 3600
        assert loaded_feeds.lookup_crypto_address("0xanything").verdict is Verdict.UNAVAILABLE


class TestScamAddresses:
    def test_known_scam_address_found(self, loaded_feeds):
        result = loaded_feeds.lookup_crypto_address(
            "0x101ce0cedd142f199c9ef61739ae59b6611a0fc0"
        )
        assert result.is_hit
        assert result.hits[0].source == "ScamSniffer"

    def test_case_insensitive(self, loaded_feeds):
        """Адреса EVM записывают в разном регистре."""
        assert loaded_feeds.lookup_crypto_address(
            "0X101CE0CEDD142F199C9EF61739AE59B6611A0FC0"
        ).is_hit

    def test_surrounding_whitespace_ignored(self, loaded_feeds):
        assert loaded_feeds.lookup_crypto_address(
            "  0x101ce0cedd142f199c9ef61739ae59b6611a0fc0  "
        ).is_hit

    def test_unknown_address_is_clean(self, loaded_feeds):
        result = loaded_feeds.lookup_crypto_address("0xdeadbeef")
        assert result.verdict is Verdict.CLEAN
        assert result.hits == []


class TestMaliciousUrls:
    def test_known_url_found(self, loaded_feeds):
        result = loaded_feeds.lookup_url("http://evil.example/bin.sh")
        assert result.is_hit
        assert any(h.threat_type == "malware_download" for h in result.hits)

    def test_host_of_known_url_also_flagged(self, loaded_feeds):
        """Если с хоста раздают малварь, подозрителен весь хост."""
        assert loaded_feeds.lookup_host("evil.example").is_hit

    def test_clean_url(self, loaded_feeds):
        assert loaded_feeds.lookup_url("https://google.com/").verdict is Verdict.CLEAN


class TestThreatFox:
    def test_domain_carries_malware_name(self, loaded_feeds):
        result = loaded_feeds.lookup_host("c2.example")
        assert result.is_hit
        hit = next(h for h in result.hits if h.source == "ThreatFox")
        assert hit.malware == "Cobalt Strike"
        assert hit.confidence == 90
        assert "beacon" in hit.tags

    def test_ip_port_indicator_matches_bare_ip(self, loaded_feeds):
        """В фиде записано 203.0.113.7:4444, пользователь пришлёт голый IP."""
        result = loaded_feeds.lookup_host("203.0.113.7")
        assert result.is_hit
        assert result.hits[0].malware == "AsyncRAT"


class TestPhishingAndC2:
    def test_phishing_domain(self, loaded_feeds):
        assert loaded_feeds.lookup_host("phish.example").is_hit

    def test_www_prefix_normalised(self, loaded_feeds):
        """В фиде домен записан с www, пользователь пришлёт без него."""
        assert loaded_feeds.lookup_host("drainer.test").is_hit

    def test_botnet_c2_ip(self, loaded_feeds):
        result = loaded_feeds.lookup_host("198.51.100.5")
        assert result.is_hit
        assert result.hits[0].malware == "Emotet"


class TestTagCleaning:
    def test_literal_none_is_dropped(self):
        """URLhaus пишет в CSV строку None вместо пустого значения."""
        assert _clean_tags("None") == ()

    def test_normal_tags_kept(self):
        assert _clean_tags("Mozi,elf") == ("Mozi", "elf")

    def test_empty_input(self):
        assert _clean_tags("") == ()
        assert _clean_tags(None) == ()

    def test_url_without_tags_has_empty_tuple(self, loaded_feeds):
        result = loaded_feeds.lookup_url("http://bad.test/payload")
        assert result.is_hit
        assert result.hits[0].tags == ()


class TestHostNormalisation:
    @pytest.mark.parametrize("raw,expected", [
        ("Example.COM", "example.com"),
        ("www.example.com", "example.com"),
        ("http://example.com/path?q=1", "example.com"),
        ("example.com:8080", "example.com"),
        ("example.com.", "example.com"),
        ("", ""),
    ])
    def test_normalise(self, raw, expected):
        assert _normalize_host(raw) == expected


class TestDiskCache:
    def test_survives_restart(self, tmp_path):
        """Перезапуск бота не должен ронять проверки до первого скачивания."""
        first = ThreatFeeds(cache_dir=str(tmp_path))
        first._write_cache(
            next(f for f in __import__(
                "services.threat_feeds", fromlist=["FEEDS"]
            ).FEEDS if f.name == "ScamSniffer-адреса"),
            SCAM_ADDRESSES,
        )

        second = ThreatFeeds(cache_dir=str(tmp_path))
        assert second.load_from_disk() >= 1
        assert second.lookup_crypto_address(
            "0x101ce0cedd142f199c9ef61739ae59b6611a0fc0"
        ).is_hit

    def test_no_cache_means_unavailable(self, tmp_path):
        store = ThreatFeeds(cache_dir=str(tmp_path / "nothing"))
        assert store.load_from_disk() == 0
        assert store.lookup_crypto_address("0x1").verdict is Verdict.UNAVAILABLE


class TestStats:
    def test_counts_reported(self, loaded_feeds):
        stats = loaded_feeds.stats
        assert stats["scam_addresses"] == 2
        assert stats["phishing_domains"] == 2
        assert stats["c2_ips"] == 1
        assert stats["feeds"]["URLhaus"]["fresh"] is True
