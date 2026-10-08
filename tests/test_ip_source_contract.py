"""Контракты независимых источников репутации IP и неполноты данных."""
import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import aiohttp
import pytest
import requests

from ip_scanner.abuseipdb_service import AbuseIpdbResult, AbuseStatus
from ip_scanner.formatter import format_ip_result
from services.threat_feeds import LookupResult, Verdict
from utils.risk_types import RiskLevel


IP = "8.8.4.4"
PROFILE = {
    "country": "United States",
    "countryCode": "US",
    "city": "New York",
    "isp": "Example access provider",
    "org": "Example access provider",
    "asname": "Example access provider",
    "source": "ipwho.is",
    "proxy": False,
    "hosting": False,
    "proxy_unknown": False,
}
FAILED_ABUSE_STATUSES = (
    AbuseStatus.NO_KEY,
    AbuseStatus.REJECTED,
    AbuseStatus.RATE_LIMITED,
    AbuseStatus.ERROR,
)


@pytest.fixture
def ip_sources(monkeypatch):
    # Все ключи синтетические; при отдельном запуске модуль конфигурации
    # получает значения до первого импорта сканера.
    monkeypatch.setenv("BOT_TOKEN", "123456789:isolated-test-token")
    for key in (
        "ABUSECH_API_KEY", "ABUSEIPDB_API_KEY", "ETHERSCAN_API_KEY",
        "SAFEBROWSING_API_KEY", "VIRUSTOTAL_API_KEY", "OTX_API_KEY",
        "VERIPHONE_API_KEY", "HIBP_API_KEY", "ADMIN_IDS",
    ):
        monkeypatch.setenv(key, "")

    network_guards = [
        Mock(side_effect=RuntimeError("Сеть в контрактных тестах запрещена")),
        Mock(side_effect=RuntimeError("Сеть в контрактных тестах запрещена")),
    ]
    monkeypatch.setattr(aiohttp, "ClientSession", network_guards[0])
    monkeypatch.setattr(requests.sessions.Session, "request", network_guards[1])

    scanner = importlib.import_module("ip_scanner.scanner")
    profile = AsyncMock(return_value=dict(PROFILE))
    abuse = AsyncMock(return_value=AbuseIpdbResult(
        status=AbuseStatus.OK, abuse_score=0, is_tor=False,
    ))
    otx = Mock(return_value={"pulse_count": 0, "malware_samples": 0})
    tor = Mock(return_value=False)
    host = Mock(return_value=LookupResult(verdict=Verdict.CLEAN))
    cache = Mock()
    cache.get.return_value = None

    monkeypatch.setattr(scanner, "settings", SimpleNamespace(ABUSEIPDB_API_KEY="test-key"))
    monkeypatch.setattr(scanner, "fetch_ip_profile_async", profile)
    monkeypatch.setattr(scanner, "check_abuseipdb", abuse)
    monkeypatch.setattr(scanner, "check_ip_reputation", otx)
    monkeypatch.setattr(scanner, "feeds", SimpleNamespace(is_tor_exit=tor, lookup_host=host))
    monkeypatch.setattr(scanner, "_ip_cache", cache)

    yield SimpleNamespace(
        scanner=scanner, profile=profile, abuse=abuse,
        otx=otx, tor=tor, host=host, cache=cache,
    )

    # Нарушение изоляции не должно скрываться за ожидаемым падением assert.
    if any(guard.called for guard in network_guards):
        raise RuntimeError("Контрактный тест попытался обратиться к сети")


def _flag_codes(result):
    return {flag.code for flag in result.flags}


def _abusive_result():
    return AbuseIpdbResult(
        status=AbuseStatus.OK,
        abuse_score=100,
        total_reports=50,
        usage_type="Data Center/Web Hosting/Transit",
    )


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="TW-01: geo failure discards successful AbuseIPDB evidence",
)
async def test_geo_failure_preserves_successful_abuseipdb(ip_sources):
    ip_sources.profile.return_value = None
    ip_sources.abuse.return_value = _abusive_result()

    result = await ip_sources.scanner.scan_ip(IP)

    ip_sources.abuse.assert_awaited_once_with(IP, "test-key")
    assert result.info.abuse_score == 100
    assert result.info.is_blacklisted is True
    assert result.info.threat_types == [ip_sources.abuse.return_value.usage_type]
    assert {"HIGH_ABUSE_SCORE", "IP_BLACKLISTED"} <= _flag_codes(result)
    assert result.risk_level is RiskLevel.HIGH
    assert "Abuse Score: 100%" in format_ip_result(result)


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="TW-01: geo failure skips an independently available Tor list",
)
async def test_geo_failure_preserves_known_tor_exit(ip_sources):
    ip_sources.profile.return_value = None
    ip_sources.tor.return_value = True

    result = await ip_sources.scanner.scan_ip(IP)

    assert result.info.is_tor is True
    ip_sources.tor.assert_called_once_with(IP)
    assert "TOR_EXIT_NODE" in _flag_codes(result)
    assert "CLEAN_IP" not in _flag_codes(result)
    assert "TOR" in format_ip_result(result)


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="TW-01: geo failure hides combined AbuseIPDB and Tor threats in the card",
)
async def test_geo_failure_keeps_abuse_and_tor_card_high_risk(ip_sources):
    ip_sources.profile.return_value = None
    ip_sources.abuse.return_value = _abusive_result()
    ip_sources.tor.return_value = True

    result = await ip_sources.scanner.scan_ip(IP)

    assert result.risk_level is RiskLevel.HIGH
    assert result.info.abuse_score == 100
    assert result.info.is_tor is True
    assert "CLEAN_IP" not in _flag_codes(result)
    card = format_ip_result(result)
    assert "Abuse Score: 100%" in card
    assert "TOR" in card


async def test_geo_failure_preserves_successful_otx(ip_sources):
    ip_sources.profile.return_value = None
    ip_sources.otx.return_value = {"pulse_count": 50, "malware_samples": 100}

    result = await ip_sources.scanner.scan_ip(IP)

    ip_sources.otx.assert_called_once_with(IP)
    assert result.otx.pulse_count == 50
    assert result.otx.malware_samples == 100
    assert "OTX_MALWARE" in _flag_codes(result)
    card = format_ip_result(result)
    assert "Threat-пульсов: 50" in card
    assert "Malware-образцов: 100" in card


async def test_healthy_geo_preserves_all_independent_threat_evidence(ip_sources):
    ip_sources.abuse.return_value = _abusive_result()
    ip_sources.tor.return_value = True
    ip_sources.otx.return_value = {"pulse_count": 50, "malware_samples": 100}

    result = await ip_sources.scanner.scan_ip(IP)

    ip_sources.profile.assert_awaited_once_with(IP)
    ip_sources.abuse.assert_awaited_once_with(IP, "test-key")
    ip_sources.otx.assert_called_once_with(IP)
    ip_sources.tor.assert_called_once_with(IP)
    assert result.info.abuse_score == 100
    assert result.info.is_tor is True
    assert result.otx.malware_samples == 100
    assert {"HIGH_ABUSE_SCORE", "TOR_EXIT_NODE", "OTX_MALWARE"} <= _flag_codes(result)
    assert "CLEAN_IP" not in _flag_codes(result)
    assert result.risk_level is RiskLevel.HIGH
    assert result.score == 10
    card = format_ip_result(result)
    assert "Abuse Score: 100%" in card
    assert "TOR" in card
    assert "Malware-образцов: 100" in card


@pytest.mark.parametrize("status", FAILED_ABUSE_STATUSES)
@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="TW-01: geo failure discards the independent AbuseIPDB failure reason",
)
async def test_geo_failure_preserves_abuse_failure_explanation(ip_sources, status):
    ip_sources.profile.return_value = None
    ip_sources.abuse.return_value = AbuseIpdbResult(status=status)

    result = await ip_sources.scanner.scan_ip(IP)

    explanation = ip_sources.abuse.return_value.explanation
    assert result.info.reputation_note == explanation
    assert explanation in format_ip_result(result)


@pytest.mark.parametrize("status", FAILED_ABUSE_STATUSES)
async def test_healthy_geo_shows_distinct_abuse_failure_explanation(ip_sources, status):
    ip_sources.abuse.return_value = AbuseIpdbResult(status=status)

    result = await ip_sources.scanner.scan_ip(IP)

    assert result.info.abuse_score is None
    assert result.info.reputation_note == ip_sources.abuse.return_value.explanation
    card = format_ip_result(result)
    assert "проверка не выполнена" in card
    assert ip_sources.abuse.return_value.explanation in card


@pytest.mark.parametrize("missing_source", (
    "all", "proxy", "abuse_no_key", "abuse_error", "tor",
))
@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="TW-05: incomplete source data is incorrectly granted CLEAN_IP trust",
)
async def test_missing_evidence_never_grants_clean_ip_trust(ip_sources, missing_source):
    if missing_source == "all":
        ip_sources.profile.return_value = None
        ip_sources.abuse.return_value = AbuseIpdbResult(status=AbuseStatus.NO_KEY)
        ip_sources.tor.return_value = None
        ip_sources.otx.return_value = None
        ip_sources.host.return_value = LookupResult(verdict=Verdict.UNAVAILABLE)
    elif missing_source == "proxy":
        ip_sources.profile.return_value["proxy_unknown"] = True
    elif missing_source == "abuse_no_key":
        ip_sources.abuse.return_value = AbuseIpdbResult(status=AbuseStatus.NO_KEY)
    elif missing_source == "abuse_error":
        ip_sources.abuse.return_value = AbuseIpdbResult(status=AbuseStatus.ERROR)
    elif missing_source == "tor":
        ip_sources.tor.return_value = None
        # Ни список, ни AbuseIPDB не подтвердили отсутствие Tor.
        ip_sources.abuse.return_value = AbuseIpdbResult(status=AbuseStatus.NO_KEY)

    result = await ip_sources.scanner.scan_ip(IP)

    assert "CLEAN_IP" not in _flag_codes(result)
    assert all(flag.weight >= 0 for flag in result.flags)


@pytest.mark.parametrize("profile", (None, {**PROFILE, "proxy_unknown": True}), ids=(
    "missing_profile", "unknown_proxy",
))
@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="TW-05: an unknown connection type is reported as residential",
)
async def test_unknown_connection_type_never_claims_residential(ip_sources, profile):
    ip_sources.profile.return_value = profile

    result = await ip_sources.scanner.scan_ip(IP)

    assert "Резиденциальный IP" not in format_ip_result(result)


async def test_successfully_checked_clean_ip_can_receive_clean_flag(ip_sources):
    result = await ip_sources.scanner.scan_ip(IP)

    ip_sources.profile.assert_awaited_once_with(IP)
    ip_sources.abuse.assert_awaited_once_with(IP, "test-key")
    ip_sources.tor.assert_called_once_with(IP)
    ip_sources.otx.assert_called_once_with(IP)
    ip_sources.host.assert_called_once_with(IP)
    assert result.info.abuse_score == 0
    assert result.info.proxy_unknown is False
    assert result.info.is_tor is False
    assert "CLEAN_IP" in _flag_codes(result)
    assert result.risk_level is RiskLevel.LOW
    card = format_ip_result(result)
    assert "Abuse Score: 0%" in card
    assert "Резиденциальный IP" in card


@pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="TW-05: successful OTX malware evidence is contradicted by CLEAN_IP",
)
async def test_otx_threat_evidence_excludes_clean_ip_flag(ip_sources):
    ip_sources.otx.return_value = {"pulse_count": 50, "malware_samples": 100}

    result = await ip_sources.scanner.scan_ip(IP)

    assert "OTX_MALWARE" in _flag_codes(result)
    assert "CLEAN_IP" not in _flag_codes(result)
