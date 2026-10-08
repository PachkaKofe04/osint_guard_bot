"""Подтвержденная угроза, косвенный признак и неполная проверка имеют разный смысл."""
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from domain_scanner.formatter import format_summary
from domain_scanner.models import DnsInfo, DomainScanResult, IpProfile, SslInfo, WhoisInfo
from domain_scanner.risk_engine import calculate_risk
from ip_scanner.formatter import format_ip_result
from ip_scanner.models import IpInfo, IpScanResult, OtxInfo
from ip_scanner.risk_engine import calculate_ip_risk
from utils.risk_scoring import calculate_risk_score
from utils.risk_types import RiskFlag, RiskLevel, ThreatVerdict
from utils.threat_flags import add_threat_flags
from wallet_scanner.models import WalletInfo
from wallet_scanner.risk_engine import calculate_wallet_risk
from url_scanner.models import UrlInfo
from url_scanner.risk_engine import calculate_url_risk


@pytest.mark.parametrize("code", ["KNOWN_THREAT", "KNOWN_SCAM_ADDRESS"])
@pytest.mark.parametrize("trust_weight", [-1, -9, -30])
def test_confirmed_threat_has_priority_over_trust(code, trust_weight):
    flags = [
        RiskFlag(code=code, level=RiskLevel.HIGH, message="Подтвержденная угроза", weight=10),
        RiskFlag(code="TRUSTED_PROVIDER", level=RiskLevel.LOW, message="Доверенный провайдер", weight=trust_weight),
    ]
    result = calculate_risk_score(flags)

    assert result.score == 10
    assert result.level is RiskLevel.HIGH
    assert any(flag.code == code for flag in result.flags)


@pytest.mark.parametrize("code", ["KNOWN_THREAT", "KNOWN_SCAM_ADDRESS"])
def test_confirmed_threat_without_trust_is_maximum(code):
    result = calculate_risk_score([
        RiskFlag(code=code, level=RiskLevel.HIGH, message="Подтвержденная угроза", weight=10)
    ])
    assert result.score == 10
    assert result.level is RiskLevel.HIGH


def test_heuristic_high_flag_is_not_a_confirmed_threat():
    result = calculate_risk_score([
        RiskFlag(code="BRAND_IMPERSONATION", level=RiskLevel.HIGH, message="Косвенный признак", weight=4),
        RiskFlag(code="TRUSTED_PROVIDER", level=RiskLevel.LOW, message="Доверие", weight=-3),
    ])
    assert result.score == 1
    assert result.level is RiskLevel.LOW


@pytest.mark.parametrize("checked,found,expected_code", [
    (True, True, "KNOWN_THREAT"),
    (True, False, "NOT_IN_THREAT_DB"),
    (False, False, "THREAT_DB_UNAVAILABLE"),
])
def test_source_outcomes_remain_distinguishable(checked, found, expected_code):
    flags = []
    add_threat_flags(flags, ThreatVerdict(checked=checked, found=found, sources=["Источник"]))
    assert [flag.code for flag in flags] == [expected_code]
    if not checked:
        assert flags[0].weight == 0
        assert not any(flag.weight < 0 for flag in flags)
        assert "не выполнялась" in flags[0].message


def test_unknown_check_does_not_reduce_an_observed_risk():
    flags = [RiskFlag(code="HEURISTIC", level=RiskLevel.MEDIUM, message="Признак", weight=5)]
    add_threat_flags(flags, ThreatVerdict(checked=False))
    assert calculate_risk_score(flags).score == 5
    assert not any(flag.code == "NOT_IN_THREAT_DB" for flag in flags)


def test_old_trusted_domain_with_phishing_hit_is_high_risk():
    threat = ThreatVerdict(checked=True, found=True, sources=["Источник"], threat_type="phishing")
    level, flags, score = calculate_risk(
        WhoisInfo(creation_date=datetime(2000, 1, 1, tzinfo=timezone.utc)),
        DnsInfo(mx_records=["mail.example.test"]),
        SslInfo(san_domains=[f"host{i}.example.test" for i in range(5)], history_complete=False),
        None,
        [IpProfile(ip="1.1.1.1", asname="Cloudflare")],
        threats=threat,
    )
    assert score == 10
    assert level is RiskLevel.HIGH
    report = format_summary(DomainScanResult(
        domain="example.test", normalized_domain="example.test", risk_level=level,
        score=score, flags=flags, threats=threat, scanned_at=datetime.now(timezone.utc),
    ))
    assert "Явных признаков недобросовестности не обнаружено" not in report


def test_confirmed_wallet_scam_is_maximum_even_with_exchange_trust():
    info = WalletInfo(
        address="0x1111111111111111111111111111111111111111",
        currency="ETH", is_valid=True, is_scam=True, scam_check_performed=True,
        scam_labels=["phishing"], exchange_name="Example exchange", balance=Decimal("1"), tx_count=1000,
    )
    level, flags, score = calculate_wallet_risk(info)
    assert score == 10
    assert level is RiskLevel.HIGH
    assert any(flag.code == "KNOWN_SCAM_ADDRESS" for flag in flags)


def test_confirmed_wallet_scam_with_activity_is_maximum():
    level, _, score = calculate_wallet_risk(WalletInfo(
        address="0x1111111111111111111111111111111111111111",
        currency="ETH", is_valid=True, is_scam=True, scam_check_performed=True,
        balance=Decimal("1"), tx_count=1000,
    ))
    assert score == 10
    assert level is RiskLevel.HIGH


@pytest.mark.parametrize("code", ["KNOWN_THREAT", "KNOWN_SCAM_ADDRESS"])
@pytest.mark.parametrize("reverse", [False, True], ids=["threat-first", "threat-last"])
def test_confirmed_threat_preserves_all_evidence_with_multiple_trust_flags(code, reverse):
    flags = [
        RiskFlag(code=code, level=RiskLevel.HIGH, message="Источник подтвердил угрозу", weight=10),
        RiskFlag(code="OLD_OBJECT", level=RiskLevel.LOW, message="Возраст", weight=-4),
        RiskFlag(code="TRUSTED_PROVIDER", level=RiskLevel.LOW, message="Провайдер", weight=-3),
        RiskFlag(code="ESTABLISHED_HISTORY", level=RiskLevel.LOW, message="История", weight=-30),
    ]
    if reverse:
        flags.reverse()
    before = [flag.model_dump() for flag in flags]

    result = calculate_risk_score(flags, confidence=42)

    assert result.score == 10
    assert result.level is RiskLevel.HIGH
    assert result.emoji == "🔴"
    assert result.confidence == 42
    assert [flag.model_dump() for flag in result.flags] == before
    assert [flag.model_dump() for flag in flags] == before


def test_ip_feed_hit_stays_maximum_with_trusted_provider_and_clean_other_sources():
    threat = ThreatVerdict(
        checked=True, found=True, sources=["Example feed"], threat_type="botnet_c2",
    )
    info = IpInfo(
        ip="8.8.4.4", asname="Google", country="United States", city="New York",
        abuse_score=0, proxy_unknown=False, connection_unknown=False, tor_unknown=False,
        threats=threat,
    )
    otx = OtxInfo(pulse_count=0, malware_samples=0)

    level, flags, score = calculate_ip_risk(info, otx)

    assert score == 10
    assert level is RiskLevel.HIGH
    assert "TRUSTED_PROVIDER" in {flag.code for flag in flags}
    assert "KNOWN_THREAT" in {flag.code for flag in flags}
    assert "CLEAN_IP" not in {flag.code for flag in flags}
    card = format_ip_result(IpScanResult(
        ip=info.ip, info=info, otx=otx, risk_level=level, flags=flags,
        score=score, scanned_at=datetime.now(timezone.utc),
    ))
    assert "10/10" in card
    assert "Example feed" in card
    assert "управляющий сервер ботнета" in card


def test_url_feed_hit_stays_maximum_with_clean_virustotal():
    info = UrlInfo(
        original_url="https://example.test/a", final_url="https://example.test/a",
        vt_total=70,
        threats=ThreatVerdict(checked=True, found=True, sources=["Example feed"]),
    )

    level, flags, score = calculate_url_risk(info)

    assert score == 10
    assert level is RiskLevel.HIGH
    assert any(flag.code == "VT_CLEAN" and flag.weight < 0 for flag in flags)
    assert "KNOWN_THREAT" in {flag.code for flag in flags}
