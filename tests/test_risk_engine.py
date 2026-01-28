# tests/test_risk_engine.py
"""Тесты для движка оценки рисков доменов."""
import pytest
from datetime import datetime, timedelta

from domain_scanner.risk_engine import (
    calculate_risk,
    _extract_base_domain,
    _is_official_domain,
    _detect_brand_impersonation,
)
from domain_scanner.models import WhoisInfo, DnsInfo, SslInfo, HttpInfo, IpProfile
from utils.risk_types import RiskLevel


class TestExtractBaseDomain:
    """Тесты функции _extract_base_domain."""

    def test_simple_domain(self):
        assert _extract_base_domain("example.com") == "example.com"

    def test_with_subdomain(self):
        assert _extract_base_domain("www.example.com") == "example.com"
        assert _extract_base_domain("sub.example.com") == "example.com"

    def test_deep_subdomain(self):
        assert _extract_base_domain("a.b.c.example.com") == "example.com"

    def test_wildcard(self):
        assert _extract_base_domain("*.example.com") == "example.com"

    def test_uppercase(self):
        assert _extract_base_domain("EXAMPLE.COM") == "example.com"


class TestIsOfficialDomain:
    """Тесты функции _is_official_domain."""

    def test_official_google(self):
        assert _is_official_domain("google.com") is True
        assert _is_official_domain("www.google.com") is True

    def test_official_facebook(self):
        assert _is_official_domain("facebook.com") is True

    def test_official_telegram(self):
        assert _is_official_domain("telegram.org") is True
        assert _is_official_domain("t.me") is True

    def test_fake_google(self):
        assert _is_official_domain("google-security.com") is False
        assert _is_official_domain("fakegoogle.com") is False

    def test_subdomain_of_official(self):
        assert _is_official_domain("mail.google.com") is True
        assert _is_official_domain("accounts.google.com") is True


class TestDetectBrandImpersonation:
    """Тесты функции _detect_brand_impersonation."""

    def test_official_domain_not_impersonation(self):
        """Официальный домен не должен определяться как имитация."""
        assert _detect_brand_impersonation("google.com") is None
        assert _detect_brand_impersonation("facebook.com") is None

    def test_fake_google(self):
        """Фейковый google должен определяться."""
        assert _detect_brand_impersonation("google-security.ru") == "google"
        # google-login.com может найти "google" или "login" — оба подозрительны
        result = _detect_brand_impersonation("google-login.com")
        assert result in ("google", "login")
        # gooogle.com — typosquatting, требует отдельной проверки на похожие написания

    def test_fake_facebook(self):
        """Фейковый facebook."""
        # facebook-login.ru может найти "facebook" или "login"
        result = _detect_brand_impersonation("facebook-login.ru")
        assert result in ("facebook", "login")
        # secure-facebook.com может найти "secure" или "facebook" — оба подозрительны
        result = _detect_brand_impersonation("secure-facebook.com")
        assert result is not None

    def test_suspicious_keywords(self):
        """Подозрительные ключевые слова."""
        # login-secure.com может найти login или secure
        result = _detect_brand_impersonation("login-secure.com")
        assert result is not None

    def test_banking_keywords(self):
        """Банковские ключевые слова."""
        # sberbank-online.ru содержит и "sber" и "sberbank"
        result = _detect_brand_impersonation("sberbank-online.ru")
        assert result in ("sber", "sberbank")
        assert _detect_brand_impersonation("tinkoff-pay.com") == "tinkoff"

    def test_no_impersonation(self):
        """Обычный домен без имитации."""
        assert _detect_brand_impersonation("mywebsite.com") is None
        assert _detect_brand_impersonation("example.org") is None


class TestCalculateRisk:
    """Тесты функции calculate_risk."""

    def test_new_domain_high_risk(self):
        """Очень новый домен должен иметь высокий риск."""
        whois = WhoisInfo(
            creation_date=datetime.utcnow() - timedelta(days=5),
            is_privacy_protected=True,
        )
        level, flags, score = calculate_risk(whois, None, None, None)

        assert level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
        assert any(f.code == "DOMAIN_VERY_NEW" for f in flags)

    def test_old_domain_low_risk(self):
        """Старый домен должен снижать риск."""
        whois = WhoisInfo(
            creation_date=datetime.utcnow() - timedelta(days=4000),  # ~11 лет
            is_privacy_protected=False,
        )
        level, flags, score = calculate_risk(whois, None, None, None)

        assert any(f.code == "DOMAIN_VERY_OLD" for f in flags)
        # Старый домен должен иметь низкий score
        assert score <= 3

    def test_whois_privacy_adds_risk(self):
        """Приватность WHOIS добавляет риск."""
        whois = WhoisInfo(
            creation_date=datetime.utcnow() - timedelta(days=365),
            is_privacy_protected=True,
        )
        level, flags, score = calculate_risk(whois, None, None, None)

        assert any(f.code == "WHOIS_PRIVACY" for f in flags)

    def test_no_mx_records(self):
        """Отсутствие MX записей."""
        dns = DnsInfo(
            a_records=["1.2.3.4"],
            mx_records=[],
            ns_records=["ns1.example.com"],
        )
        level, flags, score = calculate_risk(None, dns, None, None)

        assert any(f.code == "NO_MAIL_INFRA" for f in flags)

    def test_high_risk_country(self):
        """Хостинг в стране повышенного риска."""
        ip_profile = IpProfile(
            ip="1.2.3.4",
            country="Nigeria",
            country_code="NG",
        )
        level, flags, score = calculate_risk(None, None, None, None, [ip_profile])

        assert any(f.code == "HIGH_RISK_COUNTRY" for f in flags)

    def test_proxy_detected(self):
        """Обнаружение proxy."""
        ip_profile = IpProfile(
            ip="1.2.3.4",
            country="Netherlands",
            country_code="NL",
            proxy=True,
        )
        level, flags, score = calculate_risk(None, None, None, None, [ip_profile])

        assert any(f.code == "PROXY_DETECTED" for f in flags)

    def test_trusted_asn(self):
        """Доверенный ASN снижает риск."""
        ip_profile = IpProfile(
            ip="1.2.3.4",
            country="USA",
            country_code="US",
            asname="GOOGLE-CLOUD",
        )
        level, flags, score = calculate_risk(None, None, None, None, [ip_profile])

        assert any(f.code == "TRUSTED_ASN" for f in flags)

    def test_brand_impersonation_high_risk(self):
        """Имитация бренда должна давать высокий риск."""
        ssl = SslInfo(
            san_domains=["google-security.ru"],
            first_seen=datetime.utcnow() - timedelta(days=10),
        )
        level, flags, score = calculate_risk(None, None, ssl, None)

        assert any(f.code == "BRAND_IMPERSONATION" for f in flags)
        # Имитация бренда должна значительно повысить score
        assert score >= 4

    def test_official_brand_low_risk(self):
        """Официальный домен бренда снижает риск."""
        ssl = SslInfo(
            san_domains=["google.com", "www.google.com"],
            first_seen=datetime.utcnow() - timedelta(days=1000),
        )
        level, flags, score = calculate_risk(None, None, ssl, None)

        assert any(f.code == "OFFICIAL_BRAND_DOMAIN" for f in flags)

    def test_robots_disallow_all(self):
        """robots.txt с Disallow: /."""
        http = HttpInfo(
            url_checked="https://example.com",
            robots_exists=True,
            robots_disallow_all=True,
        )
        level, flags, score = calculate_risk(None, None, None, http)

        assert any(f.code == "MINIMAL_ROBOTS" for f in flags)
