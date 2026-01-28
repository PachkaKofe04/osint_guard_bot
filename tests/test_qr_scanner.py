# tests/test_qr_scanner.py
"""Тесты для QR сканера."""
import pytest
from qr_scanner.risk_engine import calculate_qr_risk
from qr_scanner.models import QrInfo, QrContentType, WifiInfo
from qr_scanner.scanner import (
    _detect_content_type, _parse_wifi, _parse_geo,
    _parse_crypto, _analyze_url
)
from utils.risk_types import RiskLevel


class TestDetectContentType:
    """Тесты определения типа контента."""

    def test_url_http(self):
        assert _detect_content_type("http://example.com") == QrContentType.URL

    def test_url_https(self):
        assert _detect_content_type("https://example.com") == QrContentType.URL

    def test_url_www(self):
        assert _detect_content_type("www.example.com") == QrContentType.URL

    def test_email_mailto(self):
        assert _detect_content_type("mailto:test@example.com") == QrContentType.EMAIL

    def test_email_plain(self):
        assert _detect_content_type("test@example.com") == QrContentType.EMAIL

    def test_phone_tel(self):
        assert _detect_content_type("tel:+79001234567") == QrContentType.PHONE

    def test_sms(self):
        assert _detect_content_type("sms:+79001234567") == QrContentType.SMS

    def test_wifi(self):
        assert _detect_content_type("WIFI:T:WPA;S:MyNetwork;P:password;;") == QrContentType.WIFI

    def test_vcard(self):
        assert _detect_content_type("BEGIN:VCARD\nVERSION:3.0") == QrContentType.VCARD

    def test_geo(self):
        assert _detect_content_type("geo:55.7558,37.6173") == QrContentType.GEO

    def test_bitcoin(self):
        assert _detect_content_type("bitcoin:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") == QrContentType.CRYPTO

    def test_bitcoin_address_only(self):
        assert _detect_content_type("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") == QrContentType.CRYPTO

    def test_ethereum_address(self):
        assert _detect_content_type("0x742d35Cc6634C0532925a3b844Bc9e7595f8fE01") == QrContentType.CRYPTO

    def test_text(self):
        assert _detect_content_type("Hello World") == QrContentType.TEXT


class TestParseWifi:
    """Тесты парсинга WiFi."""

    def test_parse_wifi_full(self):
        wifi = _parse_wifi("WIFI:T:WPA;S:MyNetwork;P:MyPassword;H:true;;")
        assert wifi.ssid == "MyNetwork"
        assert wifi.password == "MyPassword"
        assert wifi.security == "WPA"
        assert wifi.hidden is True

    def test_parse_wifi_open(self):
        wifi = _parse_wifi("WIFI:T:nopass;S:OpenNetwork;;")
        assert wifi.ssid == "OpenNetwork"
        assert wifi.security == "nopass"
        assert wifi.password is None

    def test_parse_wifi_minimal(self):
        wifi = _parse_wifi("WIFI:S:Network;;")
        assert wifi.ssid == "Network"


class TestParseGeo:
    """Тесты парсинга координат."""

    def test_parse_geo(self):
        lat, lon = _parse_geo("geo:55.7558,37.6173")
        assert lat == pytest.approx(55.7558)
        assert lon == pytest.approx(37.6173)

    def test_parse_geo_negative(self):
        lat, lon = _parse_geo("geo:-33.8688,151.2093")
        assert lat == pytest.approx(-33.8688)
        assert lon == pytest.approx(151.2093)

    def test_parse_geo_invalid(self):
        lat, lon = _parse_geo("invalid")
        assert lat is None
        assert lon is None


class TestParseCrypto:
    """Тесты парсинга крипто-адресов."""

    def test_bitcoin_with_amount(self):
        addr, amount = _parse_crypto("bitcoin:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2?amount=0.5")
        assert addr == "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        assert amount == "0.5"

    def test_bitcoin_without_amount(self):
        addr, amount = _parse_crypto("bitcoin:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        assert addr == "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        assert amount is None

    def test_address_only(self):
        addr, amount = _parse_crypto("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        assert addr == "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"


class TestAnalyzeUrl:
    """Тесты анализа URL."""

    def test_normal_url(self):
        result = _analyze_url("https://google.com")
        assert result["domain"] == "google.com"
        assert result["is_shortened"] is False
        assert result["looks_phishy"] is False

    def test_shortened_url(self):
        result = _analyze_url("https://bit.ly/abc123")
        assert result["is_shortened"] is True

    def test_suspicious_tld(self):
        result = _analyze_url("https://login.tk")
        assert result["has_suspicious_tld"] is True

    def test_phishing_ip(self):
        result = _analyze_url("http://192.168.1.1/login")
        assert result["looks_phishy"] is True

    def test_many_subdomains(self):
        result = _analyze_url("https://a.b.c.d.e.example.com")
        assert result["looks_phishy"] is True


class TestCalculateQrRisk:
    """Тесты функции calculate_qr_risk."""

    def test_library_error(self):
        level, flags, score = calculate_qr_risk(None, library_error=True)
        assert any(f.code == "QR_LIBRARY_ERROR" for f in flags)

    def test_no_qr_found(self):
        level, flags, score = calculate_qr_risk(None, no_qr_found=True)
        assert any(f.code == "NO_QR_FOUND" for f in flags)
        assert level == RiskLevel.LOW

    def test_safe_url(self):
        info = QrInfo(
            raw_data="https://google.com",
            content_type=QrContentType.URL,
            url="https://google.com",
            url_domain="google.com",
        )
        level, flags, score = calculate_qr_risk(info)
        assert any(f.code == "URL_CONTENT" for f in flags)

    def test_phishing_url(self):
        info = QrInfo(
            raw_data="http://192.168.1.1/login",
            content_type=QrContentType.URL,
            url="http://192.168.1.1/login",
            url_looks_phishy=True,
        )
        level, flags, score = calculate_qr_risk(info)
        assert any(f.code == "PHISHING_URL" for f in flags)
        assert score >= 5

    def test_shortened_url(self):
        info = QrInfo(
            raw_data="https://bit.ly/abc",
            content_type=QrContentType.URL,
            url="https://bit.ly/abc",
            url_is_shortened=True,
        )
        level, flags, score = calculate_qr_risk(info)
        assert any(f.code == "SHORTENED_URL" for f in flags)

    def test_wifi_with_password(self):
        info = QrInfo(
            raw_data="WIFI:T:WPA;S:Net;P:pass;;",
            content_type=QrContentType.WIFI,
            wifi=WifiInfo(ssid="Net", password="pass", security="WPA"),
        )
        level, flags, score = calculate_qr_risk(info)
        assert any(f.code == "WIFI_PASSWORD" for f in flags)

    def test_crypto_with_amount(self):
        info = QrInfo(
            raw_data="bitcoin:1Abc...?amount=1.5",
            content_type=QrContentType.CRYPTO,
            crypto_address="1AbcXYZ123456789",
            crypto_amount="1.5",
        )
        level, flags, score = calculate_qr_risk(info)
        assert any(f.code == "CRYPTO_AMOUNT" for f in flags)

    def test_email_content(self):
        info = QrInfo(
            raw_data="mailto:test@example.com",
            content_type=QrContentType.EMAIL,
            email="test@example.com",
        )
        level, flags, score = calculate_qr_risk(info)
        assert any(f.code == "EMAIL_CONTENT" for f in flags)

    def test_text_content(self):
        info = QrInfo(
            raw_data="Hello World",
            content_type=QrContentType.TEXT,
            data_length=11,
        )
        level, flags, score = calculate_qr_risk(info)
        assert any(f.code == "TEXT_CONTENT" for f in flags)
        assert level == RiskLevel.LOW
