# tests/test_url_scanner.py
"""Тесты для URL сканера."""
import pytest
from url_scanner.expander import is_shortened_url
from url_scanner.risk_engine import calculate_url_risk, analyze_url_structure
from url_scanner.scanner import normalize_url
from url_scanner.models import UrlInfo
from utils.risk_types import RiskLevel


class TestNormalizeUrl:
    """Тесты функции normalize_url."""

    def test_adds_https(self):
        """Добавляет https если нет схемы."""
        assert normalize_url("example.com") == "https://example.com"

    def test_keeps_http(self):
        """Сохраняет http если указан."""
        assert normalize_url("http://example.com") == "http://example.com"

    def test_keeps_https(self):
        """Сохраняет https."""
        assert normalize_url("https://example.com") == "https://example.com"

    def test_strips_whitespace(self):
        """Удаляет пробелы."""
        assert normalize_url("  example.com  ") == "https://example.com"


class TestIsShortenedUrl:
    """Тесты функции is_shortened_url."""

    def test_bitly(self):
        """Определяет bit.ly."""
        is_short, service = is_shortened_url("https://bit.ly/abc123")
        assert is_short is True
        assert service == "bit.ly"

    def test_tinyurl(self):
        """Определяет tinyurl."""
        is_short, service = is_shortened_url("https://tinyurl.com/xyz")
        assert is_short is True
        assert service == "tinyurl.com"

    def test_youtube_short(self):
        """Определяет youtu.be."""
        is_short, service = is_shortened_url("https://youtu.be/dQw4w9WgXcQ")
        assert is_short is True
        assert service == "youtu.be"

    def test_telegram(self):
        """Определяет t.me."""
        is_short, service = is_shortened_url("https://t.me/username")
        assert is_short is True
        assert service == "t.me"

    def test_vk_short(self):
        """Определяет vk.cc."""
        is_short, service = is_shortened_url("https://vk.cc/abc")
        assert is_short is True
        assert service == "vk.cc"

    def test_normal_url(self):
        """Обычный URL не определяется как сокращённый."""
        is_short, service = is_shortened_url("https://example.com/page")
        assert is_short is False
        assert service == ""


class TestAnalyzeUrlStructure:
    """Тесты функции analyze_url_structure."""

    def test_ip_in_url(self):
        """Определяет IP в URL."""
        result = analyze_url_structure("http://192.168.1.1/login")
        assert result["has_ip_address"] is True

    def test_suspicious_tld(self):
        """Определяет подозрительный TLD."""
        result = analyze_url_structure("https://example.tk/page")
        assert result["has_suspicious_tld"] is True

    def test_many_subdomains(self):
        """Определяет много поддоменов."""
        result = analyze_url_structure("https://a.b.c.d.e.example.com/page")
        assert result["has_many_subdomains"] is True

    def test_normal_url(self):
        """Обычный URL не имеет подозрительных признаков."""
        result = analyze_url_structure("https://example.com/page")
        assert result["has_ip_address"] is False
        assert result["has_suspicious_tld"] is False
        assert result["has_many_subdomains"] is False


class TestCalculateUrlRisk:
    """Тесты функции calculate_url_risk."""

    def test_none_info(self):
        """Если info=None — средний риск."""
        level, flags, score = calculate_url_risk(None)
        assert any(f.code == "URL_UNREACHABLE" for f in flags)

    def test_ip_in_url_high_risk(self):
        """IP в URL — высокий риск."""
        info = UrlInfo(
            original_url="http://192.168.1.1/login",
            final_url="http://192.168.1.1/login",
            has_ip_address=True,
        )
        level, flags, score = calculate_url_risk(info)
        assert any(f.code == "IP_IN_URL" for f in flags)
        assert score >= 3

    def test_shortened_url_low_risk(self):
        """Сокращённая ссылка — небольшой риск."""
        info = UrlInfo(
            original_url="https://bit.ly/abc",
            final_url="https://example.com",
            is_shortened=True,
            shortener_service="bit.ly",
        )
        level, flags, score = calculate_url_risk(info)
        assert any(f.code == "SHORTENED_URL" for f in flags)

    def test_many_redirects(self):
        """Много редиректов — средний риск."""
        info = UrlInfo(
            original_url="https://bit.ly/abc",
            final_url="https://example.com",
            redirect_count=5,
            redirect_chain=["a", "b", "c", "d", "e"],
        )
        level, flags, score = calculate_url_risk(info)
        assert any(f.code == "MANY_REDIRECTS" for f in flags)

    def test_vt_malicious_high_risk(self):
        """VirusTotal malicious — высокий риск."""
        info = UrlInfo(
            original_url="https://malicious.com",
            final_url="https://malicious.com",
            vt_malicious=5,
            vt_total=70,
        )
        level, flags, score = calculate_url_risk(info)
        assert any(f.code == "VT_MALICIOUS" for f in flags)
        assert score >= 5

    def test_clean_url(self):
        """Чистый URL — низкий риск."""
        info = UrlInfo(
            original_url="https://google.com",
            final_url="https://google.com",
            vt_malicious=0,
            vt_suspicious=0,
            vt_total=70,
        )
        level, flags, score = calculate_url_risk(info)
        assert any(f.code == "VT_CLEAN" for f in flags)

    def test_no_https(self):
        """HTTP вместо HTTPS."""
        info = UrlInfo(
            original_url="http://example.com",
            final_url="http://example.com",
        )
        level, flags, score = calculate_url_risk(info)
        assert any(f.code == "NO_HTTPS" for f in flags)

    def test_url_obfuscation(self):
        """URL с @ (обфускация)."""
        info = UrlInfo(
            original_url="https://google.com@evil.com/path",
            final_url="https://google.com@evil.com/path",
        )
        level, flags, score = calculate_url_risk(info)
        assert any(f.code == "URL_OBFUSCATION" for f in flags)
