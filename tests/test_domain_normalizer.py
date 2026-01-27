# tests/test_domain_normalizer.py
"""Тесты для нормализации доменов."""
import pytest
from utils.domain_normalizer import normalize_domain


class TestNormalizeDomain:
    """Тесты функции normalize_domain."""

    def test_simple_domain(self):
        """Простой домен без изменений."""
        assert normalize_domain("example.com") == "example.com"

    def test_domain_with_www(self):
        """Удаление www."""
        assert normalize_domain("www.example.com") == "example.com"

    def test_domain_with_https(self):
        """Извлечение домена из URL."""
        assert normalize_domain("https://example.com") == "example.com"
        assert normalize_domain("https://example.com/path") == "example.com"

    def test_domain_with_http(self):
        """HTTP URL."""
        assert normalize_domain("http://example.com") == "example.com"

    def test_domain_with_port(self):
        """URL с портом."""
        assert normalize_domain("https://example.com:8080/path") == "example.com"

    def test_domain_with_www_and_https(self):
        """URL с www и https."""
        assert normalize_domain("https://www.example.com") == "example.com"

    def test_subdomain(self):
        """Поддомен должен сохраняться."""
        assert normalize_domain("sub.example.com") == "sub.example.com"

    def test_uppercase_to_lowercase(self):
        """Приведение к нижнему регистру."""
        assert normalize_domain("EXAMPLE.COM") == "example.com"
        assert normalize_domain("ExAmPlE.CoM") == "example.com"

    def test_trailing_slash(self):
        """Удаление trailing slash."""
        assert normalize_domain("example.com/") == "example.com"

    def test_cyrillic_domain(self):
        """Кириллический домен (IDN)."""
        result = normalize_domain("пример.рф")
        assert result is not None
        # IDN должен быть преобразован в punycode
        assert "xn--" in result or result == "пример.рф"

    def test_invalid_domain(self):
        """Невалидный домен."""
        assert normalize_domain("not a domain") is None
        assert normalize_domain("") is None
        assert normalize_domain("   ") is None

    def test_ip_address(self):
        """IP-адрес вместо домена."""
        # Зависит от реализации — может быть валидным или нет
        result = normalize_domain("192.168.1.1")
        # Тест на то, что функция не падает
        assert result is None or isinstance(result, str)

    def test_domain_with_user_pass(self):
        """URL с user:pass@."""
        result = normalize_domain("https://user:pass@example.com/path")
        assert result == "example.com"
