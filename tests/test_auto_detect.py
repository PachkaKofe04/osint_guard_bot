# tests/test_auto_detect.py
"""Тесты для Auto-detect."""
import pytest
from handlers.auto_detect import detect_input_type


class TestDetectInputType:
    """Тесты функции detect_input_type."""

    # URLs
    def test_url_with_https(self):
        """URL с https."""
        input_type, value = detect_input_type("https://example.com")
        assert input_type == "url"

    def test_url_with_http(self):
        """URL с http."""
        input_type, value = detect_input_type("http://example.com/path")
        assert input_type == "url"

    def test_url_with_path(self):
        """URL с путём."""
        input_type, value = detect_input_type("https://example.com/path/to/page")
        assert input_type == "url"

    # Emails
    def test_email_simple(self):
        """Простой email."""
        input_type, value = detect_input_type("user@example.com")
        assert input_type == "email"

    def test_email_with_dots(self):
        """Email с точками."""
        input_type, value = detect_input_type("john.doe@gmail.com")
        assert input_type == "email"

    # IPs
    def test_ipv4(self):
        """IPv4 адрес."""
        input_type, value = detect_input_type("8.8.8.8")
        assert input_type == "ip"

    def test_ipv6(self):
        """IPv6 адрес."""
        input_type, value = detect_input_type("2001:4860:4860::8888")
        assert input_type == "ip"

    # Wallets
    def test_btc_wallet(self):
        """Bitcoin кошелёк."""
        input_type, value = detect_input_type("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert input_type == "wallet"

    def test_eth_wallet(self):
        """Ethereum кошелёк."""
        input_type, value = detect_input_type("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        assert input_type == "wallet"

    # Domains
    def test_domain_simple(self):
        """Простой домен."""
        input_type, value = detect_input_type("example.com")
        assert input_type == "domain"

    def test_domain_subdomain(self):
        """Домен с поддоменом."""
        input_type, value = detect_input_type("www.example.com")
        assert input_type == "domain"

    # Usernames
    def test_username_with_at(self):
        """Username с @."""
        input_type, value = detect_input_type("@john_doe")
        assert input_type == "username"
        assert value == "john_doe"  # @ удалён

    def test_username_simple(self):
        """Простой username."""
        input_type, value = detect_input_type("john_doe_123")
        assert input_type == "username"

    # Unknown
    def test_unknown_short(self):
        """Слишком короткий текст."""
        input_type, value = detect_input_type("ab")
        assert input_type == "unknown"

    def test_unknown_random(self):
        """Случайный текст."""
        input_type, value = detect_input_type("hello world how are you")
        assert input_type == "unknown"

    # Edge cases
    def test_preserves_original_value(self):
        """Сохраняет оригинальное значение."""
        input_type, value = detect_input_type("  https://example.com  ")
        assert input_type == "url"
        assert value == "https://example.com"
