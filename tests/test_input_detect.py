# tests/test_input_detect.py
"""Тесты определения типа пользовательского ввода."""
import pytest

from utils.input_detect import SCANNABLE_TYPES, detect_input_type, triggers_scan


class TestPhoneDetection:
    """Ветки телефона раньше не было вообще - /phone был недостижим без команды."""

    @pytest.mark.parametrize("value", [
        "+79991234567",
        "89991234567",
        "9991234567",
        "8(999)585-20-48",
        "+7 999 585 20 48",
        "+1-202-555-0143",
    ])
    def test_phone_detected(self, value):
        assert detect_input_type(value)[0] == "phone"

    def test_phone_not_confused_with_ip(self):
        """8.8.8.8 - это IP, а не номер."""
        assert detect_input_type("8.8.8.8")[0] == "ip"


class TestBinDetection:
    @pytest.mark.parametrize("value", ["427229", "45717360", "1234567"])
    def test_bin_detected(self, value):
        assert detect_input_type(value)[0] == "bin"

    def test_nine_digits_is_not_bin_or_phone(self):
        """9 цифр: для BIN много, для телефона мало."""
        assert detect_input_type("123456789")[0] == "unknown"


class TestCommonWords:
    """Раньше любое латинское слово запускало 20 HTTP-запросов по платформам."""

    @pytest.mark.parametrize("word", [
        "help", "menu", "start", "test", "admin", "password",
        "localhost", "settings", "cancel", "readme",
    ])
    def test_common_word_is_not_scanned(self, word):
        assert detect_input_type(word)[0] == "unknown"

    def test_case_insensitive(self):
        assert detect_input_type("HELP")[0] == "unknown"
        assert detect_input_type("Admin")[0] == "unknown"

    def test_plain_word_is_ambiguous_not_scanned(self):
        """Незнакомое слово не сканируем молча - переспрашиваем кнопками."""
        assert detect_input_type("torvalds")[0] == "ambiguous"

    def test_word_with_digits_is_username(self):
        assert detect_input_type("john_doe_123")[0] == "username"

    def test_explicit_at_is_username(self):
        input_type, value = detect_input_type("@johndoe")
        assert input_type == "username"
        assert value == "johndoe"


class TestFilenames:
    """Имена файлов уезжали в полный скан домена с WHOIS и DNS."""

    @pytest.mark.parametrize("value", [
        "readme.md", "script.js", "file.txt", "config.yml",
        "photo.jpg", "data.json", "styles.css", "app.exe",
    ])
    def test_filename_is_not_domain(self, value):
        assert detect_input_type(value)[0] != "domain"

    @pytest.mark.parametrize("value", ["google.com", "example.org", "mail.ru", "sub.example.co.uk"])
    def test_real_domain_still_detected(self, value):
        assert detect_input_type(value)[0] == "domain"


class TestBasicTypes:
    @pytest.mark.parametrize("value,expected", [
        ("https://example.com", "url"),
        ("http://example.com/path", "url"),
        ("user@example.com", "email"),
        ("8.8.8.8", "ip"),
        ("2001:4860:4860::8888", "ip"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "wallet"),
        ("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "wallet"),
        ("hello world how are you", "unknown"),
        ("ab", "unknown"),
        ("привет", "unknown"),
        ("", "unknown"),
    ])
    def test_type(self, value, expected):
        assert detect_input_type(value)[0] == expected

    def test_whitespace_stripped(self):
        input_type, value = detect_input_type("  https://example.com  ")
        assert input_type == "url"
        assert value == "https://example.com"


class TestTriggersScan:
    """Используется rate limiter'ом: тратить квоту только на реальные сканы."""

    @pytest.mark.parametrize("value", [
        "google.com", "user@mail.ru", "8.8.8.8", "+79991234567", "427229",
    ])
    def test_scannable_input(self, value):
        assert triggers_scan(value) is True

    @pytest.mark.parametrize("value", [
        "привет", "help", "как дела", "torvalds", "",
    ])
    def test_non_scannable_input(self, value):
        assert triggers_scan(value) is False

    def test_ambiguous_does_not_consume_quota(self):
        """ambiguous только переспрашивает кнопкой - внешних запросов нет."""
        assert "ambiguous" not in SCANNABLE_TYPES
