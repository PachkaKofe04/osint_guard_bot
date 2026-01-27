# tests/test_phone_scanner.py
"""Тесты для сканера телефонов."""
import pytest
from phone_scanner.scanner import normalize_phone


class TestNormalizePhone:
    """Тесты функции normalize_phone."""

    def test_russian_8_format(self):
        """Российский номер с 8."""
        assert normalize_phone("89995852048") == "79995852048"

    def test_russian_7_format(self):
        """Российский номер с 7."""
        assert normalize_phone("79995852048") == "79995852048"

    def test_russian_plus7_format(self):
        """Российский номер с +7."""
        assert normalize_phone("+79995852048") == "79995852048"

    def test_formatted_russian(self):
        """Форматированный российский номер."""
        assert normalize_phone("8(999)585-20-48") == "79995852048"
        assert normalize_phone("+7 999 585 20 48") == "79995852048"
        assert normalize_phone("8 (999) 585-20-48") == "79995852048"

    def test_ten_digit_russian(self):
        """10-значный номер без кода страны."""
        assert normalize_phone("9995852048") == "79995852048"

    def test_international_us(self):
        """Американский номер."""
        assert normalize_phone("+14152007986") == "14152007986"
        assert normalize_phone("14152007986") == "14152007986"

    def test_strips_special_chars(self):
        """Удаление специальных символов."""
        assert normalize_phone("+7-999-585-20-48") == "79995852048"
        assert normalize_phone("(999) 585 20 48") == "79995852048"

    def test_only_digits_result(self):
        """Результат содержит только цифры."""
        result = normalize_phone("+7 (999) 585-20-48")
        assert result.isdigit()

    def test_empty_input(self):
        """Пустой ввод."""
        assert normalize_phone("") == ""

    def test_non_digit_input(self):
        """Ввод без цифр."""
        assert normalize_phone("abc") == ""

    def test_short_number(self):
        """Короткий номер."""
        result = normalize_phone("12345")
        assert result == "12345"

    def test_preserves_leading_country_codes(self):
        """Сохранение кодов стран."""
        # UK
        assert normalize_phone("+447911123456") == "447911123456"
        # Germany
        assert normalize_phone("+4915123456789") == "4915123456789"
