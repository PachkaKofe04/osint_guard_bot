# tests/test_bin_scanner.py
"""Тесты для BIN сканера."""
import pytest
from bin_scanner.scanner import _normalize_bin
from bin_scanner.risk_engine import calculate_bin_risk
from bin_scanner.models import BinInfo
from utils.risk_types import RiskLevel


class TestNormalizeBin:
    """Тесты функции _normalize_bin."""

    def test_only_digits(self):
        """Только цифры."""
        assert _normalize_bin("123456") == "123456"

    def test_with_spaces(self):
        """С пробелами."""
        assert _normalize_bin("123 456") == "123456"
        assert _normalize_bin("12 34 56") == "123456"

    def test_with_dashes(self):
        """С дефисами."""
        assert _normalize_bin("123-456") == "123456"

    def test_mixed_format(self):
        """Смешанный формат."""
        assert _normalize_bin("12-34 56") == "123456"

    def test_eight_digits(self):
        """8-значный BIN."""
        assert _normalize_bin("12345678") == "12345678"

    def test_empty(self):
        """Пустой ввод."""
        assert _normalize_bin("") == ""

    def test_non_digit(self):
        """Ввод без цифр."""
        assert _normalize_bin("abc") == ""


class TestCalculateBinRisk:
    """Тесты функции calculate_bin_risk."""

    def test_bin_not_found_high_risk(self):
        """BIN не найден — высокий риск."""
        level, flags, score = calculate_bin_risk(None)

        assert any(f.code == "BIN_NOT_FOUND" for f in flags)
        assert score >= 4

    def test_prepaid_card_risk(self):
        """Предоплаченная карта."""
        info = BinInfo(
            raw_input="123456",
            bin="123456",
            scheme="visa",
            card_type="debit",
            prepaid=True,
            is_trusted=False,
        )
        level, flags, score = calculate_bin_risk(info)

        assert any(f.code == "BIN_PREPAID" for f in flags)

    def test_trusted_bank_low_risk(self):
        """Доверенный банк снижает риск."""
        info = BinInfo(
            raw_input="123456",
            bin="123456",
            scheme="visa",
            card_type="debit",
            bank_name="Sberbank",
            country_name="Russia",
            country_code="RU",
            prepaid=False,
            is_trusted=True,
        )
        level, flags, score = calculate_bin_risk(info)

        assert any(f.code == "BIN_TRUSTED_BANK" for f in flags)

    def test_unknown_bank_adds_risk(self):
        """Неизвестный банк добавляет риск."""
        info = BinInfo(
            raw_input="123456",
            bin="123456",
            scheme="visa",
            card_type="credit",
            bank_name=None,
            country_name="Unknown",
            country_code=None,
            prepaid=False,
            is_trusted=False,
        )
        level, flags, score = calculate_bin_risk(info)

        assert any(f.code == "BIN_BANK_UNKNOWN" for f in flags)

    def test_normal_card_low_risk(self):
        """Обычная карта известного банка — низкий риск."""
        info = BinInfo(
            raw_input="427600",
            bin="427600",
            scheme="visa",
            brand="Visa",
            card_type="credit",
            bank_name="Chase Bank",
            country_name="United States",
            country_code="US",
            prepaid=False,
            is_trusted=True,
        )
        level, flags, score = calculate_bin_risk(info)

        assert level == RiskLevel.LOW
        assert score <= 3
