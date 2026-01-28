# tests/test_wallet_scanner.py
"""Тесты для Crypto Wallet сканера."""
import pytest
from decimal import Decimal
from wallet_scanner.validators import (
    detect_currency, validate_address,
    validate_btc_address, validate_eth_address
)
from wallet_scanner.risk_engine import calculate_wallet_risk
from wallet_scanner.models import WalletInfo
from utils.risk_types import RiskLevel


class TestDetectCurrency:
    """Тесты функции detect_currency."""

    def test_btc_legacy_1(self):
        """Bitcoin legacy адрес (1...)."""
        assert detect_currency("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "BTC"

    def test_btc_legacy_3(self):
        """Bitcoin legacy адрес (3...)."""
        assert detect_currency("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") == "BTC"

    def test_btc_bech32(self):
        """Bitcoin bech32 адрес (bc1...)."""
        assert detect_currency("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh") == "BTC"

    def test_eth(self):
        """Ethereum адрес."""
        assert detect_currency("0x742d35Cc6634C0532925a3b844Bc454e4438f44e") == "ETH"

    def test_eth_lowercase(self):
        """Ethereum адрес в нижнем регистре."""
        assert detect_currency("0x742d35cc6634c0532925a3b844bc454e4438f44e") == "ETH"

    def test_ltc_legacy(self):
        """Litecoin legacy адрес."""
        assert detect_currency("LcHK6M7QZvjYi1E11PiSrkfEguFPkBJ3WQ") == "LTC"

    def test_trx(self):
        """TRON адрес."""
        assert detect_currency("TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW") == "TRX"

    def test_xrp(self):
        """Ripple адрес."""
        assert detect_currency("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh") == "XRP"

    def test_invalid(self):
        """Невалидный адрес."""
        assert detect_currency("invalid_address") is None

    def test_empty(self):
        """Пустой адрес."""
        assert detect_currency("") is None


class TestValidateBtcAddress:
    """Тесты функции validate_btc_address."""

    def test_valid_legacy(self):
        """Валидный legacy адрес."""
        assert validate_btc_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") is True

    def test_valid_bech32(self):
        """Валидный bech32 адрес."""
        assert validate_btc_address("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh") is True

    def test_invalid(self):
        """Невалидный адрес."""
        assert validate_btc_address("invalid") is False

    def test_eth_not_btc(self):
        """Ethereum адрес не валидный как BTC."""
        assert validate_btc_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e") is False


class TestValidateEthAddress:
    """Тесты функции validate_eth_address."""

    def test_valid(self):
        """Валидный адрес."""
        assert validate_eth_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e") is True

    def test_valid_lowercase(self):
        """Валидный адрес в нижнем регистре."""
        assert validate_eth_address("0x742d35cc6634c0532925a3b844bc454e4438f44e") is True

    def test_invalid_no_prefix(self):
        """Нет префикса 0x."""
        assert validate_eth_address("742d35Cc6634C0532925a3b844Bc454e4438f44e") is False

    def test_invalid_too_short(self):
        """Слишком короткий."""
        assert validate_eth_address("0x742d35Cc6634C0532925a3b844Bc454e") is False


class TestValidateAddress:
    """Тесты функции validate_address."""

    def test_auto_detect_btc(self):
        """Авто-определение BTC."""
        is_valid, currency = validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert is_valid is True
        assert currency == "BTC"

    def test_auto_detect_eth(self):
        """Авто-определение ETH."""
        is_valid, currency = validate_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        assert is_valid is True
        assert currency == "ETH"

    def test_explicit_currency_match(self):
        """Явное указание валюты — совпадает."""
        is_valid, currency = validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "BTC")
        assert is_valid is True
        assert currency == "BTC"

    def test_explicit_currency_mismatch(self):
        """Явное указание валюты — не совпадает."""
        is_valid, currency = validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "ETH")
        assert is_valid is False

    def test_invalid_address(self):
        """Невалидный адрес."""
        is_valid, currency = validate_address("invalid")
        assert is_valid is False
        assert currency is None


class TestCalculateWalletRisk:
    """Тесты функции calculate_wallet_risk."""

    def test_none_info(self):
        """Если info=None — средний риск."""
        level, flags, score = calculate_wallet_risk(None)
        assert any(f.code == "WALLET_ANALYSIS_FAILED" for f in flags)

    def test_invalid_wallet(self):
        """Невалидный кошелёк."""
        info = WalletInfo(
            address="invalid",
            currency="UNKNOWN",
            is_valid=False,
        )
        level, flags, score = calculate_wallet_risk(info)
        assert any(f.code == "INVALID_WALLET" for f in flags)

    def test_known_scam_address(self):
        """Известный скам-адрес — критический риск."""
        info = WalletInfo(
            address="1Ai52Uw6usjhpcDrwSmkUvjuqLpcznUuyF",
            currency="BTC",
            is_valid=True,
            is_scam=True,
            scam_labels=["phishing", "fake_giveaway"],
        )
        level, flags, score = calculate_wallet_risk(info)
        assert any(f.code == "KNOWN_SCAM_ADDRESS" for f in flags)
        assert score >= 6

    def test_known_exchange(self):
        """Известная биржа — доверие."""
        info = WalletInfo(
            address="3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5",
            currency="BTC",
            is_valid=True,
            exchange_name="Bitfinex",
        )
        level, flags, score = calculate_wallet_risk(info)
        assert any(f.code == "KNOWN_EXCHANGE" for f in flags)

    def test_empty_wallet(self):
        """Пустой кошелёк."""
        info = WalletInfo(
            address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            currency="BTC",
            is_valid=True,
            balance=Decimal(0),
        )
        level, flags, score = calculate_wallet_risk(info)
        assert any(f.code == "EMPTY_WALLET" for f in flags)

    def test_wallet_with_balance(self):
        """Кошелёк с балансом."""
        info = WalletInfo(
            address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            currency="BTC",
            is_valid=True,
            balance=Decimal("1.5"),
        )
        level, flags, score = calculate_wallet_risk(info)
        assert any(f.code == "HAS_BALANCE" for f in flags)

    def test_no_transactions(self):
        """Нет транзакций."""
        info = WalletInfo(
            address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            currency="BTC",
            is_valid=True,
            tx_count=0,
        )
        level, flags, score = calculate_wallet_risk(info)
        assert any(f.code == "NO_TRANSACTIONS" for f in flags)

    def test_high_activity(self):
        """Высокая активность."""
        info = WalletInfo(
            address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            currency="BTC",
            is_valid=True,
            tx_count=100,
        )
        level, flags, score = calculate_wallet_risk(info)
        assert any(f.code == "HIGH_ACTIVITY" for f in flags)

    def test_smart_contract(self):
        """Смарт-контракт."""
        info = WalletInfo(
            address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            currency="ETH",
            is_valid=True,
            is_contract=True,
        )
        level, flags, score = calculate_wallet_risk(info)
        assert any(f.code == "SMART_CONTRACT" for f in flags)

    def test_clean_active_wallet(self):
        """Чистый активный кошелёк — низкий риск."""
        info = WalletInfo(
            address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            currency="BTC",
            is_valid=True,
            balance=Decimal("0.5"),
            tx_count=50,
            is_scam=False,
        )
        level, flags, score = calculate_wallet_risk(info)
        assert level == RiskLevel.LOW
        assert score <= 3
