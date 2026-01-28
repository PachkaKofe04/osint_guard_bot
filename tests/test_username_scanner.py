# tests/test_username_scanner.py
"""Тесты для Username сканера."""
import pytest
from username_scanner.scanner import validate_username, detect_suspicious_patterns
from username_scanner.risk_engine import calculate_username_risk
from username_scanner.models import UsernameInfo, PlatformResult
from username_scanner.platforms import PLATFORMS, SUSPICIOUS_PATTERNS, BRAND_PATTERNS
from utils.risk_types import RiskLevel


class TestValidateUsername:
    """Тесты функции validate_username."""

    def test_valid_simple(self):
        """Простой валидный username."""
        assert validate_username("john_doe") is True

    def test_valid_with_numbers(self):
        """Username с цифрами."""
        assert validate_username("user123") is True

    def test_valid_with_dots(self):
        """Username с точками."""
        assert validate_username("john.doe") is True

    def test_valid_with_dash(self):
        """Username с дефисом."""
        assert validate_username("john-doe") is True

    def test_valid_min_length(self):
        """Минимальная длина."""
        assert validate_username("abc") is True

    def test_valid_max_length(self):
        """Максимальная длина."""
        assert validate_username("a" * 32) is True

    def test_invalid_too_short(self):
        """Слишком короткий."""
        assert validate_username("ab") is False

    def test_invalid_too_long(self):
        """Слишком длинный."""
        assert validate_username("a" * 33) is False

    def test_invalid_special_chars(self):
        """Запрещённые символы."""
        assert validate_username("user@name") is False
        assert validate_username("user name") is False
        assert validate_username("user!name") is False

    def test_invalid_empty(self):
        """Пустая строка."""
        assert validate_username("") is False


class TestDetectSuspiciousPatterns:
    """Тесты функции detect_suspicious_patterns."""

    def test_admin_pattern(self):
        """Паттерн admin."""
        patterns = detect_suspicious_patterns("admin_support")
        assert "admin" in patterns
        assert "support" in patterns

    def test_official_pattern(self):
        """Паттерн official."""
        patterns = detect_suspicious_patterns("official_account")
        assert "official" in patterns

    def test_brand_google(self):
        """Имитация Google."""
        patterns = detect_suspicious_patterns("google_support")
        assert "brand:google" in patterns
        assert "support" in patterns

    def test_brand_telegram(self):
        """Имитация Telegram."""
        patterns = detect_suspicious_patterns("telegram_official")
        assert "brand:telegram" in patterns

    def test_exact_brand_not_flagged(self):
        """Точное совпадение бренда не помечается."""
        patterns = detect_suspicious_patterns("google")
        assert "brand:google" not in patterns

    def test_no_patterns(self):
        """Обычный username без подозрительных паттернов."""
        patterns = detect_suspicious_patterns("john_doe_123")
        assert len(patterns) == 0


class TestPlatforms:
    """Тесты конфигурации платформ."""

    def test_platforms_exist(self):
        """Платформы определены."""
        assert len(PLATFORMS) > 0

    def test_platform_has_url_template(self):
        """Каждая платформа имеет URL шаблон."""
        for platform in PLATFORMS:
            assert "{username}" in platform.url_template

    def test_suspicious_patterns_exist(self):
        """Подозрительные паттерны определены."""
        assert len(SUSPICIOUS_PATTERNS) > 0

    def test_brand_patterns_exist(self):
        """Паттерны брендов определены."""
        assert len(BRAND_PATTERNS) > 0


class TestCalculateUsernameRisk:
    """Тесты функции calculate_username_risk."""

    def test_none_info(self):
        """Если info=None — средний риск."""
        level, flags, score = calculate_username_risk(None)
        assert any(f.code == "USERNAME_ANALYSIS_FAILED" for f in flags)

    def test_invalid_username(self):
        """Невалидный username."""
        info = UsernameInfo(username="ab", is_valid=False)
        level, flags, score = calculate_username_risk(info)
        assert any(f.code == "INVALID_USERNAME" for f in flags)

    def test_impersonation_pattern(self):
        """Подозрительный паттерн (admin, support)."""
        info = UsernameInfo(
            username="admin_support",
            is_valid=True,
            common_patterns=["admin", "support"],
        )
        level, flags, score = calculate_username_risk(info)
        assert any(f.code == "IMPERSONATION_PATTERN" for f in flags)

    def test_brand_impersonation(self):
        """Имитация бренда."""
        info = UsernameInfo(
            username="google_support",
            is_valid=True,
            common_patterns=["brand:google", "support"],
        )
        level, flags, score = calculate_username_risk(info)
        assert any(f.code == "BRAND_IMPERSONATION" for f in flags)

    def test_not_found_anywhere(self):
        """Не найден ни на одной платформе."""
        info = UsernameInfo(
            username="unique_username_12345",
            is_valid=True,
            found_count=0,
            checked_count=10,
            platforms=[],
        )
        level, flags, score = calculate_username_risk(info)
        assert any(f.code == "NOT_FOUND_ANYWHERE" for f in flags)

    def test_found_single(self):
        """Найден на одной платформе."""
        info = UsernameInfo(
            username="john_doe",
            is_valid=True,
            found_count=1,
            checked_count=10,
            platforms=[
                PlatformResult(platform="GitHub", url="https://github.com/john_doe", exists=True, status="exists"),
            ],
        )
        level, flags, score = calculate_username_risk(info)
        assert any(f.code == "FOUND_SINGLE" for f in flags)

    def test_found_many(self):
        """Найден на многих платформах."""
        platforms = [
            PlatformResult(platform=f"Platform{i}", url=f"https://example{i}.com/user", exists=True, status="exists")
            for i in range(5)
        ]
        info = UsernameInfo(
            username="popular_user",
            is_valid=True,
            found_count=5,
            checked_count=10,
            platforms=platforms,
        )
        level, flags, score = calculate_username_risk(info)
        assert any(f.code == "FOUND_MANY" for f in flags)
        assert any(f.code == "ESTABLISHED_PRESENCE" for f in flags)

    def test_established_user_low_risk(self):
        """Устоявшийся пользователь — низкий риск."""
        platforms = [
            PlatformResult(platform=f"Platform{i}", url=f"https://example{i}.com/user", exists=True, status="exists")
            for i in range(6)
        ]
        info = UsernameInfo(
            username="established_user",
            is_valid=True,
            found_count=6,
            checked_count=15,
            platforms=platforms,
            common_patterns=[],
        )
        level, flags, score = calculate_username_risk(info)
        assert level == RiskLevel.LOW
        assert score <= 3

    def test_suspicious_user_high_risk(self):
        """Подозрительный пользователь — высокий риск."""
        info = UsernameInfo(
            username="google_admin_support",
            is_valid=True,
            found_count=0,
            checked_count=10,
            platforms=[],
            common_patterns=["brand:google", "admin", "support"],
        )
        level, flags, score = calculate_username_risk(info)
        assert score >= 5  # Высокий риск из-за паттернов
