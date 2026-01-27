# tests/test_risk_scoring.py
"""Тесты для системы подсчёта рисков."""
import pytest
from utils.risk_types import (
    RiskLevel,
    RiskFlag,
    RiskWeight,
    get_risk_emoji,
    get_risk_level,
    get_risk_label,
)
from utils.risk_scoring import add_risk_flag, calculate_risk_score


class TestGetRiskEmoji:
    """Тесты для get_risk_emoji."""

    def test_low_risk(self):
        assert get_risk_emoji(0) == "🟢"
        assert get_risk_emoji(1) == "🟢"
        assert get_risk_emoji(3) == "🟢"

    def test_medium_risk(self):
        assert get_risk_emoji(4) == "🟡"
        assert get_risk_emoji(5) == "🟡"
        assert get_risk_emoji(6) == "🟡"

    def test_high_risk(self):
        assert get_risk_emoji(7) == "🔴"
        assert get_risk_emoji(8) == "🔴"
        assert get_risk_emoji(10) == "🔴"


class TestGetRiskLevel:
    """Тесты для get_risk_level."""

    def test_low_risk(self):
        assert get_risk_level(0) == RiskLevel.LOW
        assert get_risk_level(3) == RiskLevel.LOW

    def test_medium_risk(self):
        assert get_risk_level(4) == RiskLevel.MEDIUM
        assert get_risk_level(6) == RiskLevel.MEDIUM

    def test_high_risk(self):
        assert get_risk_level(7) == RiskLevel.HIGH
        assert get_risk_level(10) == RiskLevel.HIGH


class TestGetRiskLabel:
    """Тесты для get_risk_label."""

    def test_labels(self):
        assert get_risk_label(RiskLevel.LOW) == "Низкий риск"
        assert get_risk_label(RiskLevel.MEDIUM) == "Средний риск"
        assert get_risk_label(RiskLevel.HIGH) == "Высокий риск"


class TestAddRiskFlag:
    """Тесты для add_risk_flag."""

    def test_add_single_flag(self):
        flags = []
        add_risk_flag(flags, "TEST_FLAG", RiskLevel.MEDIUM, "Test message", 2)

        assert len(flags) == 1
        assert flags[0].code == "TEST_FLAG"
        assert flags[0].level == RiskLevel.MEDIUM
        assert flags[0].message == "Test message"
        assert flags[0].weight == 2

    def test_add_multiple_flags(self):
        flags = []
        add_risk_flag(flags, "FLAG1", RiskLevel.LOW, "Message 1", 1)
        add_risk_flag(flags, "FLAG2", RiskLevel.HIGH, "Message 2", 4)

        assert len(flags) == 2
        assert flags[0].code == "FLAG1"
        assert flags[1].code == "FLAG2"

    def test_negative_weight(self):
        """Отрицательный вес (trust signal)."""
        flags = []
        add_risk_flag(flags, "TRUSTED", RiskLevel.LOW, "Trusted source", -3)

        assert flags[0].weight == -3


class TestCalculateRiskScore:
    """Тесты для calculate_risk_score."""

    def test_empty_flags(self):
        """Нет флагов — минимальный риск."""
        flags = []
        result = calculate_risk_score(flags)

        assert result.score == 0
        assert result.level == RiskLevel.LOW

    def test_positive_weights(self):
        """Положительные веса увеличивают score."""
        flags = [
            RiskFlag(code="FLAG1", level=RiskLevel.MEDIUM, message="", weight=2),
            RiskFlag(code="FLAG2", level=RiskLevel.MEDIUM, message="", weight=3),
        ]
        result = calculate_risk_score(flags)

        assert result.score == 5
        assert result.level == RiskLevel.MEDIUM

    def test_negative_weights(self):
        """Отрицательные веса уменьшают score."""
        flags = [
            RiskFlag(code="RISK", level=RiskLevel.MEDIUM, message="", weight=4),
            RiskFlag(code="TRUST", level=RiskLevel.LOW, message="", weight=-3),
        ]
        result = calculate_risk_score(flags)

        assert result.score == 1
        assert result.level == RiskLevel.LOW

    def test_score_clamped_to_zero(self):
        """Score не может быть меньше 0."""
        flags = [
            RiskFlag(code="TRUST1", level=RiskLevel.LOW, message="", weight=-5),
            RiskFlag(code="TRUST2", level=RiskLevel.LOW, message="", weight=-5),
        ]
        result = calculate_risk_score(flags)

        assert result.score == 0

    def test_score_clamped_to_ten(self):
        """Score не может быть больше 10."""
        flags = [
            RiskFlag(code="RISK1", level=RiskLevel.HIGH, message="", weight=5),
            RiskFlag(code="RISK2", level=RiskLevel.HIGH, message="", weight=5),
            RiskFlag(code="RISK3", level=RiskLevel.HIGH, message="", weight=5),
        ]
        result = calculate_risk_score(flags)

        assert result.score == 10
        assert result.level == RiskLevel.HIGH
