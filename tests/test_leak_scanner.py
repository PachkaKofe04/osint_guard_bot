# tests/test_leak_scanner.py
"""Тесты для Leak сканера."""
import pytest
from leak_scanner.risk_engine import calculate_leak_risk
from leak_scanner.models import LeakInfo, BreachInfo
from utils.risk_types import RiskLevel


class TestCalculateLeakRisk:
    """Тесты функции calculate_leak_risk."""

    def test_none_info(self):
        """Если info=None — средний риск."""
        level, flags, score = calculate_leak_risk(None)
        assert any(f.code == "LEAK_CHECK_FAILED" for f in flags)

    def test_no_breaches(self):
        """Нет утечек — низкий риск."""
        info = LeakInfo(
            query="safe@example.com",
            is_pwned=False,
            breach_count=0,
        )
        level, flags, score = calculate_leak_risk(info)
        assert any(f.code == "NO_BREACHES_FOUND" for f in flags)
        assert level == RiskLevel.LOW

    def test_few_breaches(self):
        """Несколько утечек."""
        info = LeakInfo(
            query="user@example.com",
            is_pwned=True,
            breach_count=2,
            breaches=[
                BreachInfo(name="Breach1", title="Breach 1", domain="example1.com"),
                BreachInfo(name="Breach2", title="Breach 2", domain="example2.com"),
            ],
        )
        level, flags, score = calculate_leak_risk(info)
        assert any(f.code == "FEW_BREACHES" for f in flags)

    def test_many_breaches(self):
        """Много утечек — высокий риск."""
        breaches = [
            BreachInfo(name=f"Breach{i}", title=f"Breach {i}", domain=f"example{i}.com")
            for i in range(6)
        ]
        info = LeakInfo(
            query="leaked@example.com",
            is_pwned=True,
            breach_count=6,
            breaches=breaches,
        )
        level, flags, score = calculate_leak_risk(info)
        assert any(f.code == "MANY_BREACHES" for f in flags)
        assert score >= 5

    def test_password_leaked(self):
        """Утечка паролей — высокий риск."""
        info = LeakInfo(
            query="user@example.com",
            is_pwned=True,
            breach_count=1,
            breaches=[
                BreachInfo(
                    name="Adobe",
                    title="Adobe 2013",
                    domain="adobe.com",
                    data_classes=["Emails", "Passwords"],
                ),
            ],
        )
        level, flags, score = calculate_leak_risk(info)
        assert any(f.code == "PASSWORD_LEAKED" for f in flags)

    def test_sensitive_data(self):
        """Чувствительные данные."""
        info = LeakInfo(
            query="user@example.com",
            is_pwned=True,
            breach_count=1,
            breaches=[
                BreachInfo(
                    name="SensitiveBreach",
                    title="Sensitive Breach",
                    domain="sensitive.com",
                    is_sensitive=True,
                ),
            ],
        )
        level, flags, score = calculate_leak_risk(info)
        assert any(f.code == "SENSITIVE_DATA" for f in flags)

    def test_data_types_listed(self):
        """Типы данных перечислены."""
        info = LeakInfo(
            query="user@example.com",
            is_pwned=True,
            breach_count=1,
            breaches=[
                BreachInfo(
                    name="Breach",
                    title="Breach",
                    domain="example.com",
                    data_classes=["Emails", "Usernames", "IP addresses"],
                ),
            ],
        )
        level, flags, score = calculate_leak_risk(info)
        assert any(f.code == "DATA_TYPES" for f in flags)

    def test_breach_list(self):
        """Список утечек."""
        info = LeakInfo(
            query="user@example.com",
            is_pwned=True,
            breach_count=2,
            breaches=[
                BreachInfo(name="LinkedIn", title="LinkedIn", domain="linkedin.com"),
                BreachInfo(name="Adobe", title="Adobe", domain="adobe.com"),
            ],
        )
        level, flags, score = calculate_leak_risk(info)
        assert any(f.code == "BREACH_LIST" for f in flags)
