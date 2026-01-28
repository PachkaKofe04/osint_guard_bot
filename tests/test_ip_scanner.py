# tests/test_ip_scanner.py
"""Тесты для IP сканера."""
import pytest
from ip_scanner.scanner import validate_ip, is_private_ip, is_reserved_ip
from ip_scanner.risk_engine import calculate_ip_risk
from ip_scanner.models import IpInfo
from utils.risk_types import RiskLevel


class TestValidateIp:
    """Тесты функции validate_ip."""

    def test_valid_ipv4(self):
        """Валидный IPv4."""
        is_valid, version = validate_ip("8.8.8.8")
        assert is_valid is True
        assert version == 4

    def test_valid_ipv4_zeros(self):
        """IPv4 с нулями."""
        is_valid, version = validate_ip("0.0.0.0")
        assert is_valid is True
        assert version == 4

    def test_valid_ipv4_max(self):
        """IPv4 с максимальными значениями."""
        is_valid, version = validate_ip("255.255.255.255")
        assert is_valid is True
        assert version == 4

    def test_valid_ipv6(self):
        """Валидный IPv6."""
        is_valid, version = validate_ip("2001:4860:4860::8888")
        assert is_valid is True
        assert version == 6

    def test_valid_ipv6_full(self):
        """Полный IPv6."""
        is_valid, version = validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert is_valid is True
        assert version == 6

    def test_valid_ipv6_loopback(self):
        """IPv6 loopback."""
        is_valid, version = validate_ip("::1")
        assert is_valid is True
        assert version == 6

    def test_invalid_ipv4_octet(self):
        """Невалидный IPv4 — октет > 255."""
        is_valid, version = validate_ip("256.1.1.1")
        assert is_valid is False

    def test_invalid_format(self):
        """Невалидный формат."""
        is_valid, version = validate_ip("not-an-ip")
        assert is_valid is False

    def test_invalid_partial(self):
        """Неполный IPv4."""
        is_valid, version = validate_ip("192.168.1")
        assert is_valid is False

    def test_empty(self):
        """Пустая строка."""
        is_valid, version = validate_ip("")
        assert is_valid is False


class TestIsPrivateIp:
    """Тесты функции is_private_ip."""

    def test_private_10(self):
        """10.x.x.x приватный."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True

    def test_private_172(self):
        """172.16-31.x.x приватный."""
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True

    def test_private_192(self):
        """192.168.x.x приватный."""
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.255") is True

    def test_public_ip(self):
        """Публичный IP."""
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False

    def test_localhost(self):
        """Localhost приватный."""
        assert is_private_ip("127.0.0.1") is True


class TestIsReservedIp:
    """Тесты функции is_reserved_ip."""

    def test_loopback(self):
        """Loopback зарезервирован."""
        assert is_reserved_ip("127.0.0.1") is True

    def test_multicast(self):
        """Multicast зарезервирован."""
        assert is_reserved_ip("224.0.0.1") is True

    def test_public_not_reserved(self):
        """Публичный IP не зарезервирован."""
        assert is_reserved_ip("8.8.8.8") is False


class TestCalculateIpRisk:
    """Тесты функции calculate_ip_risk."""

    def test_none_info(self):
        """Если info=None — средний риск."""
        level, flags, score = calculate_ip_risk(None)
        assert any(f.code == "IP_ANALYSIS_FAILED" for f in flags)

    def test_invalid_ip(self):
        """Невалидный IP — высокий риск."""
        info = IpInfo(ip="invalid", is_valid=False)
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "INVALID_IP" for f in flags)
        assert score >= 5

    def test_private_ip(self):
        """Приватный IP — низкий риск."""
        info = IpInfo(
            ip="192.168.1.1",
            is_valid=True,
            is_private=True,
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "PRIVATE_IP" for f in flags)

    def test_tor_exit_high_risk(self):
        """TOR exit node — высокий риск."""
        info = IpInfo(
            ip="185.220.101.1",
            is_valid=True,
            is_tor=True,
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "TOR_EXIT_NODE" for f in flags)
        assert score >= 5

    def test_vpn_medium_risk(self):
        """VPN — средний риск."""
        info = IpInfo(
            ip="1.2.3.4",
            is_valid=True,
            is_vpn=True,
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "VPN_PROXY" for f in flags)

    def test_proxy_medium_risk(self):
        """Proxy — средний риск."""
        info = IpInfo(
            ip="1.2.3.4",
            is_valid=True,
            is_proxy=True,
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "VPN_PROXY" for f in flags)

    def test_blacklisted_high_risk(self):
        """В чёрном списке — высокий риск."""
        info = IpInfo(
            ip="1.2.3.4",
            is_valid=True,
            is_blacklisted=True,
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "IP_BLACKLISTED" for f in flags)
        assert score >= 5

    def test_high_abuse_score(self):
        """Высокий abuse score — высокий риск."""
        info = IpInfo(
            ip="1.2.3.4",
            is_valid=True,
            abuse_score=85,
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "HIGH_ABUSE_SCORE" for f in flags)

    def test_medium_abuse_score(self):
        """Средний abuse score — средний риск."""
        info = IpInfo(
            ip="1.2.3.4",
            is_valid=True,
            abuse_score=50,
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "MEDIUM_ABUSE_SCORE" for f in flags)

    def test_hosting_ip(self):
        """Хостинг IP — средний риск."""
        info = IpInfo(
            ip="1.2.3.4",
            is_valid=True,
            is_hosting=True,
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "HOSTING_IP" for f in flags)

    def test_high_risk_country(self):
        """Страна повышенного риска."""
        info = IpInfo(
            ip="1.2.3.4",
            is_valid=True,
            country="Nigeria",
            country_code="NG",
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "HIGH_RISK_COUNTRY" for f in flags)

    def test_trusted_provider(self):
        """Доверенный провайдер."""
        info = IpInfo(
            ip="8.8.8.8",
            is_valid=True,
            asname="GOOGLE",
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "TRUSTED_PROVIDER" for f in flags)

    def test_clean_ip(self):
        """Чистый IP."""
        info = IpInfo(
            ip="8.8.8.8",
            is_valid=True,
            is_proxy=False,
            is_vpn=False,
            is_tor=False,
            is_blacklisted=False,
            abuse_score=10,
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "CLEAN_IP" for f in flags)

    def test_geo_resolved(self):
        """Геолокация успешна."""
        info = IpInfo(
            ip="8.8.8.8",
            is_valid=True,
            country="United States",
            city="Mountain View",
        )
        level, flags, score = calculate_ip_risk(info)
        assert any(f.code == "GEO_RESOLVED" for f in flags)

    def test_clean_residential_ip(self):
        """Чистый резиденциальный IP — низкий риск."""
        info = IpInfo(
            ip="203.0.113.50",
            is_valid=True,
            is_private=False,
            is_proxy=False,
            is_vpn=False,
            is_tor=False,
            is_hosting=False,
            is_blacklisted=False,
            country="United States",
            country_code="US",
            city="New York",
            isp="Comcast",
        )
        level, flags, score = calculate_ip_risk(info)
        assert level == RiskLevel.LOW
        assert score <= 3
