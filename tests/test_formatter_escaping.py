# tests/test_formatter_escaping.py
"""
Пользовательские данные не должны попадать в разметку сырыми.

Неэкранированный `<` или `&` ломал parse_mode=HTML — Telegram отвечал
"can't parse entities", и пользователь не получал ответа вообще.
Особенно опасны поля, которые целиком контролируются извне: содержимое
QR-кода, EXIF-теги подготовленного файла, заголовки чужого сервера.
"""
from datetime import datetime, timezone

import pytest

from utils.risk_types import RiskLevel

PAYLOAD = '<script>alert("xss")</script> & <b>bold</b>'
ESCAPED_MARKER = "&lt;script&gt;"


def _assert_escaped(text: str) -> None:
    assert "<script>" not in text, "сырой тег дошёл до разметки сообщения"
    assert ESCAPED_MARKER in text, "полезная нагрузка не попала в отчёт вовсе"


class TestQrFormatter:
    """Содержимое QR-кода полностью задаёт тот, кто нарисовал код."""

    def test_raw_qr_data_escaped(self):
        from qr_scanner.formatter import format_qr_result
        from qr_scanner.models import QrContentType, QrInfo, QrScanResult

        info = QrInfo(
            raw_data=PAYLOAD,
            content_type=QrContentType.TEXT,
            decoded_count=1,
            data_length=len(PAYLOAD),
        )
        result = QrScanResult(
            filename="qr.png", info=info, found_qr=True,
            risk_level=RiskLevel.LOW, flags=[], score=0,
            scanned_at=datetime.now(timezone.utc),
        )
        _assert_escaped(format_qr_result(result))


class TestExifFormatter:
    """EXIF-теги берутся из файла, присланного пользователем."""

    def test_camera_and_software_escaped(self):
        from exif_scanner.formatter import format_exif_result
        from exif_scanner.models import ExifInfo, ExifScanResult

        info = ExifInfo(
            has_exif=True, file_size=1024,
            image_width=100, image_height=100, format="JPEG",
            camera_make=PAYLOAD, camera_model=PAYLOAD, software=PAYLOAD,
        )
        result = ExifScanResult(
            filename="photo.jpg", info=info,
            risk_level=RiskLevel.LOW, flags=[], score=0,
            scanned_at=datetime.now(timezone.utc),
        )
        _assert_escaped(format_exif_result(result))


class TestUsernameFormatter:
    def test_username_escaped(self):
        from username_scanner.formatter import format_username_result
        from username_scanner.models import UsernameInfo, UsernameScanResult

        result = UsernameScanResult(
            username=PAYLOAD,
            info=UsernameInfo(username=PAYLOAD, is_valid=False),
            risk_level=RiskLevel.LOW, flags=[], score=0,
            scanned_at=datetime.now(timezone.utc),
        )
        _assert_escaped(format_username_result(result))


class TestWalletFormatter:
    def test_address_escaped(self):
        from wallet_scanner.formatter import format_wallet_result
        from wallet_scanner.models import WalletInfo, WalletScanResult

        result = WalletScanResult(
            address=PAYLOAD, currency="UNKNOWN",
            info=WalletInfo(address=PAYLOAD, currency="UNKNOWN", is_valid=False),
            risk_level=RiskLevel.LOW, flags=[], score=0,
            scanned_at=datetime.now(timezone.utc),
        )
        _assert_escaped(format_wallet_result(result))


class TestIpFormatter:
    """Поля isp/org приходят от стороннего API ip-api.com."""

    def test_network_fields_escaped(self):
        from ip_scanner.formatter import format_ip_result
        from ip_scanner.models import IpInfo, IpScanResult

        info = IpInfo(
            ip="1.2.3.4", version=4, is_valid=True,
            country=PAYLOAD, city=PAYLOAD, isp=PAYLOAD, org=PAYLOAD,
        )
        result = IpScanResult(
            ip="1.2.3.4", info=info,
            risk_level=RiskLevel.LOW, flags=[], score=0,
            scanned_at=datetime.now(timezone.utc),
        )
        _assert_escaped(format_ip_result(result))


class TestDomainFormatter:
    """Заголовки Server / X-Powered-By задаёт владелец проверяемого сайта."""

    def test_http_headers_escaped(self):
        from domain_scanner.formatter import format_details
        from domain_scanner.models import DomainScanResult, HttpInfo, WhoisInfo

        result = DomainScanResult(
            domain="evil.test", normalized_domain="evil.test",
            risk_level=RiskLevel.LOW, flags=[], score=0,
            whois=WhoisInfo(registrar=PAYLOAD),
            http=HttpInfo(url_checked="https://evil.test/", server=PAYLOAD, x_powered_by=PAYLOAD),
            scanned_at=datetime.now(timezone.utc),
        )
        _assert_escaped(format_details(result))


class TestEmailFormatter:
    def test_email_escaped(self):
        from email_scanner.formatter import format_email_result
        from email_scanner.models import EmailInfo, EmailScanResult

        result = EmailScanResult(
            email=PAYLOAD,
            info=EmailInfo(email=PAYLOAD, local_part="", domain="", is_valid_format=False),
            risk_level=RiskLevel.LOW, flags=[], score=0,
            scanned_at=datetime.now(timezone.utc),
        )
        _assert_escaped(format_email_result(result))
