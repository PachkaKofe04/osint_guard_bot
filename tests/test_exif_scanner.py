# tests/test_exif_scanner.py
"""Тесты для EXIF сканера."""
import pytest
from exif_scanner.risk_engine import calculate_exif_risk
from exif_scanner.models import ExifInfo, GpsCoordinates
from utils.risk_types import RiskLevel


class TestCalculateExifRisk:
    """Тесты функции calculate_exif_risk."""

    def test_none_info(self):
        """Если info=None — средний риск."""
        level, flags, score = calculate_exif_risk(None)
        assert any(f.code == "EXIF_ANALYSIS_FAILED" for f in flags)

    def test_no_exif(self):
        """Нет EXIF — низкий риск (приватность защищена)."""
        info = ExifInfo(has_exif=False)
        level, flags, score = calculate_exif_risk(info)
        assert any(f.code == "NO_EXIF_DATA" for f in flags)
        assert level == RiskLevel.LOW

    def test_gps_found(self):
        """GPS координаты — высокий риск."""
        info = ExifInfo(
            has_exif=True,
            has_gps=True,
            gps=GpsCoordinates(latitude=55.7558, longitude=37.6173),
        )
        level, flags, score = calculate_exif_risk(info)
        assert any(f.code == "GPS_LOCATION_FOUND" for f in flags)
        assert score >= 4

    def test_no_gps(self):
        """Нет GPS — отмечается как безопасно."""
        info = ExifInfo(
            has_exif=True,
            has_gps=False,
        )
        level, flags, score = calculate_exif_risk(info)
        assert any(f.code == "NO_GPS" for f in flags)

    def test_device_info(self):
        """Информация об устройстве."""
        info = ExifInfo(
            has_exif=True,
            camera_make="Apple",
            camera_model="iPhone 13 Pro",
        )
        level, flags, score = calculate_exif_risk(info)
        assert any(f.code == "DEVICE_INFO" for f in flags)

    def test_date_taken(self):
        """Дата съёмки."""
        info = ExifInfo(
            has_exif=True,
            date_taken="2024:01:15 14:30:00",
        )
        level, flags, score = calculate_exif_risk(info)
        assert any(f.code == "DATE_TAKEN" for f in flags)

    def test_author_info(self):
        """Информация об авторе."""
        info = ExifInfo(
            has_exif=True,
            artist="John Doe",
        )
        level, flags, score = calculate_exif_risk(info)
        assert any(f.code == "AUTHOR_INFO" for f in flags)

    def test_software_info(self):
        """Информация о ПО."""
        info = ExifInfo(
            has_exif=True,
            software="Adobe Photoshop CC 2024",
        )
        level, flags, score = calculate_exif_risk(info)
        assert any(f.code == "SOFTWARE_INFO" for f in flags)

    def test_many_metadata(self):
        """Много метаданных — повышенный риск."""
        info = ExifInfo(
            has_exif=True,
            has_gps=True,
            gps=GpsCoordinates(latitude=55.7558, longitude=37.6173),
            camera_model="iPhone 13",
            date_taken="2024:01:15 14:30:00",
            software="Camera App",
            artist="User",
            privacy_concerns=[
                "GPS координаты",
                "Модель камеры/телефона",
                "Дата съёмки",
                "Программное обеспечение",
                "Имя автора",
            ],
        )
        level, flags, score = calculate_exif_risk(info)
        assert any(f.code == "MANY_METADATA" for f in flags)

    def test_image_size(self):
        """Размер изображения."""
        info = ExifInfo(
            has_exif=True,
            image_width=4032,
            image_height=3024,
        )
        level, flags, score = calculate_exif_risk(info)
        assert any(f.code == "IMAGE_SIZE" for f in flags)

    def test_high_risk_with_gps_and_device(self):
        """Высокий риск при GPS + устройство."""
        info = ExifInfo(
            has_exif=True,
            has_gps=True,
            gps=GpsCoordinates(latitude=40.7128, longitude=-74.0060),
            camera_make="Samsung",
            camera_model="Galaxy S22",
            date_taken="2024:06:01 10:00:00",
            privacy_concerns=["GPS координаты", "Модель камеры/телефона", "Дата съёмки"],
        )
        level, flags, score = calculate_exif_risk(info)
        # GPS (5) + Device (2) + Date (1) + Many (3) = 11, но максимум 10
        assert score >= 5
        assert level in (RiskLevel.HIGH, RiskLevel.MEDIUM)
