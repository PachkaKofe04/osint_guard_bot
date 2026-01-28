# exif_scanner/models.py
"""Модели данных для EXIF сканера."""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

from utils.risk_types import RiskFlag, RiskLevel


class GpsCoordinates(BaseModel):
    """GPS координаты."""
    latitude: float
    longitude: float
    altitude: Optional[float] = None


class ExifInfo(BaseModel):
    """Информация EXIF из изображения."""
    # Основная информация
    has_exif: bool = False
    file_size: Optional[int] = None
    image_width: Optional[int] = None
    image_height: Optional[int] = None
    format: Optional[str] = None

    # Камера
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    lens_model: Optional[str] = None

    # Настройки съёмки
    focal_length: Optional[str] = None
    aperture: Optional[str] = None
    iso: Optional[int] = None
    exposure_time: Optional[str] = None
    flash: Optional[str] = None

    # Дата и время
    date_taken: Optional[str] = None
    date_modified: Optional[str] = None

    # GPS
    has_gps: bool = False
    gps: Optional[GpsCoordinates] = None

    # Софт
    software: Optional[str] = None

    # Автор
    artist: Optional[str] = None
    copyright: Optional[str] = None

    # Все теги (для детального просмотра)
    all_tags: Dict[str, Any] = {}

    # Риски
    privacy_concerns: List[str] = []


class ExifScanResult(BaseModel):
    """Результат сканирования EXIF."""
    filename: str
    info: Optional[ExifInfo] = None
    risk_level: RiskLevel
    flags: List[RiskFlag] = []
    score: int
    scanned_at: datetime
