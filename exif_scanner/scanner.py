# exif_scanner/scanner.py
"""Основной модуль извлечения EXIF данных."""
import io
import logging
from datetime import datetime
from typing import Optional, Tuple, Dict, Any

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

from exif_scanner.models import ExifInfo, ExifScanResult, GpsCoordinates
from exif_scanner.risk_engine import calculate_exif_risk

log = logging.getLogger(__name__)


def _get_exif_data(image: Image.Image) -> Dict[str, Any]:
    """Извлекает EXIF данные из изображения."""
    exif_data = {}

    try:
        # Современный API Pillow (6.0+), работает для JPEG, TIFF, PNG, WebP
        raw_exif = image.getexif()
        if raw_exif:
            for tag_id, value in raw_exif.items():
                tag = TAGS.get(tag_id, tag_id)
                exif_data[tag] = value
    except Exception:
        pass

    # Fallback: устаревший JPEG-only метод
    if not exif_data:
        try:
            raw_exif = image._getexif()  # type: ignore[attr-defined]
            if raw_exif:
                for tag_id, value in raw_exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    exif_data[tag] = value
        except Exception as e:
            log.warning(f"[EXIF] Error extracting EXIF: {e}")

    return exif_data


def _convert_to_degrees(value) -> Optional[float]:
    """Конвертирует GPS координаты в градусы."""
    try:
        d, m, s = value
        return float(d) + float(m) / 60 + float(s) / 3600
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _get_gps_coordinates(exif_data: Dict[str, Any]) -> Optional[GpsCoordinates]:
    """Извлекает GPS координаты из EXIF."""
    gps_info = exif_data.get("GPSInfo")
    if not gps_info:
        return None

    gps_data = {}
    for tag_id, value in gps_info.items():
        tag = GPSTAGS.get(tag_id, tag_id)
        gps_data[tag] = value

    lat = gps_data.get("GPSLatitude")
    lat_ref = gps_data.get("GPSLatitudeRef", "N")
    lon = gps_data.get("GPSLongitude")
    lon_ref = gps_data.get("GPSLongitudeRef", "E")

    if not lat or not lon:
        return None

    latitude = _convert_to_degrees(lat)
    longitude = _convert_to_degrees(lon)

    if latitude is None or longitude is None:
        return None

    if lat_ref == "S":
        latitude = -latitude
    if lon_ref == "W":
        longitude = -longitude

    altitude = None
    if "GPSAltitude" in gps_data:
        try:
            alt = gps_data["GPSAltitude"]
            altitude = float(alt)
        except (TypeError, ValueError):
            pass

    return GpsCoordinates(
        latitude=latitude,
        longitude=longitude,
        altitude=altitude,
    )


def _safe_str(value) -> Optional[str]:
    """Безопасно конвертирует значение в строку."""
    if value is None:
        return None
    try:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore").strip("\x00")
        return str(value).strip("\x00")
    except Exception:
        return None


async def scan_exif(image_data: bytes, filename: str = "image") -> ExifScanResult:
    """
    Извлекает EXIF данные из изображения.

    Args:
        image_data: Байты изображения
        filename: Имя файла

    Returns:
        ExifScanResult
    """
    log.info(f"[EXIF Scanner] Scanning: {filename}")

    try:
        image = Image.open(io.BytesIO(image_data))
    except Exception as e:
        log.warning(f"[EXIF] Cannot open image: {e}")
        info = ExifInfo(has_exif=False)
        risk_level, flags, score = calculate_exif_risk(info)
        return ExifScanResult(
            filename=filename,
            info=info,
            risk_level=risk_level,
            flags=flags,
            score=score,
            scanned_at=datetime.utcnow(),
        )

    # Базовая информация
    file_size = len(image_data)
    width, height = image.size
    img_format = image.format

    # Извлекаем EXIF
    exif_data = _get_exif_data(image)
    has_exif = len(exif_data) > 0

    # GPS
    gps = _get_gps_coordinates(exif_data) if has_exif else None

    # Собираем информацию
    info = ExifInfo(
        has_exif=has_exif,
        file_size=file_size,
        image_width=width,
        image_height=height,
        format=img_format,
        # Камера
        camera_make=_safe_str(exif_data.get("Make")),
        camera_model=_safe_str(exif_data.get("Model")),
        lens_model=_safe_str(exif_data.get("LensModel")),
        # Настройки
        focal_length=_safe_str(exif_data.get("FocalLength")),
        aperture=_safe_str(exif_data.get("FNumber")),
        iso=exif_data.get("ISOSpeedRatings") if isinstance(exif_data.get("ISOSpeedRatings"), int) else None,
        exposure_time=_safe_str(exif_data.get("ExposureTime")),
        flash=_safe_str(exif_data.get("Flash")),
        # Дата
        date_taken=_safe_str(exif_data.get("DateTimeOriginal")),
        date_modified=_safe_str(exif_data.get("DateTime")),
        # GPS
        has_gps=gps is not None,
        gps=gps,
        # Софт
        software=_safe_str(exif_data.get("Software")),
        # Автор
        artist=_safe_str(exif_data.get("Artist")),
        copyright=_safe_str(exif_data.get("Copyright")),
        # Все теги
        all_tags={k: _safe_str(v) for k, v in exif_data.items() if k != "GPSInfo"},
    )

    # Определяем проблемы приватности
    privacy_concerns = []
    if info.has_gps:
        privacy_concerns.append("GPS координаты")
    if info.camera_model:
        privacy_concerns.append("Модель камеры/телефона")
    if info.date_taken:
        privacy_concerns.append("Дата съёмки")
    if info.software:
        privacy_concerns.append("Программное обеспечение")
    if info.artist:
        privacy_concerns.append("Имя автора")

    info.privacy_concerns = privacy_concerns

    # Закрываем изображение
    image.close()

    # Рассчитываем риск
    risk_level, flags, score = calculate_exif_risk(info)

    result = ExifScanResult(
        filename=filename,
        info=info,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.utcnow(),
    )

    log.info(f"[EXIF Scanner] Result: has_exif={has_exif}, has_gps={info.has_gps}")

    return result
