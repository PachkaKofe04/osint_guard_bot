# exif_scanner/risk_engine.py
"""Движок оценки рисков для EXIF сканера."""
from typing import List, Optional, Tuple

from exif_scanner.models import ExifInfo
from utils.risk_types import RiskFlag, RiskLevel
from utils.risk_scoring import add_risk_flag, calculate_risk_score


class ExifRiskWeight:
    """Веса рисков для EXIF."""
    # Высокие риски приватности
    GPS_LOCATION = 5          # GPS координаты
    MANY_METADATA = 3         # Много метаданных

    # Средние риски
    DEVICE_INFO = 2           # Информация об устройстве
    DATE_INFO = 1             # Дата съёмки
    AUTHOR_INFO = 2           # Информация об авторе

    # Нейтрально/доверие
    NO_EXIF = -1              # Нет EXIF (приватность сохранена)
    NO_GPS = -1               # Нет GPS


def calculate_exif_risk(info: Optional[ExifInfo]) -> Tuple[RiskLevel, List[RiskFlag], int]:
    """
    Расчёт риска приватности по EXIF данным.

    Returns:
        Tuple[RiskLevel, List[RiskFlag], score]
    """
    flags: List[RiskFlag] = []

    if info is None:
        add_risk_flag(
            flags,
            "EXIF_ANALYSIS_FAILED",
            RiskLevel.MEDIUM,
            "Не удалось проанализировать изображение",
            2,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # Нет EXIF — приватность сохранена
    if not info.has_exif:
        add_risk_flag(
            flags,
            "NO_EXIF_DATA",
            RiskLevel.LOW,
            "EXIF данные отсутствуют — приватность защищена",
            ExifRiskWeight.NO_EXIF,
        )
        risk_score = calculate_risk_score(flags)
        return risk_score.level, flags, risk_score.score

    # GPS координаты — высокий риск приватности
    if info.has_gps and info.gps:
        add_risk_flag(
            flags,
            "GPS_LOCATION_FOUND",
            RiskLevel.HIGH,
            f"⚠️ GPS координаты: {info.gps.latitude:.6f}, {info.gps.longitude:.6f}",
            ExifRiskWeight.GPS_LOCATION,
        )
    else:
        add_risk_flag(
            flags,
            "NO_GPS",
            RiskLevel.LOW,
            "GPS координаты отсутствуют",
            ExifRiskWeight.NO_GPS,
        )

    # Информация о камере/телефоне
    if info.camera_make or info.camera_model:
        device = " ".join(filter(None, [info.camera_make, info.camera_model]))
        add_risk_flag(
            flags,
            "DEVICE_INFO",
            RiskLevel.MEDIUM,
            f"Устройство: {device}",
            ExifRiskWeight.DEVICE_INFO,
        )

    # Дата съёмки
    if info.date_taken:
        add_risk_flag(
            flags,
            "DATE_TAKEN",
            RiskLevel.LOW,
            f"Дата съёмки: {info.date_taken}",
            ExifRiskWeight.DATE_INFO,
        )

    # Информация об авторе
    if info.artist or info.copyright:
        author_info = info.artist or info.copyright
        add_risk_flag(
            flags,
            "AUTHOR_INFO",
            RiskLevel.MEDIUM,
            f"Автор: {author_info}",
            ExifRiskWeight.AUTHOR_INFO,
        )

    # Программное обеспечение
    if info.software:
        add_risk_flag(
            flags,
            "SOFTWARE_INFO",
            RiskLevel.LOW,
            f"ПО: {info.software}",
            0,
        )

    # Много метаданных — повышенный риск
    if len(info.privacy_concerns) >= 3:
        add_risk_flag(
            flags,
            "MANY_METADATA",
            RiskLevel.MEDIUM,
            f"Найдено {len(info.privacy_concerns)} типов метаданных",
            ExifRiskWeight.MANY_METADATA,
        )

    # Размер и разрешение (информационно)
    if info.image_width and info.image_height:
        add_risk_flag(
            flags,
            "IMAGE_SIZE",
            RiskLevel.LOW,
            f"Разрешение: {info.image_width}x{info.image_height}",
            0,
        )

    # Рассчитываем итоговый риск
    risk_score = calculate_risk_score(flags)

    return risk_score.level, flags, risk_score.score
