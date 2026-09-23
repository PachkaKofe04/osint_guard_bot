# exif_scanner/formatter.py
"""Форматирование результатов EXIF для Telegram."""
from utils.safe_html import esc
from exif_scanner.models import ExifScanResult
from utils.risk_types import get_risk_emoji, get_risk_label, RiskLevel


def _format_file_size(size_bytes: int) -> str:
    """Форматирует размер файла."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def format_exif_result(result: ExifScanResult) -> str:
    """
    Форматирует результат анализа EXIF для Telegram.

    Args:
        result: Результат анализа

    Returns:
        Отформатированная строка с HTML разметкой
    """
    info = result.info
    emoji = get_risk_emoji(result.score)
    level_label = get_risk_label(result.risk_level)

    lines = []
    lines.append("📷 <b>Анализ метаданных изображения</b>")
    lines.append(f"<code>{esc(result.filename)}</code>")
    lines.append("")

    # Риск приватности
    lines.append(f"{emoji} <b>Риск приватности: {level_label}</b>")
    lines.append(f"Оценка: {result.score}/10")
    lines.append("")

    if info:
        # Базовая информация
        lines.append("📊 <b>Информация о файле:</b>")
        if info.file_size:
            lines.append(f"    Размер: {_format_file_size(info.file_size)}")
        if info.image_width and info.image_height:
            lines.append(f"    Разрешение: {info.image_width}×{info.image_height}")
        if info.format:
            lines.append(f"    Формат: {esc(info.format)}")
        lines.append("")

        if not info.has_exif:
            lines.append("⚠️ <b>EXIF данные не найдены</b>")
            lines.append("")
            if info.open_failed:
                lines.append("Не удалось открыть файл. Возможные причины:")
                lines.append("    • Формат не поддерживается")
                lines.append("    • Файл повреждён")
                lines.append("    • Отсутствуют зависимости (pillow-heif для HEIC)")
            else:
                lines.append("Возможные причины:")
                lines.append("    • <b>Telegram сжал фото</b> и удалил метаданные")
                lines.append("      → отправь <b>файлом</b> (Скрепка → Файл → выбери из галереи)")
                lines.append("    • <b>iOS удалил геолокацию</b> перед отправкой")
                lines.append("      → Настройки → Конфиденциальность → Службы геолокации → Камера → «При использовании»")
                lines.append("    • Фото не содержит EXIF (скриншоты, обработанные фото)")
        else:
            # GPS
            if info.has_gps and info.gps:
                lines.append("🚨 <b>GPS КООРДИНАТЫ НАЙДЕНЫ!</b>")
                lines.append(f"    📍 Широта: {info.gps.latitude:.6f}")
                lines.append(f"    📍 Долгота: {info.gps.longitude:.6f}")
                if info.gps.altitude:
                    lines.append(f"    📍 Высота: {info.gps.altitude:.1f} м")
                # Ссылка на карту
                maps_url = f"https://www.google.com/maps?q={info.gps.latitude},{info.gps.longitude}"
                lines.append(f"    🗺️ <a href=\"{maps_url}\">Открыть на карте</a>")
                lines.append("")
                lines.append("⚠️ <i>Удалите геолокацию перед публикацией!</i>")
                lines.append("")

            # Камера
            if info.camera_make or info.camera_model:
                lines.append("📱 <b>Устройство:</b>")
                if info.camera_make:
                    lines.append(f"    Производитель: {esc(info.camera_make)}")
                if info.camera_model:
                    lines.append(f"    Модель: {esc(info.camera_model)}")
                if info.lens_model:
                    lines.append(f"    Объектив: {esc(info.lens_model)}")
                lines.append("")

            # Дата
            if info.date_taken:
                lines.append("📅 <b>Дата съёмки:</b>")
                lines.append(f"    {esc(info.date_taken)}")
                lines.append("")

            # Настройки камеры
            camera_settings = []
            if info.focal_length:
                camera_settings.append(f"f={esc(info.focal_length)}")
            if info.aperture:
                camera_settings.append(f"F/{esc(info.aperture)}")
            if info.iso:
                camera_settings.append(f"ISO {info.iso}")
            if info.exposure_time:
                camera_settings.append(f"{esc(info.exposure_time)}s")

            if camera_settings:
                lines.append("⚙️ <b>Параметры съёмки:</b>")
                lines.append(f"    {esc(', '.join(camera_settings))}")
                lines.append("")

            # Софт
            if info.software:
                lines.append(f"💻 <b>ПО:</b> {esc(info.software)}")
                lines.append("")

            # Автор
            if info.artist or info.copyright:
                lines.append("👤 <b>Автор:</b>")
                if info.artist:
                    lines.append(f"    {esc(info.artist)}")
                if info.copyright:
                    lines.append(f"    © {esc(info.copyright)}")
                lines.append("")

    # Флаги рисков
    if result.flags:
        lines.append("📋 <b>Детали:</b>")
        for flag in result.flags:
            if flag.level == RiskLevel.HIGH:
                flag_emoji = "🔴"
            elif flag.level == RiskLevel.MEDIUM:
                flag_emoji = "🟡"
            else:
                flag_emoji = "🟢"
            lines.append(f"    {flag_emoji} {esc(flag.message)}")

    # Рекомендации
    if info and info.has_exif and (info.has_gps or len(info.privacy_concerns) >= 2):
        lines.append("")
        lines.append("💡 <b>Рекомендации:</b>")
        lines.append("    • Удаляйте EXIF перед публикацией в соцсетях")
        lines.append("    • Используйте инструменты вроде ExifTool")
        lines.append("    • Отключите геолокацию в настройках камеры")

    return "\n".join(lines)
