# qr_scanner/scanner.py
"""Основной модуль декодирования QR кодов."""
import io
import logging
import re
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import urlparse, parse_qs

from PIL import Image

from qr_scanner.models import (
    QrInfo, QrScanResult, QrContentType, WifiInfo
)
from qr_scanner.risk_engine import calculate_qr_risk

log = logging.getLogger(__name__)

# Попытка импортировать pyzbar
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False
    log.warning("[QR] pyzbar not available, QR decoding will be limited")


# Подозрительные TLD для URL
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Бесплатные TLD
    ".xyz", ".top", ".work", ".click",
    ".link", ".loan", ".online", ".site",
}

# Сервисы сокращения ссылок
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "j.mp", "rb.gy",
    "cutt.ly", "shorturl.at", "tiny.cc", "v.gd",
}

# Подозрительные паттерны в URL
PHISHING_PATTERNS = [
    r"login.*\d{3,}",  # login с цифрами
    r"secure.*verify",
    r"update.*account",
    r"confirm.*identity",
    r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",  # IP в URL
]


def _detect_content_type(data: str) -> QrContentType:
    """Определяет тип содержимого QR кода."""
    data_lower = data.lower()

    if data_lower.startswith(("http://", "https://", "www.")):
        return QrContentType.URL
    if data_lower.startswith("mailto:") or ("@" in data and "." in data.split("@")[-1]):
        return QrContentType.EMAIL
    if data_lower.startswith(("tel:", "phone:")):
        return QrContentType.PHONE
    if data_lower.startswith("smsto:") or data_lower.startswith("sms:"):
        return QrContentType.SMS
    if data_lower.startswith("wifi:"):
        return QrContentType.WIFI
    if data_lower.startswith("begin:vcard"):
        return QrContentType.VCARD
    if data_lower.startswith("geo:"):
        return QrContentType.GEO
    if data_lower.startswith(("bitcoin:", "ethereum:", "litecoin:")):
        return QrContentType.CRYPTO
    # Проверка на crypto адреса без префикса
    if re.match(r"^(1|3|bc1)[a-zA-Z0-9]{25,62}$", data):
        return QrContentType.CRYPTO
    if re.match(r"^0x[a-fA-F0-9]{40}$", data):
        return QrContentType.CRYPTO

    return QrContentType.TEXT


def _parse_wifi(data: str) -> Optional[WifiInfo]:
    """Парсит WiFi информацию из QR кода."""
    # Формат: WIFI:T:WPA;S:MyNetwork;P:MyPassword;H:true;;
    try:
        wifi = WifiInfo()

        # Извлекаем параметры
        if "S:" in data:
            match = re.search(r"S:([^;]*)", data)
            if match:
                wifi.ssid = match.group(1)

        if "P:" in data:
            match = re.search(r"P:([^;]*)", data)
            if match:
                wifi.password = match.group(1)

        if "T:" in data:
            match = re.search(r"T:([^;]*)", data)
            if match:
                wifi.security = match.group(1)

        if "h:true" in data.lower():
            wifi.hidden = True

        return wifi
    except Exception:
        return None


def _parse_geo(data: str) -> Tuple[Optional[float], Optional[float]]:
    """Парсит географические координаты."""
    try:
        # Формат: geo:lat,lon или geo:lat,lon?q=...
        match = re.search(r"geo:(-?[\d.]+),(-?[\d.]+)", data.lower())
        if match:
            return float(match.group(1)), float(match.group(2))
    except Exception:
        pass
    return None, None


def _parse_crypto(data: str) -> Tuple[Optional[str], Optional[str]]:
    """Парсит крипто адрес и сумму."""
    address = None
    amount = None

    try:
        # bitcoin:address?amount=X
        if ":" in data:
            parts = data.split(":", 1)
            rest = parts[1]
            if "?" in rest:
                address = rest.split("?")[0]
                parsed = parse_qs(rest.split("?")[1])
                if "amount" in parsed:
                    amount = parsed["amount"][0]
            else:
                address = rest
        else:
            address = data
    except Exception:
        pass

    return address, amount


def _analyze_url(url: str) -> dict:
    """Анализирует URL на подозрительность."""
    result = {
        "domain": None,
        "is_shortened": False,
        "has_suspicious_tld": False,
        "looks_phishy": False,
    }

    try:
        # Нормализуем URL
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        result["domain"] = domain

        # Проверка на сокращатели
        for shortener in URL_SHORTENERS:
            if shortener in domain:
                result["is_shortened"] = True
                break

        # Проверка TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result["has_suspicious_tld"] = True
                break

        # Проверка фишинговых паттернов
        full_url = url.lower()
        for pattern in PHISHING_PATTERNS:
            if re.search(pattern, full_url):
                result["looks_phishy"] = True
                break

        # Дополнительные проверки
        # Много поддоменов
        if domain.count(".") > 3:
            result["looks_phishy"] = True

        # Длинный домен с цифрами
        if len(domain) > 30 and any(c.isdigit() for c in domain):
            result["looks_phishy"] = True

    except Exception as e:
        log.warning(f"[QR] URL analysis error: {e}")

    return result


async def scan_qr(image_data: bytes, filename: str = "image") -> QrScanResult:
    """
    Декодирует QR код из изображения.

    Args:
        image_data: Байты изображения
        filename: Имя файла

    Returns:
        QrScanResult
    """
    log.info(f"[QR Scanner] Scanning: {filename}")

    # Проверяем доступность pyzbar
    if not PYZBAR_AVAILABLE:
        log.error("[QR] pyzbar library not available")
        risk_level, flags, score = calculate_qr_risk(None, library_error=True)
        return QrScanResult(
            filename=filename,
            info=None,
            found_qr=False,
            risk_level=risk_level,
            flags=flags,
            score=score,
            scanned_at=datetime.utcnow(),
        )

    try:
        image = Image.open(io.BytesIO(image_data))
    except Exception as e:
        log.warning(f"[QR] Cannot open image: {e}")
        risk_level, flags, score = calculate_qr_risk(None)
        return QrScanResult(
            filename=filename,
            info=None,
            found_qr=False,
            risk_level=risk_level,
            flags=flags,
            score=score,
            scanned_at=datetime.utcnow(),
        )

    # Декодируем QR
    try:
        decoded_objects = pyzbar_decode(image)
    except Exception as e:
        log.warning(f"[QR] Decode error: {e}")
        decoded_objects = []
    finally:
        image.close()

    if not decoded_objects:
        log.info("[QR] No QR codes found")
        risk_level, flags, score = calculate_qr_risk(None, no_qr_found=True)
        return QrScanResult(
            filename=filename,
            info=None,
            found_qr=False,
            risk_level=risk_level,
            flags=flags,
            score=score,
            scanned_at=datetime.utcnow(),
        )

    # Берём первый QR код
    qr_obj = decoded_objects[0]
    raw_data = qr_obj.data.decode("utf-8", errors="ignore")

    # Определяем тип содержимого
    content_type = _detect_content_type(raw_data)

    # Создаём QrInfo
    info = QrInfo(
        raw_data=raw_data,
        content_type=content_type,
        decoded_count=len(decoded_objects),
        data_length=len(raw_data),
    )

    # Парсим специфичные данные
    if content_type == QrContentType.URL:
        url = raw_data
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        info.url = url
        analysis = _analyze_url(url)
        info.url_domain = analysis["domain"]
        info.url_is_shortened = analysis["is_shortened"]
        info.url_has_suspicious_tld = analysis["has_suspicious_tld"]
        info.url_looks_phishy = analysis["looks_phishy"]

    elif content_type == QrContentType.EMAIL:
        email = raw_data.replace("mailto:", "").split("?")[0]
        info.email = email

    elif content_type == QrContentType.PHONE:
        phone = raw_data.replace("tel:", "").replace("phone:", "")
        info.phone = phone

    elif content_type == QrContentType.WIFI:
        info.wifi = _parse_wifi(raw_data)

    elif content_type == QrContentType.GEO:
        lat, lon = _parse_geo(raw_data)
        info.geo_lat = lat
        info.geo_lon = lon

    elif content_type == QrContentType.CRYPTO:
        address, amount = _parse_crypto(raw_data)
        info.crypto_address = address
        info.crypto_amount = amount

    # Рассчитываем риск
    risk_level, flags, score = calculate_qr_risk(info)

    result = QrScanResult(
        filename=filename,
        info=info,
        found_qr=True,
        risk_level=risk_level,
        flags=flags,
        score=score,
        scanned_at=datetime.utcnow(),
    )

    log.info(f"[QR Scanner] Decoded: type={content_type.value}, length={len(raw_data)}")

    return result
