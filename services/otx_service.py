# services/otx_service.py
"""AlienVault OTX API для проверки репутации доменов и IP."""
import logging
from typing import Optional, Dict, Any
import os

import requests

log = logging.getLogger(__name__)

OTX_API_URL = "https://otx.alienvault.com/api/v1/indicators"


def get_otx_api_key() -> Optional[str]:
    """Получить API ключ OTX из окружения."""
    return os.getenv("OTX_API_KEY")


def check_domain_reputation(domain: str) -> Optional[Dict[str, Any]]:
    """
    Проверка репутации домена через OTX.

    Returns:
        Dict с pulse_count, validation и т.д. или None если API недоступен
    """
    api_key = get_otx_api_key()
    if not api_key:
        log.debug("[OTX] API key not configured, skipping")
        return None

    try:
        headers = {"X-OTX-API-KEY": api_key}
        url = f"{OTX_API_URL}/domain/{domain}/general"

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            return {
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "malware_samples": len(data.get("malware", {}).get("data", [])),
                "validation": data.get("validation", []),
                "whois": data.get("whois"),
                "alexa_rank": data.get("alexa"),
            }
        elif response.status_code == 404:
            return {"pulse_count": 0, "malware_samples": 0, "validation": []}
        else:
            log.warning(f"[OTX] Domain check failed: {response.status_code}")
            return None

    except Exception as e:
        log.warning(f"[OTX] Domain check error: {e}")
        return None


def check_ip_reputation(ip: str) -> Optional[Dict[str, Any]]:
    """
    Проверка репутации IP через OTX.

    Returns:
        Dict с pulse_count, malware_samples и т.д. или None если API недоступен
    """
    api_key = get_otx_api_key()
    if not api_key:
        log.debug("[OTX] API key not configured, skipping")
        return None

    try:
        headers = {"X-OTX-API-KEY": api_key}

        # Определяем IPv4 или IPv6
        indicator_type = "IPv6" if ":" in ip else "IPv4"
        url = f"{OTX_API_URL}/{indicator_type}/{ip}/general"

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            return {
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "malware_samples": len(data.get("malware", {}).get("data", [])),
                "validation": data.get("validation", []),
                "reputation": data.get("reputation", 0),
                "country": data.get("country_name"),
                "asn": data.get("asn"),
            }
        elif response.status_code == 404:
            return {"pulse_count": 0, "malware_samples": 0, "validation": [], "reputation": 0}
        else:
            log.warning(f"[OTX] IP check failed: {response.status_code}")
            return None

    except Exception as e:
        log.warning(f"[OTX] IP check error: {e}")
        return None
