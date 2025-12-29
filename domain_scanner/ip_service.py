# domain_scanner/ip_service.py
import logging
from typing import Optional, Dict, Any

import requests

log = logging.getLogger(__name__)

IP_API_URL = "http://ip-api.com/json/"


def fetch_ip_profile(ip: str) -> Optional[Dict[str, Any]]:
    """
    Возвращает профиль по IP через ip-api.com (без ключа).
    """
    try:
        r = requests.get(
            f"{IP_API_URL}{ip}",
            params={"fields": "status,message,country,countryCode,city,isp,org,as,asname,proxy,hosting"},
            timeout=5,
        )
    except Exception as e:
        log.warning(f"[ip_service] request error ip={ip}: {e}")
        return None

    if r.status_code != 200:
        return None

    try:
        data = r.json()
    except ValueError:
        return None

    if data.get("status") != "success":
        return None

    return data
