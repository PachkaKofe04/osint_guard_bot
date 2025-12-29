# services/veriphone_service.py
"""
Сервис для работы с Veriphone API.
API документация: https://veriphone.io/docs/v2
"""
import logging
from typing import Optional, Dict, Any

import aiohttp

from utils.retry import retry_async

log = logging.getLogger(__name__)

VERIPHONE_API_URL = "https://api.veriphone.io/v2/verify"


@retry_async(max_attempts=2, backoff=1, exceptions=(Exception,))
async def verify_phone_veriphone(
    phone: str,
    api_key: str
) -> Optional[Dict[str, Any]]:
    """
    Проверить телефонный номер через Veriphone API.

    Args:
        phone: Номер телефона (с + или без)
        api_key: API ключ Veriphone

    Returns:
        {
            "status": "success",
            "phone": "+14155552671",
            "phone_valid": true,
            "phone_type": "mobile",
            "phone_region": "California",
            "country": "United States",
            "country_code": "US",
            "country_prefix": "1",
            "carrier": "T-Mobile USA, Inc."
        }
    """
    params = {
        "key": api_key,
        "phone": phone
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                VERIPHONE_API_URL,
                params=params,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                response.raise_for_status()
                data = await response.json()

                if data.get("status") != "success":
                    log.error(f"[VERIPHONE] API returned error: {data.get('error')}")
                    return None

                log.info(
                    f"[VERIPHONE] {phone} → "
                    f"valid={data.get('phone_valid')}, "
                    f"country={data.get('country_code')}, "
                    f"carrier={data.get('carrier')}"
                )

                return data

    except aiohttp.ClientError as e:
        log.error(f"[VERIPHONE] HTTP error for {phone}: {e}")
        return None
    except Exception as e:
        log.error(f"[VERIPHONE] Unexpected error for {phone}: {e}")
        return None
