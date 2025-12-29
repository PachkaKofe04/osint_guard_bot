# services/dns_service.py
import asyncio
import logging
from typing import List, Optional

import dns.resolver

from domain_scanner.models import DnsInfo
from utils.retry import retry_async

log = logging.getLogger(__name__)


def _resolve_records(domain: str, rtype: str, timeout: float = 3.0) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    try:
        answers = resolver.resolve(domain, rtype)
    except Exception:
        return []

    records: List[str] = []
    for rdata in answers:
        records.append(rdata.to_text())
    return records


def fetch_dns_sync(domain: str) -> Optional[DnsInfo]:
    try:
        a_records = _resolve_records(domain, "A")
        ns_records = _resolve_records(domain, "NS")
        mx_records = _resolve_records(domain, "MX")
        txt_records = _resolve_records(domain, "TXT")
    except Exception:
        return None

    return DnsInfo(
        a_records=a_records,
        ns_records=ns_records,
        mx_records=mx_records,
        txt_records=txt_records,
    )


@retry_async(max_attempts=3, backoff=2, exceptions=(Exception,))
async def fetch_dns(domain: str) -> Optional[DnsInfo]:
    """Fetch DNS records with retry mechanism"""
    log.debug(f"[DNS] Fetching DNS records for {domain}")
    result = await asyncio.to_thread(fetch_dns_sync, domain)

    if result:
        log.info(f"[DNS] Successfully fetched DNS for {domain}: A={len(result.a_records)}, NS={len(result.ns_records)}, MX={len(result.mx_records)}")
    else:
        log.warning(f"[DNS] Failed to fetch DNS for {domain}")

    return result
