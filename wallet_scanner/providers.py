# wallet_scanner/providers.py
"""
Получение балансов по сетям.

Blockchair, на котором всё держалось раньше, отдаёт HTTP 430 - наш IP у них
в блэклисте, и адресные запросы не проходят. Вместо одного универсального
источника используем по провайдеру на сеть. Все работают без ключей и
проверены живыми запросами.

    BTC             mempool.space (esplora), резерв blockstream.info
    ETH             Blockscout, резерв Etherscan V2 при наличии ключа
    LTC, DOGE, DASH BlockCypher
    TRX             TronGrid
    SOL             публичный RPC Solana
    XRP             публичный rippled

Отдельно про XMR: балансы Monero по адресу получить нельзя в принципе,
протокол их не раскрывает. Провайдер для него намеренно отсутствует, и
сканер обязан сказать об этом прямо, а не показывать пустой результат.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Optional

import aiohttp

from config import settings

log = logging.getLogger(__name__)

TIMEOUT = aiohttp.ClientTimeout(total=12)
HEADERS = {"User-Agent": "OSINT-Guard-Bot/1.0"}

# Монеты, для которых баланс недоступен по устройству сети, а не по нашей вине
PRIVACY_COINS = {"XMR"}


@dataclass
class ChainData:
    """Данные по адресу из блокчейна."""

    balance: Optional[Decimal] = None
    tx_count: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_contract: bool = False
    # Делегирование EIP-7702: адрес остаётся обычным кошельком, но исполняет
    # код смарт-аккаунта. Blockscout помечает такие как is_contract, и без
    # различения бот называл смарт-контрактом обычный кошелёк.
    is_smart_account: bool = False
    contract_name: Optional[str] = None
    source: Optional[str] = None


async def _get_json(session: aiohttp.ClientSession, url: str, **kwargs):
    async with session.get(url, headers=HEADERS, timeout=TIMEOUT, **kwargs) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        return await response.json(content_type=None)


async def _post_json(session: aiohttp.ClientSession, url: str, payload: dict):
    async with session.post(url, json=payload, headers=HEADERS, timeout=TIMEOUT) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        return await response.json(content_type=None)


# --- Bitcoin и совместимые (esplora) ---------------------------------------

async def _fetch_esplora(session, base: str, address: str, source: str) -> ChainData:
    """
    mempool.space и blockstream.info отдают одинаковый формат esplora.

    Баланс считается как funded минус spent: отдельного поля баланса в API нет.
    """
    data = await _get_json(session, f"{base}/api/address/{address}")
    chain = data.get("chain_stats", {}) or {}
    mempool = data.get("mempool_stats", {}) or {}

    funded = int(chain.get("funded_txo_sum", 0)) + int(mempool.get("funded_txo_sum", 0))
    spent = int(chain.get("spent_txo_sum", 0)) + int(mempool.get("spent_txo_sum", 0))
    tx_count = int(chain.get("tx_count", 0)) + int(mempool.get("tx_count", 0))

    return ChainData(
        balance=Decimal(funded - spent) / Decimal(10 ** 8),
        tx_count=tx_count,
        source=source,
    )


async def fetch_btc(session, address: str) -> ChainData:
    try:
        return await _fetch_esplora(session, "https://mempool.space", address, "mempool.space")
    except Exception as exc:
        log.info("[wallet] mempool.space недоступен (%s), пробую blockstream", exc)
        return await _fetch_esplora(
            session, "https://blockstream.info", address, "blockstream.info"
        )


# --- Ethereum --------------------------------------------------------------

async def fetch_eth(session, address: str) -> ChainData:
    """Blockscout как основной источник, Etherscan как резерв при наличии ключа."""
    try:
        data = await _get_json(
            session, f"https://eth.blockscout.com/api/v2/addresses/{address}"
        )
        balance = Decimal(str(data.get("coin_balance") or 0)) / Decimal(10 ** 18)
        is_smart_account = (data.get("proxy_type") or "").lower() == "eip7702"
        is_contract = bool(data.get("is_contract")) and not is_smart_account

        tx_count = None
        try:
            counters = await _get_json(
                session, f"https://eth.blockscout.com/api/v2/addresses/{address}/counters"
            )
            tx_count = int(counters.get("transactions_count") or 0)
        except Exception:
            log.debug("[wallet] Blockscout: счётчики транзакций недоступны")

        return ChainData(
            balance=balance, tx_count=tx_count,
            is_contract=is_contract,
            is_smart_account=is_smart_account,
            contract_name=data.get("name"),
            source="Blockscout",
        )
    except Exception as exc:
        if not settings.ETHERSCAN_API_KEY:
            raise
        log.info("[wallet] Blockscout недоступен (%s), пробую Etherscan", exc)
        data = await _get_json(
            session, "https://api.etherscan.io/v2/api",
            params={
                "chainid": "1", "module": "account", "action": "balance",
                "address": address, "tag": "latest",
                "apikey": settings.ETHERSCAN_API_KEY,
            },
        )
        if str(data.get("status")) != "1":
            raise RuntimeError(data.get("result") or "Etherscan вернул ошибку")
        return ChainData(
            balance=Decimal(str(data["result"])) / Decimal(10 ** 18),
            source="Etherscan",
        )


# --- BlockCypher: LTC, DOGE, DASH ------------------------------------------

BLOCKCYPHER_CHAINS = {"LTC": "ltc", "DOGE": "doge", "DASH": "dash"}


async def fetch_blockcypher(session, address: str, currency: str) -> ChainData:
    chain = BLOCKCYPHER_CHAINS[currency]
    data = await _get_json(
        session, f"https://api.blockcypher.com/v1/{chain}/main/addrs/{address}/balance"
    )
    return ChainData(
        balance=Decimal(str(data.get("balance", 0))) / Decimal(10 ** 8),
        tx_count=data.get("n_tx"),
        source="BlockCypher",
    )


# --- Tron ------------------------------------------------------------------

async def fetch_trx(session, address: str) -> ChainData:
    data = await _get_json(session, f"https://api.trongrid.io/v1/accounts/{address}")
    items = data.get("data") or []
    if not items:
        # TronGrid отвечает 200 с пустым списком для адресов без активности
        return ChainData(balance=Decimal(0), tx_count=0, source="TronGrid")

    account = items[0]
    created = account.get("create_time")
    return ChainData(
        balance=Decimal(str(account.get("balance", 0))) / Decimal(10 ** 6),
        first_seen=datetime.fromtimestamp(created / 1000) if created else None,
        source="TronGrid",
    )


# --- Solana ----------------------------------------------------------------

async def fetch_sol(session, address: str) -> ChainData:
    data = await _post_json(session, "https://api.mainnet-beta.solana.com", {
        "jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [address],
    })
    lamports = ((data.get("result") or {}).get("value"))
    if lamports is None:
        raise RuntimeError("Solana RPC не вернул баланс")
    return ChainData(
        balance=Decimal(str(lamports)) / Decimal(10 ** 9),
        source="Solana RPC",
    )


# --- XRP -------------------------------------------------------------------

async def fetch_xrp(session, address: str) -> ChainData:
    data = await _post_json(session, "https://s1.ripple.com:51234/", {
        "method": "account_info",
        "params": [{"account": address, "ledger_index": "validated"}],
    })
    result = data.get("result") or {}
    if result.get("status") == "error":
        # Незанятый адрес: в XRPL это не ошибка запроса, а отсутствие аккаунта
        if result.get("error") == "actNotFound":
            return ChainData(balance=Decimal(0), tx_count=0, source="XRPL")
        raise RuntimeError(result.get("error_message") or result.get("error"))

    account = result.get("account_data") or {}
    return ChainData(
        balance=Decimal(str(account.get("Balance", 0))) / Decimal(10 ** 6),
        tx_count=account.get("Sequence"),
        source="XRPL",
    )


# --- диспетчер -------------------------------------------------------------

async def fetch_chain_data(address: str, currency: str) -> Optional[ChainData]:
    """
    Данные по адресу. None означает «получить не удалось».

    Для монет из PRIVACY_COINS возвращается None всегда: это свойство
    протокола, а не сбой. Вызывающий код различает эти случаи сам.
    """
    if currency in PRIVACY_COINS:
        return None

    handlers = {
        "BTC": fetch_btc,
        "BCH": None,   # BlockCypher не поддерживает, Blockchair нас блокирует
        "ETH": fetch_eth,
        "TRX": fetch_trx,
        "SOL": fetch_sol,
        "XRP": fetch_xrp,
    }

    try:
        async with aiohttp.ClientSession() as session:
            if currency in BLOCKCYPHER_CHAINS:
                return await fetch_blockcypher(session, address, currency)

            handler = handlers.get(currency)
            if handler is None:
                log.info("[wallet] Для %s нет провайдера баланса", currency)
                return None

            return await handler(session, address)
    except Exception as exc:
        log.warning("[wallet] %s:%s - не удалось получить данные: %s", currency, address, exc)
        return None


def balance_available(currency: str) -> bool:
    """Поддерживается ли получение баланса для этой монеты в принципе."""
    if currency in PRIVACY_COINS:
        return False
    return currency in {"BTC", "ETH", "TRX", "SOL", "XRP"} | set(BLOCKCYPHER_CHAINS)
