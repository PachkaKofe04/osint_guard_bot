"""Живая проверка кандидатов в источники данных."""
import asyncio
import json
import time

import aiohttp

UA = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Guard/1.0)"}

# Тестовые объекты
BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"          # genesis / Satoshi
ETH = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # vitalik.eth
TRX = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"          # USDT contract
SOL = "So11111111111111111111111111111111111111112"
DOGE = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"
LTC = "LQ3hRiEcWQtRMLkfWDNHMZjHpVEwZDqCFN"
XRP = "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh"

CASES = [
    # --- утечки ---
    ("Утечки", "XposedOrNot (без ключа)",
     "https://api.xposedornot.com/v1/check-email/test@example.com", None),
    ("Утечки", "XposedOrNot breaches list",
     "https://api.xposedornot.com/v1/breaches", None),

    # --- BTC ---
    ("Кошелёк BTC", "Blockstream esplora",
     f"https://blockstream.info/api/address/{BTC}", None),
    ("Кошелёк BTC", "mempool.space",
     f"https://mempool.space/api/address/{BTC}", None),
    ("Кошелёк BTC", "blockchain.info",
     f"https://blockchain.info/rawaddr/{BTC}?limit=1", None),

    # --- ETH ---
    ("Кошелёк ETH", "Blockscout eth (v2 api)",
     f"https://eth.blockscout.com/api/v2/addresses/{ETH}", None),
    ("Кошелёк ETH", "Blockscout eth (counters)",
     f"https://eth.blockscout.com/api/v2/addresses/{ETH}/counters", None),
    ("Кошелёк ETH", "Ethplorer (freekey)",
     f"https://api.ethplorer.io/getAddressInfo/{ETH}?apiKey=freekey", None),

    # --- прочие сети ---
    ("Кошелёк TRX", "Tronscan",
     f"https://apilist.tronscanapi.com/api/account?address={TRX}", None),
    ("Кошелёк TRX", "TronGrid",
     f"https://api.trongrid.io/v1/accounts/{TRX}", None),
    ("Кошелёк SOL", "Solana public RPC", "POST", {
        "url": "https://api.mainnet-beta.solana.com",
        "json": {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [SOL]},
    }),
    ("Кошелёк DOGE", "dogechain.info",
     f"https://dogechain.info/api/v1/address/balance/{DOGE}", None),
    ("Кошелёк LTC", "litecoinspace.org (esplora)",
     f"https://litecoinspace.org/api/address/{LTC}", None),
    ("Кошелёк XRP", "XRPL public (rippled)", "POST", {
        "url": "https://s1.ripple.com:51234/",
        "json": {"method": "account_info", "params": [{"account": XRP}]},
    }),

    # --- скам-базы ---
    ("Скам-база", "ScamSniffer blacklist (GitHub raw)",
     "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json", None),
    ("Скам-база", "ScamSniffer domains",
     "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json", None),
    ("Скам-база", "CryptoScamDB blacklist (GitHub raw)",
     "https://raw.githubusercontent.com/CryptoScamDB/blacklist/master/data/urls.json", None),
    ("Скам-база", "CryptoScamDB API (старый)",
     "https://api.cryptoscamdb.org/v1/check/0x0000000000000000000000000000000000000000", None),

    # --- фишинг / URL ---
    ("Фишинг URL", "URLhaus API (POST)", "POST", {
        "url": "https://urlhaus-api.abuse.ch/v1/url/",
        "data": {"url": "http://example.com/"},
    }),
    ("Фишинг URL", "URLhaus recent feed",
     "https://urlhaus.abuse.ch/downloads/json_recent/", None),
    ("Фишинг URL", "OpenPhish community feed",
     "https://openphish.com/feed.txt", None),
    ("Фишинг URL", "Phishing.Database (GitHub raw)",
     "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-today.txt", None),

    # --- домены / SSL ---
    ("SSL / CT", "crt.sh",
     "https://crt.sh/?q=google.com&output=json", None),
    ("SSL / CT", "certspotter (без ключа)",
     "https://api.certspotter.com/v1/issuances?domain=google.com&include_subdomains=false&expand=dns_names", None),
    ("Домен", "RDAP (IANA, замена WHOIS)",
     "https://rdap.org/domain/google.com", None),

    # --- BIN ---
    ("BIN карты", "binlist.net",
     "https://lookup.binlist.net/45717360", None),
    ("BIN карты", "bincheck.io (без ключа?)",
     "https://bincheck.io/api/bin/45717360", None),
    ("BIN карты", "Handy API (без ключа?)",
     "https://data.handyapi.com/bin/45717360", None),

    # --- IP ---
    ("IP", "ip-api.com",
     "http://ip-api.com/json/8.8.8.8", None),
    ("IP", "ipwho.is (HTTPS, без ключа)",
     "https://ipwho.is/8.8.8.8", None),
    ("IP", "ipapi.co (HTTPS, без ключа)",
     "https://ipapi.co/8.8.8.8/json/", None),
    ("IP", "Tor exit list (проверка Tor)",
     "https://check.torproject.org/torbulkexitlist", None),

    # --- почта ---
    ("Email", "disposable domains (GitHub raw)",
     "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf", None),
]


async def check(session, group, name, arg1, arg2):
    t0 = time.perf_counter()
    try:
        if arg1 == "POST":
            kwargs = {k: v for k, v in arg2.items() if k != "url"}
            ctx = session.post(arg2["url"], headers=UA,
                               timeout=aiohttp.ClientTimeout(total=20), **kwargs)
        else:
            ctx = session.get(arg1, headers=UA,
                              timeout=aiohttp.ClientTimeout(total=20))
        async with ctx as r:
            body = await r.read()
            ms = int((time.perf_counter() - t0) * 1000)
            size = len(body)
            snippet = body[:95].decode("utf-8", "ignore").replace("\n", " ").replace("\r", "")
            if r.status == 200:
                mark = "OK"
            elif r.status in (401, 403):
                mark = "KEY"
            elif r.status == 429:
                mark = "LIMIT"
            else:
                mark = "FAIL"
            print(f"{mark:6}{r.status:>4} {ms:>6}ms {size:>9}b  {group:14} {name:34} {snippet[:70]}")
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        print(f"{'DEAD':6}{'---':>4} {ms:>6}ms {'-':>9}   {group:14} {name:34} {type(e).__name__}: {str(e)[:50]}")


async def main():
    conn = aiohttp.TCPConnector(limit=12, ssl=False)
    async with aiohttp.ClientSession(connector=conn) as s:
        await asyncio.gather(*[check(s, g, n, a1, a2) for g, n, a1, a2 in CASES])


asyncio.run(main())
