import asyncio, time, json
import aiohttp

TARGETS = [
    ("ip-api.com (IP гео)",        "GET", "http://ip-api.com/json/8.8.8.8", None),
    ("binlist.net (BIN)",          "GET", "https://lookup.binlist.net/45717360", None),
    ("crt.sh (SSL/CT)",            "GET", "https://crt.sh/?q=google.com&output=json", None),
    ("Blockchair BTC (wallet)",    "GET", "https://api.blockchair.com/bitcoin/dashboards/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", None),
    ("CryptoScamDB (скам-база)",   "GET", "https://api.cryptoscamdb.org/v1/check/0x742d35Cc6634C0532925a3b844Bc9e7595f8fE01", None),
    ("CoinGecko (курсы)",          "GET", "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd", None),
    ("Gravatar",                   "GET", "https://www.gravatar.com/avatar/205e460b479e2e5b48aec07710c08d50?s=200&d=404", None),
    ("HIBP (нужен ключ)",          "GET", "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com", None),
    ("AbuseIPDB (нужен ключ)",     "GET", "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8", None),
    ("OTX AlienVault",             "GET", "https://otx.alienvault.com/api/v1/indicators/domain/google.com/general", None),
    ("GitHub (username probe)",    "GET", "https://github.com/torvalds", None),
]

async def check(session, name, method, url, headers):
    t0 = time.perf_counter()
    try:
        async with session.request(method, url, headers=headers or {"User-Agent": "Mozilla/5.0 (OSINT-Guard-Audit)"},
                                   timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True) as r:
            body = await r.read()
            ms = int((time.perf_counter() - t0) * 1000)
            snippet = body[:110].decode("utf-8", "ignore").replace("\n", " ")
            verdict = "OK" if r.status == 200 else ("AUTH" if r.status in (401,403) else ("LIMIT" if r.status == 429 else "FAIL"))
            print(f"{verdict:6} {r.status:>3}  {ms:>6}ms  {name:30} {snippet[:90]}")
    except Exception as e:
        ms = int((time.perf_counter() - t0) * 1000)
        print(f"{'DEAD':6} {'---':>3}  {ms:>6}ms  {name:30} {type(e).__name__}: {str(e)[:70]}")

async def main():
    async with aiohttp.ClientSession() as s:
        await asyncio.gather(*[check(s, *t) for t in TARGETS])

asyncio.run(main())
