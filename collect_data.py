"""
collect_data.py
----------------
Pulls the latest candles for every coin/interval we track and stores them
permanently in Postgres. Meant to run on a schedule (see
.github/workflows/collect_data.yml), NOT to be run by hand each time.

Safe to re-run anytime — duplicate candles are upserted, not duplicated,
so running this every 15 minutes just keeps adding new candles as they close.
"""

import sys

from data_fetcher import get_candles
from db import upsert_candles, ensure_table, is_configured

COINS = {
    "BTC": "B-BTC_USDT",
    "ETH": "B-ETH_USDT",
    "SOL": "B-SOL_USDT",
    "XRP": "B-XRP_USDT",
    "DOGE": "B-DOGE_USDT",
    "BNB": "B-BNB_USDT",
    "ADA": "B-ADA_USDT",
    "AVAX": "B-AVAX_USDT",
    "LINK": "B-LINK_USDT",
}

# Fewer intervals than the full spec for now, to keep each run fast and
# stay comfortably inside free-tier limits. Easy to expand later.
INTERVALS = ["1m", "5m", "15m", "1h", "1d"]


def main():
    if not is_configured():
        print("ERROR: DATABASE_URL is not set. Add it as a GitHub Actions secret "
              "(Settings -> Secrets and variables -> Actions).")
        sys.exit(1)

    ensure_table()

    total = 0
    failures = 0
    for coin, pair in COINS.items():
        for interval in INTERVALS:
            df = get_candles(pair, interval=interval, limit=500)
            if df.empty:
                print(f"{coin:5s} {interval:4s} -> WARNING: no data returned")
                failures += 1
                continue
            n = upsert_candles(pair, interval, df)
            total += n
            print(f"{coin:5s} {interval:4s} -> {n} candles upserted")

    print(f"Done. {total} candle-rows processed, {failures} coin/interval combos failed this run.")
    # Don't hard-fail the whole job for a few missing combos — CoinDCX
    # occasionally hiccups on one pair without the rest being affected.
    if failures == len(COINS) * len(INTERVALS):
        sys.exit(1)


if __name__ == "__main__":
    main()
