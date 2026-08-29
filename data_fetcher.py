"""
data_fetcher.py
----------------
Talks to CoinDCX's PUBLIC market data API (no API key required).
Docs: https://coindcx.com/api/help/Market%20Data%20on%20CoinDCX%20API/Candles

If CoinDCX changes their API in the future, this is the only file
that should need updating — everything else in the app depends on
the clean pandas DataFrame this file returns, not on CoinDCX's raw
response format. That's intentional (see the "modular architecture"
requirement in the build spec).
"""

import requests
import pandas as pd

BASE_URL = "https://public.coindcx.com"
REQUEST_TIMEOUT = 10  # seconds


def get_candles(pair: str, interval: str = "5m", limit: int = 300) -> pd.DataFrame:
    """
    Fetch OHLCV candles for a given pair.

    pair: CoinDCX pair code, e.g. 'B-BTC_USDT'
    interval: one of '1m','5m','15m','30m','1h','2h','4h','6h','1d'
    limit: number of most recent candles to fetch (max ~500 per CoinDCX docs)

    Returns a DataFrame with columns: time, open, high, low, close, volume
    sorted oldest -> newest. Returns an empty DataFrame on failure so callers
    can check `.empty` instead of crashing.
    """
    url = f"{BASE_URL}/market_data/candles"
    params = {"pair": pair, "interval": interval, "limit": limit}

    try:
        resp = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return pd.DataFrame()

    if not data or not isinstance(data, list):
        return pd.DataFrame()

    df = pd.DataFrame(data)
    required_cols = {"open", "high", "low", "close", "volume", "time"}
    if not required_cols.issubset(df.columns):
        return pd.DataFrame()

    df["time"] = pd.to_datetime(df["time"], unit="ms")
    df = df.sort_values("time").reset_index(drop=True)
    df = df[["time", "open", "high", "low", "close", "volume"]]

    for col in ["open", "high", "low", "close", "volume"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna().reset_index(drop=True)
    return df


def get_ticker() -> pd.DataFrame:
    """
    Fetch current ticker snapshot (last price, 24h high/low/volume/change)
    for every market CoinDCX lists. Useful later for the market scanner (Phase 4+).
    """
    url = f"{BASE_URL}/exchange/ticker"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return pd.DataFrame(resp.json())
    except (requests.RequestException, ValueError):
        return pd.DataFrame()


def data_quality_report(df: pd.DataFrame, interval: str) -> list:
    """
    Very simple version of the "data-quality kill switch" from the build spec.
    Returns a list of human-readable warning strings. Empty list = data looks fine.

    This does NOT block anything yet (Phase 1 is display-only), but the
    warnings are surfaced in the dashboard so you get used to seeing them —
    later phases will actually refuse to generate signals when these fire.
    """
    warnings = []

    if df.empty:
        warnings.append("No data returned at all.")
        return warnings

    if len(df) < 50:
        warnings.append(f"Only {len(df)} candles available — too few for reliable indicators (need 200+ ideally).")

    # Expected seconds between candles
    interval_seconds = {
        "1m": 60, "5m": 300, "15m": 900, "30m": 1800,
        "1h": 3600, "2h": 7200, "4h": 14400, "6h": 21600, "1d": 86400,
    }.get(interval)

    if interval_seconds:
        gaps = df["time"].diff().dt.total_seconds().dropna()
        bad_gaps = gaps[gaps > interval_seconds * 1.5]
        if len(bad_gaps) > 0:
            warnings.append(f"{len(bad_gaps)} missing/irregular candle gap(s) detected.")

    # Crude outlier check: any single-candle move > 15% is worth flagging
    pct_moves = df["close"].pct_change().abs().dropna()
    extreme = pct_moves[pct_moves > 0.15]
    if len(extreme) > 0:
        warnings.append(f"{len(extreme)} candle(s) with >15% single-candle move — verify these aren't bad ticks.")

    return warnings
