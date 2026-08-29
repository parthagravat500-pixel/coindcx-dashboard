"""
indicators.py
-------------
Pure pandas/numpy implementations of the core indicators from the build spec.
No external TA library required, so there's nothing extra to install or that
can silently disagree with itself on formulas.

Every function takes a DataFrame with at least open/high/low/close/volume
columns and returns the same DataFrame with new columns added.
"""

import numpy as np
import pandas as pd


def add_moving_averages(df: pd.DataFrame) -> pd.DataFrame:
    for length in [9, 20, 50, 100, 200]:
        df[f"ema_{length}"] = df["close"].ewm(span=length, adjust=False).mean()
    for length in [20, 50, 100, 200]:
        df[f"sma_{length}"] = df["close"].rolling(length).mean()
    return df


def add_rsi(df: pd.DataFrame, period: int = 14) -> pd.DataFrame:
    delta = df["close"].diff()
    gain = delta.clip(lower=0)
    loss = -delta.clip(upper=0)
    avg_gain = gain.rolling(period).mean()
    avg_loss = loss.rolling(period).mean()
    rs = avg_gain / avg_loss.replace(0, np.nan)
    df["rsi_14"] = 100 - (100 / (1 + rs))
    return df


def add_stoch_rsi(df: pd.DataFrame, period: int = 14) -> pd.DataFrame:
    if "rsi_14" not in df.columns:
        df = add_rsi(df, period)
    rsi = df["rsi_14"]
    min_rsi = rsi.rolling(period).min()
    max_rsi = rsi.rolling(period).max()
    df["stoch_rsi"] = (rsi - min_rsi) / (max_rsi - min_rsi).replace(0, np.nan)
    return df


def add_macd(df: pd.DataFrame, fast: int = 12, slow: int = 26, signal: int = 9) -> pd.DataFrame:
    ema_fast = df["close"].ewm(span=fast, adjust=False).mean()
    ema_slow = df["close"].ewm(span=slow, adjust=False).mean()
    df["macd"] = ema_fast - ema_slow
    df["macd_signal"] = df["macd"].ewm(span=signal, adjust=False).mean()
    df["macd_hist"] = df["macd"] - df["macd_signal"]
    return df


def add_atr(df: pd.DataFrame, period: int = 14) -> pd.DataFrame:
    high_low = df["high"] - df["low"]
    high_close = (df["high"] - df["close"].shift()).abs()
    low_close = (df["low"] - df["close"].shift()).abs()
    tr = pd.concat([high_low, high_close, low_close], axis=1).max(axis=1)
    df["atr_14"] = tr.rolling(period).mean()
    return df


def add_bollinger(df: pd.DataFrame, period: int = 20, num_std: float = 2.0) -> pd.DataFrame:
    sma = df["close"].rolling(period).mean()
    std = df["close"].rolling(period).std()
    df["bb_mid"] = sma
    df["bb_upper"] = sma + num_std * std
    df["bb_lower"] = sma - num_std * std
    return df


def add_vwap(df: pd.DataFrame) -> pd.DataFrame:
    typical_price = (df["high"] + df["low"] + df["close"]) / 3
    cum_vol = df["volume"].cumsum().replace(0, np.nan)
    df["vwap"] = (typical_price * df["volume"]).cumsum() / cum_vol
    return df


def add_adx(df: pd.DataFrame, period: int = 14) -> pd.DataFrame:
    up_move = df["high"].diff()
    down_move = -df["low"].diff()

    plus_dm = np.where((up_move > down_move) & (up_move > 0), up_move, 0.0)
    minus_dm = np.where((down_move > up_move) & (down_move > 0), down_move, 0.0)

    tr = pd.concat([
        df["high"] - df["low"],
        (df["high"] - df["close"].shift()).abs(),
        (df["low"] - df["close"].shift()).abs(),
    ], axis=1).max(axis=1)

    atr = tr.rolling(period).mean()
    plus_di = 100 * pd.Series(plus_dm, index=df.index).rolling(period).mean() / atr.replace(0, np.nan)
    minus_di = 100 * pd.Series(minus_dm, index=df.index).rolling(period).mean() / atr.replace(0, np.nan)

    dx = (plus_di - minus_di).abs() / (plus_di + minus_di).replace(0, np.nan) * 100
    df["adx_14"] = dx.rolling(period).mean()
    return df


def compute_all_indicators(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df = add_moving_averages(df)
    df = add_rsi(df)
    df = add_stoch_rsi(df)
    df = add_macd(df)
    df = add_atr(df)
    df = add_bollinger(df)
    df = add_vwap(df)
    df = add_adx(df)
    return df


def detect_regime(df: pd.DataFrame) -> str:
    """
    PLACEHOLDER regime classifier — rule-based, not machine-learned.

    This exists so Phase 1 has *something* to show, but it is explicitly
    NOT the "independent regime model" the full spec calls for (section 8).
    A real version needs to be trained/validated on historical data in a
    later phase. Treat this label as descriptive, not predictive.
    """
    if len(df) < 210 or df["ema_200"].isna().iloc[-1]:
        return "INSUFFICIENT DATA"

    last = df.iloc[-1]
    ema20, ema50, ema200 = last["ema_20"], last["ema_50"], last["ema_200"]
    adx = last.get("adx_14", np.nan)

    if ema20 > ema50 > ema200:
        trend = "BULLISH TREND"
    elif ema20 < ema50 < ema200:
        trend = "BEARISH TREND"
    else:
        trend = "SIDEWAYS / MIXED"

    atr_series = df["atr_14"].dropna()
    if len(atr_series) > 20:
        atr_percentile = atr_series.rank(pct=True).iloc[-1] * 100
        if atr_percentile > 80:
            vol = "HIGH VOLATILITY"
        elif atr_percentile < 20:
            vol = "LOW VOLATILITY"
        else:
            vol = "NORMAL VOLATILITY"
    else:
        vol = "VOLATILITY: N/A"

    strength = ""
    if pd.notna(adx):
        strength = " (weak trend strength)" if adx < 20 else ""

    return f"{trend}{strength} · {vol}"
