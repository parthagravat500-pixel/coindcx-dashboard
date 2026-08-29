"""
app.py
------
PHASE 1 dashboard: live prices, candlestick charts, and technical indicators
for CoinDCX-listed coins. No predictions, no signals, no trading — just clean,
trustworthy data. That's deliberate: everything later (ML models, signals,
backtesting) needs to sit on top of a data layer you already trust.

Run with:
    streamlit run app.py
"""

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from data_fetcher import get_candles, data_quality_report
from indicators import compute_all_indicators, detect_regime

st.set_page_config(page_title="Crypto F&O Dashboard — Phase 1", layout="wide")

st.warning(
    "**PHASE 1 — LIVE DATA + INDICATORS ONLY.** "
    "No LONG/SHORT signals, no ML predictions, no trade setups yet. "
    "Everything below is real, live market data pulled from CoinDCX's public API — "
    "but nothing on this page is a trade recommendation."
)

st.title("Crypto F&O Analytics — Phase 1")
st.caption("Live Data · Indicators · Foundation for later phases (signals, backtesting, ML)")

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

INTERVALS = ["1m", "5m", "15m", "30m", "1h", "4h", "1d"]

col1, col2, col3 = st.columns([1, 1, 2])
with col1:
    coin = st.selectbox("Coin", list(COINS.keys()))
with col2:
    interval = st.selectbox("Timeframe", INTERVALS, index=1)
with col3:
    st.write("")
    refresh = st.button("🔄 Refresh live data")

pair = COINS[coin]

with st.spinner(f"Fetching {coin} {interval} candles from CoinDCX..."):
    df = get_candles(pair, interval=interval, limit=300)

warnings = data_quality_report(df, interval)
for w in warnings:
    st.warning(f"⚠️ Data quality: {w}")

if df.empty:
    st.error(
        "No usable data returned for this pair/timeframe. "
        "CoinDCX may not support this combination, the market may be inactive, "
        "or there's a temporary connection issue. Try a different coin/timeframe."
    )
    st.stop()

df = compute_all_indicators(df)
regime = detect_regime(df)

last = df.iloc[-1]
prev = df.iloc[-2]
pct_change = (last["close"] - prev["close"]) / prev["close"] * 100 if prev["close"] else 0.0

m1, m2, m3, m4 = st.columns(4)
m1.metric("Price (USDT)", f"${last['close']:,.4f}", f"{pct_change:+.2f}%")
m2.metric("RSI (14)", f"{last['rsi_14']:.1f}" if pd.notna(last["rsi_14"]) else "N/A")
m3.metric("ATR (14)", f"{last['atr_14']:.4f}" if pd.notna(last["atr_14"]) else "N/A")
m4.metric("Market Regime (rule-based, placeholder)", regime)

fig = go.Figure()
fig.add_trace(go.Candlestick(
    x=df["time"], open=df["open"], high=df["high"], low=df["low"], close=df["close"],
    name=coin,
))
fig.add_trace(go.Scatter(x=df["time"], y=df["ema_20"], line=dict(width=1), name="EMA 20"))
fig.add_trace(go.Scatter(x=df["time"], y=df["ema_50"], line=dict(width=1), name="EMA 50"))
fig.add_trace(go.Scatter(x=df["time"], y=df["bb_upper"], line=dict(width=1, dash="dot"), name="BB Upper"))
fig.add_trace(go.Scatter(x=df["time"], y=df["bb_lower"], line=dict(width=1, dash="dot"), name="BB Lower"))
fig.update_layout(
    height=600,
    xaxis_rangeslider_visible=False,
    template="plotly_dark",
    margin=dict(l=10, r=10, t=30, b=10),
    legend=dict(orientation="h", yanchor="bottom", y=1.02),
)
st.plotly_chart(fig, use_container_width=True)

st.subheader("Indicator snapshot — latest candle")
snapshot = {
    "EMA 9": last["ema_9"], "EMA 20": last["ema_20"], "EMA 50": last["ema_50"],
    "EMA 100": last["ema_100"], "EMA 200": last["ema_200"],
    "SMA 20": last["sma_20"], "SMA 50": last["sma_50"], "SMA 100": last["sma_100"], "SMA 200": last["sma_200"],
    "RSI 14": last["rsi_14"], "Stoch RSI": last["stoch_rsi"],
    "MACD": last["macd"], "MACD Signal": last["macd_signal"], "MACD Hist": last["macd_hist"],
    "ADX 14": last.get("adx_14"),
    "ATR 14": last["atr_14"],
    "Bollinger Upper": last["bb_upper"], "Bollinger Mid": last["bb_mid"], "Bollinger Lower": last["bb_lower"],
    "VWAP (session)": last["vwap"],
}
snap_df = pd.DataFrame(
    [(k, f"{v:,.5f}" if pd.notna(v) else "N/A") for k, v in snapshot.items()],
    columns=["Indicator", "Value"],
)
st.dataframe(snap_df, use_container_width=True, hide_index=True)

st.subheader("Recent candles")
st.dataframe(df.tail(20).sort_values("time", ascending=False), use_container_width=True, hide_index=True)

st.caption(
    f"Data timestamp (last candle): {last['time']} · "
    f"Interval: {interval} · Pair: {pair} · "
    "Source: CoinDCX public API (LIVE DATA) · Model version: N/A — Phase 1 has no predictive model yet."
)
