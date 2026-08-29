# Crypto F&O Dashboard — Phase 1

This is the **first working piece** of the larger platform you spec'd out. It does one job well:
show live prices, candlestick charts, and technical indicators for CoinDCX-listed coins.
No predictions, no signals, no ML yet — that comes in later phases, on top of this foundation.

No CoinDCX API key is needed for this phase — it only uses CoinDCX's public market data.

---

## 1. Install Python (skip if you already have it)

1. Go to https://www.python.org/downloads/
2. Download and install the latest version (3.10 or newer).
3. **Windows only:** on the first install screen, check the box that says
   "Add Python to PATH" before clicking Install.

To check it worked, open:
- **Windows:** Command Prompt (search "cmd" in the Start menu)
- **Mac:** Terminal (search "Terminal" in Spotlight)

and type:
```
python --version
```
You should see something like `Python 3.11.5`. (On Mac, if that doesn't work, try `python3 --version`.)

## 2. Get the project files onto your computer

Unzip the file you downloaded from this chat into a folder, e.g. `Documents/coindcx-dashboard`.

## 3. Open a terminal in that folder

- **Windows:** open the folder in File Explorer, click the address bar, type `cmd`, press Enter.
- **Mac:** right-click the folder → "New Terminal at Folder" (or open Terminal and type `cd ` then drag the folder in, then press Enter).

## 4. Install the required packages

```
pip install -r requirements.txt
```
(On Mac, if `pip` isn't found, try `pip3 install -r requirements.txt`.)

This installs Streamlit (the dashboard framework), pandas/numpy (data handling),
plotly (charts), and requests (to talk to CoinDCX).

## 5. Run the dashboard

```
streamlit run app.py
```

Your browser should open automatically to `http://localhost:8501` with the dashboard running.
If it doesn't open automatically, copy that address into your browser manually.

Pick a coin and timeframe from the dropdowns — you're now looking at live CoinDCX market data.

---

## What this does NOT do (on purpose)

- ❌ No LONG/SHORT/NO TRADE signals
- ❌ No entry/stop-loss/take-profit levels
- ❌ No machine learning
- ❌ No order book / open interest / funding rate data yet
- ❌ No connection to your CoinDCX account (no API key used at all)
- ❌ No trading of any kind

The "Market Regime" label you'll see is a simple rule-based placeholder
(based on EMA order and volatility), clearly not the trained regime model
described in the full spec — it's there so the dashboard isn't empty while
we build the real thing.

## Roadmap — what comes next

This maps to the phases in your original spec, done in an order that lets you
see and test something working at every step, rather than waiting months for
one giant system:

| Phase | What gets added |
|---|---|
| **1 (done)** | Live prices, candles, core indicators |
| **2** | Historical data storage (so we can backtest instead of only looking at "now") |
| **3** | Order book / open interest / funding rate data (CoinDCX futures-specific data) |
| **4** | Rule-based backtesting engine (fees, slippage, no look-ahead bias) |
| **5** | First ML models (direction/return prediction) + walk-forward validation |
| **6** | Confidence calibration + prediction journal (so confidence numbers are honest) |
| **7** | Paper trading mode (simulated money, real prices) |
| **8** | Live execution — **only after Phase 5–7 show real, validated statistical edge** |

Live auto-trading (Phase 8) is intentionally last. Everything in your original
spec about kill switches, drawdown limits, and "no trade is a valid answer" only
means something once there's a track record to check it against.

## A quick honest note

I'm not a financial advisor, and this tool — even once fully built — doesn't
guarantee profitable trades. Its real value is in Phase 4–7: it forces every
signal to prove itself against history and real costs *before* you risk money
on it. Treat low win rates or "NO TRADE" results as useful information, not failures.
