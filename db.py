"""
db.py
-----
Shared Postgres helpers for storing and reading historical candles.
Designed to work with Supabase's free Postgres tier (or any Postgres),
via a DATABASE_URL connection string.

Used by two different places:
  - collect_data.py (runs on a schedule via GitHub Actions, WRITES data)
  - app.py (the Streamlit dashboard, READS data to display history)

If DATABASE_URL isn't configured yet, is_configured() returns False and
the dashboard falls back gracefully instead of crashing — Phase 1 features
keep working even before Phase 2 is set up.
"""

import os
import pandas as pd
import psycopg2
from psycopg2.extras import execute_values

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS candles (
    pair TEXT NOT NULL,
    interval TEXT NOT NULL,
    time TIMESTAMPTZ NOT NULL,
    open DOUBLE PRECISION,
    high DOUBLE PRECISION,
    low DOUBLE PRECISION,
    close DOUBLE PRECISION,
    volume DOUBLE PRECISION,
    PRIMARY KEY (pair, interval, time)
);
"""

UPSERT_SQL = """
INSERT INTO candles (pair, interval, time, open, high, low, close, volume)
VALUES %s
ON CONFLICT (pair, interval, time) DO UPDATE SET
    open = EXCLUDED.open,
    high = EXCLUDED.high,
    low = EXCLUDED.low,
    close = EXCLUDED.close,
    volume = EXCLUDED.volume;
"""


def get_database_url():
    """
    Looks for DATABASE_URL in Streamlit secrets first (when running as the
    dashboard), then falls back to an environment variable (when running
    as the GitHub Actions collector script).
    """
    try:
        import streamlit as st
        if "DATABASE_URL" in st.secrets:
            return st.secrets["DATABASE_URL"]
    except Exception:
        pass
    return os.environ.get("DATABASE_URL")


def is_configured() -> bool:
    return bool(get_database_url())


def get_connection():
    url = get_database_url()
    if not url:
        raise RuntimeError("DATABASE_URL is not configured.")
    return psycopg2.connect(url)


def ensure_table():
    """Creates the candles table if it doesn't exist yet. Safe to call every time."""
    conn = get_connection()
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(CREATE_TABLE_SQL)
    cur.close()
    conn.close()


def upsert_candles(pair: str, interval: str, df: pd.DataFrame) -> int:
    """
    Saves candles to the database. Safe to call repeatedly with overlapping
    data — existing candles get updated in place rather than duplicated,
    thanks to the (pair, interval, time) primary key.
    """
    if df.empty:
        return 0

    conn = get_connection()
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(CREATE_TABLE_SQL)

    rows = [
        (pair, interval, row["time"].to_pydatetime(),
         float(row["open"]), float(row["high"]), float(row["low"]),
         float(row["close"]), float(row["volume"]))
        for _, row in df.iterrows()
    ]
    execute_values(cur, UPSERT_SQL, rows)
    cur.close()
    conn.close()
    return len(rows)


def load_candles(pair: str, interval: str, limit: int = 5000) -> pd.DataFrame:
    """Load stored historical candles for one pair/interval, oldest -> newest."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT time, open, high, low, close, volume
        FROM candles
        WHERE pair = %s AND interval = %s
        ORDER BY time DESC
        LIMIT %s
        """,
        (pair, interval, limit),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    df = pd.DataFrame(rows, columns=["time", "open", "high", "low", "close", "volume"])
    return df.sort_values("time").reset_index(drop=True)


def storage_summary() -> pd.DataFrame:
    """One row per pair/interval: how many candles are stored and the date range covered."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT pair, interval, COUNT(*) AS candle_count,
               MIN(time) AS earliest, MAX(time) AS latest
        FROM candles
        GROUP BY pair, interval
        ORDER BY pair, interval
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return pd.DataFrame(rows, columns=["pair", "interval", "candle_count", "earliest", "latest"])
