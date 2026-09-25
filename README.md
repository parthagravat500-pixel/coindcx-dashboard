# DCX Pilot worker

CoinDCX futures research and paper execution for up to five eligible USDT instruments. No established predictive edge or guaranteed returns.

Requires Node 22.13+, one process, and persistent storage. Run `npm test`, then `npm start`.

Configure ENGINE_TOKEN (at least 32 random characters), APP_ENCRYPTION_KEY (64 hexadecimal characters), DATA_DIR, PORT, ALWAYS_ON=true, and PERSISTENT_STORAGE=true. Supply secrets through the hosting platform, never through Git.

Paper observation starts automatically. Entries require fresh market data and risk checks. The API requires the server-side bearer token except for /healthz. Records and encrypted exchange credentials are persisted separately from source in SQLite. Existing paper run preferences survive restart.

New real-money orders are disabled. The protected execution adapter has mock tests but is not integrated for live entry or exchange-verified. Independent strategy qualification, live accounting, a user capital allocation, and exchange protection testing are required before live integration.

render.yaml defines one Starter service in Singapore with a 1 GB persistent disk. Base cost was approved at approximately US$7.25/month before taxes and extra usage. The deployment is not active merely because this file exists.

Research limitations: fixed baseline rules, current-universe selection bias, short recent-data diagnostics, simulated fills and funding reserve, no historical order-book or event-time news replay. RSS events act as an entry risk guard, not a verified directional prediction.
