# DCX Pilot paper engine

CoinDCX futures paper research and simulation for up to five liquid cryptocurrency contracts. The public branch contains generated worker source only. New real-money orders are disabled.

The engine combines live prices, closed candles, volume, spread and funding with five news feeds, India/US Google trending-search samples, and Alternative.me daily Bitcoin sentiment. Decision evidence is recorded with paper entries. See [engine/CONTEXT.md](engine/CONTEXT.md) for the exact source scope, polling cadence and decision rules. This is deterministic software; it does not self-train, read every website or guarantee profit.

Run with Node 22.13 or later:

    node --experimental-strip-types engine/launch.mjs

Set ENGINE_TOKEN (at least 32 characters), APP_ENCRYPTION_KEY (64 hexadecimal characters), DATA_DIR, and PORT securely. Keep the same token in the private dashboard's server configuration. Never publish these values. The worker requires a Bearer token for state, actions and exports; only /healthz is public.

Use a single always-on instance and an actual persistent disk mounted at DATA_DIR. The launcher checks the mount and otherwise stays in SETUP without opening a ledger or accepting actions. SQLite retains the paper ledger, risk halts and run preference across restarts. Back up SQLite consistently, including WAL state, using its backup API.

Run the worker verification gate:

    node --experimental-strip-types --test tests/core.test.mjs tests/execution.test.mjs tests/server.test.mjs tests/launch.test.mjs

Core tests import the context tests, so source and failure-handling cases are part of the Render build gate. Fixtures are synthetic and are not performance evidence. The existing backtest remains a price-only diagnostic; it does not validate the new news/attention layer. Exchange protection code is mock-tested and remains disabled for new live entries.

The approved deployment uses a Render Starter service with a 1 GB disk. Do not create extra paid resources or change other applications. Keep the dashboard private and credentials server-only.
