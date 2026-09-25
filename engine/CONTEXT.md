# Market, news and online attention — context-v1

This release uses real source data in deterministic paper decisions. It is not a trained model, an unrestricted internet-reading agent, or a promise of profit. Real exchange entries remain disabled.

## Sources and cadence

- CoinDCX: prices, spread, volume, funding and closed candles, on the existing 15-second scan.
- Federal Reserve, SEC, CoinDesk, Cointelegraph and Decrypt: RSS checks every minute. Health requires at least two crypto publishers and one official source to respond. Publication and first-seen timestamps are kept; future, undated and stale reports cannot vote.
- Google Trends Trending Now: the public India and US RSS samples, checked every ten minutes. Only queries mentioning an eligible coin count. An absent coin means no match in this limited sample, not zero worldwide interest. Direct X, Reddit and Telegram feeds are not connected.
- Alternative.me: daily Bitcoin Fear & Greed, checked every ten minutes, with publication time and adjacent attribution in the UI. It is a broad daily crowding input, not a live sentiment reading for individual coins.

The official source descriptions are https://support.google.com/trends/answer/3076011 and https://alternative.me/crypto/fear-and-greed-index/. CoinGecko's keyless endpoint was evaluated but is not polled in production; its documentation advises against scheduled production use without a suitable plan.

## Decision policy

1. Existing closed-candle, universe, execution and portfolio-risk checks remain mandatory.
2. Headlines are classified using explicit asset aliases, event keywords and uncertainty/negation exclusions. Only an official source or two different publishers with nonduplicate headlines establish a directional aggregate. Publisher agreement is not proof of an event. Classification uses headlines, not full-text semantic reasoning.
3. Conflicting directional news changes an entry to WAIT. Recent applicable security reports and official macro announcements pause entries when the extra shock guard is enabled.
4. Search popularity never implies long or short. A context-created candidate requires corroborated news, elevated search or multi-publisher media attention, a closed candle confirming the direction, increased volume and five-minute price momentum. It cannot override a baseline candle-gap, stale-data, warmup or volatility rejection.
5. Extreme daily sentiment and unusually crowded funding add entry checks. Missing daily sentiment is labelled PARTIAL and contributes no inferred value. Missing or stale core news/search coverage blocks new entries. Existing positions continue to receive stop/target supervision.
6. The full assessment at entry is copied into the paper trade record and export. The dashboard shows source health, the actual supporting links, freshness and the final decision reason. The existing price-only diagnostic does not validate this new decision layer.

No parameter self-training, causal loss diagnosis or model promotion is implemented. Independent forward evaluation is still required. Do not unlock live execution based on the presence of these feeds or a few successful paper trades.
