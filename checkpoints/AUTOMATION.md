# Automatic checklist execution

Version 2026.09.26.2 connects the entire 1,000-entry catalog to a durable coverage
worker and a results view. The worker evaluates up to 16 contexts every five
seconds, rotating through the owned app, listed programs and saved exact URLs.
Each context is revisited after 15 minutes. Actual external request schedules
remain those of the existing approved runners; checklist evaluation adds no
network requests.

## Implemented adapters: 30 checkpoint IDs

| Adapter | Checkpoints | Evidence and limit |
| --- | --- | --- |
| Policy metadata | SG-0001, SG-0002, SG-0006, SG-0008 | Current complete saved documents; no permission inferred from missing restrictions. |
| Python patterns | SG-0781–SG-0787 | Existing current owned-source AST results; partial source review only. |
| Additional Python patterns | SG-0795–SG-0798 | Mutable defaults, dynamic imports, temporary-name reuse and world-writable permission patterns. No inspected code executes. |
| Authorized HEAD observations | SG-0148–SG-0150, SG-0604–SG-0607, SG-0610–SG-0613 | Cookie-attribute counts and header presence from the existing exact-URL request. No cookie/header values retained in checklist receipts. Feature relevance, GET behavior and impact remain unverified. |
| Owned runtime regression | SG-0166, SG-0263, SG-0264 | Actual loopback requests with a successful authenticated control; scoped login/write/CSRF results only. |
| Approved resource comparison | SG-0161 | Existing anonymous or two-account comparisons of an owned resource, using the existing runner's validated control sequence. |

The remaining 970 checkpoints have no executable adapter in this version. They
are recorded as needing implementation or feature context. The program-specific
source and runtime adapters also require suitable inputs and current permission.
This release does **not** implement 1,000 vulnerability tests or promise bounty
discovery. A complete coverage decision is never counted as a successful test.

## Results

The dashboard's **Automatic checklist → See automatic results** view offers a
program/application selector, state filters, search and all 1,000 IDs. The private
`GET /api/checkpoint-results` endpoint supports the same bounded pagination.
`/api/state` exposes aggregate worker progress under `checkpoint_automation`.

- `evaluated`: every catalog item received a coverage decision.
- `executed`: a mapped adapter has current evidence; includes partial observations.
- `runtime_tested`: a bounded resource/operation test has actual control evidence.
- `runtime_passed`: only the recorded operation passed its comparison.
- `runtime_failed`: the recorded operation needs investigation; not a bounty claim.
- `needs_input`, `needs_context`, `needs_implementation`, `blocked`: never counted
  as a completed runtime test.

Receipts bind evidence to the exact job configuration and permission stamp.
Revocation, expiry, source changes and deployment changes invalidate evidence
where relevant. Program results cannot inherit ScopeGuard's own source or local
test results. Pause state survives restarts. Disabled targets remain disabled.
The version migration only makes the already-owned loopback regression job due,
respecting a five-minute cooldown; external permissions and schedules are untouched.

The catalog remains available separately as research guidance. Its legacy
`execution_enabled: false` flag describes the catalog-only endpoint, while the
new worker and results endpoint represent actual connected adapters.

## References

- OWASP WSTG v4.2: https://wstg.owasp.org/v4.2/
- OWASP HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

These sources inform the limits of the checks. Checklist size alone is not a
measure of application coverage or successful vulnerability discovery.
