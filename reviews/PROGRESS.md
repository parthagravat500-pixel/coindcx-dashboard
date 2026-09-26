# ScopeGuard permission review progress

## 2026-09-26, batch 03

Baseline: scopeguard-app commit ced1043b45fe30cceab4a1d19ab951d1f5e3fe94.
The latest branch, previous evidence files and this ledger were read before
selecting a new batch. No previously recorded program was repeated.

Reviewed current official policies: Uber, Superhuman (formerly Grammarly) and
Coinbase. Detailed evidence: `2026-09-26-batch-03.json` (checked
2026-09-26T02:00:47Z). Uber exposes 4 in-scope and 20 excluded asset rows and
requires owned test accounts; unvalidated automated scan/enumeration output is
ineligible. Superhuman exposes 30 in-scope rows across its own, Grammarly and
Coda products, with product-specific owned-account requirements; automated
output needs manual validation. Coinbase exposes 16 in-scope and 3 excluded
rows, but Low and Medium findings are out of scope and no explicit automation
permission or public test-account procedure was found. None of these reviews
grants ScopeGuard permission to activate a target. No numerical request limit
was found; unknown never means unlimited. No external test, account, submission,
staff contact or target activation occurred.

## Review-count visibility change

Added a `policy_review_summary` that separately reports current directory
listings, listings matched to official policy evidence, still-unreviewed
listings, total source evidence records, and how many matched reviews grant queue
permission. The dashboard now shows the matched/listed count beside discovery
status and in queue details. A synthetic regression proves that a matched
non-authorizing review increases the evidence count while creating no target and
making no network request. This prevents the listed-program counter from looking
like a reviewed, queued or completed-work counter.

Authenticated live ScopeGuard state and its private 304-entry list remain
unavailable, so these reviews cannot be claimed as three entries from that exact
list. The repository still has no supported authenticated policy-import endpoint;
the new records are non-authorizing source data only. No deployment, external
scan, confirmed vulnerability or earnings occurred.

## 2026-09-26, batch 02

Baseline: scopeguard-app commit 5f3aa5202b916a6ef637ed5f646d4213c4fbd0a6.
Latest branch and this ledger were read before selecting the batch. Personal
context confirmed the earlier named reviews and the user's standing instruction
to keep unsanctioned scanning paused. No previous batch was repeated.

Reviewed current official policies: PayPal, Discord and Dropbox. Detailed
evidence: `2026-09-26-batch-02.json` (checked 2026-09-26T01:01:27Z).
PayPal exposes 41 in-scope and 8 out-of-scope asset rows, but its policy rejects
scanner-generated reports and automated active exploit tools; it also requires
identified traffic and test-account/IP details. Discord moved to a private
Bugcrowd program on May 20, 2025 and expressly prohibits scanners/automated
vulnerability-finding tools. Dropbox has been paused since July 31, 2025 and
instructs researchers to stop testing; its 23 public target rows are masked.
No numerical request limit was found for any of these three. Unknown never means
unlimited. No external test, account, submission, staff contact or target
activation occurred.

## Queue visibility change

The queue already failed closed on an absent, stale or failed HackerOne directory
refresh, but exposed only a generic per-target reason. Added a structured
`directory_source` diagnostic with last attempt/success, current source status,
failure count and the exact global blocker. The dashboard now says when a failed
directory refresh blocks otherwise saved URLs, rather than reporting only that no
eligible checks are due. This does not relax the gate, import policy evidence into
the live database or enable a target. A synthetic regression covers failure and
recovery after a successful refresh.

## Validation and limits

The focused queue, workflow, readiness and local-mode test suites; JavaScript
syntax; and the dashboard DOM smoke test were run after the change. All network
observations in tests were mocked. The GitHub connector returned no pull-request
workflow run for the preceding direct branch commit, so there is no remote CI
result to claim for that commit.

Authenticated live ScopeGuard state remains unavailable, and the current private
304-entry directory cannot be inspected. These three reviews therefore cannot be
claimed as three of that live 304. The repository has no supported authenticated
policy-import endpoint; advisory records remain non-authorizing source data. The
exact live cause of the user's stalled queue is still unverified, while the source
now exposes the main possible blocker classes. No confirmed vulnerability or
earnings were established.

## 2026-09-26, batch 01

Baseline: scopeguard-app commit e166e73e05be3839fa843c1837f753c49984693c.
Local source was reconstructed only from files whose Git blob hashes matched the
current remote tree. No existing local copy was assumed current. No AGENTS.md
was present in that tree. Prior notes in workflow.py and readiness.py were read.

Reviewed public policies and scope: Mozilla, Shopify, Automattic.
Detailed evidence: `2026-09-26-batch-01.json` (checked 2026-09-26T00:15:17Z).
Mozilla was a follow-up to the known production-automation restriction, not a
newly discovered program. Its HackerOne banner now states submissions paused
since September 11, 2026 with reopening planned Q1 2027. Shopify and Automattic
were not covered by the existing source policy notes.

Scope tables read: 7 Mozilla, 21 Shopify and 31 Automattic asset entries.
These are scope entries, not URLs approved for this application or scan counts.
Shopify's table includes two bounty-ineligible third-party categories.
Mozilla requires staging for several services and discourages production
automation. Shopify requires owned stores with a HackerOne alias. Automattic
requires owned test accounts. No explicit permission for the planned autonomous
checks was established for Shopify or Automattic. No numerical request limit was
found in these pages; null is unknown, never unlimited. No target was activated.

## Source diagnosis and changes

- workflow.py imports directory metadata without creating targets. Its local
  scoring routine does not read official policies. Corrected the misleading
  'all listed programs reviewed' label to say directory sorting only.
- programqueue.py only selects enabled, unexpired saved URLs whose directory
  gate passes and whose due time has arrived. A stale/failed directory refresh
  can block otherwise saved targets. The worker wakes every 10 seconds; it does
  not ignore per-target intervals. New target intervals are 1–168 hours; the
  separate reviewed schedule action accepts 5 minutes–168 hours.
- Added queue counters for saved, disabled, expired, directory-blocked, eligible,
  due and waiting targets; exposed next due time and a specific queue state.
  Future-due rows now say waiting rather than queued. Future heartbeats no longer
  appear healthy. Dashboard renders these distinctions.
- Existing completed counter increases only for completed limited checks with
  observations or no observation. Errors, interrupted/stopped and inconclusive
  checks do not count. No completed check implies a confirmed or payable bug.
- Added three advisory records to the existing POLICY_REVIEWS mechanism.
  This is source preparation for a future separately authorized deployment,
  not import into the private running database. Authentication and CSRF remain
  unchanged; records create no targets or testing permission.

## Validation

31 tests passed: test_programqueue, test_workflow, test_readiness, test_local_mode.
Includes five new synthetic-fixture regressions for schedule visibility, blocker
counts, worker/pause distinctions, truthful review labelling, and advisory records
not activating checks. JavaScript syntax and the existing dashboard DOM smoke
test passed. The smoke test requires a synthetic snapshot on stdin; an initial
invocation without input failed, then the documented invocation passed.
All tests used local synthetic state and mocked external observation requests.
No external security scans, exploits, accounts, submissions, staff contacts,
paid model calls, training, deployment or new compute resources were used.

## Exact blockers and remaining work

- Authenticated live ScopeGuard state was not obtained. Its existing browser tab
  was on chrome-error://chromewebdata/; inspection was rejected by browser URL
  policy. That operation stopped, with no workaround. Therefore live target
  counts, worker health, credentials and exact cause of this user's stalled queue
  remain unverified. Source-level causes above are not a live-state diagnosis.
- No supported authenticated policy-import endpoint exists in the inspected
  source. Review notes are committed source data only, not live app changes.
- Membership of these programs in the user's current private 304-entry directory
  could not be verified. A read of the public directory mirror returned no file
  content. Do not claim three of those 304 completed or all 304 reviewed.
- Next runs should read this ledger and the latest branch first. Avoid repeating
  these three unless resolving a specific unknown. Existing earlier notes cover
  GitHub, GitLab, Cloudflare, Capital.com, Altera, Arm Mali, Trusted Firmware,
  BMW automotive, Delen and Monzo; those notes were not revalidated in this batch.
- Next useful work: obtain supported authenticated queue diagnostics when access
  is available; review another bounded batch; retain permission and activation
  separation; validate candidate checks in controlled fixtures before proposing
  real testing. No bug or earnings established.
