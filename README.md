## Automatic program research

Every directory listing receives a persistent research entry. The home screen's
**View all programs** list shows pending work, actual document requests, current
collections, changes and access blockers separately from security tests.

With authorized platform API connections, ScopeGuard reads official HackerOne
policies, paginated structured scope and reward exclusions, plus Intigriti
program rules, domains and structured requirements. It uses only documented GET
endpoints, with one metadata request at a time and at least five seconds between
requests globally. HackerOne reads are capped at 12/minute; Intigriti retains a
15-second minimum. The HackerOne scope endpoint's published limit is 50/minute.
These limits apply only to policy APIs, never to asset testing. Progress, backoff
and partial pagination survive restarts. Completed documents refresh daily;
forbidden programs do not hold up other programs. Platform authentication errors
stop that provider until the connection changes. Missing tokens cause zero API
requests and zero claimed reviews. Existing HackerOne reporting credentials can
be reused for reads; a separate research connection never enables reporting.

The authenticated research connection screen accepts private API credentials,
with explicit read consent, independently of report delivery. Tokens stay in a
server file restricted to its owner and never enter snapshots, logs or commits.
Research disconnection remains in force across restarts even if reporting is
connected. Program evidence is served only behind the existing dashboard login.

Collection is not policy interpretation or testing approval. Rule passages are
search aids; linked conditions and unknown limits remain unresolved. Intigriti
tier and automatedTooling fields are retained without guessing their meaning.
Attachments are not fetched, and their presence prevents a complete-document
claim. Mozilla production automation remains restricted. No source repository,
target, account, permission renewal, exploit or report is created by this worker.
Supported methods and missing prerequisites are shown with each collection.

Completed current collections automatically produce an offline research brief.
The brief counts exact HTTPS addresses, supported repository shapes, patterns
needing an exact address, unsupported asset types, exclusions and unknown
eligibility. It preserves the exact saved asset and proposes only a capability
match, never a runnable test or vulnerability lead. No host or wildcard is
expanded, no login requirement is inferred, and unknown Intigriti eligibility
stays unresolved. At most 80 matching rows are shown with an honest omitted count;
the full saved scope remains available. Changed, stale, blocked and incomplete
evidence retains its corresponding warnings. Filtering by prepared briefs helps
find useful research preparation without presenting it as testing approval.

Slow official API reads no longer hold the dashboard's shared work lock. A
dedicated nonblocking worker lock prevents overlapping metadata requests, and
the worker rechecks pause, current credentials, directory health and program
availability before accepting responses. Rate-limit waits start after the
response arrives, so network time does not shorten Retry-After.

Evidence is bounded to 512 KB per document snapshot and 64 MB in total (including
partial working copies), with at most 2,000
scope rows. Unsupported or oversized responses stay incomplete; none are silently
counted as complete. Third-party directory rows are used only to identify the
official programs. Unlisted private API programs are not imported.

Official API documentation checked 26 September 2026:
- https://api.hackerone.com/getting-started-hacker-api/
- https://api.hackerone.com/hacker-resources/
- https://kb.intigriti.com/en/articles/8529303-intigriti-researcher-api
- https://api.intigriti.com/external/researcher/swagger/v1.0/swagger.json

## Automatic lead investigations

Source reviews now feed a persistent, ranked lead inbox alongside repeated runtime
observations. The existing worker updates the inbox every ten seconds from saved
evidence. Changed source is analyzed automatically; unchanged evidence is not
counted again. Current owner review decisions are honored, and changed code
reopens stale decisions. Leads no longer observed are retained as historical
evidence, never labelled a proven fix. Login, CSRF, saved target permissions and
report-submission gates remain unchanged.

`querycheck.py` adds actual SQLite component experiments for a narrow supported
class of dynamic SELECT queries. An inert Python path model supplies the SQL; a
two-row in-memory fixture supplies synthetic records. A candidate must return an
extra row twice while owner controls before/after and a parameter-binding negative
control pass. The connection denies writes, attachments, pragmas, arbitrary
functions and extension loading, and bounds statement size, columns, expression
depth, VM work and returned rows. Only control booleans, counts and hashes persist.
No imported project code, credentials, real database or external website is used.

This is component evidence under an inferred schema and SQLite dialect. It is
**not execution of the application and not a confirmed application vulnerability**.
Unsupported query shapes, framework behavior and database dialects remain
unresolved. Numeric guards and safely bound queries do not receive a positive
reproduction result. Coverage is at most twelve SQL leads and three entry paths
per project review; other types retain their existing path-model evidence.

The home page's View leads opens a read-only list with evidence strength, actual
controls, recorded date, private draft and remaining validation needs. At most
100 ranked entries are shown, with truncation disclosed. Information-only header
observations are not promoted into this supported-lead count. Up to 200 old
inactive leads are retained in addition to current bounded project evidence.
A private operational receipt exposes only aggregate lead states and worker
health, not project names, drafts or findings. No general autonomous enrollment,
account verification, scope approval, exploit discovery or bounty acceptance is
claimed. Existing approved source watches and owned app checks run independently
of an open browser; unapproved sites do not get scanned.

## Simple dashboard

The phone-friendly home page shows the next permitted test, saved results, tests
on hold and recent real work. Program browsing, connection forms and specialist
controls stay in the closed advanced section. Reading results never starts a
test or sends a report. ScopeGuard self-checks are explicitly included in the
finished-check count; code reviews and policy reviews have separate counters.

Automatic workflow totals are stored independently of the last 200 journal
entries, survive restarts and are imported from retained history once. Failed,
inconclusive, skipped and interrupted attempts are not completed checks. Earlier
standalone workers and deleted history are not reconstructed or added. Stopped
tests get fixed plain-language explanations without repeating server text.
A failed or timed-out dashboard refresh removes live activity claims and disables
the main pause control until a fresh authenticated response arrives.

## Automatic runtime workflow

The existing research switch now starts one durable selector for saved header
checks, private-JSON comparisons, owned GitLab comparisons and ScopeGuard's own
login/request-protection regression. It selects the next eligible task, runs its
bounded method, records the outcome and continues to another task without a
browser session or a per-run click. Existing source and dependency workers remain
separate. The dashboard's main status shows this workflow and its private evidence.

`autopilot.py` uses a persistent dispatch lease and oldest-run ordering so a
failed task does not occupy every turn. It records due times before dispatch,
spaces tasks sharing a policy by at least 60 seconds, honors each method's longer
interval and request budget, and backs off inconclusive/failed work. Interrupted
leases are recorded as unknown and delayed, never counted as successful tests.
The central worker replaces the independent header, access, GitLab and owned-app
validation loops. No new process, resource, paid model or service is provisioned.

Only already-saved, enabled and unexpired permissions are eligible. Runners check
permission again before individual requests. The master pause survives restarts.
Mozilla production automation is explicitly blocked in the shared target gate.
No listing, source-review result, OAuth connection or saved policy note approves a
target or renews permission. A revoked profile cannot be re-enabled by a finishing
result. In-flight requests may finish, but revoked/changed work cannot create a
new confirmed result in this workflow.

Repeated boundary failures require positive controls and repeated comparisons
before an investigation draft is created. Evidence contains only generated step
labels, status codes, hashes, sizes and synthetic-marker/permission booleans;
response bodies, test markers, tokens and exception text are excluded. Drafts and
up to 200 attempts persist privately behind existing dashboard authentication;
up to 100 cases are retained, with the latest 30 displayed. Header observations,
errors and interrupted checks do not become runtime cases. These drafts do not
enter the report-sending queue. Impact, intended sharing, program eligibility and
duplicate status remain unverified.

A five-minute receipt in private host logs exposes only the deployed revision,
worker state, aggregate task kinds, fixed blocker-reason counts, next due time and
last outcome. It contains no target URL,
account, credential or finding. This permits operational health verification
without introducing an unauthenticated diagnostics endpoint.

This completes automatic orchestration for the supported, preauthorized methods.
It does not automate arbitrary program enrollment, account/identity challenges,
new testing permission, general exploit discovery or bounty acceptance.

## Automatic source investigation

When the existing master research switch is enabled, the server checks its
35 installed Python source files for changes every minute. No browser needs to
stay open. The pipeline records input paths, runs bounded synthetic path
experiments, and creates an investigation draft for each static lead. Existing
authorized source watches and project uploads use the same pipeline. Unchanged
source reuses its evidence; changes and engine upgrades trigger a fresh review.
Pause persists across restarts and is never automatically cleared. No directory
entry, policy note or OAuth connection activates a website target.

`pathcheck.py` interprets a deliberately small AST subset with generated inputs.
It models direct function calls, simple declared instance/static methods,
assignments, simple string building, conditionals and selected primitive
conversions/predicates. Inert receiver markers follow direct self-method calls;
no project class is constructed. Sensitive operations are intercepted, never
invoked. Unknown calls, inheritance, initialization, decorators, instance state,
loops and other unsupported
features stop an experiment. Limits: 20 leads, three entry points, three input
pairs, six call levels, 2,000 steps per experiment and bounded primitive values.
Source code is not imported, compiled into executable code, or executed.

Static review distributes its bounded 240,000 expression visits across declared
entry points so a large early function cannot exhaust every later function's
share. Results report declared/visited functions, class methods and work-limited
entries; these counts include partially reviewed functions, not full coverage.
The existing local SQLite component check now receives supported class-method
paths too. Repeated extra synthetic rows plus positive and parameter-binding
controls are still required. Such a result remains component evidence, never a
confirmed application exploit or bounty. Fixed aggregate host diagnostics expose
engine/version, coverage counts and worker failures without source or findings.

Results distinguish **input influence observed in the model**, **not reproduced
with sampled inputs**, **unsupported**, and **budget exhausted**. None proves
runtime exploitability, safety, authorization or bounty eligibility. For example,
a numeric SQL input can change a query argument while remaining safe from SQL
injection. Failed experiments cannot dismiss a lead. Drafts contain source
locations and evidence digests, never evaluated values or source literals. They
remain inside the authenticated evidence view and are never submitted.

`autoresearch.py` persists worker heartbeat, completed changed-source reviews,
pause/error state and retry backoff. A failed stage rolls back the new source
evidence, preserving the previous complete result. The dashboard shows this
work separately from live website checks and confirmed bounty bugs. The optional
Uber profile connector is collapsed because it is not a prerequisite for source
research. This is automatic source investigation within explicit coverage limits,
not a complete autonomous bounty researcher for arbitrary websites or accounts.

## Uber account connection (optional)

`uberconnect.py` implements an optional, read-only Uber profile OAuth connection.
It is disabled by default. A Rider login does not configure this integration.
An approved developer app and its credentials have **not** been established by
adding this code. Uber requires approval for its profile API:
https://developer.uber.com/docs/consumer-identity/references/api/v3/me-get.

Only after provider approval, an administrator configures these privately on the
existing service (never in a policy file, source commit, chat or public logs):

- `UBER_PROFILE_API_APPROVED=true` records obtained provider approval. This flag
  cannot obtain or substitute for Uber approval; the profile call must also succeed.
- `UBER_CLIENT_ID` and `UBER_CLIENT_SECRET` belong to that approved application.
- `UBER_REDIRECT_URI` is the exact HTTPS URL registered with Uber. For this
  deployment: `https://scopeguard-research.onrender.com/api/uber/callback`.

The authenticated dashboard offers authorization only when configuration is
complete. Starting/disconnecting requires existing administrator authentication
and CSRF protection. The account owner then authorizes `profile` on Uber itself.
The callback requires dashboard authentication, a short-lived single-use state
and a Secure/HttpOnly/SameSite=Lax host-only binding cookie. It only exchanges at
Uber's fixed HTTPS token endpoint and verifies `/v3/me`. Redirects, retries,
broader scopes and unverified profiles fail closed. The profile is discarded.

Access tokens stay in private process memory; there is no token file, database
column, browser-cookie import, refresh loop or background profile polling.
Restart/expiry removes usable local access and requires reconnection. A restart
does not revoke Uber's application grant. Disconnect explicitly revokes the token
and removes local access even if Uber cannot confirm revocation; the dashboard
then explains that removal from Uber's connected apps is still needed.

This verifies account access only. It does not add targets, enable checks, change
program scope, provide a browser session, import private account data, prove a
security issue or grant permission for vulnerability testing. No live OAuth
exchange or Uber API call was used to validate this implementation. Tests use
synthetic responses and local HTTP fixtures: `python -m unittest test_uberconnect`.

## Private research dashboard

The dashboard distinguishes local rules, isolated regression CI, experimental
local-model reviews, and confirmed findings. GitHub status is polled every five
minutes and marked stale after fifteen. Test results are tied to a commit; a
different deployed commit is explicitly identified. Passing regressions does
not establish a bounty finding.

Private AI review is opt-in through the authenticated dashboard. The receipt
endpoint accepts only signed, short-lived GitHub OIDC identities for this exact
repository, owner, branch, push event and AI workflow. GitHub signing certificates
are retrieved only from its fixed HTTPS endpoint and signatures are verified by
system OpenSSL. No dashboard password or GitLab token is copied into CI. Receipts
are bounded, rate-limited, revision-bound and restricted to one active run.
Pause/disable prevents new receipts. The model cannot mark a bug confirmed or
submit a report. Do not enable this on forks without reviewing and replacing the
fixed identity allowlist.

The private AI workflow runs only after relevant ScopeGuard branch pushes, not
on a timer or on the unrelated trading branch. It downloads the official
Apache-2.0 Qwen2.5-Coder-7B-Instruct Q4_K_M model and a pinned llama.cpp CPU release,
verifying both SHA-256 digests. No model is downloaded until the private server
accepts a review lease. Inference runs without external network, credentials,
capabilities or writable source, as a non-root user with 2 CPU, 10 GiB memory,
128-process and 1,000-second limits inside a disposable hosted runner.

Two tiny synthetic cases must be classified correctly before reviewing the
request handler and workload-identity verifier. This is a smoke test, NOT an
expert benchmark. Coverage is two excerpts, not a full-repository audit. Model
text is untrusted, displayed as text only, never executed, and never a confirmed
finding. Analysis is posted privately; it is not uploaded as a public Actions
artifact or printed in logs. Runner logs expose only status and counts. Existing
public source stays public. No customer tokens or application database are sent
to the runner. Disable reviews from the dashboard; an already running container
may finish, but a paused/disabled receiver rejects its receipt. Failed jobs have
no automatic retry; stalled leases expire after thirty minutes.

## Isolated regression workflow

`ScopeGuard isolated tests` runs on relevant pushes to `scopeguard-app`, separately
from the trading workflows on `main`. It uses a standard public-repository GitHub
runner, no paid AI, no larger runners, and no artifact/cache uploads. Existing
Render hosting charges are unchanged. There is no schedule or 24-hour runner;
GitHub schedules require the default branch, which this update does not change.

A disposable runner builds a test-only image containing source and synthetic tests,
not deployment data or credentials. The container has no external network, no host
mounts or Docker socket, a read-only filesystem, no Linux capabilities, no-new-
privileges, a non-root UID, and CPU/memory/process/time limits. Before test imports,
the harness verifies those isolation settings and fails closed if unsupported.
The regression suite includes real loopback HTTP authentication/CSRF tests; other
external API cases are mocked. The Python base tag receives updates; the workflow
build log records the resolved image digest. This is not a general hostile-code
sandbox, expert AI analysis, exploit discovery, or proof of bounty eligibility.

Look for **ScopeGuard isolated tests** and the `scopeguard-app` branch in Actions.
Only a completed successful run verifies that revision; publishing this file alone
does not prove the remote runtime passed. Paid API guards remain unchanged.

## Python source audits

The dashboard includes a local Python AST pattern audit for dynamic code execution, shell commands, unsafe pickle/YAML loading, disabled TLS verification, dynamic SQL construction, and non-cryptographic randomness. Matches are leads, not confirmed vulnerabilities. There is no taint/data-flow analysis, dependency vulnerability lookup, interprocedural analysis or exploit validation. No matches does not certify security.

Only a fixed list of ScopeGuard source files is automatically checked, and results are refreshed when file content changes. Operators can upload Python files they own or are authorized to audit (128 KB per file, at most 20 distinct uploaded filenames). Source text is parsed in memory, not imported or executed, and is not saved. Results store filename, digest, line number, rule and remediation without code snippets. Strip secrets before upload. This audit does not probe GitHub or automatically submit bounty reports. Existing website schedules remain unchanged.

## Background review queue

A server worker checks every 10 seconds for new or changed local program and finding data. It persists review fingerprints and results, processes batches of at most 100, resumes after restarts, honors pause, and logs real completed work. Unchanged data is not repeatedly reviewed. Worker heartbeat and pending count are exposed separately from work events. No work means an explicit waiting status.

Public bounty directories now refresh every 15 minutes, retaining exponential backoff after failures. Exact-URL website check intervals and permission expiry are unchanged. The queue makes no network requests and does not add targets or validate exploits. This is always-on scheduling, not continuous active security testing.

## Evidence review and report workspace

Findings now have rule-specific investigation priorities, benign explanations, missing-evidence prompts and contextual remediation guidance. Duplicate/ineligible/false-positive feedback lowers review priority. Local duplicate checks do not cover private platform reports.

Open a finding to save up to eight short evidence sections. Notes are unverified user assertions, rendered as text, and included in the downloadable draft. They never enable submissions, change testing permissions or trigger network requests. Current observation checks remain HEAD-only; authenticated authorization testing and exploit validation are not implemented.

Guidance references: https://docs.hackerone.com/en/articles/8475116-quality-reports and https://wstg.owasp.org/v4.2/5-Reporting/.

## Local review mode (current deployment)

Paid model API requests are disabled, including when an old key or enabled flags remain in the environment. Startup removes the saved OpenAI connection. The connection endpoint rejects paid AI setup. Existing HackerOne settings are retained.

Every listed program receives a deterministic local review of reward uncertainty and missing scope/permission evidence. Reviews are calculated from current saved data with no daily quota or model calls. Findings use the existing local supervisor rules. These are not AI or exploit-validation capabilities.

Public directories refresh every 15 minutes; approved exact-URL HEAD checks retain their individual intervals, pause controls, rate limits and permission expiry. The server runs these jobs without an open browser. Existing hosting and disk costs remain; this is zero AI API usage, not free hosting. Unproven findings cannot be submitted.

Earlier AI notes are historical and may include failed attempts. Optional legacy paid routines remain covered by tests, but the deployed local-only guard prevents their use.

# ScopeGuard — authorized research assistant

This is a working first version of a conservative security observation and report-triage tool. It is not an autonomous penetration tester or a guaranteed income system. No target is preapproved. No external scanning has been performed during development.

## What works

- Password-protected mobile-friendly dashboard, exact-URL authorization register and global pause.
- Persistent SQLite scheduler, deduplicated observations, event log and private Markdown report downloads.
- HTTPS HEAD observations of security headers and redacted cookie attributes. Optional second HEAD with a test Origin, requiring separate policy permission.
- Feedback-based ranking: accepted versus false-positive/ineligible outcomes update review priority with a smoothed ratio. This is simple adaptive ranking, not an AI model training itself, not exploit generation, and not an earnings prediction.
- Continuous scheduling with automatic restart under Docker Compose and a persistent data volume. Paused/running state survives restarts. Each target's approval expires after at most seven days and must be reviewed again.

## Easiest next step

Give your assistant the link to ONE bug bounty program you have joined, plus access to the hosting account you want to use. The current package has not been deployed. A persistent always-on host and current written program authorization are required before live use. Hosting may cost money. A free sleeping host does not provide continuous operation.

## Start on a computer or server

Python 3.12+, no pip packages required:

```bash
export ADMIN_PASSWORD='replace-with-a-unique-long-password-at-least-24-characters'
python app.py
```

Open http://127.0.0.1:8080 and sign in as `admin` with the password you set. The first installation starts paused. Add only exact URLs covered by written authorization, record the current policy restrictions, and resume.

For continuous operation on a server with Docker Compose, create a `.env` file containing `ADMIN_PASSWORD=` followed by your own unique password, then:

```bash
docker compose up -d --build
```

The port binds to loopback only. For access from your iPhone, use a TLS reverse proxy or private VPN. Do not expose plain HTTP password authentication to the internet. Run one application instance against the database. Back up the `scopeguard-data` volume. Docker restart handles process/server restarts; host/network outages can still interrupt service. This package does not provision a cloud server or guarantee uptime.

## Workflow

1. Join a program and read its current policy, scope, exclusions, rate limits, and automation requirements. Public accessibility is not authorization.
2. Add an exact HTTPS URL and policy reference. URLs with queries, credentials, fragments, alternate ports, wildcards, and non-ASCII characters are rejected in this version. No URL discovery occurs.
3. Confirm that HEAD checks and the requested interval are permitted. If special researcher headers, registered source IPs, authentication, or other unsupported controls are required, do not enable that target. Optional CORS checks add one request and must also be explicitly permitted.
4. Resume checks. The worker considers targets every ten seconds and handles one at a time. The minimum per-target interval is one hour. Shared-host traffic limits must account for every configured URL; the app does not infer organization-wide limits from policy text. Use conservative intervals and few targets.
5. Review leads. HEAD behavior can differ from GET. Missing headers or cookie flags alone usually do not establish security impact. CORS reflection alone is not proof of sensitive data disclosure. Report titles and severity do not claim otherwise.
6. Validate within program rules, check eligibility and duplicates, and add real impact before submitting privately through the platform. Report sending is manual. Feedback comes from your review or the program's actual response, not an invented acceptance signal.
7. Use Pause or Disable immediately if authorization is withdrawn. An in-flight request may finish. Re-read policies before renewing authorization; the app does not automatically monitor policy changes. Expiration is checked before each scheduled request.

## Boundaries and limits

- HTTPS only, certificate verification enabled, all DNS answers must be public; connections are pinned to a validated address. Private/reserved destinations and redirects are blocked.
- No crawling, payload injection, exploitation, login attempts, credential harvesting, file extraction, brute force, denial of service, evasion, account creation, or message sending.
- Requests are HEAD only and do not collect response bodies. Cookie values and redirect destinations are not stored. Security headers can still contain sensitive metadata; protect the database and reports.
- HTTP 401, 403, 429 or 5xx disables the target for review. Transport failures back off and disable it after three failures. Redirects and unsupported HEAD responses generate no findings.
- Observation evidence persists until you remove the application database; events are capped at 500. Findings retain first/last observation, not a full response history, and are not automatically marked resolved when absent later.
- Scope approval is an operator attestation. The software cannot determine legality, prove the policy authorizes you, or guarantee that policies have not changed. It does not treat a policy link as permission by itself.
- The dashboard uses a small standard-library HTTP server intended behind a TLS reverse proxy or private network; it is a single-user MVP, without MFA, multi-tenant isolation or distributed workers.
- Basic findings are commonly excluded from bounty rewards. Finding valuable business-logic or authorization flaws generally needs deeper, carefully authorized human work. Do not submit raw scanner output as a proven vulnerability.

## Verification

```bash
python -m unittest -v
```

Tests use synthetic responses and mocked networking. They check scope validation, DNS restrictions, scheduler gates, stopping behavior, deduplication, feedback and report access. They do not attack any live target.

Reference policies (reviewed during development):
- https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings
- https://docs.hackerone.com/en/articles/8494552-defining-scope

This project is a starting point for authorized research, not a substitute for a program's written rules.


## Supervisor (1.1)

The automatic rules review counts up to three observations separated by the approved target interval. Historical installations retain only their last observation, so older repeats are not invented. It checks scope expiry, repeatability, evidence limitations, and a verified reporting route for the configured GitHub and RoboForm URLs. Current HEAD-only observations are always held: neither repeat counts, manual feedback labels, nor AI opinions prove impact. Draft downloads include the supervisor decision. No report is sent automatically.

Optional OpenAI advisory review is implemented but disabled by default. Configure all three server-only Render environment variables to activate it after approving API costs:
- SUPERVISOR_AI_ENABLED=true
- OPENAI_API_KEY=<secret, never commit or enter in the dashboard UI>
- SUPERVISOR_AI_MODEL=<Responses API model available to your account>

AI reviews begin only after three spaced observations and while the scheduler and target remain enabled. Each distinct finding/review input is attempted once, with a persistent maximum of three attempts per UTC day for the whole app. Failed attempts consume the limit and are not automatically retried. This is a request limit, not a dollar budget. The request sends only a derived rule, observation note, repeat count and evidence limitations; no response bodies, cookie values, credentials or raw headers. store=false is requested. AI output is displayed as escaped advisory text and cannot change scope, dispatch tests, validate findings, choose recipients or send reports. Network/API validation with a real provider account remains pending.

Reporting channels were reviewed on 2026-09-24:
- GitHub, GitHub API, Gist, npm: https://hackerone.com/github (rules: https://bounty.github.com/rules).
- RoboForm: support system under Vulnerability Report, reached from https://www.roboform.com/researchers.

These routes require portal submission, not guessed email addresses. No email delivery account is configured and no SMTP/automatic portal submission is implemented. An actual reproducible impact finding and current eligibility review are required before developing a delivery workflow. The supervisor does not fetch updated program policies or renew scope automatically.

## Version 2: discovery and workflow dashboard

The dashboard has five clickable views: Websites in queue, Under review, Supervisor review, Results, and Submitted / emailed. Search, currency filters, program details, scope-review shortlisting, target details and evidence downloads work on mobile.

A persistent background worker checks the public `arkadiyt/bounty-targets-data` HackerOne and Intigriti directories every 15 minutes. It imports paid programs and reported maximum rewards, deduplicates policy URLs, preserves review state, marks removed programs unavailable, and backs off after source failures. It does not request company websites or create scan targets. Directory data is attributed to https://github.com/arkadiyt/bounty-targets-data and must be checked against the official policy. Amounts are sorted descending within each currency, without fabricated exchange rates; unknown amounts are listed separately.

New discovery is enabled by default. It can be paused independently of previously approved target checks. Directory refreshes have a five-minute cooldown. Saved catalog data and workflow state use the existing SQLite database on the persistent disk.

Optional program-intake AI requires `DISCOVERY_AI_ENABLED=true`, `OPENAI_API_KEY`, and `SUPERVISOR_AI_MODEL`. It is OFF unless explicitly configured. It makes at most one attempt/day, with the attempt recorded before dispatch. Only program name, directory source and reported reward are sent; it cannot fetch sites, create targets, authorize tests, change scope, or submit reports. Supervisor AI retains its separate three-attempt/day cap. API charges are not included in hosting and require separate configuration/approval.

Scope verification and reproducible impact still require actual evidence. This version does not automatically verify arbitrary program policies or perform exploitation. The current HEAD checks cannot establish bounty eligibility. Up to three scheduled observations lead to a held review result, never a verified bug solely on repetition.

Automatic email/portal delivery is not connected. The submission view records an actual report reference supplied by an operator, labelled `user_recorded`; this neither sends a report nor independently verifies company receipt or payout. Feedback such as "accepted" never becomes proof of delivery.

Tests: `python -m unittest -v` (including discovery isolation, changed/removed listings, mixed-currency ranking, AI limits, and receipt requirements).

## Version 2.1: simple mode and private AI setup

The phone dashboard shows five plain-language stages without horizontal scrolling: Found websites, Checking, Double-checking, Results and Sent reports. Checking counts only enabled URLs whose authorization has not expired. The single Pause everything / Resume control updates the scheduler and discovery settings together in one database transaction. Technical controls remain under Settings & details.

Finish setup opens a private OpenAI connection form. It requires explicit acknowledgement of separate paid API usage. It verifies access using GET /v1/models/gpt-4.1-mini (no generation), then stores the key only at DATA_DIR/ai-connection.json, atomically with mode 0600. Credentials are never returned by /api/state or stored in source. Both optional advisers then use gpt-4.1-mini, retaining their existing persistent daily attempt caps (3 finding reviews plus 1 program review). No paid call is made without configuration. The user still needs an API account, suitable permissions and billing; model access alone does not prove billing availability.

Disconnect removes the stored key and disables both advisers across restarts. Existing deployment-environment configuration is preserved when no private connection file exists. Failed verification leaves an existing connection unchanged.

Official references checked: https://developers.openai.com/api/docs/models/gpt-4.1-mini and https://developers.openai.com/api/reference/resources/models/methods/retrieve .

No confirmed vulnerability exists in the current header-only lead. Report delivery remains pending: GitHub requires HackerOne and RoboForm requires its support portal. A connection or AI opinion cannot replace reproducible security impact or program eligibility. No newly discovered program is authorized by this update.

## Version 2.2: HackerOne reporting connection

Finish setup now includes a private HackerOne API username/token connection. Access is verified with GET `/v1/hackers/me/reports?page[size]=1` before credentials are saved. The operator must explicitly permit submission through that account. Credentials are stored only in DATA_DIR/reporting-connection.json with mode 0600; disconnect removes them. They are never returned in the dashboard state.

A reporting worker can submit via POST `/v1/hackers/reports` only when the supervisor independently marks a report `submission_ready` and supplies a validated reproduction and demonstrated impact. The current header-only supervisor never marks its observations ready: none of the current leads qualify. AI feedback, a repeat count and manual "accepted" feedback cannot authorize delivery. Scope must remain enabled and unexpired, the scheduler must be active, and the reporting route must be a verified HackerOne program URL.

At most one delivery attempt per UTC day is allowed. An attempt is persisted before dispatch. Timeout, malformed receipt or crash requires manual reconciliation: the same finding is never blindly retried. A report appears in Sent reports only after a valid HackerOne report ID is received, labelled `hackerone_receipt`; this does not prove bounty acceptance or payment. Existing manually recorded receipts retain their separate label. RoboForm has no connector in this release because its required route is the support portal.

Official API reference: https://api.hackerone.com/hacker-resources/ (Get Reports / Create Report). Policy checks for GitHub, GitLab and Cloudflare are included in listing details, dated 2026-09-24. Reporting-route confirmation does not grant scanning permission. Program policies must be rechecked before new testing.

All 36 tests pass with mocked delivery and credentials. No real HackerOne account has been connected or real report submitted during implementation. Paid AI still requires the user's private API key and opt-in.

### Deeper review modules

Python audits now include conservative, within-function traces from selected input sources to SQL, shell, deserialization and dynamic-code operations. Trace line numbers prioritize review; they are not executable proofs. Cross-function behavior and aliases can be missed, branches are combined conservatively, and runtime impact remains unverified.

The Known vulnerability monitor accepts owned/authorized `requirements.txt` exact pins or npm `package-lock.json` v2/v3. With explicit package-sharing consent it submits only normalized package names and exact versions to OSV, never installs packages, and checks daily. Original files are discarded. Unsupported entries are counted. Maximum 10 inventories of 500 versions each; update the uploaded inventory when dependencies change. Pausing everything stops new batches. Failures retain prior results with an outdated-results warning and retry backoff. Removing an inventory stops monitoring it.

These modules do not turn the existing HEAD checks into autonomous exploit discovery. They do not establish exploitability, eligibility, severity, or a payable bug, and cannot unlock report submission. Real account and business-logic testing still needs specific scope, test cases and controlled test data.

### Executable owned-app validation

ScopeGuard now makes seven read-only HTTP checks against its own loopback listener every hour while running. A successful authenticated control is required before any result can pass. Checks cover anonymous and wrong-password access to private state, report authentication, and missing/incorrect CSRF tokens. Empty JSON on the settings route cannot modify a setting. Apparent unauthorized private-state access is repeated before being marked reproduced. This result applies only to the owned ScopeGuard instance, never to GitHub or another bounty program.

The destination and routes are fixed in code. Server credentials are used only on loopback. Evidence contains request method/path, expected/actual status, byte count and response fingerprint; response bodies and credentials are discarded. The latest 20 runs are retained. Pause is honored before every request. Network/control failures are inconclusive and retry after ten minutes. Manual runs have a five-minute cooldown. Deployment proxy/TLS behavior and all other vulnerability classes remain outside these checks.

### Private-data access comparison (external approved API)

The new profile checks one active, exact approved HTTPS URL for a unique synthetic marker in JSON. The user must attest authenticated/anonymous read-only comparisons are permitted, own the account and data, record the test-specific rules, and confirm the marker should be private. The original target scope expiry still applies; configuring a profile does not renew it. Four GETs maximum per 15 minutes: authenticated control, anonymous comparison, anonymous repeat, authenticated repeat. If the anonymous request is denied or omits the marker, the test ends after two requests. No crawling, object guessing, credential guessing, redirects, cookies or state-changing operations are performed.

Public DNS is checked and the connection is pinned to the validated address with TLS hostname verification. Response size is capped at 64 KB. Credentials and synthetic markers are stored in a private 0600 file, outside API snapshots; bodies are discarded. Evidence retains statuses, marker-presence booleans, sizes and hashes. Profiles stop on reproduced exposure, failed controls, network errors, throttling or expired/disabled scope. Global pause is checked before each request. Removing a profile deletes its credentials.

A reproduced marker exposure is a factual observation, not an automatic critical rating, payout claim or verified bounty submission. Intended access behavior, exploitation impact and program eligibility require review. This module does not cover other access-control flaws, XSS, SQL injection, RCE or business-logic vulnerabilities. No external profile is enabled merely by deploying the module.


### Capital.com demo connector

The dashboard offers a demo-only watchlist login-boundary test. Personal account creation, 2FA, API-key generation and confirmation of current program permission must be completed by the account owner. The connector is inactive until configured. It uses only the fixed demo API hostname and three method/path combinations: session login, GET watchlists, and POST one empty synthetic watchlist. No trading, balance, order, payment, ID enumeration or arbitrary URL functions exist in this connector.

Each scheduled run starts a new session, checks the owner's synthetic watchlist name with valid credentials, then compares anonymous access. A suspected exposure requires two anonymous observations and a final authenticated control. Results contain response hashes and booleans, never account data or tokens. The program's privacy rules and actual impact still need manual review; no automatic bounty submission is enabled. Scope permission expires after seven days. Checks run every 15 minutes while the service is running, resume after a restart, respect global pause, and stop on rate limits, setup failure, inconclusive responses or reproduced exposure. An ambiguous watchlist-creation request is not automatically repeated. Reconnection preserves the marker for the same account. Disconnect removes locally stored credentials; the synthetic watchlist can be deleted manually in Capital.com.

Local tests use mocked Capital.com responses. Live integration cannot be verified before an eligible owner connects their demo account. Official documentation: https://open-api.capital.com/ ; program: https://app.intigriti.com/programs/capitalcom/capitalcom/detail .

### GitLab private project connector
The dashboard now has **Finish GitLab setup**. No repository files are required.
Use a dedicated test account, your own private project, and a short-lived personal
access token with only `read_api`. This scope can read other projects the account
can access, although this connector only requests the configured project and the
token's own scope metadata. The token is stored with mode 0600 on the persistent disk.
Generate a synthetic marker in the setup form and save it in the project's description.
Record current program permission before enabling any production comparison.
GitLab recommends local GDK research for most testing; a directory listing is not permission.

The worker verifies the token's scope and Maintainer/Owner role, checks private
visibility and marker presence, then compares anonymous access. A suspected
exposure requires a second anonymous response and a final authenticated control
with the same project ID and private visibility. At most five GET requests per
15-minute run, one second apart. It follows no redirects, caps bodies at 64 KB,
pins public IPs with TLS hostname verification, and stops on errors, uncertain
responses, pause, expiry, disconnect or suspected exposure. No writes, ID guessing,
crawling, code execution or report submission occur. Permission expires after seven days.

UI evidence contains status codes and hashes, not tokens or project response bodies.
A pass only means this single check passed. A reproduced marker is not an automatic
severity rating or bounty claim; confidential impact and eligibility require review.
Tests use mocked GitLab responses; the user's live connection needs their token and
synthetic description before it can be verified. The unused Capital.com connector
card is hidden unless already configured; Capital.com is unavailable in India.

### Project research

The Project research card analyzes up to 80 UTF-8 Python files in an owner-authorized ZIP (2 MB compressed and expanded, 128 KB per Python file). Archives are read in memory, never extracted; unsafe paths, symlinks and encrypted entries are rejected. Source text is not retained or executed. Results contain file/line paths and a content fingerprint, and can be downloaded as JSON.

The bounded analyzer follows direct calls between project functions and declared class methods, arguments and returns (six call levels, 240,000 expression visits). It looks for external input reaching SQL text, shell commands, dynamic code or object deserialization. Findings remain static hypotheses: framework reachability, sanitizers, inheritance, instance state and runtime impact need separate review. It does not analyze Ruby/JavaScript, run arbitrary tests, claim critical severity, or submit reports. ScopeGuard's own 35 Python modules are reviewed automatically after code changes; uploaded archives are re-reviewed when uploaded again. Existing permission, pause and submission controls remain in force.

### Change-aware project research

Project research compares successive authorized Python ZIP uploads under the same
project name. Keep paths within the ZIP stable across revisions. It stores file
hashes, not source. New leads and leads traversing changed files appear first;
that ordering is an investigation aid, not a severity or earnings prediction.
Line-only movements preserve a lead identity. An engine upgrade starts a fresh
baseline instead of presenting historical leads as newly introduced bugs.

Each lead includes a hypothesis, an evidence checklist, and a count of other
leads using the same sensitive operation. This is grouping, not automatic
root-cause or variant validation. Investigators can save redacted notes and mark
false positives, known issues, or out-of-scope leads. A changed project invalidates
the old decision and returns the lead to active review. Notes cannot mark a lead
confirmed or enable submission. Disappearing paths are labeled "no longer
observed", never "fixed", because analysis coverage is incomplete.

The installed application is reviewed after its source changes; uploaded projects
require a new upload unless separately connected to automatic source research.
This does not execute uploaded code, run an LLM, or validate exploits. Ruby,
JavaScript, authorization logic and concurrency analysis remain outside this
analyzer's coverage.

### Automatic source research

The persistent source-watch worker supports up to three explicitly approved public
GitHub repositories. Every 15 minutes it resolves the configured branch to a
commit, downloads a bounded ZIP for that exact commit when needed, and runs the
existing Python analyzer. It strips the revision-dependent archive root so paths
remain stable across comparisons. An optional source subdirectory filters the
Python files, but archive-wide size and entry limits still apply. Changes to
other languages are not analyzed. Unchanged commits are not downloaded again;
new commits with identical Python content reuse the previous analysis. An engine
version change causes reanalysis.

Only GET requests to fixed api.github.com and codeload.github.com endpoints are
used, with public-IP pinning and TLS hostname validation. No cookies, passwords,
tokens, redirects, repository commands, dependency installs, or uploaded-code
execution are allowed. Requests honor owner pause, permission expiry, and
configuration generation changes. An already-dispatched request may finish.
Permission must be renewed within seven days. A rate-limit response backs off
all source watches, repeated transient failures stop the watch, and permanent
errors require operator review. Prior evidence is preserved on failure.

Jobs persist their next due time before network work; after process restart a
claimed job is retried when due. A worker check-in, last successful commit,
review count, and the latest 20 of up to 100 retained activity records are
visible. Background processing shares the existing single-instance service and
SQLite disk; no extra paid worker or AI API is provisioned. This is automated
source review, not permission to probe GitHub or the repository's deployed app.
The analyzer and all its static-evidence limitations still apply. A completed
review is not a validated vulnerability or a promise of a bounty.

References for source ingestion:
- https://docs.github.com/en/rest/git/refs#get-a-reference
- https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives
- https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
