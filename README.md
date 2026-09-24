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

A persistent background worker checks the public `arkadiyt/bounty-targets-data` HackerOne and Intigriti directories every six hours. It imports paid programs and reported maximum rewards, deduplicates policy URLs, preserves review state, marks removed programs unavailable, and backs off after source failures. It does not request company websites or create scan targets. Directory data is attributed to https://github.com/arkadiyt/bounty-targets-data and must be checked against the official policy. Amounts are sorted descending within each currency, without fabricated exchange rates; unknown amounts are listed separately.

New discovery is enabled by default. It can be paused independently of previously approved target checks. Directory refreshes have a five-minute cooldown. Saved catalog data and workflow state use the existing SQLite database on the persistent disk.

Optional program-intake AI requires `DISCOVERY_AI_ENABLED=true`, `OPENAI_API_KEY`, and `SUPERVISOR_AI_MODEL`. It is OFF unless explicitly configured. It makes at most one attempt/day, with the attempt recorded before dispatch. Only program name, directory source and reported reward are sent; it cannot fetch sites, create targets, authorize tests, change scope, or submit reports. Supervisor AI retains its separate three-attempt/day cap. API charges are not included in hosting and require separate configuration/approval.

Scope verification and reproducible impact still require actual evidence. This version does not automatically verify arbitrary program policies or perform exploitation. The current HEAD checks cannot establish bounty eligibility. Up to three scheduled observations lead to a held review result, never a verified bug solely on repetition.

Automatic email/portal delivery is not connected. The submission view records an actual report reference supplied by an operator, labelled `user_recorded`; this neither sends a report nor independently verifies company receipt or payout. Feedback such as "accepted" never becomes proof of delivery.

Tests: `python -m unittest -v` (including discovery isolation, changed/removed listings, mixed-currency ranking, AI limits, and receipt requirements).
