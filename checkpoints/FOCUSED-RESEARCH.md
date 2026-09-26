# Focused research upgrade — 2026.09.26.3

This release adds working components in all seven requested areas. It does not
claim that five external programs are already enrolled or that all 1,000 catalog
items are executable. The dashboard separates preparation, runtime evidence and
reviewed drafts.

| Area | Implemented behavior | Required context |
| --- | --- | --- |
| Program preparation | Automatically refreshes a five-program shortlist from saved official policies, exact web assets and configured jobs. Shows the concrete missing prerequisites. | A directory listing and reward maximum never grant testing permission. Account signup, terms and eligibility are not invented or bypassed. |
| Workflow mapping | Maps up to six exact approved GET pages. Chromium renders permitted pages when available; a clearly labeled HTML-structure fallback works without Chromium. Link/form destinations are hashed, and discovered routes never become targets. | Separate GET mapping permission, a working owned account and approved exact URLs. Redirects, writes, downloads, WebSockets and unlisted requests are blocked. |
| Deeper access testing | Up to four owned accounts and twelve resources, with expected role/resource access. Each denied comparison uses owner-before, two comparison requests, owner-after, with working second-account controls before and after authenticated comparisons. | Explicit expected access and unique synthetic markers in private JSON records; one HTTPS origin per workflow. Supports Basic/Bearer credentials, not arbitrary login forms or CAPTCHA. |
| Executable checkpoints | Adds nested-resource reads, alternate representations, exports, search and previews to the existing ownership/admin-read adapters. | Feature labels must describe the actual configured resource. Read-only testing does not cover write, deletion, membership-change or payment workflows. |
| Efficient scheduling | Durable batches/cursors, shared dispatch exclusion with the existing automatic runner, per-program gaps, request budgets, rule-change invalidation and longer intervals after repeated unchanged results. | Maximum 24 requests/run, minimum 15-minute interval. A changed result never permits an earlier request than the reviewed budget. |
| Outcome learning | Fixed detection benchmark plus feature priorities from observed inconclusive checks and operator-reviewed outcomes. Priorities remain frozen during each batch cycle to prevent starvation. | Operator-marked accepted findings are not independently verified platform acceptance. Lab accuracy does not estimate real program accuracy. |
| Verification/reporting | Independent receipt verification, structured impact/identity/scope/duplicate review, sanitized reproducible report drafts, download endpoint and separate report-ready counts. | No automatic submission by this new workflow. An observed marker difference is a candidate until intended access and real impact are verified. |

## Request and evidence boundaries

The new workflow needs a separate configuration; it never expands a saved HEAD
permission into GET permission. Both the saved target and workflow authorization
are checked before each request. Disabled/expired targets, changed policy
digests, pause state, redirects, server errors and rate limits stop the work.
Already-sent requests may complete; invalidated results cannot become findings.

Private account values live in mode-0600 files on the existing data disk. The
dashboard and evidence expose only account labels, status codes, response hashes,
marker booleans and structure metadata. No response bodies, cookie values,
credentials or screenshots are stored in reports.

Browser transport uses the same pinned-public-IP TLS checks as the other scoped
transports. All browser traffic is intercepted; a closed local proxy blocks
native fallback networking. The pinned official Playwright package and Chromium
headless shell are installed once into the existing disk by the application
entry point. Imports, unit tests and authenticated requests never trigger an
installation. A disk-space check prevents adding capacity or consuming the last
free space. Installation/startup state is visible in Detection quality and logs.

## Coverage counts

The catalog now has **35 implemented checkpoint adapters**, of which seven can
consume the configured read-only workflow matrix. Five are newly connected; the
ownership and administrative-read IDs already had narrower adapters. The other
**965** entries still need implementation or applicable feature context.

The fixed ten-case detector benchmark includes planted anonymous and cross-account exposures, their fixed
counterpart, broken owner and comparison-account controls, misleading HTTP 200 responses, transient
exposure, rate limiting, redirects and mid-run revocation. A separate integration
test verifies the same detector against vulnerable and fixed loopback HTTP
handlers. None of these are external bug findings.

## Dashboard and API

Use **Focused bug research → View focused research** for the shortlist, maps,
configured workflows and investigations. **Detection quality** shows the lab
benchmark, browser runtime and learned priorities. The setup form is available
only for saved, currently permitted exact URLs.

Authenticated, CSRF-protected mutations:

- `POST /api/workflows/configure`
- `POST /api/workflows/disable`
- `POST /api/workflows/review`

Authenticated read:

- `GET /workflow-report/<case-id>`
- `GET /api/state` → `focused_research`

## References

- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html
- https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/
- https://docs.hackerone.com/en/articles/8475116-quality-reports
- https://playwright.dev/python/docs/network
- https://pypi.org/project/playwright/1.63.0/
