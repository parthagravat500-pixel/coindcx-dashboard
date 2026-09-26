# ScopeGuard permission review progress

## 2026-09-26, program API parser compatibility

Follow-up: 8709bc04dd80eb0e98f3538dd5a2b46ec298a657 passed 293 hosted
tests and became live at 11:21 UTC. Its first request still encountered a generic
schema failure. Added fixed field-specific diagnostics for missing program data,
attributes, non-text policies and unexpected status fields. Missing descriptive
type metadata is now recorded as unspecified; exact identity and required policy
fields remain mandatory. Oversized text is identified as a size limit instead of
a format mismatch. Twenty-six focused tests passed. This does not claim that a
live policy collection has succeeded; subsequent receipts determine that.

The diagnostic release a05e92c97ea6845509f0bfe873939d99b92177d4 passed
291 hosted tests and became live at 11:16 UTC. Its fixed diagnostic confirmed
that the nominal program record type did not match the documentation example.
The actual source label was not logged, so no particular alias is claimed.

The reader now validates bounded metadata labels, exact requested program handle,
the required policy/state fields and exact scope/exclusion attribute shapes. It
preserves the platform label as metadata rather than treating a documentation
example's label as an authorization boundary. Missing fields, wrong program
identity, invalid labels and incomplete evidence still fail closed. No testing
permission or activation is produced. The source remains the fixed HTTPS API
route with the account's existing authorized connection.

A one-time parser migration reschedules unfinished parsing failures without
resetting access refusals, provider blocks, retry timers or request limits.
Twenty-five focused tests passed, including metadata variants, identity binding,
and migration preserving those controls. Real document collection remains subject
to the subsequent live worker receipt; this source change alone is not a review.

## 2026-09-26, live program research and failure explanations

Commit d51e94ef4ae81b59f6281a791b3d35b6b89a9165 passed GitHub checks and all
289 hosted build tests, and became live on the existing service at 11:08 UTC.
An aggregate worker receipt confirmed 304 tracked listings, the existing
HackerOne connection, and no Intigriti connection. Its first request was
incomplete; this is not a completed review. No private policy payload or token
was inspected or included here, and the browser access block was not bypassed.

Added fixed, non-sensitive failure codes and plain-language dashboard explanations
to distinguish HTTP refusal, transport failure, document format, identity and
storage limits. Migration preserves queued work and saved evidence; successful
collection clears previous errors. Response bodies and exception text are never
logged. Twenty-three focused API/queue tests and dashboard DOM checks passed,
including migration, restart and error privacy regressions. Live progress and any
remaining platform incompatibility are checked after publication.

## 2026-09-26, persistent research for every listed program

Baseline f469c56879229f1a51dd3b4f4380ce4e92973bc9 and all 87 tracked blobs
were verified before editing. The directory had no program-by-program official
document worker. Added programapi.py and programresearch.py, using documented
HackerOne and Intigriti researcher APIs. Official API documentation and Intigriti's
linked OpenAPI schema were read on 26 September. No third-party target was tested.

The new worker tracks every listing, uses authorized read-only API requests,
collects policy/scope/exclusions, preserves incomplete pagination, detects changes,
and continues past per-program access refusals. It stops an invalid provider
connection, respects Retry-After, and retains its request budget across restarts.
It does not infer permission, alter target activation, renew permissions, create
accounts, run exploits or send reports. Credentials stay in an owner-only file;
reading program rules never enables report delivery. No new paid resources.

A simple home-screen research panel and searchable complete program list expose
what was collected and what is missing. Exact API evidence is private behind the
existing authentication. Existing manually researched policy batches stay intact.
Rules collected, rules interpreted, configured tests and actual bugs are separate.
Intigriti tiers and automatedTooling values are not interpreted without verified
semantics; linked rules, attachments and eligibility may still need review.

Synthetic validation covers both API formats, multiple scope pages, all 304
synthetic listings with no credentials and zero completed reviews, restart,
deduplication, document changes, pause, stale directories, access denial,
provider authentication failures, backoff, bounded storage, credential redaction,
Mozilla restrictions and prompt-shaped policy text. A real authenticated loopback
HTTP test exercises connection -> worker -> private saved evidence without target
activation or submission. Dashboard checks cover text-only evidence rendering,
connection forms and stale asynchronous responses. All 289 local Python tests and
the dashboard DOM smoke test passed. Publication,
live connection availability and deployed worker progress are verified separately.

## 2026-09-26, hosting compatibility correction

The first deployment of a8c4a7038d639722bd67adea7095d722c52dfd40 was blocked
by its build tests: the host's Python SQLite module does not expose the optional
enable_load_extension method. Local and GitHub tests had passed, but the hosted
test run failed before release. The existing service version was preserved.

The component fixture now disables extension loading explicitly when that API
exists. Fresh SQLite connections keep their default disabled extension state;
the authorizer still rejects every SQL function, external database attachment
and write. An available API that fails to disable extensions still prevents the
fixture from running. Two regression tests cover the missing API, retained
sandbox restrictions, and failure cleanup. Deployment is verified separately.

## 2026-09-26, automatic lead follow-up and evidence inbox

Baseline: scopeguard-app da01ffbc852a3264907389729921b47598d46cb5. Verified all
83 local tracked blobs against the remote tree before editing. Implemented
querycheck.py and leadwork.py, connected them to the existing source-review and
worker paths, and exposed a simple View leads list without adding setup forms.

Local SQL component reproduction uses actual SQLite against inferred two-row
synthetic fixtures. It requires repeat extra-row observations plus owner and
parameter-binding controls, while prohibiting writes, attachments, pragmas and
arbitrary functions. Statement and VM work are bounded. Project code never
executes and source/query literals are not saved. The result is explicitly local
component evidence, not an application exploit, security guarantee, confirmed
bounty or submission approval. Other database dialects and unsupported paths
remain unresolved. Source-analysis version changed to invalidate old engine
caches; installed owned-source coverage is now 31 Python files.

The lead inbox ranks repeated runtime observations and local component evidence
above unverified source suspicions. It deduplicates evidence, preserves history
through restart, respects current review decisions, reopens stale decisions on
source changes and demotes configuration-changed runtime evidence. Not reproduced
and not observed never mean proven safe or fixed. Only existing saved evidence
is indexed: no target activation, permission renewal or report submission occurs.

Validation: 266 Python tests passed, including twelve new component/lead tests.
Actual quoted and numeric injection fixtures reproduce twice; numeric guards and
parameter binding do not become supported leads. Tests cover SQL authorizer
restrictions, budgets, redaction, unknown paths, deduplication, restart, review
changes and authenticated HTTP upload → production worker iteration → dashboard
evidence. Existing real-loopback boundary tests now verify runtime evidence enters
the inbox and expired permission makes it historical. The dashboard DOM smoke
test and JavaScript syntax checks passed. Owned installed-source review completed
locally in under a second and produced zero supported leads; no real vulnerability
or earnings are claimed. Synthetic demonstrations never become production leads.

Browser preview remains blocked by the earlier browser URL-policy decision; no
workaround or visual verification is claimed. Publication, the exact-commit CI
run, existing-service deployment and private aggregate worker receipt are verified
separately. No extra service, model/API charge, new compute resource or external
security test is required by this change. All unrelated trading code is preserved.

## 2026-09-26, simple home page and durable progress

Baseline: scopeguard-app 67dc2dc0fc7794acf8c87a2343199faee2ad9d3e. Verified
all local tracked blobs against that branch before edits. The main home screen
now answers what is happening, what was found, what is on hold, and what recently
finished. Specialist forms stay closed under advanced details. Policy reviews,
source reviews, successful checks and possible runtime issues remain distinct;
no general autonomous bounty-research completion is claimed.

Added durable outcome totals separate from the bounded journal, one-time import
of retained earlier workflow rows, and separate self-check/unfinished counts.
Pruning or restarting cannot reduce or double-count these totals. Earlier
standalone-worker history is not added. Disabled jobs get fixed explanations
for expired permission, access refusal, failed controls and connection problems.
The private health receipt exposes only counts of these fixed reasons. No real
user state, target names, credentials or findings are recorded in this commit.

The home page translates actual outcomes, shows each task's next permitted time,
and distinguishes waiting from running. Request timeout and response-order guards
prevent old responses from replacing newer state. Lost connectivity removes live
activity claims and disables the pause control until a fresh response arrives.
Evidence remains text-only and authenticated; reading it performs no mutations.

Validation: 254 Python tests passed. Three new tests cover history migration,
pruning/restart durability and fixed/redacted blocker explanations. Existing
end-to-end loopback tests now assert truthful completion/self-check/unfinished
counts and no repeated interrupted-lease count. Expanded DOM smoke checks pass
for the simple home, running versus waiting, safe evidence, read-only details,
timeouts, out-of-order responses and connection recovery. No external security
tests were performed for this change. A cloud-browser attempt to open the local
synthetic phone preview was blocked because file URLs are not permitted. That
operation stopped without a workaround; no visual-browser verification claimed.

Publication and deployment are verified separately. The existing service,
authentication, target permissions and resource plan are preserved. Full arbitrary
program enrollment, account/identity challenges, new testing permissions and
general vulnerability discovery remain outside the implemented automatic flow.

## 2026-09-26, live automatic-workflow receipt

Commit 11d923add56f303b52b7c57aac12d9444b94153a passed isolated GitHub run
36234151750 and was deployed to the existing service, deployment
dep-darpccvpn0mc73dggnv0, live at 09:55:03 UTC. Render's build also ran all
251 tests. Its startup receipt identified that exact revision and a healthy
scheduler. Task counts and permission state remain in private host logs.
This verifies startup, not a completed post-deployment security test or a finding.

The initial receipt did not explain blocked tasks or the next due time.
Added aggregate fixed gate-reason counts, eligible task kinds and next due time
to the same private host-log receipt. No URLs, account identities, rule text,
credentials or case details are included. The existing redaction test now also
checks expired-target reason counts and eligible-kind counts. This change makes
the real scheduling blockers diagnosable through authorized hosting access;
it introduces no unauthenticated endpoint and changes no target permissions.

## 2026-09-26, automatic runtime orchestration and private cases

Baseline: scopeguard-app 8006a69f5c4b323cb6726854d98dd5e30b623afa, tree
681f72b322440ba0aa69d0dca9f7aec9f9538f8c. Every local tracked blob was verified
against this remote tree before editing; the branch head was rechecked before
publication. Only this branch and the existing approved Render service are in
scope. Main trading code, credentials, resource plans and authentication are not
changed. No live private dashboard session was inspected.

Added autopilot.py: durable selection of already-authorized bounded runtime
checks, a persisted dispatch lease, fair task rotation, shared policy cooldowns,
failure backoff, interrupted-run recovery and private evidence follow-up. Header,
owned JSON, GitLab and owned-app validation workers now share this selector.
Their existing request limits, scope checks, stop rules and positive controls
remain in force. Other source/dependency workers retain their existing schedules.
The runtime loop creates a private draft only when control/comparison evidence
supports a repeated boundary failure, then continues other eligible work. It
does not send a report, rate severity, activate targets or approve a bounty.

The dashboard now leads with this automatic workflow, current blockers, actual
attempts and saved private cases. The previous header-only progress view is
retained as detail. Evidence is rendered as text; reading it never triggers a
test or a submission. A minimal operational receipt in private host logs exposes
aggregate scheduler health without target names, URLs, accounts or findings.
Added the scheduler to automatic installed-source review (29 Python files).

Centralized the standing Mozilla production-automation block in the target gate,
including direct bounded runner dispatch. Fixed access-profile result persistence
so finishing work cannot re-enable a profile disabled during the run. GitLab
evidence now includes only booleans for marker presence, private visibility and
ownership, allowing the new classifier to require actual control evidence.

Validation: 251 Python tests passed, including 14 new workflow tests; JavaScript
syntax and the dashboard DOM smoke test passed. A final focused 45-test run also
passed after the response-validation adjustment. Integration fixtures use two
actual loopback HTTP servers and the authenticated/CSRF-protected app API. They
exercise automatic selection, a repeated synthetic exposure, a correctly denied
resource, a failed control, own-app validation, saved drafts, restart persistence,
and continuing to the next job. Additional cases cover expired/revoked scope,
Mozilla and directory gates, rate limits, failed/duplicate workers, abandoned
leases, redacted health receipts, GitLab controls and ordinary header observations
not becoming cases. No external security checks or private real findings were
used in tests or published in source.

Operational deployment and live health are verified separately after publication.
This completes the run/evidence/next-task workflow for supported saved profiles.
It does not solve arbitrary-program permission acquisition, provider account/ID
challenges, general exploit discovery, independent bounty eligibility or report
acceptance. Keep these limitations visible; do not call the full arbitrary-site
bounty system complete based on a green test suite or a healthy worker.

## 2026-09-26, automatic source investigation

Baseline: scopeguard-app 4ac8c35db43fb1e20fb126c4f906923443bbb09c. Remote
head/tree were read and every local tracked blob matched before editing. The
user reaffirmed that ScopeGuard should perform the work automatically, without
repeated account setup. No existing permission, credential or pause state was
expanded by this change.

Added an automatic investigation stage to existing owned-source reviews,
authorized source watches and uploads. Static input paths now receive bounded
AST-model experiments with paired synthetic inputs and a private investigation
draft tied to the source evidence digest. Sensitive operations are intercepted;
no inspected code, SQL, shell command or deserializer runs. Unsupported paths,
unreproduced sampled paths and budget limits remain unresolved. Even a modeled
input flow does not establish unsafe handling, runtime reachability, authorization
failure, real impact or bounty eligibility. No automatic report submission or
new target activation was added.

The installed-source worker now covers 28 Python files, including the previously
omitted newer permission, identity, OAuth and research modules. It checks changes
once per minute inside the existing worker, deduplicates unchanged evidence,
honors the master pause, persists progress across restarts and rolls back a failed
stage before retrying with backoff. Authenticated dashboard state exposes worker
health, last review, experiments, unresolved leads and investigation drafts.
Automatic source research is the primary card; Uber profile integration and
program preparation are collapsed optional details.

Validation: all 237 Python tests passed, including 11 new automatic-research tests,
plus JavaScript syntax and dashboard DOM checks. Synthetic fixtures cover
cross-file flows, guards, safe SQL parameter binding, unsupported operations,
analysis budgets, no source-value persistence, pause, deduplication, restart,
rollback, retry and no target/submission creation. A local run on the actual 28
installed source files completed in approximately 0.4 seconds with zero static
input-flow leads and zero activated targets; this is not a clean bill of health
or a statement about the private live queue. An unchanged second pass did not
increase completed reviews.

No extra resources, paid service, Uber login, external security test, account,
submission or confirmed bounty bug was created. The full autonomous research
system for arbitrary bounty programs remains incomplete: live permission and
account barriers, unsupported languages/paths and independent runtime validation
are not solved by this source-model pipeline. Publication and deployment are
verified separately after this commit; no private live-state inspection is claimed.

## 2026-09-26, Uber profile connector implementation

Baseline: scopeguard-app 575c39d88b5ca86fbe6f5c55c7a474a3b4da3a70.
The edited existing files matched that remote tree before changes. The user
requested an actual connection. The previous source contained connection notes,
but no OAuth connector; this change implements the missing owned-app component.

The connector stays disabled without provider approval recorded in server
configuration, a registered application ID/secret, and a fixed HTTPS callback.
Only an authenticated administrator with CSRF protection can begin an explicit
account-owner authorization. A single-use, expiring state is bound to a Secure,
HttpOnly, SameSite=Lax host-only cookie. The return remains authenticated.
Only Uber's fixed token, profile and revocation endpoints are callable; redirects
and retries are disabled. The requested permission is profile only. A successful
profile response is necessary for connected status; no broader scope is accepted.

Profile contents are discarded. Tokens stay in process memory, never in source,
policy records, the database, browser storage or state responses. Expiry and
configuration changes remove connected status. Disconnect invalidates pending
work and removes local access even if remote revocation fails; unconfirmed
revocation is displayed. A restart loses local access but does not revoke Uber's
application grant. No refresh loop or background account requests were added.

The dashboard now shows operational connection status separately from saved
policy notes. Missing developer setup offers no credential form or sign-in loop.
A successful profile connection cannot enable targets, authorize testing, alter
workers, inflate completion counters or create a bounty finding. The nine policy
reviews are unchanged in count. Public progress contains no user account data.

Validation: 226 Python tests passed, including 15 new connector tests, plus
JavaScript syntax and synthetic dashboard DOM checks. Coverage includes missing
configuration/consent, callback state and browser binding, replay and expiry,
excess scope, redirects, bounded responses, secret redaction, failed profile
verification, disconnect races, CSRF and no target activation. All connector
responses were synthetic; the HTTP integration test used loopback only.

No approved developer app, real OAuth exchange, Uber API call, live connection,
security test, account creation, contact, report, purchase or additional spending
was established by this work. Developer approval and private server setup remain
external blockers. Deployment verification is pending at this commit.

## 2026-09-26, Uber connection requirements

Baseline: scopeguard-app f75af88f997a2fa64fc9b86892527507b7480840. Latest
remote source and prior preparation were read and local edited-file blob hashes
matched before starting. Existing user changes were preserved.

Official developer documentation was read for OAuth user tokens and both the
v1.2 and v3 profile APIs. Both endpoint pages state that API access requires Uber
approval. A phone login and HackerOne membership do not establish that approval.
No provider-approved application or working Uber OAuth connector was established
in ScopeGuard. The API prerequisite is separate from manual browser research
under the bounty rules; it is not represented as a blanket ban on manual testing.

Added a structured, read-only connection requirements panel to the existing
research plan. It shows provider access, implementation, owner consent and exact
testing-scope prerequisites, with official documentation URLs and a checked date.
The manual browser route is distinguished from a server API connection. Removed
repeated account-creation and username-confirmation instructions from this public
plan. No personal identity, phone number, email, credential or account screenshot
is included in source. The nine unique policy reviews remain nine; this is not
another program review or completed security check.

Connection notes accept only bounded display fields. Credential fields and
OAuth callback query parameters are discarded; connected and authorizes_testing
stay false even if an evidence file claims otherwise. No OAuth connector,
credential store or live testing permission is created by these notes.

Validation: 39 focused access-matrix, access-check, policy-evidence and HTTP tests
passed, plus JavaScript syntax and dashboard DOM smoke checks. Synthetic fixtures
verify that connection notes cannot authenticate, activate a target, collect
credentials, inflate completed checks or render executable markup. No Uber API
request, live vulnerability test, account creation, contact, submission, paid
service or new compute resource was used for this work. The shared research
browser sign-in and deployment verification remain pending at this commit.

## 2026-09-26, Uber selected for research

Baseline: scopeguard-app 780715bfca2cdcb0319f632b88909c3d2886df75. The earlier
simple dashboard deployment was confirmed live by Render and its GitHub checks
passed. The user now selected Uber and authorized preparation up to steps that
need their account or confirmation.

Re-read the current Uber HackerOne policy (dated April 30) and all 24 scope rows
(scope updated September 22): four in scope and 20 excluded/conditional rows.
This is a follow-up to the existing Uber record, not a tenth reviewed program.
The newer record in `2026-09-26-batch-04-uber.json` preserves sources, timestamp,
exact assets, exclusions and uncertainty. It corrects two potential ambiguities:
unvalidated automation output is ineligible, which is not an explicit blanket
ban on every tool; and the uber.com Domain row is not expanded into a wildcard.
The scope table's fraud exclusion takes precedence in this work over broader
policy examples. No free-ride or payment-evasion testing is planned.

Ordinary public research read https://www.uber.com/ and inspected the official
sign-in page at https://auth.uber.com/v2?next_url=https://www.uber.com. The live
form offered phone/email and Google; no identifier, password or OTP was entered.
A bounded read of the policy-linked ListDomains endpoint with offset=0 and
limit=20 returned tool-inaccessible; no asset data was obtained or used and no
alternate access route was attempted. No other Uber endpoints were tested.

Prepared a staged private-record access-control hypothesis. The first phase
needs one owned account to locate a non-financial synthetic resource and verify
exact scope; a later two-account comparison additionally needs a second owned
account with no shared access. No endpoint or credential is guessed. A maximum
of six read-only requests is a proposed local ceiling, not an Uber-published
rate limit or approval for recurring production tests. Identity, privacy,
controls, reproducibility and actual impact must be established before a report.

Added a read-only Current focus card and preparation detail view. The card shows
completed preparation and what needs the user. Plan ingestion allowlists display
fields and forces authorizes_testing=false and automatically_runs=false. It
cannot import targets, runner settings or credentials, and it does not add to
completed-check or bug counters. The nine unique policy reviews still load.

Validation: 38 focused access-matrix, access-check, policy-evidence and HTTP
tests passed; JavaScript syntax and dashboard DOM checks passed. The existing
loopback fixture distinguished protected and deliberately exposed synthetic
records; these are not results about Uber. New regressions cover malformed plan
data, credential/activation fields being discarded, no target creation and
read-only plan rendering. No live Uber vulnerability checks, account creation,
messages, submissions, purchases, additional spending or confirmed bugs.

User checkpoints: secure sign-in to an owned Uber account (including its own
verification step); existing HackerOne username; a second owned account only if
the two-account test is selected. Exact private-resource scope and unattended
tool permission remain unverified. The current signed-in dashboard is not
claimed as visually inspected; the earlier browser access block remains.
This commit prepares the visible task card; its deployment is pending here.

## 2026-09-26, simple progress dashboard

Baseline: scopeguard-app commit ff1b0062703c28b46fcb8882bb9afe06b58f938f.
The user asked to show the saved work and simplify the dashboard, following the
request to deploy the prepared policy panel to the existing ScopeGuard service.
Read-only Render inspection confirmed that automatic deployment is off and the
live service still used e166e73e05be3839fa843c1837f753c49984693c, so the overnight
source commits were not yet visible there.

The home screen now separates saved policy reviews, completed limited header
checks and confirmed bounty bugs. Unknown counts stay unknown. Plain-language
queue summaries distinguish paused checks, missing approved URLs, worker trouble,
blocked permissions, scheduled waiting and due checks. Nine recorded policy
reviews are visible with individual rules, source URLs, exact recorded assets
and checked dates. Directory browsing and technical tools are collapsed by
default; setup language distinguishes available tools from actual work.
Failed refreshes show a stale-data warning. No testing permission, target,
authentication, scheduler or deployment configuration was changed.

Validation: 29 focused policy-evidence, queue and HTTP tests; JavaScript syntax;
and dashboard DOM smoke checks passed. Synthetic dashboard fixtures distinguish
304 directory listings, nine policy records, one completed check and zero bugs,
and cover queue blockers and failed refreshes. These fixture numbers are not a
claim about private live state. Browser preview failed with
net::ERR_BLOCKED_BY_CLIENT; no access-control workaround was attempted.
Deployment of this revision and verification remain pending at this commit.

## 2026-09-26, policy evidence display repair

Baseline: scopeguard-app commit 4fc96386c0eaf6955990e1b5fda9dff69e7753fd.
The user asked why the reviewed program data was absent from the dashboard.
Source inspection confirmed that the detailed batch JSON files were never read
by the app. Only hardcoded short notes appeared inside exact-matching directory
cards. The repository deployment specification also disables automatic deploys;
the running Render revision was not verified.

Added a read-only policy-evidence loader to the existing authenticated snapshot
and a visible Program policy reviews panel. All nine saved detailed records are
available independently of directory membership or program renaming. Each view
shows exact recorded assets, exclusions, source links, checked timestamp,
automation rules, account requirements and unresolved questions. Incomplete or
masked scope stays visibly incomplete. Viewing records cannot grant permission,
create a target or change the queue. Missing or malformed evidence is reported
without crashing the dashboard; unknown request limits remain unknown. Policy
text is rendered only as text, never HTML or executable instructions.

Validation: 36 focused policy, workflow, queue, readiness and local-mode tests;
the existing HTTP authentication/CSRF and target checks; Python compilation;
JavaScript syntax; and dashboard DOM smoke tests passed.
Fixtures verify unlisted-record visibility, rejected authorization flags, malformed
record handling and text-only rendering without network checks. The packaged
source files load nine records with no unavailable entries. Existing authentication
and target activation code were not changed.

Render access stopped at the connector's workspace-selection requirement.
The connector lists My Workspace but explicitly requires user confirmation before
it can be used. No workspace was selected, and no deployment or live-dashboard
inspection occurred. No new policy research, external testing, spending or bounty
finding is claimed for this display repair.

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
