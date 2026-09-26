# September 27 overnight public research

Authorized by the operator for programs that need no account intervention.
The reviewed manifest expires at 08:30 Asia/Kolkata on September 27, 2026.
This is one bounded batch, not permission to scan every directory asset.

## Reviewed batch

| Program | Pages | Basis | Maximum requests |
|---|---|---|---:|
| GitHub / npm | Public login pages, referenced scripts on reviewed static hosts | https://bounty.github.com/rules permits low-volume tools; https://bounty.github.com/scope includes these hosts. No repositories or user records. | 6 |
| HackerOne | Explicitly approved sandbox and invite-only test-program pages | https://hackerone.com/security reviewed in the browser; tool identification header, AI research safe harbor, approved test-program identifiers. No report objects or customer programs. | 6 |
| LiveDune | Published public login page and same-host scripts | https://landing.cdn.livedune.com/files/en/bug_bounty.pdf includes subdomains and caps automated traffic at three requests/second. | 5 |

Requests are sequential, at least three seconds apart. Only GET is supported.
No login submission, credentials, cookies, forms, exploitation, browser script
execution, parameter mutation, directory guessing, reports or external messages.
Directly referenced `.js` files are admitted only on individually reviewed hosts.
Responses are bounded to one MiB. Redirects are not followed. Challenges,
denials, rate limits, errors and possible private keys stop the batch.

The analyzer looks for direct URL-to-HTML, document.write and eval syntax in
public JavaScript. A match is a hypothesis, never a reproduced vulnerability.
No page text, source excerpts, private material or credential values are saved.
Missing headers, public metadata and old version banners are not findings.

## Policy collection

The existing five-directory catalog continues to refresh. This worker requests
published policy URLs for independent listings, at most one every 45 seconds,
until the deadline. HTML/text policy candidates retain a digest and a small set
of unverified passages; links and application targets are never followed.
Platform policies continue through the existing program-research worker.

Collection is distinct from review: a retrieved policy is not an authorization
decision. A closed program, missing scope, incomplete document, identity header,
registration requirement, or automation restriction remains a blocker.
Flipkart is explicitly blocked after review of its current scanner/tool rule.
UXCam needs a registered-account identifier. Atmail needs a researcher email
header and requires special handling of third-party infrastructure. These were
not silently filled with invented identities or added to the test batch.

## Persistence and observability

Public batch and policy state live on the existing persistent SQLite disk.
The master pause applies before every request. Interrupted batches do not restart
or reset their request allowance. The deadline is fixed, never extended on boot.
Dashboard: **Research without accounts**. Log: `scopeguard_accountfree_health`.
The authenticated dashboard shows per-program outcomes; logs contain only
program names and aggregate results, with no candidate URLs or source contents.
No new infrastructure or spending is introduced.
