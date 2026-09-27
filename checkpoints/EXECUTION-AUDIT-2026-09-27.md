# Checkpoint execution audit — 27 September 2026

The catalog contains 1,000 research questions in 50 categories. There are 35
implemented adapters and 965 entries without executable tests. The coverage
worker assigns a status to every entry for every saved program; that status
assignment is not evidence of a vulnerability test.

The current adapters cover policy metadata, partial Python source patterns,
permitted HEAD response observations, selected owned-app authentication/CSRF
checks, and explicitly configured owned-resource comparisons. No general
payment, mobile, cloud, federation, or AI feature tests are implemented by
merely listing those categories.

## This update

- Keeps unimplemented and blocked entries untested.
- Adds a current per-program coverage summary, including how many programs
  have actual runtime checkpoint evidence. Owned-app results are excluded
  from external-program totals. Stale results display as unknown.
- Adds an authenticated JSON export containing every one of the 1,000 IDs,
  its title, prerequisites, required evidence, current state and saved
  observation. Filters cannot silently omit untested rows from the export.
- Includes the public-page worker module in the owned-source audit.
- Fixes a reproduced owned-validator limit: a private dashboard larger than
  one MiB caused the authenticated control read to fail. The fixed loopback
  reader allows at most eight MiB, still retains only response metadata and
  hashes, and still fails closed at its bound. External runners are unchanged.

No directory entry is newly authorized, no disabled target is enabled, no
expired overnight batch is restarted, and no program report is submitted.
The local regression suite and the seven owned-loopback requests are tests
of ScopeGuard itself, not 1,000 external-program security tests.

## Dashboard

Automatic checklist → Coverage across all programs shows runtime coverage
separately from automatic evidence and coverage decisions. Open a program to
view all checkpoint results. Download all 1,000 results for this program
exports the complete record, including every missing test and input.

Authenticated reads:

- GET /api/checkpoint-coverage
- GET /checkpoint-results.json?context=owned
- GET /checkpoint-results.json?context=program:<saved-program-id>

The requested all-checkpoint testing across all bounty programs remains
incomplete until the missing test implementations and applicable authorized
program environments exist. A complete catalog or exported file is not a
completed security assessment.
