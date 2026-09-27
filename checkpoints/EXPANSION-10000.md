# 10,000-entry research catalog — 2026-09-27

The catalog contains 1,000 preserved core prompts and 9,000 explicit scenario
variations, with 200 entries in each of the existing 50 areas. Original IDs and
wording are unchanged. New IDs run from SG-1001 through SG-10000. The catalog is
searchable in the dashboard and available as a complete Markdown download; the
per-context results export includes every entry, including untested entries.

This is an original ScopeGuard expansion informed by published OWASP WSTG,
ASVS, API Security, MASVS/MASTG, GenAI and PortSwigger Academy guidance. It is not
an endorsed list of 10,000 checks used by all leading researchers, nor 10,000
independent vulnerability classes. References are background at category level,
not exact mappings to standard requirements.

## How the expansion works

`scenario-matrix.json` defines nine concrete review conditions for each area.
For example, authorization is reconsidered after an owned object's access is
revoked, through a batch operation, or on a soft-deleted test object. Payments
use sandbox conditions; concurrency uses bounded local fixtures. Each core
prompt is combined with those nine conditions and retains its parent ID.

Applicability is a separate decision: some combinations will not exist in a
particular application or will not meaningfully apply to a particular control.
Those require a documented reason, not a forced test or an automatic pass.
Each applicable variant needs its own baseline, expected and observed decision,
configuration, and negative control. Parent evidence never validates a variant.

Rebuild deterministically with:

```sh
python ci/expand_checkpoints.py
python ci/export_checkpoints.py
```

The generator verifies a fixed SHA-256 digest of the original 1,000 entries,
requires nine distinct conditions per area, and fails if the total is not 10,000.
The runtime validates IDs, unique titles, parent relationships, distribution,
and composition. Existing receipts are invalidated by the engine version change
and refreshed from saved evidence by the existing worker.

## Execution remains evidence-based

The results engine still has 35 adapters; 9,965 entries have no executable
adapter. The catalog adds no target requests, accounts, report submissions,
testing permissions, automatic findings, or spending. Every listed program
receives all entries as coverage decisions, not as executed tests.

Persistent receipts store aggregate counts per context. Descriptions and
scenario guidance are generated on demand. This avoids storing millions of
duplicate descriptions across the program directory. A complete JSON results
download is roughly 16 MB; ordinary dashboard requests remain paginated.
