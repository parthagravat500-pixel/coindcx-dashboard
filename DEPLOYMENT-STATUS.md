# ScopeGuard deployment record

Existing deployment: https://scopeguard-research.onrender.com
Service: `srv-daq6cvgjo6nc73d9bf50`, Singapore Starter, one instance.
Repository: `parthagravat500-pixel/coindcx-dashboard`, branch `scopeguard-app`.
Persistent disk: 1 GB at `/opt/render/project/src/data`. Automatic deployment is off.
Approved hosting ceiling: USD 8/month. This update adds no hosting resources.

The operator authorized scheduled checks in the conversation. Preserve the saved scheduler state, exact targets, rates and expiry times. Do not infer current runtime status from this document. Verify `/api/state` after deployment.

Version 2 adds passive discovery (two public directory files every six hours), currency-aware reward sorting, and five dashboard stages. It does not authorize new scan targets. Optional intake and supervisor AI remain off without explicit configuration. Automatic report delivery is not connected. No credentials or production database are included in the source.

Local tests passed (25). Production deployment and post-deployment verification must be checked in Render for the exact commit; this source file does not assert a successful rollout.
