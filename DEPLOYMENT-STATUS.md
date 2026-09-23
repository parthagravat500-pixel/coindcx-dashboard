# ScopeGuard deployment status — 23 September 2026

## Hosting approved and service live

The user approved Render hosting up to USD 8/month and confirmed My Workspace (`tea-da4b2am417fc73cdvin0`). A single Starter Python web service was created in Singapore with automatic deployments off.

- Service: `scopeguard-research` (`srv-daq6cvgjo6nc73d9bf50`)
- Dashboard: https://dashboard.render.com/web/srv-daq6cvgjo6nc73d9bf50
- App: https://scopeguard-research.onrender.com
- Repository: `parthagravat500-pixel/coindcx-dashboard`, branch `scopeguard-app`
- Deployed commit: `c2d6d82df8fc56376aee9be24612d96f6071871a`
- Initial deploy: `dep-daq6d08jo6nc73d9bh9g`, confirmed live
- Build command: `DATA_DIR=/tmp/scopeguard-build-test python -m unittest -v`
- Start command: `python app.py`
- All 10 build tests passed; public `/healthz` returned HTTP 200.
- A randomly generated ADMIN_PASSWORD is configured in Render environment variables. No credential is committed to source.

Keep scanning paused. No live targets were configured or scanned by the assistant. The original main branch remains unchanged.

## Persistent storage still required

The connected Render creation tool cannot attach disks. Dashboard access in the assistant browser remains unauthenticated; the user's phone browser session is separate. No persistent disk is attached yet. Settings and reports can be lost across restarts or redeployments until this is completed.

Attach a 1 GB disk to this existing service at `/opt/render/project/src/data`, matching its DATA_DIR. Do not create a duplicate service or apply the original Blueprint as a second deployment. The original render.yaml is a proposal using a different data mount, not the current service configuration.

Published base estimate: USD 7/month for the service, plus USD 0.25/month for a 1 GB disk when attached, excluding tax and metered overages. Do not expand resources beyond the user's approved limit without approval. Pricing: https://render.com/pricing

The application is an initial observation and report-triage assistant, not an autonomous bounty-earning system. Target authorization and scanning activation remain separate from hosting approval.
