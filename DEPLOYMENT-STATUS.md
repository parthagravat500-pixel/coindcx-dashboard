# ScopeGuard deployment status — 24 September 2026

## Hosting and storage

The user approved Render hosting up to USD 8/month and confirmed My Workspace (`tea-da4b2am417fc73cdvin0`). A single Starter Python service is deployed in Singapore with automatic deployments off.

- Service: `scopeguard-research` (`srv-daq6cvgjo6nc73d9bf50`)
- Dashboard: https://dashboard.render.com/web/srv-daq6cvgjo6nc73d9bf50
- App: https://scopeguard-research.onrender.com
- Repository: `parthagravat500-pixel/coindcx-dashboard`, branch `scopeguard-app`
- Initial deployed commit: `c2d6d82df8fc56376aee9be24612d96f6071871a`
- Initial deployment confirmed live; all 10 build tests passed and `/healthz` returned HTTP 200.
- Build: `DATA_DIR=/tmp/scopeguard-build-test python -m unittest -v`
- Start: `python app.py`
- ADMIN_PASSWORD is securely configured in Render environment variables; username is `admin`. No credential is committed to source.

## Persistent disk attached

Render service metadata confirms disk `dsk-daq6g8s9v7es73c0e5ng`, size 1 GB, mounted at `/opt/render/project/src/data`, matching the deployed DATA_DIR. The user attached this disk through the Dashboard. Its automatic deployment `dep-daq6g949v7es73c0e6t0` targets commit `e08e6a953532855f7120056b4c5f4c34db688376`; build passed and rollout was in progress at this documentation update.

Do not create a duplicate service or apply the original Blueprint as a second deployment. The original render.yaml is a proposal using a different data mount, not the current service configuration. Files under the attached mount persist across subsequent restarts and deployments; other filesystem paths do not.

Published base estimate: USD 7/month service plus USD 0.25/month for the disk, excluding tax and metered overages. Do not expand resources beyond the approved limit without approval. Pricing: https://render.com/pricing

## Scanning remains paused

Initial authenticated verification confirmed paused=true, zero targets and zero findings. No live targets were configured or scanned by the assistant. Keep scanning paused pending explicit authorization. The original main branch is unchanged.

This is an initial observation and report-triage assistant, not an autonomous bounty-earning system. Target authorization and scanning activation remain separate from hosting approval.
