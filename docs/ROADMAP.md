# Roadmap

This roadmap tracks near-term (monthly) and quarterly priorities aligned to GitHub Projects. Use the issue templates to create cards for each item with acceptance criteria and validation commands.

## Monthly (next 4 weeks)
- Sprint 1
  - CVE enrichment (Phase 1): render CVE chips in finding drawer, include CVE IDs in CSV/JSON exports, add UI placeholders for CVSS v3.1 score/vector. Labels: frontend, api-change, ui.
  - Auth hardening: login rate limiting, audit logging for auth events (login success/fail, password reset, MFA setup). Labels: auth.
- Sprint 2
  - Scan scalability foundations: background job queue for scans with retries/cancellation hooks; server-side pagination/filtering for /findings, /scans, /assets. Labels: core, api, infra.
  - Observability and safety: structured logs + basic metrics, Docker rebuild cadence baked into CI notes; add “blocked” surfacing in UI/API responses where applicable. Labels: infra, core.

## Quarterly (Q1)
- Credentialed scanning (Linux MVP): task model + `/agents/ingest`, collectors for distro/kernel/pkg inventory/service config, offline queue/backoff, signed releases + integrity checks. Labels: core, infra, auth.
- CVE/NVD enrichment (Phase 2/3): local NVD JSON cache with daily sync/backoff, CPE inference file, enrichment job on scan completion, confidence labeling, CVSS surfacing in UI. Labels: core, api, frontend, nmap-profile.
- Scan lifecycle and distribution: scheduled scans (cron/presets), worker pool for large jobs, SSE/WebSocket progress updates, load-balancing strategy outline. Labels: core, infra.
- Reporting and exports: CVSS band aggregation, executive/technical report exports (CSV/PDF/JSON), badges for KEV/EPSS when available. Labels: frontend, api.

## How to use
- Create an issue per bullet using the Task/Bug templates; set fields: Status, Sprint, Area, Risk.
- Link PRs to issues; automation moves cards across the board. Use branch naming `issue-<id>-<slug>`.
- Validate with standard commands: `poetry run ruff check src frontend && poetry run black src`, `pytest`, `cd frontend && npm run build` (or `npm test` when touched), and `scripts/rebuild.sh`.
