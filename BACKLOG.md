# Product Backlog (Open Items Only)

## Near-term backlog (prioritized)
- [x] CVE enrichment Phase 1 (UI chips, CSV/JSON exports, CVSS placeholders) — Labels: frontend, ui, api-change
- [x] Auth hardening: login rate limiting and auth event audit logging (login success/fail/throttled) — Labels: auth
- [x] Background job queue for scans with retries/cancellation hooks — Labels: core, infra
- [x] Server-side pagination and filtering for /findings, /scans, /assets — Labels: api, core
- [x] Structured logs + basic metrics for scanner and API — Labels: infra
- [x] Scheduled scans (cron/presets) — Labels: core, infra
- [x] NVD enrichment Phase 2 (cache + CPE inference + enrichment job) — Labels: core, api, frontend, nmap-profile
- [x] Credentialed scanning Linux agent MVP (collect distro/kernel/pkg inventory, config) — Labels: core, infra, auth
- [x] SSE/WebSocket scan progress updates — Labels: frontend, core
- [x] Reporting: CVSS band aggregation and CSV/PDF/JSON exports — Labels: frontend, api
- [x] Service fingerprinting + protocol parsers (HTTP/TLS/SSH/SMB/SQL/SNMP/RDP) with version confidence and structured evidence — Labels: core, nmap-profile
- [x] CPE inference library + curated mapping file with confidence scores and source tags — Labels: core, api
- [x] Evidence grading, deduping, and “why this finding” traces — Labels: core, ui
- [x] Rule coverage audit (unmatched services/banners with suggested rule stubs and fixtures) — Labels: core, tests
- [ ] Credentialed vuln detection Phase 2: expand package advisories + distro OVAL/OSV feeds, service-version rules, kernel/OS release checks, config-level findings, and CPE inference upgrades for SSH scans — Labels: core, agent, vuln-detection

Note: This backlog excludes features already present in the codebase (e.g., Nmap-based unauthenticated scanning, basic OS/service fingerprinting, basic rule-driven CVE mapping, assets/scans/findings UI). Items below are not implemented yet.

## Core Vulnerability Scanner Features

- [ ] Authenticated scanning (SSH, WinRM, SMB, sudo escalation)
- [ ] Protocol-aware enumeration (HTTP, TLS, SSH, SMB, SNMP, RDP, SQL, etc.)
- [ ] CVE matching via major databases (NVD, vendor advisories) with syncing
- [ ] Pluggable detection architecture (extend current rules into versioned plugins)
- [ ] Misconfiguration checks (CIS-like)
- [ ] Weak credential checks
- [ ] Package inventory + patch level tracking
- [ ] Missing updates and EOL software detection

### Scan Management
- [ ] Scheduled scans (cron-like + presets per environment)
- [ ] Distributed scan agents/workers
- [ ] Load balancing for large jobs
- [ ] Asset discovery + automatic host grouping
- [ ] Incremental/differential scanning

### Reporting
- [ ] Executive summary reports
- [ ] Technical remediation reports
- [ ] Export formats (PDF, CSV, JSON, XML)
- [ ] CVSS v3.1 scoring across findings
- [ ] Delta reporting (change-over-time)

## Advanced Capabilities

### Agent-Based Scanning
- [ ] Lightweight agents for servers/workstations
- [ ] Real-time vuln detection + offline cache/sync
- [ ] Deep OS inspection (registry, kernel modules, cron, etc.)

### Web Application Security
- [ ] Active DAST (injection, XSS, SSRF, RCE, etc.)
- [ ] Passive crawling + advanced JS/SPA crawling (Selenium)
- [ ] API scanning (OpenAPI/Swagger ingestion)
- [ ] Endpoint/parameter fuzzing
- [ ] Auth support (cookies, JWT, OAuth2)

### Container & IaC Security
- [ ] Container image scanning (OS pkgs, libs, config)
- [ ] Registry scanning (ECR, GCR, ACR, Harbor, Docker Hub)
- [ ] Dockerfile/Kubernetes manifest scanning
- [ ] IaC scanning (Terraform, CloudFormation, ARM, Helm)

### Configuration Compliance
- [ ] CIS benchmark evaluation
- [ ] NIST 800-53 / NIST CSF mapping
- [ ] STIG/DoD profiles
- [ ] PCI-DSS checks
- [ ] Custom policy authoring

## Cloud-Native Security (Essential)

### Cloud Provider Integration
- [ ] AWS/Azure/GCP integrations
- [ ] CSPM checks (S3 exposure, IAM, logging, KMS, etc.)
- [ ] Permission graphing (excessive privileges, lateral movement)
- [ ] Provider security service integrations (GuardDuty, SecurityHub, Defender)

### Serverless & SaaS Posture
- [ ] Lambda/function scanning (deps, env, perms)
- [ ] Storage misconfig detection (S3/Blob/GCS)
- [ ] SaaS posture (GitHub/GitLab/Okta/M365/GWS)

## DevSecOps / CI-CD

### SDLC Integration
- [ ] Pre-commit scanning hooks
- [ ] CI pipeline scanning (Actions, GitLab CI, Jenkins, Azure DevOps)
- [ ] MR/PR annotations
- [ ] Severity gating (block merges on critical)

### SAST / SCA
- [ ] SAST for source code
- [ ] SCA for libraries + SBOM generation
- [ ] SBOM ingestion (CycloneDX/SPDX)
- [ ] Dependency correlation across services

## AI-Assisted Enhancements

- [ ] AI-assisted detection (pattern recognition, anomaly detection)
- [ ] AI-guided exploitation simulation (safe/non-destructive)
- [ ] Remediation recommendations (summaries, autofix PRs)
- [ ] AI-driven prioritization (exploitability, exposure, asset value, attack paths)
- [ ] Real-time risk scoring beyond CVSS

## Enterprise Features

### User & Role Management
- [x] RBAC (admin/operator/viewer with bearer tokens)
- [ ] SSO/SAML/OIDC
- [ ] Multi-tenant (MSSP/large orgs)
- [ ] Audit logging

### Asset Inventory & Attack Surface
- [ ] External attack surface discovery
- [ ] Continuous passive monitoring
- [ ] DNS/IP/domain enumeration
- [ ] Shadow IT discovery
- [ ] Risk tagging and grouping

### Scalability & Architecture
- [ ] Distributed workers / clusters
- [ ] High-availability
- [ ] Horizontal scaling
- [ ] Full REST coverage of all functions

### Data Enrichment & Threat Intel
- [ ] Exploitability intel (Exploit-DB, CISA KEV)
- [ ] Threat intelligence feed correlation
- [ ] Attack path mapping (graph analysis)

### Integrations
- [ ] SIEM (Splunk/Elastic/QRadar/Sentinel)
- [ ] Ticketing (Jira/ServiceNow)
- [ ] SOAR integrations
- [ ] Webhooks/custom integrations

## Authentication Backlog (Open Items)

User Registration
- [ ] Registration form (email, password)
- [ ] Email/password validation (strength rules)
- [ ] Email verification link flow

User Login
- [ ] Basic rate limiting on login attempts

Password Reset
- [ ] “Forgot password” request endpoint
- [ ] Send reset email with time‑limited token
- [ ] Reset form + token validation

Session & Cookie Security
- [ ] Secure session cookies (HttpOnly, Secure, SameSite)
- [ ] Session expiration + idle timeout

MFA (Phase 1)
- [ ] TOTP setup + verification flow
- [ ] Store hashed TOTP secret + recovery codes

Account Management
- [ ] Profile page (update email, change password)
- [ ] Revoke all active sessions (user‑initiated UI)

Admin Controls
- [ ] View/search users (search/filter UI)
- [ ] (Optional) Force password reset via UI controls

Audit Logging
- [ ] Record login success/failure
- [ ] Record password resets and MFA changes

## Extra Differentiators

- [ ] Gamified engineer dashboards
- [ ] Executive dashboards for CISOs
- [ ] Peer benchmarking
- [ ] Cost-of-risk analytics
- [ ] Time-to-remediate analytics
- [ ] Live asset behavior analysis (optional EDR-like)
- [ ] Digital twin attack-chain simulations
- [ ] Automatic remediation verification

---

Housekeeping / Foundations (cross-cutting)
- [x] Server-side pagination and filtering for /findings, /scans, /assets
- [ ] WebSocket/SSE for live scan progress
- [ ] Background job queue for scans (workers + retries + cancellation)
- [ ] Metrics + structured logs
- [ ] AuthN/Z and hardening
- [ ] CI/CD: lint, tests, build, Docker, vulnerability scan

## Investigation — Evidence Solidification & Validation

- [ ] Survey enrichment sources for corroboration and gaps
  - NVD JSON 2.0, CVE Services 2.1, vendor advisories (OVAL/USN/RHSA), CIRCL CVE fallback
- [ ] Evaluate exploitability/prioritization signals
  - CISA KEV (known exploited), FIRST EPSS (probability), Exploit‑DB and Metasploit module mapping
- [ ] Strengthen service fingerprint → CPE mapping
  - WhatWeb/Wappalyzer signatures, TLS/SSL analyzers (testssl/SSLyze), ssh‑audit; calibrate version trust and vendor/product inference
- [ ] Reproducible, safe validation probes (non‑destructive)
  - Curated nuclei templates for common services; optional weak‑credential checks with guardrails
- [ ] Confidence model & evidence grading
  - Data model for confidence score (source count, version match quality, exploit signal); UI badges and filters
- [ ] Data quality and rate limiting
  - Caching, backoff, dedupe, and source reconciliation to reduce false positives and API throttling
- [ ] Deliverables
  - Tech spike report with recommended stack, PoC plan, and acceptance criteria for integration in phases

## NVD/CVE Enrichment Roadmap

Phase 1 — UI Enrichment (no backend changes)
- [ ] Parse `Finding.cve_ids` (JSON string) and render CVE chips with NVD links in the finding drawer
- [ ] Include CVE IDs in Findings CSV/JSON exports
- [ ] Add placeholders in UI for CVSS v3.1 base score and vector

Phase 2 — Backend Enrichment + Caching
- [ ] Schema: add fields on Finding (or normalized Vulnerability table) for `cpe`, `cvss_v31_base`, `cvss_vector`, `references` (JSON), `last_enriched_at`, `source`
- [ ] Implement `core/enrichment.py` for CPE inference, NVD lookups, and merge logic (rule CVEs + inferred CVEs)
- [ ] Maintain a local NVD JSON 2.0 cache with daily sync; add backoff/rate limiting for API fallback
- [ ] Create curated CPE mapping file (`core/cpe_map.json`) for common services
- [ ] Add re-enrichment job on scan completion and an API endpoint to re-enrich a scan or finding
- [ ] De-duplication and confidence labeling (rule vs. inferred vs. external)

Phase 3 — UI Surfacing
- [ ] Show CVSS (score + vector) and top references in finding drawer
- [ ] Severity band aggregation (Critical/High/Medium/Low) from CVSS in the overview panel
- [ ] Badge indicators for CISA KEV/EPSS (when available)

Quality & Safety
- [ ] Strict matching to reduce false positives (vendor+product required when possible; clear labeling of inferred items)
- [ ] Rate-limited enrichment with retry and graceful offline behavior

## Credentialed Scan Agent Roadmap

Control Plane
- [ ] Define task model and `/agents/ingest` endpoint (mTLS or signed tokens)
- [ ] Store artifacts and trigger enrichment after ingestion

Linux Agent (MVP)
- [ ] Collectors: distro, kernel, package inventory (dpkg/rpm), running services, key config (e.g., sshd_config)
- [ ] Normalize output to a host-inventory schema (for CVE correlation)
- [ ] Offline queue with backoff + retry; minimal observability/heartbeat

Windows Agent (next)
- [ ] PowerShell/WMI collectors: installed updates/software, services
- [ ] Windows service wrapper

Security & Deployment
- [ ] Least-privilege collection; scoped sudo where necessary
- [ ] Key/credential management (SSH keys/WinRM creds from secure vault); short-lived tokens
- [ ] Signed releases; integrity checks; auto-update channel gated by signature

Observability
- [ ] Structured logs with redaction; basic metrics; task status reporting

## Enterprise user management, access control and remediation assignment

Source: architecture brief (2026-11-15).
**Status: Milestone 1 backend implemented** (permissions, bootstrap hardening, refresh
rotation, session revocation, audit attribution, `/access/*` + user lifecycle
endpoints, 17 tests). The **Users & Access interface, teams, invitations, asset
ownership and ticketing remain open** — see the milestone list below.
Scope discipline per `AGENTS.md`: this is recorded here and in
`docs/requirements.md` before code, and delivered through the milestones below.

### Verified assessment of this checkout (blocking first)

| # | Severity | Finding | Evidence |
|---|---|---|---|
| B0.1 | **Blocking** | `main.py` imports `build_scan_job_queue`, which did not exist — the app could not import, so no endpoint or test could run. **Fixed**: `core/job_queue.py` now provides the factory and *fails closed* for the `redis`/`rq` backend and for `max_concurrency > 1` instead of silently running single-threaded | `main.py:40`, `core/job_queue.py:165` |
| B0.2 | **Blocking** | `main.py` imports the `ReportJob` table from `db/models.py`, which did not exist. **Fixed**: restored from its call sites (`_process_report_job`, `_serialize_report_job`) with the fields the code reads/writes | `main.py:52,3136-3200`, `db/models.py` |
| B0.3 | High | `pytest tests/` cannot pass in this checkout: **18 of 25 failures are missing fixtures that were never committed** (`tests/data/agent_parsers/*`, `tests/data/rule_gaps.json`, protocol parser fixtures); only 4 files exist under `tests/data` | `tests/data/`, `.gitignore` |

Baseline after B0.1/B0.2: `49 passed, 25 failed` — 18 `FileNotFoundError`
(fixtures), 4 assertion failures in CPE inference/rule-gap summarisation that need
investigation once fixtures exist, 3 other. Reported as-is; no test is claimed to
pass that was not run.

### Verified authentication / authorisation risks (Phase 10)

| # | Severity | Finding | Evidence |
|---|---|---|---|
| S1 | **Critical** | Startup seeding overwrites an existing administrator: sets `hashed_password` from the env value, forces `role="admin"`, sets `active=True`, and clears its login lockouts — on **every restart**. A rotating env secret or a deliberate disable/lockout is undone by a restart | `main.py:1988-2005` (`_seed_admin_if_configured`), duplicated at `overlay/auth/api.py:206` |
| S2 | High | Role is a free string with no validation; `User.role` defaults to **`admin`** in the model and `create_user` defaults to `operator`. Unknown role strings become valid access levels | `db/models.py:291`, `main.py:1356-1362,1907` |
| S3 | High | Refresh tokens are not rotated on use: `/auth/refresh` issues new tokens without revoking the presented one, so a stolen refresh token replays until expiry and reuse is undetectable | `main.py:1805-1823` |
| S4 | High | Password reset and privilege changes do not revoke existing sessions (`update_user` never touches `SessionToken`), so a compromised session survives a credential reset | `main.py:1917-1942` |
| S5 | Medium | Audit rows for user create/update record `actor_user_id=None` — administrative changes are unattributable | `main.py:1913,1940` |
| S6 | Medium | Authorisation is `require_roles("admin", …)` by name throughout; no permission vocabulary, so new roles require editing handlers | `overlay/auth/security.py:110`, `overlay/rbac_override.py` |
| S7 | Medium | `rbac_override.py` removes and re-registers routes at import time; if import order changes, protection disappears silently with no test guarding it | `overlay/rbac_override.py:26-71` |
| S8 | Medium | Session tokens are stored in plaintext (`SessionToken.token`) | `overlay/auth/models.py` |

### Milestones (each item states its acceptance criterion)

**M1 — Secure user administration** (do the security items first)
1. S1: bootstrap seeds only when *no* user exists; never rewrites an existing
   account's password/role/active state. Password rotation becomes an explicit,
   audited action. Duplicate seeding path in `overlay/` removed.
2. S2: central role allowlist (`admin`, `operator`, `viewer`, plus new
   `security_engineer`, `system_operator`, `developer`, `auditor`), validated on
   every write; new users default to the least-privileged role.
3. S3/S4: refresh rotation with reuse detection (reuse → revoke the whole family);
   disabling an account, changing a role, or resetting a password revokes all of
   that user's tokens immediately.
4. S5: every user/team/role change records the authenticated actor.
5. S6/S7: one permission service (`users.read`, `users.manage`, `teams.manage`,
   `roles.manage`, `findings.assign`, `findings.verify`, `tickets.create`,
   `remediation.request|approve|execute|verify`, `audit.read`,
   `integrations.manage`), enforced server-side; `require_roles` kept as a thin
   shim for existing routes; route-table mutation removed in favour of explicit
   dependencies.
- *Acceptance:* a viewer/developer/auditor cannot reach any admin endpoint
  (tested per endpoint, not only in the UI); a disabled user's access token and
  refresh token both fail immediately; a refresh replay revokes the family; the
  bootstrap cannot change an existing account.

**M2 — Teams and asset ownership**
- `Team` + `TeamMembership` (a user may hold several teams with one primary),
  `AssetOwnership` (team, primary user, secondary team, business service,
  environment, criticality, maintenance window, source, status).
- Migration keeps the legacy free-text `Asset.owner` verbatim; unresolved assets
  appear in an **Unassigned** queue, never defaulted to Security Engineering.
- Bulk assignment from Users & Access and from the asset inventory.
- *Acceptance:* ownership is relational, legacy values preserved, unassigned
  assets are visible as such, no automatic default ownership.

**M3 — Remediation assignment**
- Finding → team/engineer routing from the asset's ownership plus a configurable
  responsibility map (OS/deps/config/cloud/code); "My Remediation Work" view
  scoped to the caller's authorisation; SLA due dates from existing risk inputs.
- *Acceptance:* a new finding lands on the owning team, is visible only to its
  scope, and shows a due date it can explain.

**M4 — Ticketing (one provider, honestly labelled)**
- Provider interface; **Jira implemented and tested against a mocked API**;
  ServiceNow designed but labelled *not implemented* until connectivity, sync and
  error handling exist (the UI must not repeat today's fake "connected" states).
- Deterministic grouping + idempotent create/update keyed by a stable group id;
  closing a ticket never resolves a finding without verification.
- *Acceptance:* a mocked end-to-end run creates one ticket for N compatible
  findings, a rescan updates instead of duplicating, and a ticket comment cannot
  trigger execution.

**M5 — Verification, audit and UI**
- Users & Access page (directory, invite, roles, teams, disable, revoke sessions,
  audit activity) replacing the Users modal; CVE flyout remediation tab; audit
  evidence for every administrative action.
- *Acceptance:* the brief's 11 acceptance criteria, exercised by Playwright against
  the real backend with a mocked ticket provider.

### Decisions required before M2/M4
1. Whether TOTP is in scope for privileged roles (S1/S3 hardening).
2. Ownership write-back to the CMDB, or Clanker Guard as the source of truth.
3. Ticket closure policy: automatic after verification, or owner confirmation.
4. Approval model for remediation execution (single vs dual control).
5. Whether `operator` is migrated to `security_engineer` or `system_operator` —
   **must not silently widen privileges**; the mapping needs an explicit choice.

### Not implemented in this change (explicit)
No user-management UI, teams, ownership, remediation assignment, ticketing, or
permission service has been written yet. Only the two blocking import defects and
this assessment landed. The brief's Milestones 1–5 remain open work; the security
items S1–S8 are the first things to fix because they are verified in code.
