# Product Backlog (Open Items Only)

## Near-term backlog (prioritized)
- [ ] CVE enrichment Phase 1 (UI chips, CSV/JSON exports, CVSS placeholders) — Labels: frontend, ui, api-change
- [ ] Auth hardening: login rate limiting; audit logging for auth events (login success/fail, password reset, MFA setup) — Labels: auth
- [ ] Background job queue for scans with retries/cancellation hooks — Labels: core, infra
- [ ] Server-side pagination and filtering for /findings, /scans, /assets — Labels: api, core
- [ ] Structured logs + basic metrics for scanner and API — Labels: infra
- [ ] Scheduled scans (cron/presets) — Labels: core, infra
- [ ] NVD enrichment Phase 2 (cache + CPE inference + enrichment job) — Labels: core, api, frontend, nmap-profile
- [ ] Credentialed scanning Linux agent MVP (collect distro/kernel/pkg inventory, config) — Labels: core, infra, auth
- [ ] SSE/WebSocket scan progress updates — Labels: frontend, core
- [ ] Reporting: CVSS band aggregation and CSV/PDF/JSON exports — Labels: frontend, api

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
- [ ] Server-side pagination and filtering for /findings, /scans, /assets
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
