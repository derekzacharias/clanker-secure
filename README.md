# Clanker

Lightweight vulnerability scanning MVP built with FastAPI, SQLModel, and nmap.

## Getting Started
1. Create the virtualenv and install deps:
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install poetry
   .venv/bin/poetry install --with dev
   ```
2. Launch the API/UI on all interfaces:
   ```bash
   .venv/bin/poetry run uvicorn clanker.main:app --host 0.0.0.0 --port 8000
   ```
3. Start the background scan worker (handles queued scan execution and retries):
   ```bash
   .venv/bin/poetry run python -m clanker.worker
   ```
4. Visit `http://<host>:8000` for the HTML dashboard or `http://<host>:8000/docs` for OpenAPI docs.

## Configuration
The app uses environment variables (read via `.env` if present):

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./clanker.db` | SQLModel connection string. |
| `NMAP_PATH` | `nmap` | Path to the nmap binary. |
| `RULES_PATH` | `src/clanker/rules/basic_rules.json` | Rule-set for banner → CVE mapping. |
| `XML_OUTPUT_DIR` | `./scan_artifacts` | Where raw XML outputs are stored. |
| `SCAN_RETRY_LIMIT` | `1` | How many times to retry an asset after a failure. |
| `SCAN_JOB_MAX_ATTEMPTS` | `3` | Max attempts per scan job (worker retries are derived from this). |
| `SCAN_JOB_DISPATCH_INTERVAL_SECONDS` | `0.5` | How often the worker polls for queued scans. |
| `AGENT_ADVISORIES_PATH` | `./data/agent_advisories.json` | File or directory for agent advisory feeds. |
| `ENUM_TOOLS_ENABLED` | `nikto,whatweb,testssl,openssl,amass,subfinder,masscan,lynis` | Comma-separated external enum tools to run when binaries are present. |
| `ENUM_TOOL_TIMEOUT_SECONDS` | `120` | Per-tool timeout for external enumeration helpers. |
| `ENUM_TOOL_OUTPUT_DIR` | `./scan_artifacts/enum` | Where raw outputs from external enumeration are stored. |
| `ENUM_MASSCAN_RATE` | `5000` | Packet rate for masscan (when enabled). |
| `ENUM_ALLOW_REMOTE_LYNIS` | `false` | Allow Lynis to run against non-local targets (defaults to local-only). |

## Key Components
- **Assets API** – Full CRUD plus metadata (`environment`, `owner`) using a single `target` field for host/IP/CIDR (e.g., `10.0.0.10`, `10.0.0.0/24`, `web01.corp.local`).
- **Scans API** – Queue scans, inspect per-asset progress, fetch events, and review severity summaries.
- **Scan Job Queue** – Dedicated worker (`python -m clanker.worker`) dispatches queued scans with persistence, cancellation, and retries; re-enqueue via `POST /scans/{scan_id}/enqueue`.
- **Agent Advisory Feeds** – Distro-aware package advisories loaded from JSON (single file or directory, recursive). Supports `package_advisories`, `osv_records`, and `oval_definitions` with optional `distro_hint` and `backport_fixed_version` for vendor backports. Bundled feeds can also use `distro_feeds`/`vendor_feeds` to scope OVAL/OSV/vendor rules to a distro and inherit feed-level sources.

Example feed payload:
```json
{
  "source": "ubuntu-security",
  "osv_records": [
    {
      "rule_id": "OSV-PKG-LIBSSL-BACKPORT",
      "package": "libssl3",
      "fixed_version": "3.0.0",
      "backport_fixed_version": "1.1.1n-0ubuntu2.10",
      "cve_ids": ["CVE-2024-0001"],
      "severity": "critical",
      "description": "Upstream fix backported by distro",
      "distro_hint": "ubuntu"
    }
  ],
  "oval_definitions": [
    {
      "definition_id": "oval:com.ubuntu.jammy:def:20230778",
      "package": "openssl",
      "fixed_version": "1.1.1n-1ubuntu2.2",
      "backport_fixed_version": "1.1.1n-1ubuntu2.1",
      "cve_ids": ["CVE-2024-0002"],
      "severity": "high",
      "description": "Vendor OVAL backport",
      "distro_hint": "ubuntu"
    }
  ],
  "distro_feeds": [
    {
      "distro": "ubuntu",
      "source": "ubuntu-oval/osv",
      "oval_definitions": [
        {
          "definition_id": "oval:com.ubuntu.jammy:def:20230779",
          "package": "curl",
          "fixed_version": "7.81.0-1ubuntu1.16",
          "backport_fixed_version": "7.81.0-1ubuntu1.15",
          "cve_ids": ["CVE-2023-38545"],
          "severity": "high",
          "description": "Ubuntu OVAL feed with a distro-specific backport"
        }
      ]
    }
  ]
}
```
- **Scan Engine** – Runs `nmap -sV` with profile-based port lists, parses XML, and maps services to CVEs via JSON rules.
- **External Enumeration** – Optional passes with Nikto/WhatWeb/TestSSL.sh/OpenSSL for HTTP(S), Amass/Subfinder for domains, Masscan for fast port sweeps (opt-in), and Lynis for local credentialed hardening checks; outputs saved under `scan_artifacts/enum` and logged as scan events when binaries exist.
- **Findings API** – Filterable list plus status/owner updates to track remediation work.
- **UI** – Minimal dashboard for adding assets, starting scans, and reviewing activity without extra tooling.

### Scan Profiles
- **All TCP Ports Scan** – `-sS -p 1-65535 -Pn`; SYN scan across every TCP port.
- **Common TCP Connect/SYN/Version Scans** – Curated port-set scans using `-sT`, `-sS`, or `-sV` for faster coverage of popular services.
- **Honeypot Version Demo** – `-sV -p 1433,3306,4899,5900,8000,10000 -n -Pn -r`; highlights banner versions on honeypot-friendly ports.
- **Intense Scan (default)** – `-T4 -A -v`; intrusive OS/version/script/traceroute combo.
- **Intense Scan Plus UDP** – `-sS -sU -T4 -A -v`; adds UDP alongside TCP.
- **Intense (All TCP) / Intense (No Ping)** – Variants that cover all ports or skip host discovery.
- **Ping Scan** – `-sn`; host discovery only.
- **Quick Scan / Quick Scan Plus** – `-T4 -F` and `-sV -T4 -O -F --version-light` for rapid sweeps with optional OS detection.
- **Quick Traceroute** – `-sn --traceroute`; map paths without a port scan.
- **Random Telnet Scans** – Sample 10 or 100 random hosts for open Telnet (`-sS -p 23 -n -iR ... --open`).
- **Regular Scan** – Baseline `nmap` defaults.
- **Slow Comprehensive Scan** – Highly intrusive TCP/UDP scan with numerous probes and scripts for maximum coverage.

nmap must be installed on the host that runs the scan engine (`sudo apt install nmap`).

## Web UI (React + Mantine)
1. `cd frontend`
2. `npm install` (Node.js 20.19+ recommended for Vite 7)
3. `VITE_API_BASE=http://localhost:8000 npm run dev` (defaults to 8000 if unset)
4. Navigate to the printed Vite dev URL (typically `http://localhost:5173`) to use the React dashboard.

For production builds, run `npm run build`. The FastAPI server detects `frontend/dist`, serves the React UI at `/app`, and automatically redirects `/` there. The classic server-rendered dashboard remains available at `/legacy` if you need the original forms.

## Docker
Build and run the container (includes backend, nmap, and the bundled frontend if present):

```bash
docker build -t clanker .
docker run -p 8000:8000 --cap-add=NET_ADMIN clanker
```

> `NET_ADMIN` (or running with higher privileges) may be required for certain nmap scans, depending on your environment. Adjust to your security policy.
