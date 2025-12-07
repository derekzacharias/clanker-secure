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
3. Visit `http://<host>:8000` for the HTML dashboard or `http://<host>:8000/docs` for OpenAPI docs.

## Configuration
The app uses environment variables (read via `.env` if present):

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./clanker.db` | SQLModel connection string. |
| `NMAP_PATH` | `nmap` | Path to the nmap binary. |
| `RULES_PATH` | `src/clanker/rules/basic_rules.json` | Rule-set for banner → CVE mapping. |
| `XML_OUTPUT_DIR` | `./scan_artifacts` | Where raw XML outputs are stored. |
| `SCAN_RETRY_LIMIT` | `1` | How many times to retry an asset after a failure. |

## Key Components
- **Assets API** – Full CRUD plus metadata (`environment`, `owner`) using a single `target` field for host/IP/CIDR (e.g., `10.0.0.10`, `10.0.0.0/24`, `web01.corp.local`).
- **Scans API** – Queue scans, inspect per-asset progress, fetch events, and review severity summaries.
- **Scan Engine** – Runs `nmap -sV` with profile-based port lists, parses XML, and maps services to CVEs via JSON rules.
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
