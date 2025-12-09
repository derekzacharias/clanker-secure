# Repository Guidelines

## Project Structure & Module Organization
Runtime code lives in `src/clanker/` and is split by responsibility: `api/` (FastAPI routers, response models), `core/` (scan engine, nmap parsing, CVE mapping), `db/` (SQLModel tables/migrations), and `rules/` (JSON matchers for banner → CVE). Static HTML templates stay under `templates/`, React assets are in `frontend/`, and raw nmap XML drops into `scan_artifacts/` so they can be inspected. Keep any new automation or notebooks out of `src/` unless they ship with the service.

## Backlog Snapshot (keep in sync with BACKLOG.md)
- Auth hardening: login rate limiting and auth event audit logging.
- Background job queue for scans with retries and cancellation hooks.
- Server-side pagination and filtering for `/findings`, `/scans`, and `/assets`.
- Structured logs plus basic metrics for the scanner and API.
- Scheduled scans (cron/presets).

## Build, Test, and Development Commands
Use Poetry for everything Python: `poetry install --with dev` to bootstrap, `poetry run uvicorn clanker.main:app --host 0.0.0.0 --port 8000` for local API/UI. Frontend work happens via Vite: `cd frontend && npm install && npm run dev` (set `VITE_API_BASE=http://localhost:8000`). Production parity lives in Docker: `docker build -t clanker .` followed by `docker run -d -p 8181:8000 --cap-add=NET_ADMIN clanker`.

Notes:
- React is pinned to 18.x for Mantine compatibility.
- The React app is the primary UI; the legacy Jinja templates are disabled at runtime.

## Coding Style & Naming Conventions
Target Python 3.11+, four-space indent, strict type hints, and Ruff/Black for lint + format (`poetry run ruff check src frontend && poetry run black src`). Modules and files use `snake_case`, classes `PascalCase`, and SQLModel tables stay singular (e.g., `Scan`). Prefer dependency-injected helpers inside `core` so scanner logic remains testable and portable.

## Testing Guidelines
Place unit tests beside the mirrored package path under `tests/` (e.g., `tests/core/test_scanner.py`). Use pytest markers to separate slow network-driven scans from fast logic checks, and record representative XML fixtures in `tests/data/` so parsing is deterministic. Aim for coverage around the high-signal modules (`core/scanner.py`, `core/findings.py`) before expanding UI features.

## Commit & Pull Request Guidelines
Follow Conventional Commits (`feat: add traceroute badges`, `fix: normalize host latency`). PRs should include: context, manual/automated test evidence (`pytest`, `npm test`, curl snippets), and screenshots or GIFs whenever the React UI changes. Rebase on `main`, keep diffs focused (backend vs. frontend vs. infra), and call out schema or Dockerfile updates so reviewers know to rebuild containers.

## Security & Deployment Tips
Keep `.env` files local—FastAPI reads them via `python-dotenv`, and Docker copies only what you explicitly add. Never commit scan artifacts containing customer IPs; scrub personally identifiable data before attaching logs to issues. When exposing the container (`-p 8181:8000`), enforce firewall rules around nmap privileges (`NET_ADMIN`) and document which scan profiles are safe for each environment.

## Auth, Users, and RBAC
- Endpoints are protected by bearer tokens. Obtain tokens via `POST /auth/login` and attach `Authorization: Bearer <access>`.
- Roles: `admin`, `operator`, `viewer`.
  - Admin: manage users, full write access.
  - Operator: write access to assets/scans/findings; cannot manage users.
  - Viewer: read‑only access (UI respects this; write endpoints are blocked).
- Seed an initial admin by setting env vars before `scripts/rebuild.sh`:
  - `CLANKER_ADMIN_EMAIL=admin@example.com`
  - `CLANKER_ADMIN_PASSWORD=strong-password`
- User management endpoints (admin only):
  - `GET /users`
  - `POST /users` { email, name?, role, password, active? }
  - `PATCH /users/{id}` { name?, role?, active?, password? }
- Session endpoints:
  - `POST /auth/login` → { access_token, refresh_token }
  - `POST /auth/refresh` → rotate tokens
  - `GET /auth/me`, `PATCH /auth/me` (update name)
  - `POST /auth/logout` (current or all sessions)

## Agent Automation
Always rebuild and restart the Docker container after any code or asset change.

- One-shot: `scripts/rebuild.sh`
- Continuous watch: `scripts/auto_rebuild.sh` (polling every 2s by default; set `INTERVAL=1` to speed up)
- Equivalent manual commands:
  - `docker build -t clanker .`
  - `docker stop clanker-ui && docker rm clanker-ui || true`
  - `docker run -d -p 8181:8000 --cap-add=NET_ADMIN --name clanker-ui clanker`

This applies to frontend and backend edits to ensure the running app reflects the latest changes.

## Additional Docs
- See `docs/GETTING_STARTED.md` for quick start and seeding an admin.
- See `docs/AUTH_RBAC.md` for auth/roles details and API examples.
