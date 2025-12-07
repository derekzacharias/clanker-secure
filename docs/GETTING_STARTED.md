Clanker: Getting Started

Prerequisites
- Docker (recommended) or Python 3.11+ with Poetry
- Optional: Node 20+ for local frontend dev

One‑shot (Docker)
- Build and run: `scripts/rebuild.sh`
- App: http://localhost:8181/app/

Seed an Admin (first run)
- Export before rebuild:
  - `export CLANKER_ADMIN_EMAIL=admin@example.com`
  - `export CLANKER_ADMIN_PASSWORD='ChangeMe123!'`
- Run `scripts/rebuild.sh`. On startup, the admin is created if no users exist.

Login & Tokens
- POST `/auth/login` with email/password → returns `access_token` and `refresh_token`.
- Attach `Authorization: Bearer <access_token>` to write endpoints.

Roles
- `admin`: manage users + full write
- `operator`: write to assets/scans/findings
- `viewer`: read‑only

Local Dev (backend)
- `poetry install --with dev`
- `poetry run uvicorn clanker.main:app --host 0.0.0.0 --port 8000`

Local Dev (frontend)
- `cd frontend && npm install && npm run dev`
- Set `VITE_API_BASE=http://localhost:8000` (env or `.env`)

Rebuild/Restart
- Always run `scripts/rebuild.sh` after changes to ensure the container reflects the latest code.

