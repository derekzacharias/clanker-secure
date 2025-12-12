# Architecture

- FastAPI backend (`src/clanker`) with SQLModel persistence and rule-based CVE mapping.
- React + Vite frontend (`frontend/`) consuming the public API.
- Background scan execution via Nmap wrapper and agent-based credentialed collection.
- Optional SSH agent ingest writes findings through the same pipeline as Nmap observations.
- Docker image bundles backend + built frontend; overlay binds for local overrides.

