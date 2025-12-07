# Agile Workflow (GitHub Projects)

This repo uses GitHub Projects + issue/PR templates to keep agents aligned, avoid overlap, and maintain sprint visibility.

## Board and fields
- Columns: Backlog → In Progress → Review → Done (use Blocked when needed).
- Custom fields to keep cards filterable:
  - Sprint: free-text (e.g., `Sprint 12`, `2024-W33`).
  - Area: `core`, `api`, `db`, `frontend`, `infra`.
  - Risk: `migration`, `api-change`, `auth`, `nmap-profile`, `ui`.
- Always attach the issue to the Project (Projects sidebar on the right).
- Saved views to set up in the Project: Backlog, Current Sprint, Blocked, Review, By Area (grouped), By Risk.

## Issue intake
- Use the issue templates (`Bug`, `Task / Story`) so context, scope, acceptance criteria, and validation steps are captured up front.
- Keep scope tight; split large work instead of spanning multiple areas in one card.
- Mark in/out of scope and add risks (migrations, API changes, env vars, shared modules).

## Claiming work
- Before coding: assign yourself, set Sprint/Area/Risk fields, and move the card to In Progress.
- Post a status ping (branch name, plan, risks) in the team channel/log.
- If touching shared modules (`src/clanker/core`, auth), drop a heads-up to avoid overlap.

## Branches and PRs
- Branch naming: `issue-<id>-<slug>` (one issue per branch).
- PR title: Conventional Commit style (`fix:`, `feat:`, `chore:`) and link the issue.
- PR description: what/why bullets, test evidence, screenshots/GIFs for UI, rollout notes (migrations, env vars, Docker rebuild).
- Required checks before requesting review:
  - `poetry run ruff check src frontend && poetry run black src`
  - `pytest` (scope or full suite as appropriate)
  - Frontend touched: `cd frontend && npm test` or `npm run build`
  - Rebuild container so changes are reflected: `scripts/rebuild.sh`

## GitHub Projects automation
- Issue/PR intake: `.github/workflows/project-automation.yml` auto-adds new issues and PRs to the Project.
- Requirements: set repo secrets `PROJECT_URL` (Projects URL) and `PROJECT_TOKEN` (PAT with `project:write`, `repo` scopes). Without these, the workflow skips with a notice.
- Labels: `.github/labels.yml` defines shared labels (area/risk/priority) and `.github/workflows/labels.yml` can sync them via `workflow_dispatch` or on edits to `.github/labels.yml`.
- Suggested Project setup:
  - Add fields: `Sprint` (text), `Area` (single-select: core/api/db/frontend/infra), `Risk` (single-select: migration/api-change/auth/nmap-profile/ui), `Status` (Backlog/In Progress/Review/Done/Blocked).
  - Saved views: Backlog, Current Sprint, Blocked, Review, By Area, By Risk.
  - Automation: default Status to Backlog on new items; move to Review when PR opens; Done on merge (configure in Project UI).

## Status and handoffs
- Daily/shift ping: Doing (issue/branch), Done, Next/Blockers.
- Move cards promptly: In Progress when you start, Review with PR open, Done once merged/deployed.
- Add blockers on the card and in the channel; tag owners quickly for decisions.

## Sprint hygiene
- Keep Backlog groomed with clear acceptance criteria and validation commands.
- Use the Current Sprint view to watch burndown; re-scope early if risk grows.
- Merge small, focused PRs daily to reduce drift; avoid piggybacking unrelated changes.

## Security and data
- Do not attach real customer IPs or PII; scrub scan artifacts before sharing.
- Follow auth/RBAC notes in `docs/AUTH_RBAC.md`; keep `.env` local.
