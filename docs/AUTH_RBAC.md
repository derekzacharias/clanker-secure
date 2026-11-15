Authentication, Profiles, and Roles

Overview
- The service uses bearer tokens stored server‑side (SessionToken) rather than JWTs.
- Access tokens expire in ~30 minutes; refresh tokens last ~7 days.

Endpoints
- POST `/auth/login` { email, password } → { access_token, access_expires_at, refresh_token, refresh_expires_at }
- POST `/auth/refresh` { refresh_token } → new token pair
- GET `/auth/me` → current user profile
- PATCH `/auth/me` { name? } → update display name
- POST `/auth/logout` { revoke_all? } → revoke current token or all tokens

User Management (admin)
- GET `/users` → list users
- POST `/users` { email, name?, role, password, active? } → create
- PATCH `/users/{id}` { name?, role?, active?, password? } → update

Roles
- `admin`: manage users, full write access
- `operator`: write access to assets/scans/findings; no user management
- `viewer`: read‑only

UI Integration
- The React UI prompts for login if no token is present.
- Role is displayed in the header; admin can open the Users modal to manage accounts.

Seeding Admin
- Set `CLANKER_ADMIN_EMAIL` and `CLANKER_ADMIN_PASSWORD` env vars before running `scripts/rebuild.sh`. If no users exist, an admin is created at startup.

RBAC Enforcement
- `overlay/rbac_override.py` wraps write APIs (`/assets` POST/PATCH/DELETE, `/scans` POST/DELETE, `/findings/{id}` PATCH) to require `admin` or `operator` roles.


## Active implementation (verified)

`uvicorn clanker.main:app` is the runtime entrypoint and **nothing imports
`overlay/`** — `overlay/auth/*`, `overlay/rbac_override.py` and
`overlay/main_override.py` are inert in the deployed build. All authentication and
authorisation therefore lives in `src/clanker/main.py`; do not add a third variant.

### Permissions

`src/clanker/core/authz.py` is the single vocabulary: 20 permissions
(`users.read`, `users.manage`, `findings.assign`, `findings.verify`,
`remediation.request|approve|execute|verify`, `audit.read`, …) and the role → permission
table. Handlers ask `require_permission("findings.assign")`; `require_roles(...)` is kept
only as a shim so older handlers keep working, and it reads the same table.

| Role | Notable permissions |
|---|---|
| `admin` | everything |
| `security_engineer` | findings.assign, findings.verify, tickets.*, remediation.request/verify, audits — **not** remediation.approve/execute |
| `system_operator` | assets.manage, scans.run, remediation.request/**execute** — **not** approve |
| `developer` | read + remediation.request |
| `auditor` | read + audit.read |
| `operator` (legacy) | assets.manage, scans.run, findings.assign — exactly what it had before; no new capabilities |
| `viewer` (new default) | read only |

New accounts default to `viewer`: creating a user can no longer create an operator by
accident, and `role` is validated on every write (an invented string is a 400, not an
access level).

### Hardening applied

* **Bootstrap is create-only.** `_seed_admin_if_configured` no longer rewrites an
  existing account's password, role or active flag, and no longer clears lockouts; a
  restart cannot undo a disable or a deliberate credential rotation.
* **Refresh tokens rotate and are single use.** Replaying a consumed refresh token
  revokes every session for that user (treated as a leak).
* **Session revocation follows the credential**: disabling an account, changing its
  role, resetting its password (self-service or administrator) revokes all of its
  tokens immediately.
* **Audit attribution**: `user_created`, `user_updated`, `sessions_revoked`,
  `password_reset_by_admin` and `refresh_reuse_detected` all record the acting user.
* **No mail provider is assumed**: administrator password resets take a new password
  instead of pretending to send a link.

### Endpoints

```
GET    /access/me                     identity + effective permissions (UI gating)
GET    /access/roles                  role → permission matrix
GET    /users?…                       users.read
POST   /users                         users.manage (role validated, default viewer)
PATCH  /users/{id}                    users.manage (revokes sessions on disable/role/password)
POST   /users/{id}/revoke-sessions    users.manage
POST   /users/{id}/reset-password     users.manage
GET    /audit_logs                    audit.read
```

## Planned change: enterprise user management and access control

A dedicated Users & Access area, permission-based authorisation, teams, asset
ownership and remediation assignment are **planned, not implemented**. The
assessment (verified security findings S1–S8, milestones and acceptance criteria)
lives in [`BACKLOG.md`](../BACKLOG.md) under "Enterprise user management, access
control and remediation assignment".

Read that section before changing anything in `overlay/auth/` or the user
endpoints: the bootstrap seeding path (`main.py:_seed_admin_if_configured`) is
known to reset an existing administrator on restart, and refresh tokens are not
rotated on use.
