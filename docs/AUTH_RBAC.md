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

