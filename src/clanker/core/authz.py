"""Centralised authorisation: roles, permissions and the dependency guards.

Before this module the backend asked `require_roles("admin", "operator")` in each
handler. That works, but it makes every new role a code change and it lets a handler
silently forget a guard. Permissions are the vocabulary; roles are a bundle of them;
handlers ask for the permission they actually need.

Nothing here trusts the client: `require_permission` resolves the caller from the
session token on every request.
"""

from __future__ import annotations

from typing import Iterable

from fastapi import Depends, HTTPException

# Permission vocabulary. Keep it explicit: a permission that no handler uses is a
# bug, and one that several handlers invent locally is a missing entry here.
PERMISSIONS: tuple[str, ...] = (
    "users.read",
    "users.manage",
    "teams.manage",
    "roles.manage",
    "assets.read",
    "assets.manage",
    "findings.read",
    "findings.assign",
    "findings.verify",
    "tickets.create",
    "tickets.assign",
    "tickets.manage",
    "remediation.request",
    "remediation.approve",
    "remediation.execute",
    "remediation.verify",
    "scans.run",
    "audit.read",
    "integrations.manage",
    "settings.manage",
)

ALL_PERMISSIONS = frozenset(PERMISSIONS)

# Role → permissions.
#
# `operator` is preserved exactly as it behaved before (assets, scans and findings
# write access) — the compatibility rule is "never grant more than before", and it
# deliberately does NOT get remediation.approve or remediation.execute, which are new
# capabilities that arrive with the automation work.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": ALL_PERMISSIONS,
    "security_engineer": frozenset({
        "users.read",
        "assets.read",
        "findings.read",
        "findings.assign",
        "findings.verify",
        "tickets.create",
        "tickets.assign",
        "tickets.manage",
        "remediation.request",
        "remediation.verify",
        "scans.run",
        "audit.read",
    }),
    "system_operator": frozenset({
        "assets.read",
        "assets.manage",
        "findings.read",
        "remediation.request",
        "remediation.execute",
        "scans.run",
    }),
    "developer": frozenset({
        "assets.read",
        "findings.read",
        "remediation.request",
    }),
    "auditor": frozenset({
        "users.read",
        "assets.read",
        "findings.read",
        "audit.read",
    }),
    # Legacy roles. `operator` maps to the same capabilities the pre-permission build
    # gave it; `viewer` stays read-only.
    "operator": frozenset({
        "assets.read",
        "assets.manage",
        "findings.read",
        "findings.assign",
        "scans.run",
    }),
    "viewer": frozenset({
        "assets.read",
        "findings.read",
    }),
}

# The role a new account receives when the caller does not choose one. Least
# privilege: creating a user must not create an operator by accident.
DEFAULT_ROLE = "viewer"

# Roles an administrator may assign. Sorted for the UI.
ASSIGNABLE_ROLES: tuple[str, ...] = (
    "admin",
    "security_engineer",
    "system_operator",
    "developer",
    "auditor",
    "operator",
    "viewer",
)


def normalise_role(raw: str | None) -> str:
    """Return a validated role name.

    Unknown strings are refused rather than stored: a typo must not become an access
    level, and a role column holding "Admim" is a silent lockout.
    """
    role = (raw or "").strip().lower()
    if not role:
        return DEFAULT_ROLE
    if role not in ROLE_PERMISSIONS:
        raise ValueError(f"unknown role {raw!r}; expected one of {', '.join(ASSIGNABLE_ROLES)}")
    return role


def permissions_for(role: str | None) -> frozenset[str]:
    return ROLE_PERMISSIONS.get((role or "").strip().lower(), frozenset())


def has_permission(role: str | None, permission: str) -> bool:
    return permission in permissions_for(role)


# NOTE: the FastAPI dependency lives in clanker.main (`require_permission`), because
# it needs `get_current_user` and importing it here would create a cycle. This module
# stays a pure vocabulary + table so it can be unit-tested without the app.

def roles_matrix() -> list[dict[str, object]]:
    """Role → permissions, for the Roles & Permissions tab."""
    return [
        {
            "role": role,
            "permissions": sorted(ROLE_PERMISSIONS[role]),
            "assignable": role in ASSIGNABLE_ROLES,
            "default": role == DEFAULT_ROLE,
        }
        for role in ASSIGNABLE_ROLES
    ]


def expand(prefixes: Iterable[str]) -> list[str]:
    """Return every permission that starts with one of the prefixes (UI helpers)."""
    out: list[str] = []
    for prefix in prefixes:
        out.extend(p for p in PERMISSIONS if p.startswith(prefix))
    return sorted(set(out))
