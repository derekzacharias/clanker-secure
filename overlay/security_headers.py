from __future__ import annotations

import os

from clanker.main import app
from starlette.requests import Request
from starlette.responses import Response


DEFAULT_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'"
)
CSP_POLICY = os.getenv("CLANKER_CSP_POLICY", DEFAULT_CSP).strip()
CSP_REPORT_ONLY = os.getenv("CLANKER_CSP_REPORT_ONLY")


@app.middleware("http")
async def _security_headers(request: Request, call_next):  # type: ignore[no-redef]
    resp: Response = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-XSS-Protection", "0")
    if CSP_POLICY:
        header_name = "Content-Security-Policy-Report-Only" if CSP_REPORT_ONLY else "Content-Security-Policy"
        resp.headers.setdefault(header_name, CSP_POLICY)
    return resp
