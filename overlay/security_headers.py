from __future__ import annotations

from clanker.main import app
from starlette.requests import Request
from starlette.responses import Response


@app.middleware("http")
async def _security_headers(request: Request, call_next):  # type: ignore[no-redef]
    resp: Response = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-XSS-Protection", "0")
    resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
    return resp

