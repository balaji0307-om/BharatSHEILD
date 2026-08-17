"""Security wrapper for BharatSHIELD's existing FastAPI application.

Keeps the full feature set intact while adding a strict deployment boundary:
- exact CORS allowlist (no wildcard Render-origin trust)
- authentication enforcement for sensitive API endpoints
- conservative request-size limits
- security response headers
- rejects credential-bearing URLs before they reach the legacy URL analyzer
"""

import os
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import main as legacy

app = FastAPI(title="BharatSHIELD Secure Gateway")

PUBLIC_PREFIXES = {
    "/health",
    "/api/login",
    "/api/signup",
}

ALLOWED_ORIGINS = {
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "https://bharatshield.onrender.com",
    "https://bharatsheild.onrender.com",
}
ALLOWED_ORIGINS.update(
    origin.strip().rstrip("/")
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
)

MAX_BODY_BYTES = 1_000_000


def is_public(path: str) -> bool:
    return path in PUBLIC_PREFIXES or not path.startswith("/api/")


def has_valid_session(request: Request) -> bool:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return False
    token = header[7:].strip()
    return bool(token) and token in getattr(legacy, "SESSION_TOKENS", {})


@app.middleware("http")
async def security_boundary(request: Request, call_next):
    origin = request.headers.get("origin", "").rstrip("/")

    if origin and origin not in ALLOWED_ORIGINS:
        return JSONResponse({"detail": "Origin is not allowed."}, status_code=403)

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                return JSONResponse({"detail": "Request body is too large."}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)

    if request.method != "OPTIONS" and request.url.path.startswith("/api/") and not is_public(request.url.path):
        if not has_valid_session(request):
            return JSONResponse({"detail": "Authentication required."}, status_code=401)

    if request.url.path == "/api/url-check" and request.method == "POST":
        try:
            payload = await request.json()
            raw = str(payload.get("url", ""))
            parsed = urlparse(raw if "://" in raw else "https://" + raw)
            if parsed.username or parsed.password:
                return JSONResponse(
                    {"detail": "URLs containing embedded credentials are not accepted."},
                    status_code=400,
                )
        except Exception:
            pass

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(self), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; connect-src 'self' https://generativelanguage.googleapis.com; "
        "img-src 'self' data: blob:; media-src 'self' blob:; "
        "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response


# Mount the unchanged application so QR identity, tamper detection,
# security cases, PDF reports, and the existing frontend remain available.
app.mount("/", legacy.app)
