"""Security gateway for the existing BharatSHIELD FastAPI app."""

import os
from urllib.parse import parse_qs, urlparse
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from . import main as legacy

app = FastAPI(title="BharatSHIELD Secure Gateway")
PUBLIC_PREFIXES = {"/health", "/api/login", "/api/signup", "/api/analyze", "/api/url-check"}
ALLOWED_ORIGINS = {"http://127.0.0.1:5173", "http://localhost:5173", "https://bharatshield.onrender.com", "https://bharatsheild.onrender.com"}
ALLOWED_ORIGINS.update(x.strip().rstrip("/") for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip())
MAX_BODY_BYTES = 1_000_000

def is_public(path: str) -> bool:
    return path in PUBLIC_PREFIXES or not path.startswith("/api/")

def has_valid_session(request: Request) -> bool:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return False
    return header[7:].strip() in getattr(legacy, "SESSION_TOKENS", {})

def local_qr_fallback(content: str) -> dict:
    raw = content.strip()
    parsed = urlparse(raw)
    params = parse_qs(parsed.query)
    upi_id = params.get("pa", [""])[0] or "Not found"
    merchant = params.get("pn", [""])[0] or "Not found"
    amount = params.get("am", [""])[0] or "Not found"
    note = params.get("tn", [""])[0] or "Not found"
    destination = raw if parsed.scheme in {"http", "https"} else "Not found"
    lowered = f"{raw} {upi_id} {merchant} {note}".lower()
    score = 10
    signals = []
    if parsed.scheme == "upi":
        score += 18
    elif parsed.scheme in {"http", "https"}:
        score += 28
        signals.append("QR opens a website destination")
    if upi_id != "Not found":
        signals.append(f"Recipient UPI ID: {upi_id}")
    if merchant != "Not found":
        signals.append(f"Recipient name: {merchant}")
    if amount != "Not found":
        try:
            value = float(amount)
            if value >= 5000:
                score += 16
                signals.append("High payment amount")
            elif value >= 1000:
                score += 10
        except ValueError:
            score += 8
            signals.append("Amount is not a clean number")
    credential_risk = any(term in lowered for term in ("otp", "pin", "password"))
    if any(term in lowered for term in ("otp", "pin", "password", "kyc", "refund", "verify", "support")):
        score += 20
        signals.append("QR payload contains a potentially risky keyword")
    score = max(0, min(99, score))
    risk = "Critical" if score >= 75 else "High" if score >= 55 else "Medium" if score >= 30 else "Low"
    return {
        "score": score, "risk": risk, "confidence": 70, "rule_score": score,
        "url_score": score if destination != "Not found" else None, "safety_score": 100 - score,
        "scam_type": "UPI QR Review" if upi_id != "Not found" else "QR Review",
        "explanation": "Local QR payload review completed safely.",
        "what_we_found": f"QR payload decoded for {upi_id}; merchant {merchant}; amount {amount}.",
        "why_dangerous": "Verify recipient, amount, and destination inside your UPI app before paying.",
        "how_sure": "70% confidence based on local QR payload parsing.",
        "reason_breakdown": [
            {"label": "Message language", "score": 0, "why": "QR payload reviewed separately."},
            {"label": "Urgency and pressure", "score": 0, "why": "Check the payment request yourself before approving."},
            {"label": "Credential risk", "score": 30 if credential_risk else 0, "why": "Never share OTP, UPI PIN, or password."},
            {"label": "URL / QR risk", "score": score, "why": "QR payload and destination were inspected locally."},
        ],
        "breakdown": {"language": 0, "urgency": 0, "emotional_manipulation": 0, "pressure": 0, "credential_request": 30 if credential_risk else 0},
        "call_analysis": {"emotion": "Not analyzed", "pressure_score": 0, "otp_demand": False, "live_warning": score >= 70},
        "signals": [{"label": "QR", "reason": signal} for signal in signals[:8]],
        "recommendations": ["Verify recipient name, UPI ID, amount, and purpose inside your UPI app.", "Never share OTP, UPI PIN, passwords, or card details.", "Do not approve an unknown payment request because of urgency or pressure."],
        "url_checks": [],
        "qr_analysis": {"score": score, "upi_id": upi_id, "merchant": merchant, "amount": amount, "note": note, "destination_url": destination, "hidden_redirect": destination != "Not found", "recipient_reputation": "Unknown", "previous_reports": 0, "fingerprint": "BS-QR-LOCAL", "risk_signals": signals, "checks": [{"label": "Status", "result": "Local QR verification completed"}]},
        "local_review": True,
    }

@app.middleware("http")
async def security_boundary(request: Request, call_next):
    origin = request.headers.get("origin", "").rstrip("/")
    if origin and origin not in ALLOWED_ORIGINS:
        return JSONResponse({"detail": "Origin is not allowed."}, status_code=403)
    length = request.headers.get("content-length")
    if length:
        try:
            if int(length) > MAX_BODY_BYTES:
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
                return JSONResponse({"detail": "URLs containing embedded credentials are not accepted."}, status_code=400)
        except Exception:
            pass
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(self), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; connect-src 'self' https://generativelanguage.googleapis.com; img-src 'self' data: blob:; media-src 'self' blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response

@app.post("/api/analyze")
async def analyze_gateway(request: Request):
    payload = await request.json()
    try:
        model = legacy.AnalyzeRequest.model_validate(payload)
        result = await legacy.analyze(model)
        if payload.get("channel") != "qr" or result.get("qr_analysis"):
            return result
    except Exception:
        pass
    if payload.get("channel") == "qr" or str(payload.get("content", "")).lower().startswith("upi://"):
        return local_qr_fallback(str(payload.get("content", "")))
    return JSONResponse({"detail": "Analysis service unavailable."}, status_code=503)

app.mount("/", legacy.app)
