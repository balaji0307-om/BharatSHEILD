"""Security gateway for the existing BharatSHIELD FastAPI app."""

import hashlib
import os
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import main as legacy

app = FastAPI(title="BharatSHIELD Secure Gateway")
PUBLIC_PREFIXES = {"/health", "/api/login", "/api/signup", "/api/analyze", "/api/url-check"}
ALLOWED_ORIGINS = {
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "https://bharatshield.onrender.com",
    "https://bharatsheild.onrender.com",
}
ALLOWED_ORIGINS.update(x.strip().rstrip("/") for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip())
MAX_BODY_BYTES = 1_000_000


def is_public(path: str) -> bool:
    return path in PUBLIC_PREFIXES or not path.startswith("/api/")


def has_valid_session(request: Request) -> bool:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return False
    return header[7:].strip() in getattr(legacy, "SESSION_TOKENS", {})


def _decode(value: str) -> str:
    try:
        return unquote(value or "").strip()
    except Exception:
        return str(value or "").strip()


def _fingerprint(*parts: str) -> str:
    normalized = "|".join(str(part or "").strip().lower() for part in parts)
    return "BS-QR-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:8].upper()


def _extract_phone(upi_id: str) -> str:
    local = str(upi_id or "").split("@", 1)[0]
    digits = "".join(char for char in local if char.isdigit())
    return digits[-10:] if len(digits) >= 10 else "Not found"


def local_qr_fallback(content: str, verified_baseline=None) -> dict:
    """Deterministic QR fallback that always returns a usable structured result."""
    raw = str(content or "").strip()
    parsed = urlparse(raw)
    params = parse_qs(parsed.query, keep_blank_values=True)

    upi_id = _decode(params.get("pa", [""])[0]) or "Not found"
    merchant = _decode(params.get("pn", [""])[0]) or "Not found"
    amount = _decode(params.get("am", [""])[0]) or "Not found"
    note = _decode(params.get("tn", [""])[0]) or "Not found"
    destination = raw if parsed.scheme.lower() in {"http", "https"} else "Not found"

    identity = {
        "recipient_name": merchant,
        "recipient_name_normalized": merchant.lower(),
        "upi_id": upi_id,
        "upi_id_normalized": upi_id.lower(),
        "phone_number": _extract_phone(upi_id),
        "amount": amount,
        "amount_normalized": amount,
        "payment_note": note,
        "note_normalized": note.lower(),
        "destination_url": destination,
        "fingerprint": _fingerprint(upi_id, merchant, amount, note, destination),
        "payload_consistent": bool(upi_id != "Not found" and "@" in upi_id),
        "verified_at": None,
        "user_verified": False,
    }

    baseline = verified_baseline if isinstance(verified_baseline, dict) else None
    tamper_changes = []
    if baseline:
        baseline_upi = str(baseline.get("upi_id", "Not found"))
        baseline_name = str(baseline.get("recipient_name", baseline.get("merchant", "Not found")))
        baseline_amount = str(baseline.get("amount", "Not found"))
        baseline_note = str(baseline.get("payment_note", baseline.get("note", "Not found")))
        baseline_url = str(baseline.get("destination_url", "Not found"))

        if baseline_upi != "Not found" and upi_id != "Not found" and baseline_upi.lower() != upi_id.lower():
            tamper_changes.append({"field": "Recipient / UPI ID", "previous": baseline_upi, "current": upi_id})
        if baseline_name != "Not found" and merchant != "Not found" and baseline_name.strip().lower() != merchant.strip().lower():
            tamper_changes.append({"field": "Recipient Name", "previous": baseline_name, "current": merchant})
        if baseline_amount != "Not found" and amount != "Not found" and baseline_amount != amount:
            tamper_changes.append({"field": "Amount", "previous": baseline_amount, "current": amount})
        if baseline_note != "Not found" and note != "Not found" and baseline_note.strip().lower() != note.strip().lower():
            tamper_changes.append({"field": "Payment Note", "previous": baseline_note, "current": note})
        if baseline_url != "Not found" and destination != "Not found" and baseline_url != destination:
            tamper_changes.append({"field": "Destination URL", "previous": baseline_url, "current": destination})

    upi_changed = any(item["field"] == "Recipient / UPI ID" for item in tamper_changes)
    name_changed = any(item["field"] == "Recipient Name" for item in tamper_changes)
    amount_changed = any(item["field"] == "Amount" for item in tamper_changes)
    tamper_detected = bool(tamper_changes)
    tamper_severity = "none"
    tamper_headline = ""
    if upi_changed and name_changed:
        tamper_severity = "high"
        tamper_headline = "Recipient Identity Changed"
    elif upi_changed:
        tamper_severity = "high"
        tamper_headline = "QR Tampering / Recipient Change Detected"
    elif name_changed:
        tamper_severity = "medium"
        tamper_headline = "Payee Name Changed"
    elif amount_changed:
        tamper_severity = "medium"
        tamper_headline = "Payment Amount Changed"
    elif tamper_detected:
        tamper_severity = "low"
        tamper_headline = "QR Payload Changed"

    score = 10
    signals = []
    if parsed.scheme.lower() == "upi":
        score += 18
        signals.append("QR contains a UPI payment intent")
    elif parsed.scheme.lower() in {"http", "https"}:
        score += 28
        signals.append("QR opens a website destination")
    else:
        score += 6
        signals.append("QR contains non-UPI content")

    if upi_id != "Not found":
        signals.append(f"Recipient UPI ID: {upi_id}")
        if "@" not in upi_id:
            score += 18
            signals.append("Recipient UPI ID has an unusual structure")
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
                signals.append("Moderate payment amount")
        except ValueError:
            score += 8
            signals.append("Amount is not a clean number")

    lowered = f"{raw} {upi_id} {merchant} {note}".lower()
    credential_risk = any(term in lowered for term in ("otp", "pin", "password"))
    risky_terms = ("otp", "pin", "password", "kyc", "refund", "verify", "support", "helpdesk")
    if any(term in lowered for term in risky_terms):
        score += 20
        signals.append("QR payload contains a potentially risky keyword")

    if tamper_detected:
        score += 35 if upi_changed else 15
        signals.insert(0, tamper_headline)

    score = max(0, min(99, score))
    risk = "Critical" if score >= 75 else "High" if score >= 55 else "Medium" if score >= 30 else "Low"
    confidence = 96 if upi_changed else 90 if tamper_detected else 72

    tamper = {
        "tamper_detected": tamper_detected,
        "severity": tamper_severity,
        "headline": tamper_headline,
        "change_status": tamper_headline or "No Verified Baseline",
        "changes": tamper_changes,
        "previous": baseline,
        "current": identity,
        "summary": "Recipient identity changed from the verified baseline." if upi_changed else ("QR payload changed from the verified baseline." if tamper_detected else "No previously user-verified QR baseline found for comparison."),
        "explanation": "The current QR differs from the previously verified QR. Confirm the payee before paying." if tamper_detected else "",
    }

    identity_check = {
        "recipient_name": identity["recipient_name"],
        "upi_id": identity["upi_id"],
        "phone_number": identity["phone_number"],
        "amount": identity["amount"],
        "payment_note": identity["payment_note"],
        "fingerprint": identity["fingerprint"],
        "consistency_state": "Recipient Changed" if upi_changed else ("Payload Changed" if tamper_detected else ("No Verified Baseline" if not baseline else "Matches Verified Baseline")),
        "checks": {
            "recipient_name": identity["payload_consistent"] and identity["recipient_name"] != "Not found",
            "upi_id": identity["payload_consistent"] and not upi_changed,
            "phone_number": identity["phone_number"] != "Not found",
            "fingerprint": bool(identity["fingerprint"]),
        },
        "ownership_disclaimer": "BharatSHIELD cannot independently prove bank-account ownership from a QR payload alone.",
        "tamper": tamper,
    }

    checks = [
        {"label": "Status", "result": "Recipient change detected" if upi_changed else "Local QR verification completed"},
        {"label": "Recipient", "result": upi_id},
        {"label": "Merchant", "result": merchant},
        {"label": "Amount", "result": amount},
        {"label": "Payment Note", "result": note},
        {"label": "QR Fingerprint", "result": identity["fingerprint"]},
    ]
    checks.extend({"label": change["field"], "result": f"Changed: {change['previous']} → {change['current']}"} for change in tamper_changes)

    qr_analysis = {
        "score": score,
        "upi_id": upi_id,
        "merchant": merchant,
        "amount": amount,
        "note": note,
        "destination_url": destination,
        "hidden_redirect": destination != "Not found",
        "recipient_reputation": "Suspicious" if upi_changed else ("Review" if tamper_detected else "Unknown"),
        "previous_reports": 0,
        "fingerprint": identity["fingerprint"],
        "risk_signals": signals,
        "checks": checks,
        "identity": identity,
        "identity_check": identity_check,
        "tamper_check": tamper,
    }

    return {
        "score": score,
        "risk": risk,
        "confidence": confidence,
        "rule_score": score,
        "url_score": score if destination != "Not found" else None,
        "safety_score": max(0, 100 - score),
        "scam_type": "QR Identity Tampering" if upi_changed else ("QR Tamper Review" if tamper_detected else ("UPI QR Review" if upi_id != "Not found" else "QR Review")),
        "explanation": "QR identity was compared against the user-verified baseline." if tamper_detected else "Local QR payload review completed deterministically.",
        "what_we_found": f"QR payload decoded for {upi_id}; merchant {merchant}; amount {amount}." + (f" {tamper_headline}." if tamper_detected else ""),
        "why_dangerous": "The recipient identity encoded in this QR changed after verification. Do not pay until the payee is independently confirmed." if upi_changed else ("Verify recipient, amount, and destination inside your UPI app before paying." if not tamper_detected else "The QR payload changed from its verified baseline. Confirm payee details before paying."),
        "how_sure": f"{confidence}% confidence based on deterministic QR payload and baseline checks.",
        "reason_breakdown": [
            {"label": "QR identity change", "score": 96 if upi_changed else (65 if tamper_detected else 0), "why": "Current recipient details were compared with the saved verified baseline."},
            {"label": "Credential risk", "score": 30 if credential_risk else 0, "why": "Never share OTP, UPI PIN, or password."},
            {"label": "URL / QR risk", "score": score, "why": "QR payload, recipient, amount, and destination were inspected locally."},
        ],
        "breakdown": {"language": 0, "urgency": 0, "emotional_manipulation": 0, "pressure": 0, "credential_request": 30 if credential_risk else 0},
        "call_analysis": {"emotion": "Not analyzed", "pressure_score": 0, "otp_demand": False, "live_warning": score >= 70},
        "signals": [{"label": "QR", "reason": signal} for signal in signals[:10]],
        "recommendations": [
            "Verify recipient name, UPI ID, amount, and purpose inside your UPI app before approving payment.",
            "Never share OTP, UPI PIN, passwords, or card details.",
            "Do not approve an unknown payment request because of urgency or pressure.",
        ],
        "url_checks": [],
        "qr_analysis": qr_analysis,
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
    if payload.get("channel") == "qr" or str(payload.get("content", "")).lower().startswith("upi://"):
        return local_qr_fallback(str(payload.get("content", "")), payload.get("verified_baseline"))
    try:
        model = legacy.AnalyzeRequest.model_validate(payload)
        return await legacy.analyze(model)
    except Exception:
        return JSONResponse({"detail": "Analysis service unavailable."}, status_code=503)


# Forward non-QR API routes and health check to the legacy app
for route in legacy.app.routes:
    app.routes.append(route)

# Serve Vite-built frontend from dist/
DIST_DIR = Path(__file__).resolve().parent.parent / "dist"

if DIST_DIR.is_dir():
    # Serve static assets (JS, CSS, images)
    ASSETS_DIR = DIST_DIR / "assets"
    if ASSETS_DIR.is_dir():
        app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

    # Serve other static files from public/ that end up in dist/ (favicons, images, etc.)
    @app.get("/{full_path:path}")
    async def serve_spa(request: Request, full_path: str):
        # Try to serve the file directly from dist/
        file_path = DIST_DIR / full_path
        if full_path and file_path.is_file() and DIST_DIR in file_path.resolve().parents:
            return FileResponse(str(file_path))
        # Fallback to index.html for SPA routing
        index_path = DIST_DIR / "index.html"
        if index_path.is_file():
            return FileResponse(str(index_path))
        return JSONResponse({"detail": "Not found"}, status_code=404)
