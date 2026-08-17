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


def local_qr_fallback(content: str, verified_baseline=None) -> dict:
    """Analyze a UPI QR and detect changes from a previously user-verified baseline."""
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
    tamper_changes = []
    tamper_detected = False
    tamper_severity = "none"
    tamper_headline = ""

    baseline = verified_baseline if isinstance(verified_baseline, dict) else None
    if baseline:
        baseline_upi = str(baseline.get("upi_id", "Not found"))
        baseline_name = str(baseline.get("recipient_name", baseline.get("merchant", "Not found")))
        baseline_amount = str(baseline.get("amount", "Not found"))
        baseline_note = str(baseline.get("payment_note", baseline.get("note", "Not found")))

        if baseline_upi != "Not found" and upi_id != baseline_upi:
            tamper_changes.append({"field": "Recipient / UPI ID", "previous": baseline_upi, "current": upi_id})
            score += 35
            tamper_detected = True
            tamper_severity = "high"
            tamper_headline = "Recipient Identity Changed"
            signals.append(f"Recipient changed from {baseline_upi} to {upi_id}")

        if baseline_name != "Not found" and merchant != "Not found" and baseline_name.strip().lower() != merchant.strip().lower():
            tamper_changes.append({"field": "Recipient Name", "previous": baseline_name, "current": merchant})
            score += 15
            tamper_detected = True
            tamper_severity = "high" if tamper_severity == "high" else "medium"
            tamper_headline = tamper_headline or "Payee Name Changed"
            signals.append(f"Recipient name changed from {baseline_name} to {merchant}")

        if baseline_amount != "Not found" and amount != "Not found" and baseline_amount != amount:
            tamper_changes.append({"field": "Amount", "previous": baseline_amount, "current": amount})
            score += 16
            tamper_detected = True
            if tamper_severity == "none": tamper_severity = "medium"
            tamper_headline = tamper_headline or "Payment Amount Changed"
            signals.append(f"Payment amount changed from INR {baseline_amount} to INR {amount}")

        if baseline_note != "Not found" and note != "Not found" and baseline_note.strip().lower() != note.strip().lower():
            tamper_changes.append({"field": "Payment Note", "previous": baseline_note, "current": note})
            score += 8
            tamper_detected = True
            if tamper_severity == "none": tamper_severity = "low"
            tamper_headline = tamper_headline or "Payment Note Changed"

    if parsed.scheme == "upi":
        score += 18
    elif parsed.scheme in {"http", "https"}:
        score += 28
        signals.append("QR opens a website destination")

    if upi_id != "Not found": signals.append(f"Recipient UPI ID: {upi_id}")
    if merchant != "Not found": signals.append(f"Recipient name: {merchant}")

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

    if tamper_detected:
        signals.insert(0, tamper_headline or "QR payload changed from the verified baseline")

    return {
        "score": score,
        "risk": risk,
        "confidence": 92 if tamper_detected and any(c["field"] == "Recipient / UPI ID" for c in tamper_changes) else 70,
        "rule_score": score,
        "url_score": score if destination != "Not found" else None,
        "safety_score": max(0, 100 - score),
        "scam_type": "QR Identity Tampering" if tamper_detected and tamper_severity == "high" else ("UPI QR Review" if upi_id != "Not found" else "QR Review"),
        "explanation": "QR identity was compared against the user-verified baseline." if tamper_detected else "Local QR payload review completed safely.",
        "what_we_found": f"QR payload decoded for {upi_id}; merchant {merchant}; amount {amount}." + (f" {tamper_headline}." if tamper_detected else ""),
        "why_dangerous": "The recipient identity encoded in this QR changed after verification. Do not make the payment until the payee is independently confirmed." if tamper_detected else "Verify recipient, amount, and destination inside your UPI app before paying.",
        "how_sure": "92% confidence for recipient-change detection based on the verified QR baseline." if tamper_detected and any(c["field"] == "Recipient / UPI ID" for c in tamper_changes) else "70% confidence based on local QR payload parsing.",
        "reason_breakdown": [
            {"label": "QR identity change", "score": 95 if any(c["field"] == "Recipient / UPI ID" for c in tamper_changes) else 0, "why": "Current recipient was compared with the saved verified baseline."},
            {"label": "Credential risk", "score": 30 if credential_risk else 0, "why": "Never share OTP, UPI PIN, or password."},
            {"label": "URL / QR risk", "score": score, "why": "QR payload, recipient, amount, and destination were inspected."},
        ],
        "breakdown": {"language": 0, "urgency": 0, "emotional_manipulation": 0, "pressure": 0, "credential_request": 30 if credential_risk else 0},
        "call_analysis": {"emotion": "Not analyzed", "pressure_score": 0, "otp_demand": False, "live_warning": score >= 70},
        "signals": [{"label": "QR", "reason": signal} for signal in signals[:10]],
        "recommendations": [
            "Do not make the payment until recipient details match a trusted source.",
            "Never share OTP, UPI PIN, passwords, or card details.",
            "Open your UPI app yourself and verify the recipient name and UPI ID.",
        ],
        "url_checks": [],
        "qr_analysis": {
            "score": score,
            "upi_id": upi_id,
            "merchant": merchant,
            "amount": amount,
            "note": note,
            "destination_url": destination,
            "hidden_redirect": destination != "Not found",
            "recipient_reputation": "Suspicious" if tamper_detected else "Unknown",
            "previous_reports": 0,
            "fingerprint": "BS-QR-BASELINE-COMPARED" if baseline else "BS-QR-LOCAL",
            "risk_signals": signals,
            "checks": [
                {"label": "Status", "result": "Recipient change detected" if tamper_detected and any(c["field"] == "Recipient / UPI ID" for c in tamper_changes) else "Local QR verification completed"},
                *[{"label": change["field"], "result": f"Changed: {change['previous']} → {change['current']}"} for change in tamper_changes],
            ],
            "tamper_check": {
                "tamper_detected": tamper_detected,
                "severity": tamper_severity,
                "headline": tamper_headline,
                "changes": tamper_changes,
                "summary": "Recipient identity changed from the verified baseline." if any(c["field"] == "Recipient / UPI ID" for c in tamper_changes) else "No recipient identity change detected.",
            },
        },
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
    if request.url.scheme == "https": response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response


@app.post("/api/analyze")
async def analyze_gateway(request: Request):
    payload = await request.json()
    if payload.get("channel") == "qr" or str(payload.get("content", "")).lower().startswith("upi://"):
        # QR analysis is intentionally handled here so baseline/tamper detection
        # cannot be masked by a legacy analyzer fallback.
        return local_qr_fallback(str(payload.get("content", "")), payload.get("verified_baseline"))
    try:
        model = legacy.AnalyzeRequest.model_validate(payload)
        return await legacy.analyze(model)
    except Exception:
        return JSONResponse({"detail": "Analysis service unavailable."}, status_code=503)


app.mount("/", legacy.app)
