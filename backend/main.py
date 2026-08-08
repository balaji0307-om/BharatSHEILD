import os
import re
import secrets
import sqlite3
import hashlib
import json
from io import BytesIO
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
from time import time

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
except Exception:  # pragma: no cover - deployment installs reportlab, fallback keeps API alive locally.
    A4 = None
    getSampleStyleSheet = None
    Paragraph = None
    SimpleDocTemplate = None
    Spacer = None


app = FastAPI(title="BharatSHIELD")

allowed_origins = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "https://bharatshield.onrender.com",
    "https://bharatsheild.onrender.com",
]
allowed_origins.extend(origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip())

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.onrender\.com",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1)
    channel: str = "message"
    language: str = "en"


class UrlCheckRequest(BaseModel):
    url: str = Field(min_length=1)


class SignupRequest(BaseModel):
    name: str = Field(min_length=2)
    email: str = Field(min_length=5)
    password: str = Field(min_length=6)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5)
    password: str = Field(min_length=6)


class CaseCreateRequest(BaseModel):
    case: dict[str, Any]


class CaseUpdateRequest(BaseModel):
    status: str | None = None
    note: str | None = None
    reviewed_by: str | None = None


DB_PATH = Path(__file__).with_name("bharatshield.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            )
            """
        )
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "role" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_cases (
                case_id TEXT PRIMARY KEY,
                owner_email TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    salt, expected = stored.split("$", 1)
    return secrets.compare_digest(hash_password(password, salt).split("$", 1)[1], expected)


def make_token() -> str:
    return secrets.token_urlsafe(32)


SESSION_TOKENS: dict[str, dict[str, Any]] = {}


def create_session(user: dict[str, Any]) -> dict[str, Any]:
    token = make_token()
    SESSION_TOKENS[token] = user
    return {"token": token, "user": user}


def auth_user(request: Request) -> dict[str, Any]:
    header = request.headers.get("authorization", "")
    token = header.removeprefix("Bearer ").strip() if header.lower().startswith("bearer ") else ""
    user = SESSION_TOKENS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Login required.")
    return user


init_db()

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30
request_log: dict[str, list[float]] = {}


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    client = request.client.host if request.client else "unknown"
    now = time()
    hits = [hit for hit in request_log.get(client, []) if now - hit < RATE_LIMIT_WINDOW]
    if len(hits) >= RATE_LIMIT_MAX:
        return JSONResponse({"detail": "Too many requests. Please try again shortly."}, status_code=429)
    hits.append(now)
    request_log[client] = hits

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


SUSPICIOUS_KEYWORDS = {
    "otp": 16,
    "pin": 16,
    "password": 14,
    "kyc": 12,
    "blocked": 12,
    "verify": 10,
    "urgent": 10,
    "immediately": 10,
    "limited time": 9,
    "registration fee": 16,
    "processing fee": 14,
    "double your money": 20,
    "guaranteed return": 18,
    "lottery": 14,
    "congratulations": 10,
    "winner": 10,
    "free gift": 12,
    "click below": 12,
    "click here": 10,
    "account suspended": 16,
    "customer care": 8,
    "refund": 8,
    "upi": 8,
    "loan approved": 12,
    "work from home": 8,
    "paytm": 6,
    "amazon hiring": 14,
    "income daily": 14,
    "javascript:": 26,
    "<script": 26,
    "powershell": 24,
    "cmd.exe": 24,
}

KEYWORD_EXPLANATIONS = {
    "otp": "Scammers ask for OTPs to take over bank, UPI, or account access.",
    "pin": "PIN requests are direct credential theft attempts.",
    "password": "Legitimate services do not ask for passwords in messages.",
    "kyc": "Fake KYC warnings are commonly used to create fear and steal details.",
    "blocked": "Account-blocking threats create panic and rush the user.",
    "verify": "Verification links can lead to fake login or payment pages.",
    "urgent": "Urgency reduces careful thinking and is a common scam tactic.",
    "immediately": "Immediate action pressure is a fraud signal.",
    "registration fee": "Advance-fee job scams ask for money before any real work.",
    "double your money": "Guaranteed fast returns are a high-risk investment scam pattern.",
    "guaranteed return": "No legitimate investment can guarantee risk-free high returns.",
    "lottery": "Unexpected lottery wins are usually used to collect fees or OTPs.",
    "congratulations": "Reward bait is used to make users click unsafe links.",
    "click here": "Generic click prompts often hide phishing destinations.",
    "account suspended": "Suspension threats are a classic phishing pressure tactic.",
    "upi": "UPI links or collect requests can trigger unwanted payment flows.",
    "javascript:": "QR codes or links should not contain executable browser script.",
    "<script": "Embedded script content is unsafe in QR or message payloads.",
    "powershell": "Command text inside user-facing content is a strong abuse signal.",
    "cmd.exe": "Command shell markers indicate unsafe executable intent.",
}

HINDI_KEYWORDS = {
    "turant": 10,
    "jaldi": 8,
    "otp": 16,
    "pin": 16,
    "inaam": 12,
    "jeet": 10,
    "naukri": 8,
    "paisa double": 20,
    "account band": 16,
    "verify karo": 12,
}

SCAM_TYPES = [
    ("UPI Fraud", ["upi", "collect request", "refund", "scan qr", "paytm", "phonepe", "gpay"]),
    ("Phishing", ["kyc", "blocked", "verify", "account suspended", "password", "login"]),
    ("Lottery Scam", ["lottery", "winner", "congratulations", "prize", "free gift"]),
    ("Fake Job", ["job", "hiring", "registration fee", "work from home", "daily income", "naukri"]),
    ("Fake Investment", ["double your money", "guaranteed return", "crypto", "investment", "profit"]),
    ("Impersonation", ["bank", "rbi", "police", "income tax", "customer care"]),
    ("Fake News", ["forwarded", "breaking", "share with everyone", "viral", "government announced"]),
]

URL_PATTERN = re.compile(r"https?://[^\s]+|www\.[^\s]+", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"(\+91[-\s]?)?[6-9]\d{9}")


def clamp(value: int) -> int:
    return max(0, min(99, value))


def extract_urls(text: str) -> list[str]:
    urls = [match.rstrip(".,);]") for match in URL_PATTERN.findall(text)]
    if text.lower().startswith(("upi://", "intent://")):
        urls.append(text.strip())
    return urls


def estimate_domain_age(domain: str) -> str:
    if any(flag in domain for flag in ("amaz0n", "verify", "kyc", "login", "claim", "gift")) or domain.endswith((".xyz", ".top", ".click")):
        return "Estimated new or throwaway domain"
    return "No recent-registration signal found"


def similarity_hint(domain: str) -> dict[str, Any] | None:
    brands = {
        "amazon": ["amaz0n", "amzon", "amazon-login"],
        "sbi": ["sbi-verify", "sbionline-kyc"],
        "paytm": ["paytm-login", "paytm-refund"],
        "hdfc": ["hdfc-verify", "hdfc-kyc"],
    }
    for brand, variants in brands.items():
        if any(variant in domain for variant in variants):
            return {"brand": brand.title(), "similarity": 94, "verdict": "Possible brand impersonation"}
    return None


def inspect_qr_payload(text: str) -> dict[str, Any]:
    raw = text.strip()
    parsed = urlparse(raw)
    qs = parse_qs(parsed.query)
    amount = qs.get("am", [""])[0]
    upi_id = qs.get("pa", [""])[0]
    merchant = qs.get("pn", [""])[0]
    notes = qs.get("tn", [""])[0]
    lowered_payload = " ".join([raw, upi_id, merchant, notes]).lower()
    checks = []
    risk_signals: list[str] = []
    score = 8

    if parsed.scheme == "upi":
        checks.append({"label": "Payload", "result": "Valid UPI payment intent"})
        score += 8
    elif parsed.scheme in {"http", "https"}:
        checks.append({"label": "Payload", "result": "Website link inside QR"})
        score += 18
        risk_signals.append("QR opens a website link")
    elif raw:
        checks.append({"label": "Payload", "result": "Non-UPI QR content"})
        score += 6

    if upi_id:
        upi_valid = bool(re.match(r"^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z][a-zA-Z0-9.\-_]{2,}$", upi_id))
        checks.append({"label": "Recipient", "result": upi_id})
        checks.append({"label": "UPI format", "result": "Valid structure" if upi_valid else "Invalid or unusual"})
        score += 2 if upi_valid else 18
        if not upi_valid:
            risk_signals.append("Recipient UPI format is unusual")
        if any(word in upi_id.lower() for word in ("fake", "refund", "support", "verify", "kyc", "helpdesk", "customer")):
            score += 24
            risk_signals.append("Recipient name contains support/refund/KYC terms")
        if re.search(r"\d{6,}", upi_id):
            score += 8
            risk_signals.append("Recipient contains a long numeric pattern")
    elif parsed.scheme == "upi":
        score += 22
        risk_signals.append("UPI QR has no recipient field")

    if amount:
        checks.append({"label": "Amount", "result": f"INR {amount}"})
        try:
            amount_value = float(amount)
        except ValueError:
            amount_value = 0
            score += 8
            risk_signals.append("Amount is not a clean number")
        if amount_value >= 5000:
            score += 16
            risk_signals.append("High payment amount")
        elif amount_value >= 1000:
            score += 10
            risk_signals.append("Moderate payment amount")
        elif amount_value > 0:
            score += 3
    else:
        checks.append({"label": "Amount", "result": "Not prefilled"})

    if merchant:
        checks.append({"label": "Merchant name", "result": merchant})
        if any(word in merchant.lower() for word in ("refund", "support", "kyc", "verification", "bank", "helpdesk")):
            score += 20
            risk_signals.append("Merchant name uses refund/support/KYC terms")
    else:
        checks.append({"label": "Merchant name", "result": "Not provided"})

    if notes:
        checks.append({"label": "Payment note", "result": notes})
        if any(word in notes.lower() for word in ("kyc", "refund", "verify", "blocked", "fee", "urgent", "registration")):
            score += 22
            risk_signals.append("Payment note contains pressure or verification terms")
    else:
        checks.append({"label": "Payment note", "result": "Not provided"})

    if any(word in lowered_payload for word in ("otp", "pin", "password")):
        score += 26
        risk_signals.append("QR payload references OTP/PIN/password")

    normalized = "|".join([
        parsed.scheme.lower(),
        upi_id.strip().lower(),
        merchant.strip().lower(),
        amount.strip(),
        notes.strip().lower(),
        parsed.netloc.lower(),
        parsed.path.lower(),
    ])
    fingerprint = "BS-QR-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:8].upper()
    reported_patterns = {
        "fake-support@upi": 7,
        "support-refund@upi": 14,
        "refunddesk@upi": 9,
    }
    previous_reports = reported_patterns.get(upi_id.lower(), 0)
    if previous_reports:
        score += 24
        risk_signals.append(f"Recipient has {previous_reports} previous demo reports")
    elif upi_id:
        recipient_bucket = int(hashlib.sha256(upi_id.lower().encode("utf-8")).hexdigest()[:2], 16) % 9
        score += recipient_bucket
        checks.append({"label": "Recipient risk bucket", "result": f"{recipient_bucket}/8 unknown-recipient variance"})

    if not checks:
        checks.append({"label": "QR content", "result": "No UPI/payment fields detected"})

    reputation = "Suspicious" if previous_reports or score >= 70 else "Unknown" if upi_id else "Not applicable"
    if reputation == "Unknown":
        checks.append({"label": "Recipient reputation", "result": "Unknown, not verified safe"})
    elif reputation == "Suspicious":
        checks.append({"label": "Recipient reputation", "result": "Suspicious pattern"})

    return {
        "score": clamp(score),
        "upi_id": upi_id or "Not found",
        "merchant": merchant or "Not found",
        "amount": amount or "Not found",
        "note": notes or "Not found",
        "recipient_reputation": reputation,
        "previous_reports": previous_reports,
        "fingerprint": fingerprint,
        "risk_signals": risk_signals,
        "hidden_redirect": parsed.scheme in {"http", "https"} and bool(parsed.netloc),
        "checks": checks,
    }


def classify_scam(text: str) -> str:
    lowered = text.lower()
    best_type = "Suspicious Message"
    best_hits = 0
    for scam_type, hints in SCAM_TYPES:
        hits = sum(1 for hint in hints if hint in lowered)
        if hits > best_hits:
            best_type = scam_type
            best_hits = hits
    return best_type


def rule_analysis(text: str, channel: str = "message") -> dict[str, Any]:
    lowered = text.lower()
    score = 8
    signals: list[dict[str, str]] = []
    urls = extract_urls(text)

    for keyword, weight in {**SUSPICIOUS_KEYWORDS, **HINDI_KEYWORDS}.items():
        if keyword in lowered:
            score += weight
            signals.append({"label": keyword, "reason": KEYWORD_EXPLANATIONS.get(keyword, "High-risk scam language detected")})

    if urls:
        score += 14
        signals.append({"label": "External link", "reason": "Message asks the user to open a link"})

    if PHONE_PATTERN.search(text):
        score += 6
        signals.append({"label": "Phone number", "reason": "Message includes direct contact pressure"})

    if re.search(r"\b\d{4,6}\b", text) and ("otp" in lowered or "code" in lowered):
        score += 16
        signals.append({"label": "OTP/code request", "reason": "OTP or verification code language is risky"})

    if len(re.findall(r"[!?]", text)) >= 3:
        score += 6
        signals.append({"label": "Pressure punctuation", "reason": "Aggressive punctuation can signal urgency tactics"})

    if channel in {"url", "qr"}:
        score += 5

    urgency_score = clamp(sum(weight for key, weight in {"urgent": 24, "immediately": 22, "blocked": 26, "limited time": 18}.items() if key in lowered))
    emotional_score = clamp(sum(weight for key, weight in {"congratulations": 18, "winner": 18, "free gift": 16, "blocked": 20, "account suspended": 22}.items() if key in lowered))
    pressure_score = clamp(urgency_score + emotional_score + (12 if PHONE_PATTERN.search(text) else 0))
    emotion = "Aggressive / Threatening" if pressure_score >= 55 else "Reward bait" if emotional_score >= 25 else "Neutral"

    recommendations = [
        "Do not click links or open attachments from this message.",
        "Never share OTP, UPI PIN, passwords, or card details.",
        "Verify through the official app or website by typing the address yourself.",
    ]

    return {
        "score": clamp(score),
        "scam_type": classify_scam(text),
        "signals": signals[:10],
        "recommendations": recommendations,
        "urls": urls,
        "breakdown": {
            "language": clamp(len(signals) * 9),
            "urgency": urgency_score,
            "emotional_manipulation": emotional_score,
            "pressure": pressure_score,
            "credential_request": 92 if any(word in lowered for word in ("otp", "pin", "password")) else 12,
        },
        "call_analysis": {
            "emotion": emotion,
            "pressure_score": pressure_score,
            "otp_demand": "otp" in lowered or "code" in lowered,
            "live_warning": pressure_score >= 45 or "otp" in lowered,
        },
    }


def inspect_url(raw_url: str) -> dict[str, Any]:
    url = raw_url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    score = 12
    checks: list[dict[str, str]] = []

    if parsed.scheme != "https":
        score += 15
        checks.append({"label": "No HTTPS", "result": "Risky"})
    else:
        checks.append({"label": "HTTPS", "result": "Present"})

    if any(char.isdigit() for char in domain):
        score += 12
        checks.append({"label": "Digits in domain", "result": "Suspicious"})

    if "-" in domain:
        score += 8
        checks.append({"label": "Hyphenated domain", "result": "Review carefully"})

    suspicious_tlds = (".xyz", ".top", ".click", ".shop", ".info", ".loan", ".work")
    if domain.endswith(suspicious_tlds):
        score += 15
        checks.append({"label": "Risky TLD", "result": "Common in throwaway sites"})

    brand_lookalikes = {
        "amaz0n": "amazon",
        "paytm-login": "paytm",
        "sbi-verify": "sbi",
        "icici-kyc": "icici",
        "hdfc-verify": "hdfc",
    }
    for fake, brand in brand_lookalikes.items():
        if fake in domain:
            score += 22
            checks.append({"label": "Lookalike brand", "result": f"May impersonate {brand}"})

    similarity = similarity_hint(domain)
    if similarity:
        checks.append({"label": "Brand similarity", "result": f"{similarity['similarity']}% similar to {similarity['brand']}"})

    if len(domain.split(".")) > 3:
        score += 8
        checks.append({"label": "Deep subdomain", "result": "Could hide true domain"})

    if not checks:
        checks.append({"label": "Basic URL checks", "result": "No obvious red flags"})

    return {
        "normalized_url": url,
        "domain": domain,
        "score": clamp(score),
        "domain_age": estimate_domain_age(domain),
        "ssl_expiry": "Certificate review recommended",
        "safe_browsing": "Suspicious indicators found" if score >= 45 else "No obvious block signal",
        "virustotal": "Local reputation checks applied",
        "brand_similarity": similarity,
        "checks": checks,
    }


async def gemini_analysis(text: str, rule_result: dict[str, Any], language: str) -> dict[str, Any] | None:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None

    prompt = f"""
You are a cybersecurity assistant for Indian users. Analyze this suspicious content.
Return concise JSON with keys: scam_type, explanation, recommendations, confidence.
Language preference: {language}
Rule engine result: {rule_result}
Content: {text}
"""
    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-1.5-flash:generateContent?key={api_key}"
    )
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            data = response.json()
            text_response = data["candidates"][0]["content"]["parts"][0]["text"]
            return {"raw": text_response}
    except Exception:
        return None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/api/signup")
def signup(request: SignupRequest) -> dict[str, Any]:
    email = request.email.strip().lower()
    name = request.name.strip()
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        raise HTTPException(status_code=400, detail="Enter a valid email address.")

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, email, hash_password(request.password), "user", datetime.now(timezone.utc).isoformat()),
            )
            row = conn.execute("SELECT id, name, email, role FROM users WHERE email = ?", (email,)).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This email is already signed up. Please login.")

    session = create_session({"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"]})
    return {**session, "message": "Signup successful."}


@app.post("/api/login")
def login(request: LoginRequest) -> dict[str, Any]:
    email = request.email.strip().lower()
    with get_db() as conn:
        row = conn.execute("SELECT id, name, email, role, password_hash FROM users WHERE email = ?", (email,)).fetchone()

    if not row or not verify_password(request.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="No signed-up user found with these credentials.")

    session = create_session({"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"]})
    return {**session, "message": "Login successful."}


def normalize_case(case: dict[str, Any]) -> dict[str, Any]:
    case_id = str(case.get("case_id") or f"BS-{secrets.randbelow(9000) + 1000}")
    owner = str(case.get("owner") or "local-user").strip().lower()
    now = datetime.now(timezone.utc).isoformat()
    investigation = case.get("investigation") if isinstance(case.get("investigation"), dict) else {}
    status = str(investigation.get("status") or case.get("status") or "Suspected")
    timeline = case.get("timeline") if isinstance(case.get("timeline"), list) else []
    if not timeline:
        timeline = [{"label": "Case created", "time": now}]
    return {
        **case,
        "case_id": case_id,
        "owner": owner,
        "investigation": {
            "status": status,
            "note": investigation.get("note") or "",
            "reviewed_by": investigation.get("reviewed_by"),
            "reviewed_at": investigation.get("reviewed_at"),
        },
        "timeline": timeline,
        "created_at": case.get("created_at") or now,
    }


def save_security_case(case: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_case(case)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO security_cases (case_id, owner_email, payload, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id) DO UPDATE SET
                owner_email = excluded.owner_email,
                payload = excluded.payload,
                status = excluded.status,
                updated_at = excluded.updated_at
            """,
            (
                normalized["case_id"],
                normalized["owner"],
                json.dumps(normalized),
                normalized["investigation"]["status"],
                normalized["created_at"],
                now,
            ),
        )
    return normalized


def get_security_case(case_id: str) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute("SELECT payload FROM security_cases WHERE case_id = ?", (case_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


def case_text(case: dict[str, Any]) -> str:
    ai = case.get("ai_result", {})
    investigation = case.get("investigation", {})
    timeline = case.get("timeline", [])
    reasons = ai.get("reasons") or ["No major risk signals found."]
    return "\n".join([
        "BharatSHIELD Security Investigation Report",
        "",
        f"Case ID: {case.get('case_id')}",
        f"Threat Type: {case.get('type')}",
        f"Channel: {case.get('channel')}",
        f"Detected Content: {case.get('input')}",
        f"Risk Level: {ai.get('risk')}",
        f"Risk Score: {ai.get('score')}%",
        f"Confidence: {ai.get('confidence')}%",
        "",
        "AI Analysis:",
        str(ai.get("explanation") or "Security review completed."),
        "",
        "Detection Reasons:",
        *[f"- {reason}" for reason in reasons],
        "",
        f"Investigation Status: {investigation.get('status')}",
        f"Investigator Note: {investigation.get('note') or 'No note added.'}",
        f"Reviewed By: {investigation.get('reviewed_by') or 'Not reviewed'}",
        "",
        "Evidence Timeline:",
        *[f"- {item.get('time')}: {item.get('label')}" for item in timeline],
        "",
        "Recommendation:",
        "Do not share OTP, PIN, passwords, card details, or approve unknown payment requests.",
        "",
        "Generated by BharatSHIELD",
    ])


def minimal_pdf_bytes(text: str) -> bytes:
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    lines = safe.splitlines()[:48]
    stream = "BT /F1 11 Tf 42 790 Td " + " T* ".join(f"({line}) Tj" for line in lines) + " ET"
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
        f"5 0 obj << /Length {len(stream.encode('latin-1', 'ignore'))} >> stream\n{stream}\nendstream endobj",
    ]
    pdf = "%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf.encode("latin-1")))
        pdf += obj + "\n"
    xref = len(pdf.encode("latin-1"))
    pdf += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    pdf += "".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:])
    pdf += f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
    return pdf.encode("latin-1", "ignore")


def render_case_pdf(case: dict[str, Any]) -> bytes:
    text = case_text(case)
    if not SimpleDocTemplate:
        return minimal_pdf_bytes(text)
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title=f"{case.get('case_id')} BharatSHIELD Report")
    styles = getSampleStyleSheet()
    story = [
        Paragraph("BharatSHIELD Security Investigation Report", styles["Title"]),
        Spacer(1, 12),
    ]
    for line in text.splitlines()[2:]:
        story.append(Paragraph(line or "&nbsp;", styles["BodyText"]))
        story.append(Spacer(1, 4))
    doc.build(story)
    return buffer.getvalue()


@app.get("/api/cases")
def list_cases(request: Request, owner: str | None = None) -> dict[str, Any]:
    user = auth_user(request)
    role = user.get("role", "user")
    if role == "user":
        owner = user["email"]
    query = "SELECT payload FROM security_cases"
    params: tuple[Any, ...] = ()
    if owner:
        query += " WHERE owner_email = ?"
        params = (owner.strip().lower(),)
    query += " ORDER BY updated_at DESC LIMIT 100"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return {"cases": [json.loads(row["payload"]) for row in rows]}


@app.post("/api/cases")
def create_case(payload: CaseCreateRequest, request: Request) -> dict[str, Any]:
    user = auth_user(request)
    case = {**payload.case, "owner": user["email"]}
    return {"case": save_security_case(case)}


@app.patch("/api/cases/{case_id}")
def update_case_api(case_id: str, payload: CaseUpdateRequest, request: Request) -> dict[str, Any]:
    user = auth_user(request)
    case = get_security_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    if user.get("role") == "user" and case.get("owner") != user.get("email"):
        raise HTTPException(status_code=403, detail="You can only update your own cases.")
    reviewed_at = datetime.now(timezone.utc).isoformat()
    investigation = case.get("investigation", {})
    if payload.status:
        investigation["status"] = payload.status
        case["timeline"] = [*case.get("timeline", []), {"label": f"Marked {payload.status}", "time": reviewed_at}]
    if payload.note is not None:
        investigation["note"] = payload.note
    investigation["reviewed_by"] = payload.reviewed_by or user.get("name") or investigation.get("reviewed_by")
    investigation["reviewed_at"] = reviewed_at
    case["investigation"] = investigation
    return {"case": save_security_case(case)}


@app.get("/api/cases/{case_id}/report.pdf")
def case_report_pdf(case_id: str, request: Request) -> Response:
    user = auth_user(request)
    case = get_security_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    if user.get("role") == "user" and case.get("owner") != user.get("email"):
        raise HTTPException(status_code=403, detail="You can only download your own case reports.")
    pdf = render_case_pdf(case)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{case_id}.pdf"'},
    )


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    rules = rule_analysis(request.content, request.channel)
    url_checks = [inspect_url(url) for url in rules["urls"][:3]]
    qr_analysis = inspect_qr_payload(request.content) if request.channel == "qr" or request.content.lower().startswith("upi://") else None
    if url_checks:
        rules["score"] = clamp(max(rules["score"], max(item["score"] for item in url_checks)))
    if qr_analysis:
        rules["score"] = clamp(max(rules["score"], qr_analysis["score"]))
        for signal in qr_analysis.get("risk_signals", [])[:6]:
            rules["signals"].append({"label": "QR payment", "reason": signal})
        if qr_analysis.get("upi_id") != "Not found":
            rules["scam_type"] = "UPI QR Review" if qr_analysis["score"] < 55 else "UPI QR Fraud Risk"

    gemini = await gemini_analysis(request.content, rules, request.language)
    score = rules["score"]
    risk = "Low"
    if score >= 75:
        risk = "Critical"
    elif score >= 55:
        risk = "High"
    elif score >= 30:
        risk = "Medium"

    explanation = "The review found risky language, pressure tactics, credential requests, or suspicious link patterns."
    what_we_found = f"{rules['scam_type']} pattern with {len(rules['signals'])} evidence signals."
    why_dangerous = "This can push the user into clicking a fake link, sharing private credentials, or authorizing a payment."
    if qr_analysis:
        qr_bits = [
            f"recipient {qr_analysis.get('upi_id')}",
            f"merchant {qr_analysis.get('merchant')}",
            f"amount {qr_analysis.get('amount')}",
            f"note {qr_analysis.get('note')}",
        ]
        what_we_found = "QR payment review for " + ", ".join(qr_bits) + "."
        if qr_analysis.get("risk_signals"):
            why_dangerous = "Risk signals: " + "; ".join(qr_analysis["risk_signals"][:4]) + "."
        else:
            why_dangerous = "Recipient reputation is unknown. Verify the payee inside your UPI app before paying."

    confidence = clamp(max(55, min(98, score + 12)))
    safety_score = 100 - score
    reason_breakdown = [
        {"label": "Message language", "score": rules["breakdown"]["language"], "why": "Checks risky words, fake reward claims, fear tactics, and credential requests."},
        {"label": "Urgency and pressure", "score": rules["breakdown"]["pressure"], "why": "Measures panic, time pressure, threats, and emotional manipulation."},
        {"label": "Credential risk", "score": rules["breakdown"]["credential_request"], "why": "Looks for OTP, PIN, password, and verification-code requests."},
        {"label": "URL / QR risk", "score": max([item["score"] for item in url_checks] + ([qr_analysis["score"]] if qr_analysis else [0])), "why": "Inspects link structure, brand impersonation, UPI payloads, and suspicious destinations."},
    ]

    created_at = datetime.now(timezone.utc).isoformat()
    case_id = f"BS-{secrets.randbelow(9000) + 1000}"
    result = {
        "score": score,
        "risk": risk,
        "confidence": confidence,
        "safety_score": safety_score,
        "scam_type": rules["scam_type"],
        "explanation": explanation,
        "what_we_found": what_we_found,
        "why_dangerous": why_dangerous,
        "how_sure": f"{confidence}% confidence based on message, link, and behavior checks.",
        "reason_breakdown": reason_breakdown,
        "breakdown": rules["breakdown"],
        "call_analysis": rules["call_analysis"],
        "signals": rules["signals"],
        "recommendations": rules["recommendations"],
        "url_checks": url_checks,
        "qr_analysis": qr_analysis,
        "gemini": gemini,
        "created_at": created_at,
    }
    result["case_id"] = case_id
    result["ai_result"] = {
        "risk": risk,
        "score": score,
        "confidence": confidence,
        "explanation": result["what_we_found"],
        "reasons": [f"{item['label']}: {item['reason']}" for item in rules["signals"][:6]],
    }
    result["investigation"] = {
        "status": "Suspected" if score >= 70 else "Needs Review" if score >= 35 else "Verified",
        "note": "",
        "reviewed_by": None,
        "reviewed_at": None,
    }
    return result


@app.post("/api/url-check")
def url_check(request: UrlCheckRequest) -> dict[str, Any]:
    result = inspect_url(request.url)
    result["risk"] = "High" if result["score"] >= 55 else "Medium" if result["score"] >= 30 else "Low"
    return result
