import os
import re
import secrets
import sqlite3
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse
from time import time

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


app = FastAPI(title="BharatSHIELD")

allowed_origins = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
]
allowed_origins.extend(origin.strip().rstrip("/") for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip())

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
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
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
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


SESSION_TTL_SECONDS = 60 * 60 * 24 * 7

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc)
    expires = datetime.fromtimestamp(now.timestamp() + SESSION_TTL_SECONDS, timezone.utc)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (hash_token(token), user_id, now.isoformat(), expires.isoformat()),
        )
    return token

def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required.")
    token = authorization[7:].strip()
    if not token or len(token) < 32:
        raise HTTPException(status_code=401, detail="Invalid authentication token.")
    with get_db() as conn:
        row = conn.execute(
            """SELECT u.id, u.name, u.email, s.expires_at
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token_hash = ?""",
            (hash_token(token),),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    try:
        expired = datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc)
    except ValueError:
        expired = True
    if expired:
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
        raise HTTPException(status_code=401, detail="Session expired. Please login again.")
    return {"id": row["id"], "name": row["name"], "email": row["email"]}


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
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(self), geolocation=()"
    api_origin = str(request.base_url).rstrip("/")
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "connect-src 'self' " + api_origin + " https://generativelanguage.googleapis.com; "
        "img-src 'self' data: blob:; media-src 'self' blob:; "
        "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
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
        return "Heuristic: domain may be disposable or suspicious"
    return "Not independently checked (WHOIS/RDAP API not connected)"


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
    parsed = urlparse(text.strip())
    qs = parse_qs(parsed.query)
    amount = qs.get("am", [""])[0]
    upi_id = qs.get("pa", [""])[0]
    merchant = qs.get("pn", [""])[0]
    notes = qs.get("tn", [""])[0]
    checks = []
    score = 10

    if parsed.scheme == "upi":
        checks.append({"label": "UPI payload", "result": "Payment intent detected"})
        score += 18
    if upi_id:
        checks.append({"label": "UPI ID", "result": upi_id})
        if any(word in upi_id.lower() for word in ("fake", "refund", "support", "verify")):
            score += 20
    if amount:
        checks.append({"label": "Amount", "result": f"INR {amount}"})
        score += 12
    if merchant:
        checks.append({"label": "Merchant name", "result": merchant})
    if notes:
        checks.append({"label": "Payment note", "result": notes})
        if any(word in notes.lower() for word in ("kyc", "refund", "verify")):
            score += 14

    if not checks:
        checks.append({"label": "QR content", "result": "No UPI/payment fields detected"})

    return {
        "score": clamp(score),
        "upi_id": upi_id or "Not found",
        "merchant": merchant or "Not found",
        "amount": amount or "Not found",
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

    # Context matters: educational/warning statements mentioning OTP/PIN are not
    # themselves credential theft. Only score credential terms strongly when the
    # message appears to request, share, or collect the secret.
    warning_context = bool(re.search(
        r"\b(never|don't|do not|dont|avoid|beware|warning|fraud|scam|share with no one|कभी|\u0928\u0939\u0940)\b",
        lowered,
    ))
    credential_request = bool(re.search(
        r"\b(share|send|tell|enter|provide|submit|confirm|give|forward|type)\b.{0,45}\b(otp|pin|password|passcode|cvv|card number|verification code)\b|\b(otp|pin|password|passcode|cvv)\b.{0,45}\b(share|send|tell|enter|provide|submit|confirm|give)\b",
        lowered,
    ))
    if warning_context and re.search(r"\b(never|do not|don't|dont|avoid)\b.{0,30}\b(share|send|tell|enter|provide|give)\b", lowered):
        credential_request = False

    for keyword, weight in {**SUSPICIOUS_KEYWORDS, **HINDI_KEYWORDS}.items():
        if keyword in lowered:
            adjusted_weight = weight
            if keyword in {"otp", "pin", "password"} and warning_context and not credential_request:
                adjusted_weight = 0
            if adjusted_weight:
                score += adjusted_weight
                signals.append({"label": keyword, "reason": KEYWORD_EXPLANATIONS.get(keyword, "High-risk scam language detected")})

    if credential_request:
        score += 24
        signals.append({"label": "Credential request", "reason": "The message appears to ask the user to disclose a secret such as an OTP, PIN, password, or code."})

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
            "credential_request": 92 if credential_request else 8,
        },
        "call_analysis": {
            "emotion": emotion,
            "pressure_score": pressure_score,
            "otp_demand": credential_request,
            "live_warning": pressure_score >= 45 or credential_request,
        },
    }


def inspect_url(raw_url: str) -> dict[str, Any]:
    url = raw_url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Enter a valid HTTP/HTTPS URL.")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="URLs containing embedded credentials are not accepted.")
    domain = parsed.hostname.lower().rstrip(".")
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
        "ssl_expiry": "Not independently checked",
        "safe_browsing": "Heuristic review only — Safe Browsing API not connected",
        "virustotal": "Heuristic review only — VirusTotal API not connected",
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
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, hash_password(request.password), datetime.now(timezone.utc).isoformat()),
            )
            row = conn.execute("SELECT id, name, email FROM users WHERE email = ?", (email,)).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This email is already signed up. Please login.")

    return {
        "token": create_session(row["id"]),
        "user": {"id": row["id"], "name": row["name"], "email": row["email"]},
        "message": "Signup successful.",
    }


@app.post("/api/login")
def login(request: LoginRequest) -> dict[str, Any]:
    email = request.email.strip().lower()
    with get_db() as conn:
        row = conn.execute("SELECT id, name, email, password_hash FROM users WHERE email = ?", (email,)).fetchone()

    if not row or not verify_password(request.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="No signed-up user found with these credentials.")

    return {
        "token": create_session(row["id"]),
        "user": {"id": row["id"], "name": row["name"], "email": row["email"]},
        "message": "Login successful.",
    }


@app.get("/api/me")
def me(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return {"user": current_user}


@app.post("/api/logout")
def logout(authorization: str | None = Header(default=None)) -> dict[str, str]:
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        if token:
            with get_db() as conn:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))
    return {"message": "Logged out."}


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    rules = rule_analysis(request.content, request.channel)
    url_checks = [inspect_url(url) for url in rules["urls"][:3]]
    qr_analysis = inspect_qr_payload(request.content) if request.channel == "qr" or request.content.lower().startswith("upi://") else None
    if url_checks:
        rules["score"] = clamp(max(rules["score"], max(item["score"] for item in url_checks)))
    if qr_analysis:
        rules["score"] = clamp(max(rules["score"], qr_analysis["score"]))

    gemini = await gemini_analysis(request.content, rules, request.language)
    score = rules["score"]
    risk = "Low"
    if score >= 75:
        risk = "Critical"
    elif score >= 55:
        risk = "High"
    elif score >= 30:
        risk = "Medium"

    explanation = (
        "The review found risky language, pressure tactics, credential requests, "
        "or suspicious link patterns."
    )

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
        "what_we_found": f"{rules['scam_type']} pattern with {len(rules['signals'])} evidence signals.",
        "why_dangerous": "This can push the user into clicking a fake link, sharing private credentials, or authorizing a payment.",
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
