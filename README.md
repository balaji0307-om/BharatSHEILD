# BharatSHIELD

**AI-powered digital scam detection and response platform for India.**

BharatSHIELD helps users inspect suspicious messages, links, QR codes, emails, job offers, investment pitches, fake news forwards, and call transcripts before they act on them. The platform combines explainable rule-based checks with optional Gemini analysis, URL inspection, QR parsing, safety recommendations, and a complaint-ready reporting flow.

[Live Demo](https://bharatshield.onrender.com) | [Cyber Crime Portal](https://cybercrime.gov.in)

---

## Problem

Digital scams are increasingly delivered through everyday channels such as SMS, WhatsApp, QR codes, fake websites, social media messages, and phone calls. Many users do not need malware protection only; they need decision-time guidance that explains whether a message, link, or payment request is risky and what to do next.

BharatSHIELD focuses on three outcomes:

- Detect suspicious content before the user clicks, pays, or shares credentials.
- Explain the reason behind every risk score in simple language.
- Help the user respond with reporting, emergency steps, and evidence organization.

---

## What BharatSHIELD Does

- Scans SMS, WhatsApp messages, emails, fake job posts, investment offers, and fake news forwards.
- Checks suspicious URLs for phishing signals, brand impersonation, risky keywords, and unsafe patterns.
- Decodes QR images and reviews QR payloads before opening payment or website links.
- Reviews call transcripts for OTP requests, threat language, urgency, and social engineering.
- Generates a risk score, confidence score, evidence highlights, and recommended actions.
- Creates security cases with status tracking, notes, timelines, and export options.
- Provides emergency guidance for active fraud situations, including helpline 1930 and cybercrime portal support.
- Includes a Guardian page that demonstrates browser-style warning overlays for fake login pages.

---

## Key Features

### Scan Anything

Users can scan:

- SMS and WhatsApp messages
- Website links
- QR code images
- Call transcripts or audio-assisted text
- Emails
- Fake job offers
- Investment messages
- Fake news forwards

### Explainable Risk Result

Each scan returns:

- Overall risk score
- AI confidence
- Rule engine score
- URL or QR risk
- Evidence heatmap
- Reason breakdown
- Recommended user action
- Final safety seal: **Verified by BharatSHIELD**

### QR Safety Flow

The QR scanner is designed for safe preview first:

- Upload QR image
- Decode payload
- Identify UPI ID, merchant name, amount, and suspicious notes
- Detect risky payment or redirect patterns
- Show recommendation before the user opens anything

### Guardian Mode

Guardian demonstrates how BharatSHIELD can work as a browser protection layer:

- Detects lookalike banking pages
- Flags OTP/password collection
- Shows a high-risk warning overlay
- Provides leave-site and report actions
- Explains why the page was blocked

### Report Scam

The reporting flow helps users prepare complaint material:

- Select scam type
- Upload evidence
- Generate complaint summary
- Download complaint draft
- Open the official cybercrime portal

### Emergency Help

For active fraud situations, BharatSHIELD provides:

- Call 1930 action
- Cyber Crime Portal access
- Stop payment guidance
- Evidence checklist
- SOS mode instructions

---

## Security and Privacy Approach

BharatSHIELD is built with a privacy-first demo architecture:

- User passwords are hashed with PBKDF2-HMAC-SHA256 and are never stored in browser localStorage.
- Authenticated analysis endpoints require a server-side session token.
- CORS uses an explicit allowlist; there is no wildcard Render-origin rule.
- API rate limiting is included to reduce abuse.
- Secure response headers are added by the backend.
- Evidence selection is limited to approved media/document extensions and a 15 MB client-side size limit.
- The current evidence flow stores the filename for report drafting; it does not upload the file to the API.
- Sensitive evidence is treated as temporary review data in the user flow.
- The app does not request contacts, photos, location, OTPs, passwords, or background microphone permissions for scanning.

This project provides AI-assisted risk estimation for awareness and prevention. It is not an official cybersecurity verification service.

---

## Tech Stack

| Layer | Technology |
| --- | --- |
| Frontend | React, Vite, CSS |
| Backend | FastAPI, Python |
| AI | Gemini API support with rule-engine fallback |
| QR Analysis | jsQR and browser BarcodeDetector support |
| Authentication | FastAPI sessions, SQLite, PBKDF2-HMAC-SHA256 |
| Deployment | Render |
| Version Control | Git and GitHub |

---

## Architecture

```text
React Frontend
    |
    |-- scan input, QR upload, audio upload, reports
    |
FastAPI Backend
    |
    |-- rule engine
    |-- optional Gemini analysis
    |-- heuristic URL and QR checks
    |-- authenticated session API
    |-- security case response
```

---

## Local Setup

### 1. Install frontend dependencies

```bash
npm install
```

### 2. Install backend dependencies

```bash
pip install -r backend/requirements.txt
```

### 3. Configure environment variables

Create an environment variable only if you want Gemini-backed analysis:

```bash
GEMINI_API_KEY=your_gemini_api_key
```

Without the key, BharatSHIELD still runs using the built-in heuristic rule engine. External Safe Browsing, VirusTotal, WHOIS/RDAP, and SSL certificate intelligence are not claimed unless those integrations are configured.

### 4. Start backend

```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### 5. Start frontend

```bash
npm run dev
```

Frontend runs at:

```text
http://127.0.0.1:5173
```

---

## Deployment Notes

For Render or similar hosting:

- Set the frontend build command to `npm run build`.
- Set the frontend publish directory to `dist`.
- Deploy the FastAPI backend separately if backend auth and API scanning are required.
- Set `VITE_API_BASE_URL` to the deployed backend URL.
- Add only the exact frontend domain to `CORS_ORIGINS` for the backend.
- Keep the SQLite database on a persistent Render disk, or migrate the auth store to managed PostgreSQL for multi-instance production deployment.

---

## Demo Flow

1. User signs up or logs in.
2. User scans a suspicious WhatsApp message, URL, QR image, or transcript.
3. BharatSHIELD displays a risk score and highlighted evidence.
4. User reads what was found, why it is dangerous, and what action to take.
5. If needed, user generates a complaint draft and opens the official cybercrime portal.
6. Emergency mode guides the user to call 1930 and preserve evidence.

---

## Future Scope

- Installable browser extension
- Android share-to-scan integration
- Live camera QR scanning
- Stronger domain reputation checks
- Real-time phishing page comparison
- Community scam reputation database
- PDF complaint generation with evidence snapshots
- Multi-language safety guidance

---

## Team

**Care Coders**

Built for hackathon demonstration with a focus on practical cyber safety, explainable AI, and user-first scam prevention.

