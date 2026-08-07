# BharatSHIELD

Protecting India's Digital Future.

BharatSHIELD detects UPI fraud, phishing SMS, WhatsApp scams, fake jobs, fake investments, risky links, QR payloads, and call transcripts.

## Features

- Hybrid scam scoring: rule engine plus optional Gemini analysis
- SMS, WhatsApp, email, job, investment, fake news, call transcript, URL, and QR modes
- Suspicious keyword highlighting
- URL technical checks for HTTPS, risky TLDs, brand lookalikes, hyphens, digits, and deep subdomains
- Hindi and English UI labels
- Local scam history and trend chart
- Browser speech recognition for call transcript capture
- QR scanning through the browser `BarcodeDetector` API when available
- Dark mode and responsive dashboard
- Report export through browser print/save as PDF

## Run Frontend

```powershell
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

## Run Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Optional Gemini support:

```powershell
$env:GEMINI_API_KEY="your_key_here"
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Without `GEMINI_API_KEY`, the app still works using the local rule engine.
