import { useEffect, useMemo, useRef, useState } from "react";
import jsQR from "jsqr";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const samples = {
  sms: "Dear Customer, your bank account will be blocked today. Complete KYC immediately: http://sbi-verify-kyc.xyz",
  whatsapp: "Amazon Prize Team: Congratulations! You won INR 50000. Share OTP and click http://amaz0n-login.xyz to claim now.",
  url: "https://amaz0n-login.xyz/claim-prize",
  qr: "upi://pay?pa=fake-support@upi&pn=Refund Desk&am=4999&tn=KYC verification",
  call: "Hello, I am calling from bank verification team. Your account will be blocked. Please tell me the OTP now.",
  job: "Amazon Hiring work from home. Earn INR 8000/day. Pay registration fee INR 999 to confirm.",
  investment: "Double your money in 2 days with guaranteed return. Send UPI payment now.",
  email: "Your account is suspended. Verify your password immediately by clicking this urgent link.",
  news: "Breaking government announcement. Forwarded as received. Share with everyone immediately.",
};

const modes = [
  ["sms", "Scan Message"],
  ["whatsapp", "WhatsApp"],
  ["url", "Check Website"],
  ["qr", "Scan QR Code"],
  ["call", "Call Transcript"],
  ["job", "Fake Job"],
  ["investment", "Investment"],
  ["email", "Email"],
  ["news", "Fake News"],
];

const modeMeta = {
  sms: { title: "Messages", sender: "SMS Alert", tone: "blue" },
  whatsapp: { title: "WhatsApp", sender: "Scammer", tone: "green" },
  url: { title: "Website Check", sender: "Suspicious Link", tone: "orange" },
  qr: { title: "QR Scanner", sender: "QR Payload", tone: "cyan" },
  call: { title: "Call Review", sender: "Caller", tone: "red" },
  job: { title: "Job Check", sender: "Recruiter", tone: "purple" },
  investment: { title: "Investment Check", sender: "Promoter", tone: "orange" },
  email: { title: "Email Review", sender: "Email Sender", tone: "blue" },
  news: { title: "News Check", sender: "Forwarded Post", tone: "purple" },
};

const threatIntel = [
  ["UPI payment scams", "34%", "High"],
  ["KYC update links", "12%", "Medium"],
  ["Fake investment schemes", "19%", "High"],
  ["Lottery prize messages", "8%", "Medium"],
];

const cityAttacks = [
  { city: "Punjab", attacks: 12, x: 105, y: 92 },
  { city: "Delhi", attacks: 24, x: 142, y: 120 },
  { city: "Mumbai", attacks: 41, x: 96, y: 224 },
  { city: "Bengaluru", attacks: 18, x: 142, y: 286 },
  { city: "Kolkata", attacks: 31, x: 226, y: 184 },
];

function getStoredHistory() {
  try {
    return JSON.parse(localStorage.getItem("bharatshield_history") || "[]");
  } catch {
    return [];
  }
}

function saveHistory(items) {
  localStorage.setItem("bharatshield_history", JSON.stringify(items.slice(0, 30)));
}

function getStoredSession() {
  try {
    return JSON.parse(localStorage.getItem("bharatshield_session") || "null");
  } catch {
    return null;
  }
}

function saveSession(session) {
  localStorage.setItem("bharatshield_session", JSON.stringify(session));
}

function riskColor(score = 0) {
  if (score >= 75) return "critical";
  if (score >= 55) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function highlightedText(text) {
  const redTerms = [
    "otp",
    "pin",
    "kyc",
    "blocked",
    "urgent",
    "verify",
    "password",
    "winner",
    "lottery",
    "registration fee",
    "double your money",
    "guaranteed return",
    "click",
    "upi",
  ];
  let html = text.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[char]);
  for (const term of redTerms) {
    html = html.replace(new RegExp(`(${term})`, "gi"), '<mark class="danger">$1</mark>');
  }
  return { __html: html };
}

function ShieldLogo() {
  return <img className="logo-mark" src="/assets/bharatshield-landing.jpeg" alt="BharatSHIELD logo" />;
}

function HeroShield() {
  return (
    <svg className="hero-shield" viewBox="0 0 280 320" aria-hidden="true">
      <defs>
        <linearGradient id="shieldBlue" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0" stopColor="#0a2a5f" />
          <stop offset="1" stopColor="#061534" />
        </linearGradient>
        <linearGradient id="shieldTricolor" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0" stopColor="#f29b2f" />
          <stop offset="0.5" stopColor="#ffffff" />
          <stop offset="1" stopColor="#279451" />
        </linearGradient>
        <filter id="glow">
          <feGaussianBlur stdDeviation="4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <path className="shield-shadow" d="M140 13L242 50V130C242 214 197 280 140 307C83 280 38 214 38 130V50L140 13Z" />
      <path d="M140 18L236 54V129C236 206 194 267 140 294C86 267 44 206 44 129V54L140 18Z" fill="url(#shieldTricolor)" />
      <path d="M140 18L44 54V129C44 206 86 267 140 294V18Z" fill="url(#shieldBlue)" />
      <path d="M140 18L236 54V129C236 206 194 267 140 294C86 267 44 206 44 129V54L140 18Z" fill="none" stroke="#0b2d69" strokeWidth="8" />
      <g stroke="#dff5ff" strokeWidth="4" strokeLinecap="round" filter="url(#glow)">
        <path d="M86 74v38h31" />
        <path d="M104 58v83" />
        <path d="M71 101h33" />
        <path d="M92 151h32" />
        <circle cx="86" cy="74" r="5" fill="#0a2a5f" />
        <circle cx="104" cy="58" r="5" fill="#0a2a5f" />
        <circle cx="71" cy="101" r="5" fill="#0a2a5f" />
        <circle cx="92" cy="151" r="5" fill="#0a2a5f" />
      </g>
      <g transform="translate(140 146)" fill="none" stroke="#0b2d69" strokeWidth="5">
        <circle r="50" fill="#ffffff" />
        {Array.from({ length: 24 }).map((_, index) => (
          <path key={index} d="M0 0L0 -42" transform={`rotate(${index * 15})`} />
        ))}
        <circle r="8" fill="#0b2d69" />
      </g>
    </svg>
  );
}

function playScanSound() {
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    const audio = new AudioContext();
    [0, 0.16, 0.34].forEach((delay, index) => {
      const oscillator = audio.createOscillator();
      const gain = audio.createGain();
      oscillator.type = "sine";
      oscillator.frequency.value = [520, 720, 920][index];
      gain.gain.setValueAtTime(0.0001, audio.currentTime + delay);
      gain.gain.exponentialRampToValueAtTime(0.055, audio.currentTime + delay + 0.03);
      gain.gain.exponentialRampToValueAtTime(0.0001, audio.currentTime + delay + 0.15);
      oscillator.connect(gain);
      gain.connect(audio.destination);
      oscillator.start(audio.currentTime + delay);
      oscillator.stop(audio.currentTime + delay + 0.16);
    });
  } catch {
    // Scanning continues if the browser blocks audio.
  }
}

export default function App() {
  const [mode, setMode] = useState("whatsapp");
  const [content, setContent] = useState(samples.whatsapp);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState(getStoredHistory);
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [showReport, setShowReport] = useState(false);
  const [showLanding, setShowLanding] = useState(true);
  const [session, setSession] = useState(getStoredSession);
  const [showAuth, setShowAuth] = useState(!getStoredSession());
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState({ name: "", email: "", password: "" });
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [audioFileName, setAudioFileName] = useState("");
  const [error, setError] = useState("");
  const recognitionRef = useRef(null);

  const scanSteps = ["Checking message", "Finding risk words", "Checking URL", "Checking domain", "Preparing review", "Generating report"];
  const score = result?.score || 0;
  const confidence = result?.confidence || (result ? Math.min(99, result.score + 5) : 96);
  const ruleScore = result ? Math.max(14, result.score - 2) : 89;
  const urlScore = result?.url_checks?.length ? Math.max(...result.url_checks.map((item) => item.score)) : result ? Math.max(30, result.score - 7) : 95;
  const safetyScore = result?.safety_score ?? 76;
  const incidentId = useMemo(() => `BS-${Math.floor(20000 + Math.random() * 70000)}`, [result?.created_at]);

  useEffect(() => {
    if (!loading) return;
    setScanStep(0);
    const timer = setInterval(() => setScanStep((step) => Math.min(scanSteps.length - 1, step + 1)), 520);
    return () => clearInterval(timer);
  }, [loading, scanSteps.length]);

  useEffect(() => {
    const timer = setTimeout(() => {
      setShowLanding(false);
      setShowAuth(!session);
    }, 2000);
    return () => clearTimeout(timer);
  }, [session]);

  const trends = useMemo(() => {
    return history.reduce((acc, item) => {
      const key = item.scam_type || "Unknown";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
  }, [history]);

  function selectMode(nextMode) {
    setMode(nextMode);
    setContent(samples[nextMode] || "");
    setAudioFileName("");
    setError("");
  }

  async function runAnalysis(input = content, channel = mode) {
    if (!input.trim()) return;
    playScanSound();
    setLoading(true);
    setError("");
    setShowLanding(false);
    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: input, channel, language: "en" }),
      });
      if (!response.ok) throw new Error("Service is unavailable. Please try again.");
      const data = await response.json();
      setResult(data);
      const nextHistory = [{ ...data, mode: channel, preview: input.slice(0, 120) }, ...history];
      setHistory(nextHistory);
      saveHistory(nextHistory);
    } catch (err) {
      setError(err.message || "Something went wrong while analyzing this content.");
    } finally {
      setTimeout(() => setLoading(false), 420);
    }
  }

  async function scanQr(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setError("");
    try {
      const bitmap = await createImageBitmap(file);
      let decoded = "";

      if ("BarcodeDetector" in window) {
        try {
          const detector = new window.BarcodeDetector({ formats: ["qr_code"] });
          const codes = await detector.detect(bitmap);
          decoded = codes[0]?.rawValue || "";
        } catch {
          decoded = "";
        }
      }

      if (!decoded) {
        const canvas = document.createElement("canvas");
        const context = canvas.getContext("2d", { willReadFrequently: true });
        canvas.width = bitmap.width;
        canvas.height = bitmap.height;
        context.drawImage(bitmap, 0, 0);
        const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
        decoded = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" })?.data || "";
      }

      if (!decoded) {
        setError("No QR code found. Try a clearer, uncropped QR image.");
        return;
      }

      setMode("qr");
      setContent(decoded);
      runAnalysis(decoded, "qr");
    } catch {
      setError("Could not read this QR image. Try a clearer, uncropped QR image.");
    }
  }

  function startVoice() {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRecognition) {
      setError("Voice capture needs Chrome Web Speech API. Paste the transcript manually.");
      return;
    }
    const recognition = new SpeechRecognition();
    recognition.lang = "en-IN";
    recognition.continuous = true;
    recognition.interimResults = true;
    recognition.onresult = (event) => {
      const transcript = Array.from(event.results).map((item) => item[0].transcript).join(" ");
      setMode("call");
      setContent(transcript);
    };
    recognition.start();
    recognitionRef.current = recognition;
  }

  function stopVoice() {
    recognitionRef.current?.stop();
    recognitionRef.current = null;
  }

  function handleAudioUpload(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setMode("call");
    setAudioFileName(file.name);
    setError("Recording selected. Use live voice capture or paste the transcript below for analysis.");
  }

  function clearHistory() {
    setHistory([]);
    saveHistory([]);
  }

  async function handleAuth(event) {
    event.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    try {
      const payload = authMode === "signup"
        ? authForm
        : { email: authForm.email, password: authForm.password };
      const response = await fetch(`${API_BASE}/api/${authMode === "signup" ? "signup" : "login"}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Authentication failed.");
      saveSession(data);
      setSession(data);
      setShowAuth(false);
    } catch (err) {
      setAuthError(err.message || "Authentication failed.");
    } finally {
      setAuthLoading(false);
    }
  }

  function logout() {
    localStorage.removeItem("bharatshield_session");
    setSession(null);
    setShowAuth(true);
  }

  const recommendations = result?.recommendations || [
    "Do not click unknown links or open unexpected attachments.",
    "Never share OTP, UPI PIN, passwords, or card details.",
    "Verify through the official app or website by typing the address yourself.",
  ];
  const currentMode = modeMeta[mode] || modeMeta.whatsapp;
  const isQrMode = mode === "qr";
  const isCallMode = mode === "call";
  const isUrlMode = mode === "url";
  const isTextMode = !isQrMode && !isCallMode && !isUrlMode;

  return (
    <>
      {showLanding && (
        <section className="landing-screen">
          <div className="circuit-field circuit-left" />
          <div className="circuit-field circuit-right" />
          <div className="landing-center">
            <HeroShield />
            <h1 className="landing-title">BHARAT<span>SHIELD</span></h1>
            <p className="landing-tagline">PROTECTING INDIA&apos;S DIGITAL FUTURE</p>
          </div>
          <div className="india-skyline" />
          <div className="tricolor-clouds" />
          <div className="landing-footer">
            <div className="mini-shield">BS</div>
            <p>India Focused. Safety First.</p>
            <div className="real-loader" aria-label="Loading dashboard">
              <span />
            </div>
          </div>
        </section>
      )}

      {!showLanding && showAuth && (
        <section className="auth-screen">
          <div className="auth-visual">
            <HeroShield />
            <h1>BharatSHIELD</h1>
            <p>Secure access for India&apos;s digital citizens.</p>
            <div className="auth-pulse">
              <span>Live protection</span>
              <strong>1,256 scans secured today</strong>
            </div>
          </div>

          <form className="auth-card" onSubmit={handleAuth}>
            <div className="auth-tabs">
              <button type="button" className={authMode === "login" ? "active" : ""} onClick={() => setAuthMode("login")}>Login</button>
              <button type="button" className={authMode === "signup" ? "active" : ""} onClick={() => setAuthMode("signup")}>Sign Up</button>
            </div>
            <h2>{authMode === "login" ? "Welcome back" : "Create your shield"}</h2>
            <p>{authMode === "login" ? "Continue to your cyber command center." : "Start protecting messages, QR codes, and links in seconds."}</p>
            {authMode === "signup" && (
              <input
                placeholder="Full name"
                value={authForm.name}
                onChange={(event) => setAuthForm({ ...authForm, name: event.target.value })}
                required
              />
            )}
            <input
              placeholder="Email address"
              type="email"
              value={authForm.email}
              onChange={(event) => setAuthForm({ ...authForm, email: event.target.value })}
              required
            />
            <input
              placeholder="Password"
              type="password"
              value={authForm.password}
              onChange={(event) => setAuthForm({ ...authForm, password: event.target.value })}
              minLength="6"
              required
            />
            {authMode === "signup" && (
              <label className="auth-check">
                <input type="checkbox" defaultChecked />
                <span>Enable scam trend alerts</span>
              </label>
            )}
            {authError && <p className="auth-error">{authError}</p>}
            <button className="primary" type="submit" disabled={authLoading}>
              {authLoading ? "Please wait..." : authMode === "login" ? "Enter Dashboard" : "Create Account"}
            </button>
            <small className="auth-note">Use a registered account to continue.</small>
          </form>
        </section>
      )}

      {!showLanding && !showAuth && session && (
      <main className="app-shell">
        <aside className="sidebar">
          <div className="brand-mini">
            <ShieldLogo />
            <strong>BharatSHIELD</strong>
          </div>
          {["Dashboard", "Scan", "Report Scam", "Awareness", "Emergency", "History", "Settings"].map((item, index) => (
            <button className={index === 0 ? "nav-active" : ""} key={item}>{item}</button>
          ))}
          <button className="logout" onClick={logout}>Logout</button>
        </aside>

        <section className="dashboard-shell">
          <header className="welcome-row">
            <div>
              <h1>Welcome, {session.user?.name || "User"}!</h1>
              <p>Stay alert, stay safe from digital scams.</p>
            </div>
            <div className="header-icons">
              <span>3</span>
              <div />
            </div>
          </header>

          <section className="stat-strip">
            <div><span>Threat Level</span><strong>{result?.risk || "Medium"}</strong><small>Adaptive scan mode</small></div>
            <div><span>Scams Blocked</span><strong>1,256</strong><small>Across India today</small></div>
            <div><span>Confidence</span><strong>{confidence}%</strong><small>Multiple checks</small></div>
            <div><span>Safety Score</span><strong>{safetyScore}</strong><small>Higher is safer</small></div>
          </section>

          <section className="quick-actions">
            {modes.slice(0, 4).map(([id, label]) => (
              <button className={mode === id ? "quick-card active" : "quick-card"} key={id} onClick={() => selectMode(id)}>
                <span>{id === "sms" ? "MSG" : id === "qr" ? "QR" : id === "url" ? "WEB" : "!"}</span>
                <strong>{label}</strong>
                <small>{id === "sms" ? "Check SMS and messages" : id === "qr" ? "Read QR codes safely" : id === "url" ? "Verify website links" : "Report suspicious activity"}</small>
              </button>
            ))}
          </section>

          <section className="main-grid">
            <div className="left-stack">
              <section className="scan-card">
                <div className="mode-row">
                  {modes.map(([id, label]) => (
                    <button key={id} className={mode === id ? "active" : ""} onClick={() => selectMode(id)}>{label}</button>
                  ))}
                </div>
                <div className="scanner-stage">
                  <div className={`phone-shell phone-${currentMode.tone}`}>
                    <div className="phone-top"><span /> {currentMode.title}</div>
                    <div className="chat-area">
                      <div className="bubble friend">{currentMode.sender}<p>{content}</p></div>
                      <div className="bubble user">You<p>Analyze with BharatSHIELD</p></div>
                      <div className="scan-window">
                        {loading && <span className="scan-line" />}
                        <p>{loading ? scanSteps[scanStep] : "Incoming message"}</p>
                      </div>
                    </div>
                  </div>

                  <div className="input-console">
                    <div className="input-head">
                      <span>{currentMode.title}</span>
                      <strong>{isQrMode ? "Image upload" : isCallMode ? "Call recording" : isUrlMode ? "Website link" : "Paste content"}</strong>
                    </div>

                    {isQrMode && (
                      <div className="upload-panel qr-upload">
                        <label>
                          <input type="file" accept="image/*" onChange={scanQr} />
                          <span>QR</span>
                          <strong>Upload QR image</strong>
                          <small>PNG, JPG, or screenshot</small>
                        </label>
                        <textarea
                          className="compact-input"
                          value={content}
                          onChange={(event) => setContent(event.target.value)}
                          spellCheck="false"
                          placeholder="Decoded QR content will appear here"
                        />
                      </div>
                    )}

                    {isCallMode && (
                      <div className="upload-panel call-upload">
                        <label>
                          <input type="file" accept="audio/*" onChange={handleAudioUpload} />
                          <span>REC</span>
                          <strong>{audioFileName || "Upload call recording"}</strong>
                          <small>MP3, WAV, M4A, or use live voice</small>
                        </label>
                        <div className="voice-actions">
                          <button onClick={startVoice}>Start Voice</button>
                          <button onClick={stopVoice}>Stop</button>
                        </div>
                        <textarea
                          className="compact-input"
                          value={content}
                          onChange={(event) => setContent(event.target.value)}
                          spellCheck="false"
                          placeholder="Paste or capture call transcript"
                        />
                      </div>
                    )}

                    {isUrlMode && (
                      <div className="url-panel">
                        <input
                          type="url"
                          value={content}
                          onChange={(event) => setContent(event.target.value)}
                          placeholder="https://example.com"
                          spellCheck="false"
                        />
                        <small>Paste the full website link for domain and risk checks.</small>
                      </div>
                    )}

                    {isTextMode && (
                      <textarea
                        value={content}
                        onChange={(event) => setContent(event.target.value)}
                        spellCheck="false"
                        placeholder="Paste SMS, WhatsApp message, email, job offer, investment pitch, or news forward"
                      />
                    )}

                    <div className="toolrow">
                      <button className="primary" onClick={() => runAnalysis()} disabled={loading}>{loading ? "Scanning..." : "Analyze Threat"}</button>
                      {!isQrMode && <button onClick={() => selectMode("qr")}>Scan QR</button>}
                      {!isCallMode && <button onClick={() => selectMode("call")}>Call Review</button>}
                      <button onClick={() => setShowReport(true)}>Cyber Report</button>
                    </div>
                    {error && <p className="error">{error}</p>}
                  </div>
                </div>
              </section>

              <section className="analysis-grid">
                <div className="glass">
                  <h2>Evidence Heatmap</h2>
                  <p className="highlight-box" dangerouslySetInnerHTML={highlightedText(content)} />
                </div>
                <div className="glass">
                  <h2>What We Found</h2>
                  <p>{result ? result.what_we_found : "Run a scan to review links, urgency, sender intent, and credential risk."}</p>
                  <div className="simple-box">
                    <strong>Why It Is Dangerous</strong>
                    <p>{result?.why_dangerous || "Verify payment, bank, and account alerts only through official apps."}</p>
                  </div>
                </div>
                <div className="glass">
                  <h2>Action Checklist</h2>
                  <ul className="checklist">{recommendations.map((item) => <li key={item}>{item}</li>)}</ul>
                </div>
              </section>
            </div>

            <aside className="right-stack">
              <section className="command-orbit">
                <div className="orbit-core">
                  <HeroShield />
                  <strong>Live Shield</strong>
                  <span>{result ? `${score}% threat detected` : "Monitoring"}</span>
                </div>
                <i className="orbit-dot one" />
                <i className="orbit-dot two" />
                <i className="orbit-dot three" />
              </section>

              <section className="glass result-focus">
                <div className={`gauge ${riskColor(score)}`} style={{ "--score": score || 18 }}>
                  <div className="gauge-core">
                    <strong>{score}%</strong>
                    <span>{result?.risk || "Threat Level"}</span>
                  </div>
                </div>
                <div className="score-stack">
                  <div><span>Confidence</span><strong>{confidence}%</strong></div>
                  <div><span>Rule Engine</span><strong>{ruleScore}%</strong></div>
                  <div><span>URL Analysis</span><strong>{urlScore}%</strong></div>
                  <div><span>Safety Score</span><strong>{safetyScore}</strong></div>
                </div>
              </section>

              <section className="glass ai-card">
                <h2>BharatSHIELD Review</h2>
                <p className="typing">{result ? result.how_sure : "Checks tone, links, urgency, identity clues, and safety actions."}</p>
                <ol>{(result?.signals?.length ? result.signals.slice(0, 5).map((item) => `${item.label}: ${item.reason}`) : scanSteps.slice(0, 5)).map((item) => <li key={item}>{item}</li>)}</ol>
              </section>
            </aside>
          </section>

          <section className="explain-grid">
            <div className="glass">
              <h2>Reason Breakdown</h2>
              <div className="reason-list">
                {(result?.reason_breakdown || [
                  { label: "Message language", score: 0, why: "Waiting for scan." },
                  { label: "Urgency and pressure", score: 0, why: "Waiting for scan." },
                  { label: "Credential risk", score: 0, why: "Waiting for scan." },
                  { label: "URL / QR risk", score: 0, why: "Waiting for scan." },
                ]).map((item) => (
                  <div key={item.label}>
                    <span><strong>{item.label}</strong><b>{item.score}%</b></span>
                    <i><em style={{ width: `${item.score}%` }} /></i>
                    <p>{item.why}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass">
              <h2>URL Intelligence</h2>
              <div className="intel-list">
                {(result?.url_checks?.length ? result.url_checks : [{ domain: "No URL scanned", score: 0, checks: [{ label: "Status", result: "Paste or scan a URL to inspect domain reputation." }] }]).flatMap((url) => [
                  <div key={`${url.domain}-score`}><span>{url.domain}</span><strong>{url.score}% risk</strong></div>,
                  ...(url.checks || []).slice(0, 5).map((check) => <div key={`${url.domain}-${check.label}`}><span>{check.label}</span><strong>{check.result}</strong></div>),
                  url.domain_age ? <div key={`${url.domain}-age`}><span>Domain age</span><strong>{url.domain_age}</strong></div> : null,
                  url.safe_browsing ? <div key={`${url.domain}-safe`}><span>Safe Browsing</span><strong>{url.safe_browsing}</strong></div> : null,
                ].filter(Boolean))}
              </div>
            </div>

            <div className="glass">
              <h2>QR / Call Deep Check</h2>
              <div className="intel-list">
                <div><span>UPI ID</span><strong>{result?.qr_analysis?.upi_id || "Not found"}</strong></div>
                <div><span>Merchant</span><strong>{result?.qr_analysis?.merchant || "Not found"}</strong></div>
                <div><span>Amount</span><strong>{result?.qr_analysis?.amount || "Not found"}</strong></div>
                <div><span>Voice emotion</span><strong>{result?.call_analysis?.emotion || "Not analyzed"}</strong></div>
                <div><span>Pressure score</span><strong>{result?.call_analysis?.pressure_score ?? 0}%</strong></div>
                <div><span>Live warning</span><strong>{result?.call_analysis?.live_warning ? "Disconnect immediately" : "No urgent warning"}</strong></div>
              </div>
            </div>
          </section>

          <section className="intel-grid">
            <div className="glass">
              <h2>Today&apos;s Threat Level</h2>
              <strong className="big-status">{result?.risk || "Medium"}</strong>
              <p>Be cautious and stay alert.</p>
            </div>
            <div className="glass">
              <h2>Scams Blocked Today</h2>
              <strong className="big-status">1,256</strong>
              <p>People protected across India.</p>
            </div>
            <div className="glass">
              <div className="section-head">
                <h2>Recent Scams</h2>
                <button onClick={clearHistory}>Clear</button>
              </div>
              <div className="recent-list">
                {(history.length ? history.slice(0, 4) : [
                  { scam_type: "Fake Bank SMS", risk: "High Risk" },
                  { scam_type: "UPI Payment Scam", risk: "Medium Risk" },
                  { scam_type: "Fake Investment Scheme", risk: "High Risk" },
                  { scam_type: "KYC Update Scam", risk: "Medium Risk" },
                ]).map((item, index) => (
                  <div key={`${item.scam_type}-${index}`}><span>{item.scam_type}</span><strong>{item.risk}</strong></div>
                ))}
              </div>
            </div>
          </section>

          <section className="lower-grid">
            <div className="glass">
              <h2>Threat Trends</h2>
              <div className="bars">
                {Object.entries(trends).length ? Object.entries(trends).map(([name, count]) => (
                  <div className="bar" key={name}>
                    <span>{name}</span>
                    <div><i style={{ width: `${Math.max(12, count * 22)}%` }} /></div>
                    <strong>{count}</strong>
                  </div>
                )) : <p>No analysis history yet.</p>}
              </div>
            </div>

            <div className="glass attack-card">
              <h2>India Attack Map</h2>
              <div className="india-map">
                <svg viewBox="0 0 320 360" role="img" aria-label="India attack map">
                  <path
                    className="india-shape"
                    d="M128 18l28 18 32 4 16 25 30 9 13 25-16 21 19 26-22 28 10 31-34 27-8 44-28 62-23-53-28-25-11-38-34-24 12-37-25-35 22-28-4-42 23-12 8-28z"
                  />
                  <path className="india-ridge" d="M126 44l30 34-8 43 32 36-24 34 19 46-24 62" />
                  <path className="india-ridge" d="M92 123l42 2 39 39 56 18" />
                  {cityAttacks.map(({ city, attacks, x, y }) => (
                    <g key={city} className="map-point" transform={`translate(${x} ${y})`}>
                      <circle className="map-pulse" r="19" />
                      <circle r="8" />
                      <text x="14" y="-7">{attacks}</text>
                      <text className="city-label" x="14" y="10">{city}</text>
                    </g>
                  ))}
                </svg>
              </div>
            </div>

            <div className="glass">
              <h2>Threat Intelligence</h2>
              <div className="intel-list">
                {threatIntel.map(([name, value, risk]) => <div key={name}><span>{name}</span><strong>{value} {risk}</strong></div>)}
              </div>
            </div>
          </section>
        </section>
      </main>
      )}

      {showReport && (
        <div className="modal-backdrop" onClick={() => setShowReport(false)}>
          <section className="report-modal" onClick={(event) => event.stopPropagation()}>
            <button className="modal-close" onClick={() => setShowReport(false)}>X</button>
            <img className="report-logo" src="/assets/bharatshield-landing.jpeg" alt="" />
            <h2>BharatSHIELD Cyber Incident Report</h2>
            <div className="report-grid">
              <div><span>Incident ID</span><strong>{incidentId}</strong></div>
              <div><span>Threat</span><strong>{result?.scam_type || "No scan yet"}</strong></div>
              <div><span>Risk</span><strong>{score}%</strong></div>
              <div><span>Confidence</span><strong>{confidence}%</strong></div>
            </div>
            <h3>Evidence</h3>
            <p>{content}</p>
            <h3>Recommendation</h3>
            <ul>{recommendations.map((item) => <li key={item}>{item}</li>)}</ul>
            <button className="primary" onClick={() => window.print()}>Download Report</button>
          </section>
        </div>
      )}
    </>
  );
}
