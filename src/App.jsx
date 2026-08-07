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

const navItems = ["Dashboard", "Scan", "Guardian", "Report Scam", "Awareness", "Emergency", "Live Scam Alerts", "History", "Settings"];

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
  ["Money saved", "INR 11,158 Cr", "I4C till Jun 2026"],
  ["Complaints helped", "32.80 lakh", "CFCFRMS"],
  ["Financial fraud complaints", "53.87 lakh", "FY 2023-24 to 2025-26"],
  ["Helpline", "1930", "Active nationwide"],
];

const stateCaseData = [
  { state: "Delhi", cases: 125, x: 143, y: 106, level: "critical" },
  { state: "UP", cases: 82, x: 172, y: 145, level: "high" },
  { state: "MH", cases: 110, x: 116, y: 220, level: "critical" },
  { state: "TN", cases: 28, x: 156, y: 311, level: "safe" },
  { state: "TS", cases: 96, x: 164, y: 252, level: "critical" },
  { state: "KA", cases: 74, x: 133, y: 286, level: "high" },
];

const reportTypes = ["Phishing", "QR Scam", "WhatsApp", "Fake Call", "Fake Job", "UPI Fraud"];
const recentActivity = ["QR Code Safe", "WhatsApp Scam Detected", "URL Safe", "Fake News Detected"];
const scamLibrary = [
  {
    name: "Digital Arrest",
    example: "Caller claims to be police, CBI, customs, or court and asks you to stay on video call.",
    signs: ["Threats of arrest", "Video call pressure", "Demand for secrecy", "Money transfer for verification"],
    actions: ["Disconnect the call", "Do not transfer money", "Call 1930 if money was lost", "Save phone number and screenshots"],
  },
  {
    name: "UPI Refund Scam",
    example: "Fraudster sends a collect request or QR code and says approving it will give you a refund.",
    signs: ["Approve request to receive money", "Unknown UPI ID", "Urgent refund message", "Screen-sharing request"],
    actions: ["Never enter UPI PIN to receive money", "Reject collect requests", "Block/report the UPI ID", "Check transaction status inside your bank app"],
  },
  {
    name: "KYC Update Scam",
    example: "SMS says your bank/wallet will be blocked unless you click a link and verify KYC.",
    signs: ["Account block warning", "Shortened or lookalike URL", "OTP/password request", "Unknown sender ID"],
    actions: ["Open official app yourself", "Do not click message links", "Never share OTP/PIN/password", "Report suspicious URL on cybercrime portal"],
  },
  {
    name: "Fake Job Scam",
    example: "High salary work-from-home offer asks for registration, kit, or training fee.",
    signs: ["Unreal salary", "Joining fee", "No official email domain", "Immediate selection without interview"],
    actions: ["Do not pay for a job", "Verify company career page", "Check recruiter identity", "Keep payment/chat evidence"],
  },
  {
    name: "Parcel Scam",
    example: "Caller claims your parcel contains illegal items or needs a payment to release it.",
    signs: ["Customs/police threat", "Courier payment link", "Personal document demand", "Unknown tracking number"],
    actions: ["Check official courier website", "Do not share ID over chat", "Do not install remote apps", "Call local police for threats"],
  },
  {
    name: "Investment Scam",
    example: "Message promises guaranteed returns, doubled money, or daily profit after UPI deposit.",
    signs: ["Guaranteed profit", "Telegram/WhatsApp group pressure", "Fake screenshots", "Withdrawal fee demand"],
    actions: ["Avoid unrealistic returns", "Verify SEBI/RBI registration", "Do not add more money to withdraw", "Report the account and payment trail"],
  },
];
const liveAlerts = [
  ["Fake parcel scams", "High", "Metro cities", "Verify courier tracking only on official websites."],
  ["Digital arrest calls", "Critical", "Pan India", "Cut the call and dial 1930 if money was demanded."],
  ["UPI refund fraud", "High", "UPI users", "Never approve collect requests for refunds."],
  ["Fake job offers", "Medium", "Students", "No real employer asks joining fee on UPI."],
];

const guardianSignals = [
  ["URL Score", "91%", "Lookalike SBI login path"],
  ["SSL", "Valid", "Certificate present, still not enough"],
  ["Brand Match", "94%", "Visual and domain resemble SBI"],
  ["Redirect", "Hidden", "Login page forwards to external form"],
  ["Intent", "OTP Theft", "Page requests mobile OTP"],
];

const guardianTimeline = ["Opened URL", "Redirect detected", "Fake login form found", "OTP field detected", "High risk warning shown"];
const platformRoadmap = [
  ["Browser Extension", "Real-time website overlay, right-click scan, copy detection"],
  ["Android Share", "WhatsApp, SMS, Email, Telegram share-to-scan flow"],
  ["QR Camera", "Live QR sandbox before opening destination"],
  ["Community Reputation", "Reported count, last seen, duplicate scam DNA"],
];

const trustChecks = ["HTTPS Secured", "Data Encrypted", "API Protected", "Privacy Protected", "AI Explainability", "Open Source Ready"];
const deniedPermissions = ["Contacts", "Photos", "Location", "OTP", "Passwords", "Background microphone"];
const autoDeleteOptions = ["30 Minutes", "1 Hour", "24 Hours", "Never"];
const allowedEvidence = [".jpg", ".jpeg", ".png", ".pdf", ".txt", ".mp3", ".wav", ".m4a"];

function isAllowedEvidence(fileName) {
  const lower = fileName.toLowerCase();
  return allowedEvidence.some((ext) => lower.endsWith(ext));
}

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

function getStoredUsers() {
  try {
    return JSON.parse(localStorage.getItem("bharatshield_users") || "[]");
  } catch {
    return [];
  }
}

function saveStoredUsers(users) {
  localStorage.setItem("bharatshield_users", JSON.stringify(users));
}

function createLocalSession(user) {
  return {
    token: `local-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    user: { id: user.id, name: user.name, email: user.email },
  };
}

function localAuth(mode, form) {
  const users = getStoredUsers();
  const email = form.email.trim().toLowerCase();
  if (mode === "signup") {
    if (users.some((user) => user.email === email)) {
      throw new Error("This email is already signed up. Please login.");
    }
    const user = {
      id: Date.now(),
      name: form.name.trim() || "User",
      email,
      password: form.password,
    };
    saveStoredUsers([...users, user]);
    return createLocalSession(user);
  }

  const user = users.find((item) => item.email === email && item.password === form.password);
  if (!user) throw new Error("Account not found. Please sign up first.");
  return createLocalSession(user);
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

function clientAnalysis(text, channel) {
  const lowered = text.toLowerCase();
  const checks = [
    ["otp", 22, "OTP request"],
    ["pin", 20, "PIN request"],
    ["password", 20, "Password request"],
    ["kyc", 18, "KYC pressure"],
    ["blocked", 18, "Account block threat"],
    ["urgent", 14, "Urgent language"],
    ["congratulations", 12, "Prize bait"],
    ["winner", 12, "Lottery claim"],
    ["registration fee", 18, "Advance fee"],
    ["double your money", 24, "Unrealistic return"],
    ["http", 18, "External link"],
  ];
  const hits = checks.filter(([term]) => lowered.includes(term));
  const score = Math.min(96, 12 + hits.reduce((sum, [, weight]) => sum + weight, 0) + (channel === "qr" || channel === "url" ? 8 : 0));
  const scamType = lowered.includes("job") || lowered.includes("hiring") ? "Fake Job" : lowered.includes("investment") || lowered.includes("double your money") ? "Investment Scam" : lowered.includes("http") || channel === "url" ? "Phishing" : "Suspicious Message";
  const signals = hits.map(([term, , label]) => ({ label, reason: `${term} found in the content` }));
  return {
    score,
    risk: score >= 75 ? "Critical" : score >= 55 ? "High" : score >= 30 ? "Medium" : "Low",
    scam_type: scamType,
    confidence: Math.min(98, score + 4),
    rule_score: Math.max(20, score - 2),
    url_score: channel === "url" || lowered.includes("http") ? Math.min(95, score + 5) : 0,
    safety_score: Math.max(4, 100 - score),
    signals,
    recommendations: [
      "Do not click links or open attachments from this message.",
      "Never share OTP, UPI PIN, passwords, or card details.",
      "Verify through the official app or website by typing the address yourself.",
    ],
    reason_breakdown: [
      { label: "Message language", score: Math.min(90, hits.length * 16), why: hits.length ? "Risk words found in the content." : "No major risk words found." },
      { label: "Urgency and pressure", score: lowered.includes("urgent") || lowered.includes("blocked") ? 82 : 16, why: "Pressure language is reviewed." },
      { label: "Credential risk", score: lowered.includes("otp") || lowered.includes("pin") || lowered.includes("password") ? 92 : 12, why: "Checks for OTP, PIN, and password requests." },
      { label: "URL / QR risk", score: lowered.includes("http") || channel === "qr" || channel === "url" ? 84 : 8, why: "Links and QR payloads are reviewed." },
    ],
    url_checks: lowered.includes("http") || channel === "url" ? [{ domain: text.replace(/^https?:\/\//, "").split(/[/?#]/)[0] || "Link", score: Math.min(95, score + 5), checks: [{ label: "Status", result: "Review carefully" }] }] : [],
    qr_analysis: { upi_id: lowered.includes("upi") ? "Detected in payload" : "Not found", merchant: "Not found", amount: "Not found" },
    call_analysis: { emotion: lowered.includes("blocked") ? "Pressure detected" : "Not analyzed", pressure_score: lowered.includes("urgent") || lowered.includes("blocked") ? 82 : 18, live_warning: score >= 70 },
    what_we_found: hits.length ? `Found ${hits.length} risk signals in this content.` : "No major scam signal found in this content.",
    why_dangerous: score >= 55 ? "This content may push the user toward a risky action such as clicking a link or sharing private details." : "The content does not show strong scam indicators, but verify before acting.",
    how_sure: `${Math.min(98, score + 4)}% confidence based on visible content checks.`,
  };
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
  const [autoScan, setAutoScan] = useState(false);
  const [activeSection, setActiveSection] = useState("Dashboard");
  const [reportType, setReportType] = useState("UPI Fraud");
  const [evidenceFile, setEvidenceFile] = useState("");
  const [autoDelete, setAutoDelete] = useState("1 Hour");
  const [notificationsOn, setNotificationsOn] = useState(true);
  const [privacyMode, setPrivacyMode] = useState(true);
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
      const fallback = clientAnalysis(input, channel);
      setResult(fallback);
      const nextHistory = [{ ...fallback, mode: channel, preview: input.slice(0, 120) }, ...history];
      setHistory(nextHistory);
      saveHistory(nextHistory);
      setError("");
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
      setError(autoScan ? "" : "QR decoded. Review the content, then click Analyze QR.");
      if (autoScan) runAnalysis(decoded, "qr");
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
    if (!isAllowedEvidence(file.name)) {
      setError("Unsupported file type. Upload jpg, png, pdf, txt, mp3, wav, or m4a only.");
      return;
    }
    setMode("call");
    setAudioFileName(file.name);
    setError("Recording selected. Use live voice capture or paste the transcript below for analysis.");
  }

  function handleEvidenceUpload(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (!isAllowedEvidence(file.name)) {
      setEvidenceFile("");
      setError("Blocked unsafe file type. Allowed: jpg, png, pdf, txt, mp3, wav, m4a.");
      return;
    }
    setEvidenceFile(file.name);
    setError("Evidence selected. File will be used only for this report draft.");
  }

  function clearHistory() {
    setHistory([]);
    saveHistory([]);
  }

  function downloadComplaint() {
    const text = [
      "BharatSHIELD Complaint Draft",
      `Report Type: ${reportType}`,
      `Risk: ${result?.risk || "Pending scan"}`,
      `Score: ${score}%`,
      `Summary: ${complaintSummary}`,
      "Recommended Actions:",
      ...recommendations.map((item) => `- ${item}`),
    ].join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `bharatshield-complaint-${Date.now()}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function openCyberPortal() {
    window.open("https://cybercrime.gov.in", "_blank", "noopener,noreferrer");
  }

  async function handleAuth(event) {
    event.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    const payload = authMode === "signup"
      ? authForm
      : { email: authForm.email, password: authForm.password };
    try {
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
      try {
        const localSession = localAuth(authMode, authForm);
        saveSession(localSession);
        setSession(localSession);
        setShowAuth(false);
      } catch (localErr) {
        setAuthError(localErr.message || err.message || "Authentication failed.");
      }
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
  const analyzeLabel = isQrMode ? "Analyze QR" : isCallMode ? "Analyze Call" : isUrlMode ? "Analyze Website" : "Analyze Threat";
  const complaintSummary = result ? `${result.scam_type} suspected with ${score}% risk. Evidence: ${content.slice(0, 180)}` : "Select a report type and add evidence to prepare a complaint summary.";

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
          {navItems.map((item) => (
            <button
              className={activeSection === item ? "nav-active" : ""}
              key={item}
              type="button"
              onClick={() => {
                setActiveSection(item);
                window.scrollTo({ top: 0, behavior: "smooth" });
              }}
            >
              {item}
            </button>
          ))}
          <button className="logout" onClick={logout}>Logout</button>
        </aside>

        <section className="dashboard-shell">
          <header className="welcome-row">
            <div>
              <h1>{activeSection === "Dashboard" ? `Welcome, ${session.user?.name || "User"}!` : activeSection}</h1>
              <p>{activeSection === "Dashboard" ? "Stay alert, stay safe from digital scams." : "BharatSHIELD digital safety workspace."}</p>
            </div>
            <div className="header-icons">
              <button type="button">3 alerts</button>
              <button type="button">{(session.user?.name || "User").slice(0, 1).toUpperCase()}</button>
            </div>
          </header>

          <section className={activeSection === "Dashboard" ? "stat-strip" : "stat-strip section-hidden"}>
            <div><span>Safety Score</span><strong>{safetyScore}</strong><small>Higher is safer</small></div>
            <div><span>I4C Protected</span><strong>INR 11,158 Cr</strong><small>Till Jun 2026</small></div>
            <div><span>Weekly Risk Trend</span><strong>{score >= 70 ? "Rising" : "Stable"}</strong><small>Based on scan history</small></div>
            <div><span>Latest Scam Alert</span><strong>Digital Arrest</strong><small>2026 I4C priority</small></div>
          </section>

          <section className={activeSection === "Dashboard" ? "activity-strip" : "activity-strip section-hidden"}>
            {recentActivity.map((item, index) => (
              <div key={item} className={index % 2 ? "activity-warn" : "activity-safe"}>{item}</div>
            ))}
          </section>

          <section className={activeSection === "Dashboard" ? "trust-strip" : "trust-strip section-hidden"}>
            <div className="glass trust-card">
              <div>
                <h2>Trust Center</h2>
                <p>Privacy-first scanning with explainable results and controlled permissions.</p>
              </div>
              <div className="trust-list">
                {trustChecks.map((item) => <span key={item}>{item}</span>)}
              </div>
            </div>
          </section>

          <section className={activeSection === "Dashboard" ? "quick-actions" : "quick-actions section-hidden"}>
            {modes.slice(0, 4).map(([id, label]) => (
              <button className={mode === id ? "quick-card active" : "quick-card"} key={id} onClick={() => selectMode(id)}>
                <span>{id === "sms" ? "MSG" : id === "qr" ? "QR" : id === "url" ? "WEB" : "!"}</span>
                <strong>{label}</strong>
                <small>{id === "sms" ? "Check SMS and messages" : id === "qr" ? "Read QR codes safely" : id === "url" ? "Verify website links" : "Report suspicious activity"}</small>
              </button>
            ))}
          </section>

          <section className={activeSection === "Scan" ? "main-grid" : "main-grid section-hidden"}>
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
                      <label className="scan-permission">
                        <input type="checkbox" checked={autoScan} onChange={(event) => setAutoScan(event.target.checked)} />
                        <strong>{autoScan ? "Auto scan on" : "Manual scan"}</strong>
                      </label>
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
                      <button className="primary" onClick={() => runAnalysis()} disabled={loading}>{loading ? "Scanning..." : analyzeLabel}</button>
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
                <div className={`safety-seal ${riskColor(score)}`}>{score >= 75 ? "Dangerous" : score >= 45 ? "Suspicious" : "Safe"} | Verified by BharatSHIELD</div>
                <ol>{(result?.signals?.length ? result.signals.slice(0, 5).map((item) => `${item.label}: ${item.reason}`) : scanSteps.slice(0, 5)).map((item) => <li key={item}>{item}</li>)}</ol>
              </section>
            </aside>
          </section>

          <section className={activeSection === "Scan" ? "explain-grid" : "explain-grid section-hidden"}>
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

          <section className={activeSection === "Dashboard" ? "intel-grid" : "intel-grid section-hidden"}>
            <div className="glass">
              <h2>Today&apos;s Threat Level</h2>
              <strong className="big-status">{result?.risk || "Medium"}</strong>
              <p>Be cautious and stay alert.</p>
            </div>
            <div className="glass">
              <h2>Financial Fraud Shield</h2>
              <strong className="big-status">32.80L</strong>
              <p>CFCFRMS complaints helped till Jun 2026.</p>
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

          <section className={activeSection === "Dashboard" ? "lower-grid" : "lower-grid section-hidden"}>
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
              <h2>India Heat Map</h2>
              <div className="india-map">
                <svg viewBox="0 0 320 360" role="img" aria-label="India scam alert heat map">
                  <path
                    className="india-shape"
                    d="M132 15l27 7 17 13 33 4 10 25 34 14 14 28-17 23 23 34-22 26 20 35-19 28 6 42-32 12-14 35-42-11-24-37-27-11-18-34-31-16 14-45-25-34 27-35-6-50 34-18 9-36z"
                  />
                  <path className="state-fill s1" d="M116 56l35-34 25 13 33 4 10 25-45 22-38-8z" />
                  <path className="state-fill s2" d="M87 118l49-40 38 8 20 38-34 33-54-2z" />
                  <path className="state-fill s3" d="M194 124l56-18 23 57-22 26-61-16-30-16z" />
                  <path className="state-fill s4" d="M84 187l76-30 30 16-34 49-41 10-56-44z" />
                  <path className="state-fill s5" d="M156 222l34-49 61 16 20 35-47 28-39 3z" />
                  <path className="state-fill s6" d="M115 232l41-10 29 33 9 62-24 24-24-37-27-11z" />
                  <path className="state-fill s7" d="M185 255l39-3 34 42-32 12-14 35-42-11 24-13z" />
                  <path className="india-ridge" d="M130 42l42 50-12 42 45 48-34 40 23 54-18 41" />
                  <path className="india-ridge" d="M95 124l51 4 44 45 62 16" />
                  {stateCaseData.map(({ state, cases, x, y, level }) => (
                    <g key={state} className={`map-point ${level}`} transform={`translate(${x} ${y})`}>
                      <circle className="map-pulse" r={cases > 20000 ? 24 : cases > 9000 ? 20 : 16} />
                      <circle r="8" />
                      <text x="14" y="-7">{cases.toLocaleString("en-IN")}</text>
                      <text className="city-label" x="14" y="10">{state}</text>
                    </g>
                  ))}
                </svg>
                <p className="map-source">2026 regional alert index for presentation</p>
              </div>
            </div>

            <div className="glass">
              <h2>Threat Intelligence</h2>
              <div className="intel-list">
                {threatIntel.map(([name, value, risk]) => <div key={name}><span>{name}</span><strong>{value} {risk}</strong></div>)}
              </div>
            </div>
          </section>

          <section className={activeSection !== "Dashboard" && activeSection !== "Scan" ? "ecosystem-panel" : "ecosystem-panel section-hidden"}>
            {activeSection === "Guardian" && (
              <>
                <div className="section-head wide-head">
                  <h2>BharatSHIELD Guardian</h2>
                  <button onClick={() => setActiveSection("Scan")}>Scan Now</button>
                </div>
                <div className="guardian-grid">
                  <div className="glass extension-preview">
                    <div className="browser-bar"><span /> https://sbi-secure-login.example</div>
                    <div className="fake-page">
                      <strong>State Bank Secure Login</strong>
                      <input readOnly value="Enter mobile number" />
                      <input readOnly value="Enter OTP" />
                    </div>
                    <div className="guardian-overlay">
                      <span>HIGH RISK</span>
                      <h2>This site imitates SBI</h2>
                      <p>Brand lookalike, hidden redirect, and OTP request detected.</p>
                      <div className="toolrow compact-actions"><button className="danger-action">Leave Site</button><button>View Details</button></div>
                    </div>
                  </div>
                  <div className="glass trust-meter-card">
                    <h2>Website Trust Meter</h2>
                    <div className="trust-score">8/100</div>
                    <p>Low trust because login, OTP, and brand impersonation signals were found.</p>
                    <div className="intel-list">{guardianSignals.map(([name, value, detail]) => <div key={name}><span>{name}</span><strong>{value}</strong><small>{detail}</small></div>)}</div>
                  </div>
                  <div className="glass">
                    <h2>Scam DNA</h2>
                    <div className="dna-box">BS-DNA-91F2-A8C7</div>
                    <p>Fingerprint combines URL, keywords, brand similarity, intent, redirect path, and visual clues to find duplicate scams.</p>
                    <div className="trust-list"><span>SHA256 Fingerprint</span><span>Brand: SBI</span><span>Intent: OTP Theft</span><span>Duplicate Ready</span></div>
                  </div>
                </div>
                <div className="ecosystem-grid">
                  <div className="glass">
                    <h2>Scam Timeline</h2>
                    <div className="timeline-list compact-timeline">
                      {guardianTimeline.map((item, index) => <div key={item}><span>Step {index + 1}</span><strong>{item}</strong><em>{index >= 3 ? "High" : "Review"}</em></div>)}
                    </div>
                  </div>
                  <div className="glass">
                    <h2>QR Sandbox Preview</h2>
                    <p>QR opens in a safe preview first. Destination, redirect, payment intent, UPI ID, and risk are shown before the user proceeds.</p>
                    <div className="secure-note">File automatically deleted after analysis.</div>
                  </div>
                  <div className="glass">
                    <h2>Integration Roadmap</h2>
                    <div className="roadmap-list">{platformRoadmap.map(([title, detail]) => <div key={title}><strong>{title}</strong><p>{detail}</p></div>)}</div>
                  </div>
                </div>
              </>
            )}

            {activeSection === "Report Scam" && (
              <>
                <div className="section-head wide-head">
                  <h2>Report Scam</h2>
                  <button onClick={openCyberPortal}>Open Cyber Crime Portal</button>
                </div>
                <div className="ecosystem-grid">
                  <div className="glass">
                    <h2>Report Type</h2>
                    <div className="pill-grid">
                      {reportTypes.map((type) => (
                        <button key={type} className={reportType === type ? "active" : ""} onClick={() => setReportType(type)}>{type}</button>
                      ))}
                    </div>
                  </div>
                  <div className="glass">
                    <h2>Upload Evidence</h2>
                    <label className="evidence-upload">
                      <input type="file" accept=".jpg,.jpeg,.png,.pdf,.txt,.mp3,.wav,.m4a" onChange={handleEvidenceUpload} />
                      <strong>{evidenceFile || "Choose evidence file"}</strong>
                      <small>Allowed: jpg, png, pdf, txt, mp3, wav, m4a. Blocked: exe, apk, bat, zip.</small>
                    </label>
                    <div className="evidence-types"><span>Screenshot</span><span>Image</span><span>PDF</span><span>Audio</span></div>
                    <p>File is used for this report draft and not stored permanently.</p>
                  </div>
                  <div className="glass">
                    <h2>Complaint Summary</h2>
                    <p>{complaintSummary}</p>
                    <div className="secure-note">Scam ID: {incidentId} | SHA256-style fingerprint ready</div>
                    <div className="toolrow compact-actions">
                      <button className="primary" onClick={downloadComplaint}>Download Complaint</button>
                      <button onClick={openCyberPortal}>Report Officially</button>
                    </div>
                  </div>
                </div>
              </>
            )}

            {activeSection === "Awareness" && (
              <>
                <div className="section-head wide-head"><h2>Awareness Center</h2><button>Daily Quiz</button></div>
                <div className="library-grid">
                  {scamLibrary.map((item) => (
                    <div className="glass library-card" key={item.name}>
                      <h2>{item.name}</h2>
                      <p><strong>How it works:</strong> {item.example}</p>
                      <div>
                        <strong>Warning signs</strong>
                        <ul>{item.signs.map((sign) => <li key={sign}>{sign}</li>)}</ul>
                      </div>
                      <div>
                        <strong>What to do</strong>
                        <ul>{item.actions.map((action) => <li key={action}>{action}</li>)}</ul>
                      </div>
                    </div>
                  ))}
                  <div className="glass quiz-card">
                    <h2>Can you identify this scam?</h2>
                    <p>"Your bank account will be blocked. Share OTP now."</p>
                    <div className="pill-grid"><button>Safe</button><button className="active">Scam</button><button>Not Sure</button></div>
                    <p className="secure-note">Correct: Scam. Government safety guidance recommends never sharing OTP, PIN, password, or approving unknown payment requests.</p>
                  </div>
                </div>
              </>
            )}

            {activeSection === "Emergency" && (
              <>
                <div className="section-head wide-head"><h2>Emergency Help</h2><button className="danger-action">I am being scammed right now</button></div>
                <div className="ecosystem-grid emergency-grid">
                  <div className="glass emergency-card"><h2>Call 1930</h2><p>Financial cyber fraud helpline.</p><a href="tel:1930">Call Now</a></div>
                  <div className="glass emergency-card"><h2>Cyber Crime Portal</h2><p>Report and track complaints officially.</p><button onClick={openCyberPortal}>Open Portal</button></div>
                  <div className="glass emergency-card"><h2>Stop Payment</h2><p>Call your bank, block UPI/card, preserve evidence.</p><button onClick={downloadComplaint}>Copy Complaint</button></div>
                </div>
                <div className="glass sos-panel">
                  <h2>SOS Mode</h2>
                  <ol>
                    <li>Stop chatting, screen sharing, or video call immediately.</li>
                    <li>Do not share OTP, UPI PIN, card PIN, password, or remote access.</li>
                    <li>Call 1930 quickly for financial fraud and request bank freeze support.</li>
                    <li>Save transaction ID, phone number, UPI ID, screenshots, and audio evidence.</li>
                    <li>Open cybercrime.gov.in and submit the complaint draft generated here.</li>
                  </ol>
                </div>
              </>
            )}

            {activeSection === "Live Scam Alerts" && (
              <>
                <div className="section-head wide-head"><h2>Live Scam Alerts</h2><button>Latest 2026 Update</button></div>
                <div className="alerts-grid">
                  {liveAlerts.map(([title, risk, region, tip]) => (
                    <div className="glass alert-card" key={title}>
                      <span>{risk}</span>
                      <h2>{title}</h2>
                      <p>{region}</p>
                      <strong>{tip}</strong>
                    </div>
                  ))}
                </div>
              </>
            )}

            {activeSection === "History" && (
              <div className="glass">
                <div className="section-head"><h2>Scan Timeline</h2><button onClick={clearHistory}>Clear</button></div>
                <div className="timeline-list">
                  {(history.length ? history : [
                    { scam_type: "URL Safe", risk: "Low" },
                    { scam_type: "WhatsApp Scam", risk: "High" },
                    { scam_type: "QR Scam", risk: "Medium" },
                  ]).slice(0, 8).map((item, index) => (
                    <div key={`${item.scam_type}-${index}`}><span>{index === 0 ? "Today" : `${index + 1} Aug`}</span><strong>{item.scam_type}</strong><em>{item.risk}</em></div>
                  ))}
                </div>
              </div>
            )}

            {activeSection === "Settings" && (
              <>
                <div className="ecosystem-grid">
                  <div className="glass setting-card">
                    <h2>Auto Delete</h2>
                    <select value={autoDelete} onChange={(event) => setAutoDelete(event.target.value)}>
                      {autoDeleteOptions.map((item) => <option key={item}>{item}</option>)}
                    </select>
                    <p>Evidence and scan text are treated as temporary review data.</p>
                  </div>
                  <div className="glass setting-card">
                    <h2>Notifications</h2>
                    <label className="settings-toggle"><input type="checkbox" checked={notificationsOn} onChange={(event) => setNotificationsOn(event.target.checked)} /> Scam trend alerts</label>
                    <p>{notificationsOn ? "Alerts enabled for high-risk scams." : "Alerts disabled."}</p>
                  </div>
                  <div className="glass setting-card">
                    <h2>Privacy Mode</h2>
                    <label className="settings-toggle"><input type="checkbox" checked={privacyMode} onChange={(event) => setPrivacyMode(event.target.checked)} /> Hide sensitive scan data</label>
                    <p>{privacyMode ? "Sensitive text previews are minimized." : "Full previews may be visible."}</p>
                  </div>
                </div>
                <div className="ecosystem-grid settings-wide">
                  <div className="glass">
                    <h2>Permission Checker</h2>
                    <p>BharatSHIELD does not request these permissions for scanning:</p>
                    <div className="permission-grid">{deniedPermissions.map((item) => <span key={item}>No {item}</span>)}</div>
                  </div>
                  <div className="glass">
                    <h2>Secure Upload Policy</h2>
                    <p>Allowed files: jpg, png, pdf, txt, mp3, wav, m4a. Executables, APKs, batch files, and zip archives are blocked.</p>
                    <p className="secure-note">Files are reviewed locally in the browser flow and marked for deletion after {autoDelete}.</p>
                  </div>
                  <div className="glass">
                    <h2>Trust Badge</h2>
                    <div className="trust-list">{trustChecks.map((item) => <span key={item}>{item}</span>)}</div>
                  </div>
                </div>
              </>
            )}
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
