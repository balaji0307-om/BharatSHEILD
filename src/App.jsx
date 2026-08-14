import { useEffect, useMemo, useRef, useState } from "react";
import jsQR from "jsqr";
import { buildMetricDisplay } from "./displayMetrics.mjs";
import {
  buildLocalQrAnalysisResult,
  getVerifiedQrBaseline,
  saveVerifiedQrBaseline,
} from "./qrAnalysis.mjs";

function resolveApiBase() {
  const configured = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "");
  if (configured) return configured;
  if (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost") {
    return "http://127.0.0.1:8000";
  }
  if (window.location.hostname.endsWith(".onrender.com")) {
    return window.location.origin;
  }
  return "";
}

const API_BASE = resolveApiBase();
const LANDING_DURATION_MS = 5200;

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

const navItems = ["Dashboard", "Scan", "Guardian", "Report Scam", "Awareness", "Emergency", "Scam Awareness", "History", "Settings"];

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
  ["Scans analyzed", "127", "Demo workspace"],
  ["Threats detected", "34", "From recent scans"],
  ["Reports generated", "8", "Complaint drafts"],
  ["Helpline", "1930", "Emergency support"],
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

const guardianTimeline = ["Opened URL", "Redirect detected", "Fake login form found", "OTP field detected", "High risk warning shown"];
const protectionChannels = [
  ["Browser Guard", "Warns before a risky login page or copied link is opened."],
  ["Share to Scan", "Checks WhatsApp, SMS, email, and social messages shared by the user."],
  ["QR Preview", "Shows destination, amount, UPI ID, and risk before opening the QR link."],
  ["Report Support", "Keeps evidence ready for complaint download and official reporting."],
];

const deniedPermissions = ["Contacts", "Photos", "Location", "OTP", "Passwords", "Background microphone"];
const autoDeleteOptions = ["30 Minutes", "1 Hour", "24 Hours", "Never"];
const allowedEvidence = [".jpg", ".jpeg", ".png", ".pdf", ".txt", ".mp3", ".wav", ".m4a"];
const caseStatuses = ["Suspected", "Verified", "Needs Review"];
const caseRoles = ["User", "Investigator", "Reviewer", "Admin", "Authority"];

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

function getStoredCases() {
  try {
    return JSON.parse(localStorage.getItem("bharatshield_cases") || "[]");
  } catch {
    return [];
  }
}

function saveCases(items) {
  localStorage.setItem("bharatshield_cases", JSON.stringify(items.slice(0, 50)));
}

function authHeaders(token, extra = {}) {
  return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
}

async function fetchBackendCases(owner, token) {
  const query = owner ? `?owner=${encodeURIComponent(owner)}` : "";
  const response = await fetch(`${API_BASE}/api/cases${query}`, {
    headers: authHeaders(token),
  });
  if (!response.ok) throw new Error("Could not load cases.");
  return response.json();
}

async function saveBackendCase(item, token) {
  const response = await fetch(`${API_BASE}/api/cases`, {
    method: "POST",
    headers: authHeaders(token, { "Content-Type": "application/json" }),
    body: JSON.stringify({ case: item }),
  });
  if (!response.ok) throw new Error("Could not save case.");
  return response.json();
}

async function patchBackendCase(caseId, patch, token) {
  const response = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}`, {
    method: "PATCH",
    headers: authHeaders(token, { "Content-Type": "application/json" }),
    body: JSON.stringify(patch),
  });
  if (!response.ok) throw new Error("Could not update case.");
  return response.json();
}

function makeCaseId() {
  return `BS-${Math.floor(1000 + Math.random() * 9000)}`;
}

function buildSecurityCase(analysis, input, channel, user) {
  const createdAt = new Date().toISOString();
  const numericScore = Number.isFinite(Number(analysis.score)) ? Number(analysis.score) : 45;
  const tamper = analysis.qr_analysis?.tamper_check;
  let status = analysis.verification_failed
    ? "Needs Review"
    : numericScore >= 70
      ? "Suspected"
      : numericScore >= 35
        ? "Needs Review"
        : "Verified";
  if (tamper?.tamper_detected) {
    status = tamper.severity === "high" ? "Suspected" : "Needs Review";
  } else if (analysis.scam_type === "QR Verified Baseline" || analysis.qr_analysis?.user_verified) {
    status = "Verified";
  }
  const timeline = [
    { label: "Content submitted", time: createdAt },
    { label: "Analysis completed", time: createdAt },
    { label: `${analysis.risk || "Medium"} risk detected`, time: createdAt },
  ];
  if (tamper?.tamper_detected) {
    timeline.push({ label: tamper.headline || tamper.change_status || "QR tamper detected", time: createdAt });
  }
  timeline.push({ label: `Case marked ${status}`, time: createdAt });
  return {
    case_id: analysis.case_id || makeCaseId(),
    type: analysis.scam_type || "Security Review",
    channel,
    input,
    owner: user?.email || "local-user",
    ai_result: {
      risk: analysis.risk,
      score: numericScore,
      confidence: analysis.confidence,
      explanation: analysis.what_we_found || analysis.explanation || "Security review completed.",
      reasons: (analysis.signals || []).slice(0, 6).map((item) => `${item.label}: ${item.reason}`),
      qr_analysis: analysis.qr_analysis || null,
    },
    investigation: {
      status,
      note: tamper?.tamper_detected ? tamper.summary || tamper.explanation || "" : "",
      reviewed_by: null,
      reviewed_at: null,
    },
    timeline,
    created_at: createdAt,
  };
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

function upsertLocalUser(user, password) {
  if (!user?.email || !password) return;
  const users = getStoredUsers();
  const email = user.email.trim().toLowerCase();
  const localUser = {
    id: user.id || Date.now(),
    name: user.name || "User",
    email,
    password,
  };
  const nextUsers = users.some((item) => item.email === email)
    ? users.map((item) => item.email === email ? { ...item, ...localUser } : item)
    : [...users, localUser];
  saveStoredUsers(nextUsers);
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

function qrUnableToVerifyAnalysis(text) {
  let qrPayload = {
    upi_id: "Not found",
    merchant: "Not found",
    amount: "Not found",
    note: "Not found",
    destination_url: "Not found",
    hidden_redirect: false,
    fingerprint: "BS-QR-UNVERIFIED",
    recipient_reputation: "Unknown",
    previous_reports: 0,
    risk_signals: [],
  };
  try {
    const url = new URL(text.trim());
    qrPayload = {
      ...qrPayload,
      upi_id: url.searchParams.get("pa") || "Not found",
      merchant: url.searchParams.get("pn") || "Not found",
      amount: url.searchParams.get("am") || "Not found",
      note: url.searchParams.get("tn") || "Not found",
      destination_url: url.protocol === "http:" || url.protocol === "https:" ? text.trim() : "Not found",
      hidden_redirect: url.protocol === "http:" || url.protocol === "https:",
    };
  } catch {
    // Keep minimal unverified payload fields.
  }
  return {
    score: null,
    risk: "Unable to verify",
    scam_type: "QR Verification Unavailable",
    confidence: null,
    rule_score: null,
    url_score: null,
    safety_score: null,
    verification_failed: true,
    mode: "qr",
    signals: [{ label: "QR verification", reason: "Backend QR verification was unavailable." }],
    recommendations: [
      "Unable to verify this QR. Do not make the payment yet.",
      "Open your UPI app yourself and verify recipient, merchant, amount, and purpose.",
      "Do not approve payment if the sender is pressuring you.",
    ],
    reason_breakdown: [
      { label: "Message language", score: 0, why: "Backend verification was unavailable." },
      { label: "Urgency and pressure", score: 0, why: "Do not continue if the sender is creating urgency." },
      { label: "Credential risk", score: 0, why: "Never share OTP, PIN, or password." },
      { label: "URL / QR risk", score: 45, why: "QR payload is unverified. Payment should not continue yet." },
    ],
    url_checks: qrPayload.hidden_redirect ? [{ domain: qrPayload.destination_url, score: 45, checks: [{ label: "Status", result: "Unverified QR destination" }] }] : [],
    qr_analysis: qrPayload,
    call_analysis: { emotion: "Not analyzed", pressure_score: 0, live_warning: false },
    what_we_found: `QR payload decoded for recipient ${qrPayload.upi_id}, merchant ${qrPayload.merchant}, amount ${qrPayload.amount}, note ${qrPayload.note}.`,
    why_dangerous: "Unable to verify this QR. Do not make the payment yet.",
    how_sure: "55% confidence because only local QR parsing completed.",
  };
}

function makeGuardianOtp(mobile) {
  const digits = mobile.replace(/\D/g, "").slice(-10);
  if (digits.length < 10) return "";
  let seed = 0;
  for (let index = 0; index < digits.length; index += 1) {
    seed = (seed * 31 + Number(digits[index])) % 1000000;
  }
  return String((seed + 100000) % 1000000).padStart(6, "0");
}

function maskMobile(mobile) {
  const digits = mobile.replace(/\D/g, "").slice(-10);
  if (digits.length < 4) return "";
  return `+91 ******${digits.slice(-4)}`;
}

function detectHiddenImagePayload(bytes, fileName) {
  const view = new Uint8Array(bytes);
  const text = Array.from(view.slice(0, Math.min(view.length, 16000)))
    .map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : " "))
    .join("")
    .toLowerCase();
  const ext = fileName.toLowerCase().split(".").pop() || "";
  const signatures = [
    ["<script", "script tag"],
    ["javascript:", "javascript payload"],
    ["powershell", "PowerShell command"],
    ["cmd.exe", "command shell marker"],
    ["<?php", "PHP code"],
    ["eval(", "eval code"],
    ["mzm", "executable marker"],
  ];
  const marker = signatures.find(([pattern]) => text.includes(pattern));
  if (marker) return `Hidden ${marker[1]} found inside image bytes.`;

  if (view[0] === 0x50 && view[1] === 0x4b) return "ZIP/APK-style file signature found. This is not a safe QR image.";
  if (view[0] === 0x4d && view[1] === 0x5a) return "Executable file signature found. This is not a safe QR image.";

  if (ext === "png") {
    const tail = "iend";
    const ascii = Array.from(view).map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : " ")).join("").toLowerCase();
    const endIndex = ascii.lastIndexOf(tail);
    if (endIndex >= 0 && view.length - endIndex > 32) {
      const afterEnd = ascii.slice(endIndex + tail.length).trim();
      if (afterEnd.length > 12) return "Extra hidden data found after PNG end marker.";
    }
  }

  if ((ext === "jpg" || ext === "jpeg") && view.length > 4) {
    let end = -1;
    for (let index = view.length - 2; index >= 0; index -= 1) {
      if (view[index] === 0xff && view[index + 1] === 0xd9) {
        end = index + 2;
        break;
      }
    }
    if (end > 0 && view.length - end > 24) return "Extra hidden data found after JPEG end marker.";
  }

  return "";
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
  const score = Math.min(96, 12 + hits.reduce((sum, [, weight]) => sum + weight, 0) + (channel === "url" ? 8 : 0));
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
      { label: "URL / QR risk", score: lowered.includes("http") || channel === "url" ? 84 : 8, why: "Links and QR payloads are reviewed." },
    ],
    url_checks: lowered.includes("http") || channel === "url" ? [{ domain: text.replace(/^https?:\/\//, "").split(/[/?#]/)[0] || "Link", score: Math.min(95, score + 5), checks: [{ label: "Status", result: "Review carefully" }] }] : [],
    qr_analysis: null,
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

const landingSignals = [
  { type: "QR", text: "upi://pay" },
  { type: "URL", text: "sbi-secure-login" },
  { type: "SMS", text: "OTP request" },
  { type: "UPI", text: "refund-support@upi" },
];

function CinematicLanding() {
  return (
    <section className="landing-screen cinematic-landing">
      <div className="landing-mesh" aria-hidden="true" />
      <div className="landing-light landing-light-left" aria-hidden="true" />
      <div className="landing-light landing-light-right" aria-hidden="true" />
      <div className="particle-field" aria-hidden="true">
        {Array.from({ length: 30 }).map((_, index) => (
          <span
            key={index}
            style={{
              "--i": String(index),
              "--x": `${(index * 37) % 100}%`,
              "--y": `${(index * 19) % 100}%`,
              "--z": `${index * 2}px`,
              "--duration": `${5.5 + index * 0.12}s`,
              "--delay": `${index * -0.22}s`,
            }}
          />
        ))}
      </div>
      <div className="threat-cloud" aria-hidden="true">
        {landingSignals.map((signal, index) => (
          <span
            key={`${signal.type}-${signal.text}`}
            style={{
              "--i": String(index),
              "--x": `${9 + index * 18}%`,
              "--y": `${15 + index * 13}%`,
              "--delay": `${index * -1.3}s`,
            }}
          >
            <b>{signal.type}</b>
            {signal.text}
          </span>
        ))}
      </div>

      <div className="landing-stage">
        <div className="shield-rings" aria-hidden="true">
          <i />
          <i />
          <i />
        </div>
        <div className="shield-3d">
          <HeroShield />
          <span className="shield-scan" aria-hidden="true" />
        </div>
      </div>

      <div className="landing-copy">
        <h1>BharatSHIELD</h1>
        <span>Protect every link, QR code, message, and payment before it becomes a threat.</span>
      </div>

      <div className="landing-status">
        <strong>India Focused. Safety First.</strong>
        <div className="real-loader" aria-label="Loading dashboard">
          <span />
        </div>
        <small>Initializing shield</small>
      </div>
    </section>
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
  const [cases, setCases] = useState(getStoredCases);
  const [loading, setLoading] = useState(false);
  const [activeAnalysisMode, setActiveAnalysisMode] = useState("");
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
  const [caseStatusFilter, setCaseStatusFilter] = useState("All");
  const [caseRole, setCaseRole] = useState("Investigator");
  const [evidenceFile, setEvidenceFile] = useState("");
  const [autoDelete, setAutoDelete] = useState("1 Hour");
  const [notificationsOn, setNotificationsOn] = useState(true);
  const [privacyMode, setPrivacyMode] = useState(true);
  const [error, setError] = useState("");
  const [profileOpen, setProfileOpen] = useState(false);
  const [guardianForm, setGuardianForm] = useState({ mobile: "", otp: "", sentOtp: "", otpSent: false });
  const recognitionRef = useRef(null);

  const scanSteps = ["Checking message", "Finding risk words", "Checking URL", "Checking domain", "Preparing review", "Generating report"];
  const displayResult = result?.mode === mode ? result : null;
  const isQrResult = displayResult?.mode === "qr" || Boolean(displayResult?.qr_analysis);
  const isQrPanel = mode === "qr" || activeAnalysisMode === "qr" || isQrResult;
  const isAnalyzingCurrentMode = loading && activeAnalysisMode === mode;
  const metricDisplay = buildMetricDisplay({ displayResult, mode, activeAnalysisMode, loading });
  const score = metricDisplay.scoreValue ?? 0;
  const gaugeScore = metricDisplay.gaugeScore;
  const scoreDisplay = metricDisplay.scoreDisplay;
  const confidenceDisplay = metricDisplay.confidenceDisplay;
  const ruleScoreDisplay = metricDisplay.ruleScoreDisplay;
  const urlScoreDisplay = metricDisplay.urlScoreDisplay;
  const dashboardSafetyScore = Number.isFinite(Number(displayResult?.safety_score)) ? Number(displayResult.safety_score) : 76;
  const safetyScoreDisplay = metricDisplay.safetyScoreDisplay;
  const liveShieldStatus = metricDisplay.liveShieldStatus;
  const threatCardTitle = isQrPanel ? "QR Risk Analysis" : "Threat Level";
  const riskLevelDisplay = isAnalyzingCurrentMode ? "Analyzing" : displayResult?.risk || threatCardTitle;
  const incidentId = useMemo(() => `BS-${Math.floor(20000 + Math.random() * 70000)}`, [result?.created_at]);
  const guardianOtp = makeGuardianOtp(guardianForm.mobile);
  const guardianMaskedMobile = maskMobile(guardianForm.mobile);

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
    }, LANDING_DURATION_MS);
    return () => clearTimeout(timer);
  }, [session]);

  useEffect(() => {
    if (!session?.user?.email) return;
    let cancelled = false;
    fetchBackendCases(session.user.email, session.token)
      .then((data) => {
        if (cancelled || !Array.isArray(data.cases) || !data.cases.length) return;
        setCases(data.cases);
        saveCases(data.cases);
      })
      .catch(() => {
        // Keep local cases for offline demo mode.
      });
    return () => {
      cancelled = true;
    };
  }, [session?.user?.email, session?.token]);

  const trends = useMemo(() => {
    return history.reduce((acc, item) => {
      const key = item.scam_type || "Unknown";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
  }, [history]);

  const visibleCases = useMemo(() => {
    const roleCases = caseRole === "User" ? cases.filter((item) => item.owner === session?.user?.email) : cases;
    return caseStatusFilter === "All" ? roleCases : roleCases.filter((item) => item.investigation.status === caseStatusFilter);
  }, [caseRole, caseStatusFilter, cases, session?.user?.email]);

  const caseCounts = useMemo(() => {
    return {
      total: cases.length,
      suspected: cases.filter((item) => item.investigation.status === "Suspected").length,
      verified: cases.filter((item) => item.investigation.status === "Verified").length,
      review: cases.filter((item) => item.investigation.status === "Needs Review").length,
    };
  }, [cases]);

  function selectMode(nextMode) {
    setMode(nextMode);
    setContent(samples[nextMode] || "");
    setAudioFileName("");
    setError("");
    setResult(null);
    setActiveAnalysisMode("");
  }

  async function analyzeQrPayload(input) {
    const verifiedBaseline = getVerifiedQrBaseline();
    if (API_BASE) {
      try {
        const response = await fetch(`${API_BASE}/api/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            content: input,
            channel: "qr",
            language: "en",
            verified_baseline: verifiedBaseline,
          }),
        });
        const contentType = response.headers.get("content-type") || "";
        if (response.ok && contentType.includes("application/json")) {
          const data = await response.json();
          if (data?.qr_analysis) return { ...data, mode: "qr" };
        }
      } catch {
        // Use local deterministic QR review when backend is unavailable.
      }
    }
    return { ...(await buildLocalQrAnalysisResult(input, verifiedBaseline)), mode: "qr" };
  }

  async function verifyAndSaveQr() {
    if (!content.trim()) {
      setError("Upload a QR image or paste decoded QR content first.");
      return;
    }
    const identity = displayResult?.qr_analysis?.identity;
    if (!identity) {
      setError("Analyze the QR first before saving a verified baseline.");
      return;
    }
    setError("");
    if (API_BASE && session?.token) {
      try {
        const response = await fetch(`${API_BASE}/api/qr/verify`, {
          method: "POST",
          headers: { ...authHeaders(session.token), "Content-Type": "application/json" },
          body: JSON.stringify({ content }),
        });
        if (response.ok) {
          const data = await response.json();
          if (data.baseline) saveVerifiedQrBaseline(data.baseline);
          if (data.case) {
            const nextCases = [data.case, ...cases.filter((item) => item.case_id !== data.case.case_id)];
            setCases(nextCases);
            saveCases(nextCases);
          }
          await runAnalysis(content, "qr");
          return;
        }
      } catch {
        // Fall back to local baseline storage.
      }
    }
    const baseline = saveVerifiedQrBaseline(identity);
    const verifiedAnalysis = {
      score: displayResult?.score ?? 0,
      risk: "Low",
      confidence: 62,
      scam_type: "QR Verified Baseline",
      what_we_found: "User verified this QR baseline for future tamper comparison.",
      signals: [{ label: "QR baseline", reason: "User verified QR baseline saved locally." }],
      qr_analysis: { ...displayResult.qr_analysis, user_verified: true, verified_baseline: baseline },
    };
    const verifiedCase = buildSecurityCase(verifiedAnalysis, content, "qr", session?.user);
    verifiedCase.investigation = {
      status: "Verified",
      note: "User verified QR baseline.",
      reviewed_by: session?.user?.name || null,
      reviewed_at: new Date().toISOString(),
    };
    const nextCases = [verifiedCase, ...cases];
    setCases(nextCases);
    saveCases(nextCases);
    saveBackendCase(verifiedCase, session?.token).catch(() => {});
    await runAnalysis(content, "qr");
  }

  async function runAnalysis(input = content, channel = mode) {
    if (!input.trim()) {
      setError(channel === "qr" ? "Upload a QR image or paste decoded QR content first." : "Paste content first.");
      return;
    }
    playScanSound();
    setLoading(true);
    setActiveAnalysisMode(channel);
    setError("");
    setResult(null);
    setContent(input);
    setShowLanding(false);
    try {
      let data;
      if (channel === "qr") {
        data = await analyzeQrPayload(input);
      } else {
        const response = await fetch(`${API_BASE}/api/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: input, channel, language: "en" }),
        });
        if (!response.ok) throw new Error("Service is unavailable. Please try again.");
        data = { ...(await response.json()), mode: channel };
      }
      setResult(data);
      const nextHistory = [{ ...data, mode: channel, preview: input.slice(0, 120) }, ...history];
      const nextCases = [buildSecurityCase(data, input, channel, session?.user), ...cases];
      setHistory(nextHistory);
      saveHistory(nextHistory);
      setCases(nextCases);
      saveCases(nextCases);
      saveBackendCase(nextCases[0], session?.token).catch(() => {});
    } catch (err) {
      if (channel === "qr") {
        try {
          const fallback = { ...(await buildLocalQrAnalysisResult(input, getVerifiedQrBaseline())), mode: channel };
          setResult(fallback);
          const nextHistory = [{ ...fallback, mode: channel, preview: input.slice(0, 120) }, ...history];
          const nextCases = [buildSecurityCase(fallback, input, channel, session?.user), ...cases];
          setHistory(nextHistory);
          saveHistory(nextHistory);
          setCases(nextCases);
          saveCases(nextCases);
          saveBackendCase(nextCases[0], session?.token).catch(() => {});
          setError("");
        } catch {
          const fallback = { ...qrUnableToVerifyAnalysis(input), mode: channel };
          setResult(fallback);
          const nextHistory = [{ ...fallback, mode: channel, preview: input.slice(0, 120) }, ...history];
          const nextCases = [buildSecurityCase(fallback, input, channel, session?.user), ...cases];
          setHistory(nextHistory);
          saveHistory(nextHistory);
          setCases(nextCases);
          saveCases(nextCases);
          saveBackendCase(nextCases[0], session?.token).catch(() => {});
          setError("Unable to verify this QR. Do not make the payment yet.");
        }
      } else {
        const fallback = { ...clientAnalysis(input, channel), mode: channel };
        setResult(fallback);
        const nextHistory = [{ ...fallback, mode: channel, preview: input.slice(0, 120) }, ...history];
        const nextCases = [buildSecurityCase(fallback, input, channel, session?.user), ...cases];
        setHistory(nextHistory);
        saveHistory(nextHistory);
        setCases(nextCases);
        saveCases(nextCases);
        saveBackendCase(nextCases[0], session?.token).catch(() => {});
      }
    } finally {
      setTimeout(() => {
        setLoading(false);
        setActiveAnalysisMode("");
      }, 420);
    }
  }

  async function scanQr(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setError("");
    try {
      if (!/^image\/(png|jpe?g|webp|bmp|gif)$/i.test(file.type)) {
        setError("Blocked: upload a real image file only for QR scanning.");
        return;
      }
      const bytes = await file.arrayBuffer();
      const hiddenPayload = detectHiddenImagePayload(bytes, file.name);
      if (hiddenPayload) {
        setMode("qr");
        setContent("");
        setResult({
          score: 88,
          risk: "Critical",
          confidence: 94,
          rule_score: 90,
          url_score: 0,
          safety_score: 12,
          scam_type: "Unsafe QR Image",
          signals: [{ label: "Image payload", reason: hiddenPayload }],
          recommendations: [
            "Do not scan or share this image.",
            "Ask the sender for a clean QR image from an official source.",
            "Report the sender if this image came with payment pressure.",
          ],
          reason_breakdown: [
            { label: "Image safety", score: 92, why: hiddenPayload },
            { label: "QR verification", score: 88, why: "QR scan was blocked before decoding." },
            { label: "Credential risk", score: 20, why: "No credential text was decoded." },
            { label: "URL / QR risk", score: 88, why: "Image container has suspicious hidden payload markers." },
          ],
          url_checks: [],
          qr_analysis: {
            upi_id: "Blocked",
            merchant: "Blocked",
            amount: "Blocked",
            note: hiddenPayload,
            recipient_reputation: "Unsafe image",
            previous_reports: 0,
            fingerprint: "BS-QR-BLOCKED",
            hidden_redirect: false,
            checks: [{ label: "Image safety", result: hiddenPayload }],
          },
          call_analysis: { emotion: "Not analyzed", pressure_score: 0, live_warning: false },
          what_we_found: "This QR image was blocked before scanning because hidden payload markers were detected.",
          why_dangerous: "Attackers can hide script, executable, or extra data inside image files. BharatSHIELD refused to process this image.",
          how_sure: "94% confidence based on image container safety checks.",
        });
        setError(`Blocked unsafe QR image: ${hiddenPayload}`);
        return;
      }
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
        event.target.value = "";
        return;
      }

      setMode("qr");
      setContent(decoded);
      setResult(null);
      setError(autoScan ? "" : "QR decoded. Review the content, then click Analyze QR.");
      if (autoScan) runAnalysis(decoded, "qr");
    } catch {
      setError("Could not read this QR image. Try a clearer, uncropped QR image.");
    } finally {
      event.target.value = "";
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

  function updateCase(caseId, field, value) {
    const reviewedAt = new Date().toISOString();
    let updatedCase = null;
    const nextCases = cases.map((item) => {
      if (item.case_id !== caseId) return item;
      const investigation = {
        ...item.investigation,
        [field]: value,
        reviewed_by: session?.user?.name || caseRole,
        reviewed_at: reviewedAt,
      };
      const timeline = field === "status"
        ? [...item.timeline, { label: `Marked ${value}`, time: reviewedAt }]
        : item.timeline;
      updatedCase = { ...item, investigation, timeline };
      return updatedCase;
    });
    setCases(nextCases);
    saveCases(nextCases);
    if (updatedCase) {
      patchBackendCase(caseId, {
        status: updatedCase.investigation.status,
        note: updatedCase.investigation.note,
        reviewed_by: updatedCase.investigation.reviewed_by,
      }, session?.token)
        .then((data) => {
          if (!data.case) return;
          const synced = nextCases.map((item) => item.case_id === caseId ? data.case : item);
          setCases(synced);
          saveCases(synced);
        })
        .catch(() => {});
    }
  }

  function caseReportText(item) {
    const qr = item.ai_result?.qr_analysis || null;
    const identity = qr?.identity_check || qr?.identity || null;
    const tamper = qr?.tamper_check || null;
    const qrLines = qr ? [
      "",
      "QR Analysis:",
      `QR Fingerprint: ${qr.fingerprint || "Not generated"}`,
      `Recipient / UPI ID: ${qr.upi_id || identity?.upi_id || "Not found"}`,
      `Recipient Name: ${identity?.recipient_name || qr.merchant || "Not found"}`,
      `Phone (from UPI): ${identity?.phone_number || "Not found"}`,
      `Amount: ${qr.amount || "Not found"}`,
      `Payment Note: ${qr.note || identity?.payment_note || "Not found"}`,
      `Consistency: ${identity?.consistency_state || "Not assessed"}`,
      `Recipient Reputation: ${qr.recipient_reputation || "Unknown"}`,
      `Previous BharatSHIELD Reports: ${qr.previous_reports ?? 0}`,
      ...(tamper?.tamper_detected ? [
        "",
        "Tamper Check:",
        `Status: ${tamper.change_status}`,
        `Severity: ${tamper.severity}`,
        `Summary: ${tamper.summary || tamper.explanation}`,
        ...(tamper.changes?.length ? ["Changes Detected:", ...tamper.changes.map((change) => `- ${change.field}: ${change.previous} -> ${change.current}`)] : []),
      ] : []),
      ...(qr.risk_signals?.length ? ["Risk Signals:", ...qr.risk_signals.map((signal) => `- ${signal}`)] : []),
    ] : [];
    return [
      "BHARATSHIELD",
      "Security Investigation Report",
      "",
      `Case ID: ${item.case_id}`,
      `Threat Type: ${item.type}`,
      `Detected Content: ${item.input}`,
      `AI Risk Score: ${item.ai_result.score}%`,
      `Risk Level: ${item.ai_result.risk}`,
      `AI Confidence: ${item.ai_result.confidence}%`,
      "",
      "AI Analysis:",
      item.ai_result.explanation,
      "",
      "Detection Reasons:",
      ...(item.ai_result.reasons.length ? item.ai_result.reasons : ["No major risk signals found."]).map((reason) => `- ${reason}`),
      ...qrLines,
      "",
      `Investigation Status: ${item.investigation.status}`,
      `Investigator Note: ${item.investigation.note || "No note added."}`,
      `Reviewed By: ${item.investigation.reviewed_by || "Not reviewed"}`,
      "",
      "Evidence Timeline:",
      ...item.timeline.map((entry) => `- ${new Date(entry.time).toLocaleString()}: ${entry.label}`),
      "",
      "Recommendation:",
      "Do not share OTP, PIN, passwords, card details, or approve unknown payment requests.",
      "",
      `Generated At: ${new Date().toLocaleString()}`,
      "Generated by BharatSHIELD",
    ].join("\n");
  }

  function downloadCaseReport(item, format = "pdf") {
    const text = caseReportText(item);
    const html = `<html><head><title>${item.case_id}</title><style>body{font-family:Arial,sans-serif;padding:28px;line-height:1.5;color:#142233}pre{white-space:pre-wrap;font:inherit}h1{color:#0b2446}</style></head><body><h1>BharatSHIELD</h1><pre>${text.replace(/[&<>]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[char])}</pre></body></html>`;
    if (format === "csv") {
      const csv = [
        "case_id,threat_type,risk,score,status,note,created_at",
        `"${item.case_id}","${item.type}","${item.ai_result.risk}","${item.ai_result.score}","${item.investigation.status}","${item.investigation.note.replace(/"/g, '""')}","${item.created_at}"`,
      ].join("\n");
      downloadBlob(csv, `${item.case_id}.csv`, "text/csv");
      return;
    }
    if (format === "html") {
      downloadBlob(html, `${item.case_id}.html`, "text/html");
      return;
    }
    fetch(`${API_BASE}/api/cases/${encodeURIComponent(item.case_id)}/report.pdf`, {
      headers: authHeaders(session?.token),
    })
      .then((response) => {
        if (!response.ok) throw new Error("PDF unavailable.");
        return response.blob();
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `${item.case_id}.pdf`;
        link.click();
        URL.revokeObjectURL(url);
      })
      .catch(() => {
        downloadBlob(html, `${item.case_id}.html`, "text/html");
      });
    return;
  }

  function downloadBlob(text, filename, type) {
    const blob = new Blob([text], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
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
    const cleanForm = {
      name: authForm.name.trim(),
      email: authForm.email.trim().toLowerCase(),
      password: authForm.password,
    };
    const payload = authMode === "signup"
      ? cleanForm
      : { email: cleanForm.email, password: cleanForm.password };
    try {
      const response = await fetch(`${API_BASE}/api/${authMode === "signup" ? "signup" : "login"}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Authentication failed.");
      upsertLocalUser(data.user, cleanForm.password);
      saveSession(data);
      setSession(data);
      setShowAuth(false);
    } catch (err) {
      try {
        const localSession = localAuth(authMode, cleanForm);
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
    setProfileOpen(false);
  }

  const recommendations = displayResult?.recommendations || result?.recommendations || [
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
  const qrIdentityCheck = displayResult?.qr_analysis?.identity_check;
  const qrTamper = displayResult?.qr_analysis?.tamper_check;
  const qrIdentity = displayResult?.qr_analysis?.identity;
  const complaintSummary = displayResult ? `${displayResult.scam_type} suspected with ${score}% risk. Evidence: ${content.slice(0, 180)}` : "Select a report type and add evidence to prepare a complaint summary.";

  return (
    <>
      {showLanding && <CinematicLanding />}

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
              <p>{activeSection === "Dashboard" ? "Stay alert, stay safe from digital scams." : "Manage your digital safety here."}</p>
            </div>
            <div className="header-icons">
              <button type="button" onClick={() => setActiveSection("Scam Awareness")}>Alerts</button>
              <div className="profile-menu">
                <button type="button" title={session.user?.name || "User"} onClick={() => setProfileOpen((open) => !open)}>
                  {(session.user?.name || "User").slice(0, 1).toUpperCase()}
                </button>
                {profileOpen && (
                  <div className="profile-popover">
                    <strong>{session.user?.name || "User"}</strong>
                    <span>{session.user?.email || "Local account"}</span>
                    <button type="button" onClick={() => { setActiveSection("Settings"); setProfileOpen(false); }}>Profile</button>
                    <button type="button" onClick={() => { setActiveSection("History"); setProfileOpen(false); }}>Scan History</button>
                    <button type="button" onClick={logout}>Logout</button>
                  </div>
                )}
              </div>
            </div>
          </header>

          <section className={activeSection === "Dashboard" ? "stat-strip" : "stat-strip section-hidden"}>
            <div><span>Safety Score</span><strong>{dashboardSafetyScore}</strong><small>Higher is safer</small></div>
            <div><span>Threats Detected</span><strong>{Math.max(caseCounts.suspected + caseCounts.review, history.filter((item) => (item.score || 0) >= 55).length)}</strong><small>From this workspace</small></div>
            <div><span>Reports Ready</span><strong>{cases.length}</strong><small>Security cases</small></div>
            <div><span>Latest Alert</span><strong>Digital Arrest</strong><small>Awareness item</small></div>
          </section>

          <section className={activeSection === "Dashboard" ? "activity-strip" : "activity-strip section-hidden"}>
            {recentActivity.map((item, index) => (
              <div key={item} className={index % 2 ? "activity-warn" : "activity-safe"}>{item}</div>
            ))}
          </section>

          <section className={activeSection === "Dashboard" || activeSection === "History" ? "case-workbench" : "case-workbench section-hidden"}>
            <div className="section-head wide-head">
              <div>
                <h2>Security Cases</h2>
                <p>AI verdict stays unchanged. Investigation status and notes are added separately.</p>
              </div>
              <div className="case-controls">
                <select value={caseRole} onChange={(event) => setCaseRole(event.target.value)}>
                  {caseRoles.map((role) => <option key={role}>{role}</option>)}
                </select>
                <select value={caseStatusFilter} onChange={(event) => setCaseStatusFilter(event.target.value)}>
                  {["All", ...caseStatuses].map((status) => <option key={status}>{status}</option>)}
                </select>
              </div>
            </div>
            <div className="case-counts">
              <div><span>Total</span><strong>{caseCounts.total || 3}</strong></div>
              <div><span>Suspected</span><strong>{caseCounts.suspected || 1}</strong></div>
              <div><span>Verified</span><strong>{caseCounts.verified || 1}</strong></div>
              <div><span>Review</span><strong>{caseCounts.review || 1}</strong></div>
            </div>
            <div className="case-grid">
              {(visibleCases.length ? visibleCases : [
                buildSecurityCase({ score: 94, risk: "High", confidence: 96, scam_type: "Phishing", what_we_found: "Brand impersonation detected.", signals: [{ label: "Fake domain", reason: "Banking lookalike URL" }] }, "https://suspicious-login.example", "url", session?.user),
                buildSecurityCase({ score: 38, risk: "Medium", confidence: 70, scam_type: "QR Review", what_we_found: "Payment payload requires review.", signals: [{ label: "UPI payload", reason: "Unknown merchant" }] }, "upi://pay?pa=unknown@upi", "qr", session?.user),
                buildSecurityCase({ score: 18, risk: "Low", confidence: 82, scam_type: "URL Safe", what_we_found: "No strong risk signal.", signals: [] }, "https://example.com", "url", session?.user),
              ]).slice(0, activeSection === "Dashboard" ? 3 : 8).map((item) => (
                <div className="glass case-card" key={item.case_id}>
                  <div className="case-top">
                    <span className={`case-status ${item.investigation.status.toLowerCase().replace(/\s/g, "-")}`}>{item.investigation.status}</span>
                    <strong>{item.case_id}</strong>
                  </div>
                  <h2>{item.type}</h2>
                  <p className="case-input" title={item.input}>{item.input}</p>
                  <div className="case-ai">
                    <div><span>AI Risk</span><strong>{item.ai_result.score}%</strong></div>
                    <div><span>Threat</span><strong>{item.ai_result.risk}</strong></div>
                  </div>
                  <label>
                    Status
                    <select value={item.investigation.status} onChange={(event) => updateCase(item.case_id, "status", event.target.value)}>
                      {caseStatuses.map((status) => <option key={status}>{status}</option>)}
                    </select>
                  </label>
                  <label>
                    Investigator Note
                    <textarea className="case-note" value={item.investigation.note} onChange={(event) => updateCase(item.case_id, "note", event.target.value)} placeholder="Add review note" />
                  </label>
                  <div className="case-timeline">
                    {item.timeline.slice(-3).map((entry) => <span key={`${item.case_id}-${entry.label}-${entry.time}`}>{entry.label}</span>)}
                  </div>
                  <div className="toolrow compact-actions">
                    <button onClick={() => downloadCaseReport(item, "pdf")}>PDF</button>
                    <button onClick={() => downloadCaseReport(item, "csv")}>CSV</button>
                    <button onClick={() => downloadCaseReport(item, "html")}>HTML</button>
                  </div>
                </div>
              ))}
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
                      <button className="primary" onClick={() => runAnalysis(content, mode)} disabled={loading}>{loading ? "Scanning..." : analyzeLabel}</button>
                      {isQrMode && displayResult?.qr_analysis?.identity && (
                        <button type="button" onClick={verifyAndSaveQr} disabled={loading}>Verify &amp; Save QR</button>
                      )}
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
                  <p>{displayResult ? displayResult.what_we_found : "Run a scan to review links, urgency, sender intent, and credential risk."}</p>
                  <div className="simple-box">
                    <strong>Why It Is Dangerous</strong>
                    <p>{displayResult?.why_dangerous || "Verify payment, bank, and account alerts only through official apps."}</p>
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
                  <span>{liveShieldStatus}</span>
                </div>
                <i className="orbit-dot one" />
                <i className="orbit-dot two" />
                <i className="orbit-dot three" />
              </section>

              <section className="glass result-focus">
                <h2>{threatCardTitle}</h2>
                <div className={`gauge ${riskColor(score)}`} style={{ "--score": gaugeScore }}>
                  <div className="gauge-core">
                    <strong>{scoreDisplay}</strong>
                    <span>{riskLevelDisplay}</span>
                  </div>
                </div>
                <div className="score-stack">
                  <div><span>Confidence</span><strong>{confidenceDisplay}</strong></div>
                  <div><span>Rule Engine</span><strong>{ruleScoreDisplay}</strong></div>
                  <div><span>URL Analysis</span><strong>{urlScoreDisplay}</strong></div>
                  <div><span>Safety Score</span><strong>{safetyScoreDisplay}</strong></div>
                </div>
              </section>

              <section className="glass ai-card">
                <h2>BharatSHIELD Review</h2>
                <p className="typing">{isAnalyzingCurrentMode ? "Analyzing current QR payload..." : displayResult ? displayResult.how_sure : "Checks tone, links, urgency, identity clues, and safety actions."}</p>
                <ol>{(displayResult?.signals?.length ? displayResult.signals.slice(0, 5).map((item) => `${item.label}: ${item.reason}`) : scanSteps.slice(0, 5)).map((item) => <li key={item}>{item}</li>)}</ol>
                <div className={`safety-seal ${riskColor(score)}`}>
                  <strong>{isAnalyzingCurrentMode ? "Analyzing" : displayResult?.verification_failed ? "Review Required" : score >= 75 ? "Dangerous" : score >= 45 ? "Suspicious" : "Safe"}</strong>
                  <span>Verified by BharatSHIELD</span>
                </div>
              </section>
            </aside>
          </section>

          <section className={activeSection === "Scan" ? "explain-grid" : "explain-grid section-hidden"}>
            <div className="glass">
              <h2>Reason Breakdown</h2>
              <div className="reason-list">
                {(displayResult?.reason_breakdown || [
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
                {(displayResult?.url_checks?.length ? displayResult.url_checks : [{ domain: "No URL scanned", score: 0, checks: [{ label: "Status", result: "Paste or scan a URL to inspect domain reputation." }] }]).flatMap((url) => [
                  <div key={`${url.domain}-score`}><span>{url.domain}</span><strong>{url.score}% risk</strong></div>,
                  ...(url.checks || []).slice(0, 5).map((check) => <div key={`${url.domain}-${check.label}`}><span>{check.label}</span><strong>{check.result}</strong></div>),
                  url.domain_age ? <div key={`${url.domain}-age`}><span>Domain age</span><strong>{url.domain_age}</strong></div> : null,
                  url.safe_browsing ? <div key={`${url.domain}-safe`}><span>Safe Browsing</span><strong>{url.safe_browsing}</strong></div> : null,
                ].filter(Boolean))}
              </div>
            </div>

            <div className="glass">
              <h2>{isQrPanel ? "QR Security Analysis" : "QR / Call Deep Check"}</h2>
              {isQrPanel ? (
                <div className="qr-security-panel">
                  <div className="qr-section">
                    <h3>Identity Check</h3>
                    <div className="intel-list">
                      <div><span>Recipient Name</span><strong>{qrIdentityCheck?.recipient_name || qrIdentity?.recipient_name || displayResult?.qr_analysis?.merchant || "Not found"}</strong></div>
                      <div><span>UPI ID</span><strong>{qrIdentityCheck?.upi_id || displayResult?.qr_analysis?.upi_id || "Not found"}</strong></div>
                      <div><span>Phone (from UPI)</span><strong>{qrIdentityCheck?.phone_number || qrIdentity?.phone_number || "Not found"}</strong></div>
                      <div><span>Amount</span><strong>{qrIdentityCheck?.amount || displayResult?.qr_analysis?.amount || "Not found"}</strong></div>
                      <div><span>Payment Note</span><strong>{qrIdentityCheck?.payment_note || displayResult?.qr_analysis?.note || "Not found"}</strong></div>
                      <div><span>QR Fingerprint</span><strong>{qrIdentityCheck?.fingerprint || displayResult?.qr_analysis?.fingerprint || "Not generated"}</strong></div>
                      <div><span>Consistency</span><strong className={qrTamper?.tamper_detected ? "status-alert" : "status-ok"}>{qrIdentityCheck?.consistency_state || "Not assessed"}</strong></div>
                      <div><span>Recipient Reputation</span><strong>{displayResult?.qr_analysis?.recipient_reputation || "Unknown"}</strong></div>
                      <div><span>Previous Reports</span><strong>{displayResult?.qr_analysis?.previous_reports ?? 0}</strong></div>
                    </div>
                    {qrIdentityCheck?.ownership_disclaimer && (
                      <p className="ownership-disclaimer">{qrIdentityCheck.ownership_disclaimer}</p>
                    )}
                  </div>

                  {qrTamper?.tamper_detected ? (
                    <div className={`tamper-alert severity-${qrTamper.severity || "medium"}`}>
                      <h3>Changes Detected</h3>
                      <strong>{qrTamper.headline || qrTamper.change_status}</strong>
                      <p>{qrTamper.explanation || qrTamper.summary}</p>
                      {qrTamper.changes?.length > 0 && (
                        <ul className="tamper-changes">
                          {qrTamper.changes.map((change) => (
                            <li key={change.field}>
                              <span>{change.field}</span>
                              <strong>{change.previous} → {change.current}</strong>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ) : (
                    <div className="qr-section">
                      <h3>Tamper Check</h3>
                      <p>{qrTamper?.summary || "No previously user-verified QR baseline found for comparison."}</p>
                    </div>
                  )}

                  <div className="qr-section">
                    <h3>Recommendation</h3>
                    <p>
                      {qrTamper?.tamper_detected
                        ? "This QR differs from your verified baseline. Confirm payee details inside your UPI app before paying."
                        : displayResult?.qr_analysis?.recipient_reputation === "Unknown"
                          ? "Recipient is unknown. Verify payee identity in your UPI app before approving payment."
                          : "Verify recipient, amount, and purpose inside your UPI app before paying."}
                    </p>
                    {displayResult?.qr_analysis?.risk_signals?.length > 0 && (
                      <p className="risk-signals">Risk signals: {displayResult.qr_analysis.risk_signals.join("; ")}</p>
                    )}
                  </div>
                </div>
              ) : (
                <div className="intel-list">
                  <div><span>Recipient</span><strong>{displayResult?.qr_analysis?.upi_id || "Not found"}</strong></div>
                  <div><span>Merchant</span><strong>{displayResult?.qr_analysis?.merchant || "Not found"}</strong></div>
                  <div><span>Amount</span><strong>{displayResult?.qr_analysis?.amount || "Not found"}</strong></div>
                  <div><span>Payment Note</span><strong>{displayResult?.qr_analysis?.note || "Not found"}</strong></div>
                  <div><span>Destination URL</span><strong>{displayResult?.qr_analysis?.destination_url || "Not found"}</strong></div>
                  <div><span>Voice emotion</span><strong>{displayResult?.call_analysis?.emotion || "Not analyzed"}</strong></div>
                  <div><span>Pressure score</span><strong>{displayResult?.call_analysis?.pressure_score ?? 0}%</strong></div>
                  <div><span>Live warning</span><strong>{displayResult?.call_analysis?.live_warning ? "Disconnect immediately" : "No urgent warning"}</strong></div>
                </div>
              )}
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
              <p>Complaints supported till Jun 2026.</p>
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
                <p className="map-source">Regional scam alert index</p>
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
                      <input
                        type="tel"
                        value={guardianForm.mobile}
                        onChange={(event) => {
                          const mobile = event.target.value.replace(/\D/g, "").slice(0, 10);
                          setGuardianForm((form) => ({
                            ...form,
                            mobile,
                            otp: mobile === form.mobile ? form.otp : "",
                            sentOtp: "",
                            otpSent: false,
                          }));
                        }}
                        placeholder="Enter mobile number"
                        inputMode="numeric"
                        maxLength={10}
                      />
                      <div className="otp-row">
                        <input
                          type="text"
                          value={guardianForm.otp}
                          onChange={(event) => {
                            const otp = event.target.value.replace(/\D/g, "").slice(0, 6);
                            setGuardianForm((form) => ({ ...form, otp }));
                          }}
                          placeholder="Enter OTP"
                          inputMode="numeric"
                          maxLength={6}
                        />
                        <button
                          type="button"
                          disabled={!guardianOtp}
                          onClick={() => setGuardianForm((form) => ({ ...form, sentOtp: guardianOtp, otpSent: true }))}
                        >
                          Send OTP
                        </button>
                      </div>
                      <small>{guardianForm.otpSent ? `BharatSHIELD OTP sent to ${guardianMaskedMobile}` : "Enter a 10 digit number to receive OTP"}</small>
                    </div>
                    <div className="guardian-overlay">
                      <span>HIGH RISK</span>
                      <h2>This site imitates SBI</h2>
                      <p>{guardianForm.mobile || guardianForm.otp ? "Sensitive entry detected. Stop and use the official SBI app only." : "Do not enter mobile number, OTP, password, or UPI PIN on this page."}</p>
                      <div className="toolrow compact-actions">
                        <button className="danger-action" onClick={() => setGuardianForm({ mobile: "", otp: "", sentOtp: "", otpSent: false })}>Leave Site</button>
                        <button onClick={() => setActiveSection("Scan")}>View Details</button>
                      </div>
                    </div>
                  </div>
                  <div className="glass trust-meter-card">
                    <h2>Site Safety</h2>
                    <div className="trust-score">8/100</div>
                    <p>This page looks unsafe because it asks for OTP on a lookalike banking website.</p>
                    <div className="intel-list">
                      <div><span>Final action</span><strong>Leave site</strong></div>
                      <div><span>Do not share</span><strong>OTP or PIN</strong></div>
                      <div><span>Next step</span><strong>Use official app</strong></div>
                    </div>
                  </div>
                  <div className="glass">
                    <h2>Why Blocked</h2>
                    <div className="blocked-list">
                      <span>Fake banking login</span>
                      <span>OTP request</span>
                      <span>Hidden redirect</span>
                      <span>Brand lookalike</span>
                    </div>
                    <p className="secure-note">Verified by BharatSHIELD</p>
                  </div>
                </div>
                <div className="ecosystem-grid">
                  <div className="glass">
                    <h2>What Happened</h2>
                    <div className="timeline-list compact-timeline">
                      {guardianTimeline.map((item, index) => <div key={item}><span>Step {index + 1}</span><strong>{item}</strong><em>{index >= 3 ? "High" : "Review"}</em></div>)}
                    </div>
                  </div>
                  <div className="glass">
                    <h2>QR Sandbox Preview</h2>
                    <p>QR links open in preview first. User sees destination, UPI ID, amount, and risk before continuing.</p>
                    <div className="toolrow compact-actions">
                      <button onClick={() => { setMode("qr"); setActiveSection("Scan"); }}>Check QR</button>
                      <button onClick={() => setActiveSection("Report Scam")}>Report</button>
                    </div>
                  </div>
                  <div className="glass">
                    <h2>Protection Channels</h2>
                    <div className="roadmap-list">{protectionChannels.map(([title, detail]) => <div key={title}><strong>{title}</strong><p>{detail}</p></div>)}</div>
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
                    <div className="secure-note">Report ID: {incidentId}</div>
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
                    <p className="secure-note">Correct: Scam. Never share OTP, PIN, password, or approve unknown payment requests.</p>
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

            {activeSection === "Scam Awareness" && (
              <>
                <div className="section-head wide-head"><h2>Scam Awareness Alerts</h2><button>Curated Alerts</button></div>
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
                    <h2>Privacy Permissions</h2>
                    <p>BharatSHIELD does not request these permissions for scanning:</p>
                    <div className="permission-grid">{deniedPermissions.map((item) => <span key={item}>No {item}</span>)}</div>
                  </div>
                  <div className="glass">
                    <h2>Safe Uploads</h2>
                    <p>Allowed files: jpg, png, pdf, txt, mp3, wav, m4a. Executables, APKs, batch files, and zip archives are blocked.</p>
                    <p className="secure-note">Files are only used for the selected scan or report draft in this demo flow.</p>
                  </div>
                  <div className="glass">
                    <h2>Account Safety</h2>
                    <p>Use a strong password, keep alerts on, and report high-risk scans immediately.</p>
                    <div className="toolrow compact-actions"><button onClick={() => setActiveSection("Emergency")}>Emergency Help</button><button onClick={() => setActiveSection("Report Scam")}>Report Scam</button></div>
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
              <div><span>Risk</span><strong>{scoreDisplay}</strong></div>
              <div><span>Confidence</span><strong>{confidenceDisplay}</strong></div>
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
