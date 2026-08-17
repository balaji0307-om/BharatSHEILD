import {
  buildIdentityCheck,
  compareIdentity,
  displayPayeeName,
  getVerifiedQrBaseline,
  OWNERSHIP_DISCLAIMER,
  saveVerifiedQrBaseline,
  tamperRiskBoost,
} from "./qrIdentity.mjs";

const PRESSURE_TERMS = ["kyc", "refund", "verify", "blocked", "fee", "urgent", "registration"];
const MERCHANT_SUSPICIOUS_TERMS = ["refund", "support", "kyc", "verification", "bank", "helpdesk"];
const SUSPICIOUS_UPI_TERMS = ["fake", "refund", "support", "verify", "kyc", "helpdesk", "customer"];
const UPI_ID_PATTERN = /^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z][a-zA-Z0-9.\-_]{2,}$/;
const HANDLE_PATTERN = /^[a-zA-Z][a-zA-Z0-9.\-_]{2,}$/;

function clamp(value) {
  return Math.max(0, Math.min(99, Number.isFinite(Number(value)) ? Number(value) : 0));
}

function deterministicFingerprint(text) {
  let hashA = 0x811c9dc5;
  let hashB = 0x01000193;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    hashA = Math.imul(hashA ^ code, 16777619);
    hashB = Math.imul(hashB ^ (code + index), 2246822519);
  }
  return `BS-QR-${(`${(hashA >>> 0).toString(16)}${(hashB >>> 0).toString(16)}`).padStart(16, "0").slice(0, 8).toUpperCase()}`;
}

function normalizeName(name) {
  try {
    return decodeURIComponent(name || "").trim().replace(/\s+/g, " ");
  } catch {
    return String(name || "").trim().replace(/\s+/g, " ");
  }
}

function parseUpiFields(text) {
  const raw = String(text || "").trim();
  const url = new URL(raw);
  const upiId = url.searchParams.get("pa") || "";
  const merchant = normalizeName(url.searchParams.get("pn") || "");
  const amount = url.searchParams.get("am") || "";
  const note = normalizeName(url.searchParams.get("tn") || "");
  const [local = "", handle = ""] = upiId.split("@");
  const scheme = url.protocol.replace(":", "").toLowerCase();
  return {
    raw,
    scheme,
    upiId,
    merchant: merchant || "Not found",
    amount: amount || "Not found",
    note: note || "Not found",
    upiHandle: handle,
    localPart: local,
    destinationUrl: scheme === "http" || scheme === "https" ? raw : "Not found",
    hiddenRedirect: scheme === "http" || scheme === "https",
  };
}

function buildIdentity(fields) {
  const upiId = fields.upiId || "Not found";
  const merchant = fields.merchant || "Not found";
  const amount = fields.amount || "Not found";
  const note = fields.note || "Not found";
  const destinationUrl = fields.destinationUrl || "Not found";
  const normalized = [upiId, merchant, amount, note, destinationUrl].map((value) => String(value).toLowerCase()).join("|");
  const phone = /^\d{10,}$/.test(fields.localPart || "") ? String(fields.localPart).slice(-10) : "Not found";
  return {
    recipient_name: merchant,
    recipient_name_normalized: merchant.toLowerCase(),
    upi_id: upiId,
    upi_id_normalized: upiId.toLowerCase(),
    phone_number: phone,
    amount,
    amount_normalized: amount,
    payment_note: note,
    note_normalized: note.toLowerCase(),
    destination_url: destinationUrl,
    fingerprint: deterministicFingerprint(normalized),
    payload_consistent: upiId !== "Not found" && UPI_ID_PATTERN.test(upiId),
    verified_at: null,
    user_verified: false,
  };
}

function inspectUrlLocal(rawUrl) {
  let url = String(rawUrl || "").trim();
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { score: 60, domain: "Invalid", checks: [{ label: "URL format", result: "Invalid URL" }] };
  }
  const domain = parsed.hostname.toLowerCase();
  let score = 12;
  const checks = [];
  if (parsed.protocol !== "https:") { score += 15; checks.push({ label: "No HTTPS", result: "Risky" }); }
  if (/[0-9]/.test(domain)) { score += 12; checks.push({ label: "Digits in domain", result: "Suspicious" }); }
  if (domain.includes("-")) { score += 8; checks.push({ label: "Hyphenated domain", result: "Review carefully" }); }
  if (/\.(xyz|top|click|shop|info|loan|work)$/i.test(domain)) { score += 15; checks.push({ label: "Risky TLD", result: "Common in throwaway sites" }); }
  for (const fake of ["amaz0n", "paytm-login", "sbi-verify", "hdfc-verify"]) {
    if (domain.includes(fake)) { score += 22; checks.push({ label: "Lookalike brand", result: "Possible impersonation" }); break; }
  }
  if (!checks.length) checks.push({ label: "Basic URL checks", result: "No obvious red flags" });
  return { score: clamp(score), domain, checks };
}

export function countLocalPayeeReports(upiId) {
  try {
    const cases = JSON.parse(localStorage.getItem("bharatshield_cases") || "[]");
    const key = String(upiId || "").trim().toLowerCase();
    if (!key) return 0;
    return cases.filter((item) => String(item.ai_result?.qr_analysis?.upi_id || "").trim().toLowerCase() === key).length;
  } catch {
    return 0;
  }
}

export async function inspectQrPayloadLocal(text, verifiedBaseline = null) {
  try {
    const fields = parseUpiFields(text);
    const identity = buildIdentity(fields);
    let tamper;
    try {
      tamper = compareIdentity(identity, verifiedBaseline ?? getVerifiedQrBaseline());
    } catch {
      tamper = { tamper_detected: false, change_status: "Comparison unavailable", severity: "none", summary: "No verified baseline comparison was available.", changes: [], current: identity };
    }
    const identityCheck = buildIdentityCheck(identity, tamper);
    const checks = [];
    const riskSignals = [];
    let score = 0;

    if (fields.scheme === "upi") checks.push({ label: "Payload", result: "Valid UPI payment intent" });
    else if (fields.hiddenRedirect) {
      const inspection = inspectUrlLocal(fields.raw);
      score += inspection.score;
      riskSignals.push("QR opens a website link");
      checks.push({ label: "Destination URL", result: fields.destinationUrl });
      for (const check of inspection.checks.slice(0, 3)) checks.push({ label: `URL ${check.label}`, result: check.result });
    } else {
      score += 6;
      checks.push({ label: "Payload", result: "Non-UPI QR content" });
    }

    if (fields.upiId) {
      const valid = UPI_ID_PATTERN.test(fields.upiId);
      checks.push({ label: "Recipient", result: fields.upiId });
      checks.push({ label: "UPI format", result: valid ? "Valid structure" : "Invalid or unusual" });
      if (!valid) { score += 18; riskSignals.push("Recipient UPI format is unusual"); }
      if (SUSPICIOUS_UPI_TERMS.some((term) => fields.upiId.toLowerCase().includes(term))) { score += 24; riskSignals.push("Recipient UPI ID contains a suspicious term"); }
      if (fields.upiHandle && (!HANDLE_PATTERN.test(fields.upiHandle) || SUSPICIOUS_UPI_TERMS.some((term) => fields.upiHandle.toLowerCase().includes(term)))) {
        score += 14;
        riskSignals.push("UPI provider handle is malformed or unusual");
      }
    } else if (fields.scheme === "upi") {
      score += 22;
      riskSignals.push("UPI QR has no recipient field");
    }

    if (fields.amount !== "Not found") {
      checks.push({ label: "Amount", result: `INR ${fields.amount}` });
      const value = Number.parseFloat(fields.amount);
      if (!Number.isFinite(value)) { score += 8; riskSignals.push("Amount is not a clean number"); }
      else if (value >= 5000) { score += 16; riskSignals.push("High payment amount"); }
      else if (value >= 1000) { score += 10; riskSignals.push("Moderate payment amount"); }
    } else checks.push({ label: "Amount", result: "Not prefilled" });

    if (fields.merchant !== "Not found") {
      checks.push({ label: "Merchant name", result: fields.merchant });
      if (MERCHANT_SUSPICIOUS_TERMS.some((term) => fields.merchant.toLowerCase().includes(term))) { score += 20; riskSignals.push("Merchant name uses refund/support/KYC terms"); }
    } else checks.push({ label: "Merchant name", result: "Not provided" });

    if (fields.note !== "Not found") {
      checks.push({ label: "Payment note", result: fields.note });
      if (PRESSURE_TERMS.some((term) => fields.note.toLowerCase().includes(term))) { score += 22; riskSignals.push("Payment note contains pressure or verification terms"); }
    } else checks.push({ label: "Payment note", result: "Not provided" });

    if (["otp", "pin", "password"].some((term) => fields.raw.toLowerCase().includes(term))) {
      score += 26;
      riskSignals.push("QR payload references OTP/PIN/password");
    }

    if (tamper.tamper_detected) {
      score += tamperRiskBoost(tamper);
      riskSignals.push(tamper.change_status || "QR payload changed from verified baseline");
      if (tamper.headline) riskSignals.push(tamper.headline);
    }

    const previousReports = countLocalPayeeReports(fields.upiId);
    if (previousReports) {
      score += Math.min(30, 12 + previousReports * 6);
      riskSignals.push(`Recipient matched ${previousReports} previous BharatSHIELD case(s)`);
    }
    checks.push({ label: "Previous BharatSHIELD reports", result: String(previousReports) });
    checks.push({ label: "QR fingerprint", result: identity.fingerprint });

    let reputation = "Not applicable";
    if (fields.upiId) reputation = riskSignals.length ? "Review" : "Unknown";
    if (SUSPICIOUS_UPI_TERMS.some((term) => fields.upiId.toLowerCase().includes(term)) || previousReports) reputation = "Suspicious";
    checks.push({ label: "Recipient reputation", result: reputation === "Unknown" ? "Unknown — not verified safe" : reputation });

    return {
      score: clamp(score), upi_id: fields.upiId || "Not found", merchant: fields.merchant, amount: fields.amount, note: fields.note,
      destination_url: fields.destinationUrl, recipient_reputation: reputation, previous_reports: previousReports,
      fingerprint: identity.fingerprint, risk_signals: riskSignals, hidden_redirect: fields.hiddenRedirect, checks,
      identity, identity_check: identityCheck, tamper_check: tamper,
    };
  } catch {
    return null;
  }
}

export async function buildLocalQrAnalysisResult(text, verifiedBaseline = null) {
  let qrAnalysis = await inspectQrPayloadLocal(text, verifiedBaseline);
  if (!qrAnalysis) {
    // Last-resort deterministic payload extraction. This must never surface as a generic failure.
    try {
      const fields = parseUpiFields(text);
      const identity = buildIdentity(fields);
      qrAnalysis = {
        score: 18,
        upi_id: fields.upiId || "Not found",
        merchant: fields.merchant,
        amount: fields.amount,
        note: fields.note,
        destination_url: fields.destinationUrl,
        recipient_reputation: fields.upiId ? "Unknown" : "Not applicable",
        previous_reports: 0,
        fingerprint: identity.fingerprint,
        risk_signals: ["Local QR payload parsed successfully; independent reputation verification is unavailable."],
        hidden_redirect: fields.hiddenRedirect,
        checks: [{ label: "Status", result: "Local QR parsing completed" }],
        identity,
        identity_check: { consistency_state: "Unknown — Not Independently Verified" },
        tamper_check: { tamper_detected: false, severity: "none", changes: [] },
      };
    } catch {
      throw new Error("Could not read the QR payload.");
    }
  }

  const tamper = qrAnalysis.tamper_check || {};
  const score = clamp(qrAnalysis.score);
  const risk = score >= 75 ? "Critical" : score >= 55 ? "High" : score >= 30 ? "Medium" : "Low";
  const confidence = score === 0 ? 62 : clamp(Math.max(55, Math.min(98, score + 12)));
  const signals = (qrAnalysis.risk_signals || []).map((reason) => ({ label: "QR payment", reason }));
  if (tamper.tamper_detected) signals.unshift({ label: "QR tamper check", reason: tamper.headline || tamper.change_status });

  const recommendations = [
    OWNERSHIP_DISCLAIMER,
    "Verify recipient, merchant, amount, and purpose inside your UPI app before paying.",
    "Never share OTP, UPI PIN, passwords, or card details.",
  ];
  if (tamper.tamper_detected) recommendations.push("This QR differs from your verified baseline. Confirm payee details before paying.");
  else if (qrAnalysis.recipient_reputation === "Unknown") recommendations.push("Unknown recipient — not verified safe. Confirm payee identity before payment.");

  return {
    score, risk, confidence, rule_score: score, url_score: qrAnalysis.hidden_redirect ? score : null, safety_score: 100 - score,
    scam_type: tamper.tamper_detected ? (tamper.severity === "high" ? "QR Identity Tampering" : "QR Tamper Review") : (qrAnalysis.upi_id !== "Not found" ? (score >= 55 ? "UPI QR Fraud Risk" : "UPI QR Review") : "QR Review"),
    signals, recommendations,
    reason_breakdown: [
      { label: "Message language", score: 0, why: "QR payload was reviewed separately." },
      { label: "Urgency and pressure", score: PRESSURE_TERMS.some((term) => String(qrAnalysis.note).toLowerCase().includes(term)) ? 82 : 16, why: "Payment note pressure terms are reviewed." },
      { label: "Credential risk", score: signals.some((item) => /otp|pin|password/i.test(item.reason)) ? 92 : 12, why: "Checks for OTP, PIN, and password references." },
      { label: "URL / QR risk", score, why: "UPI payload, amount, merchant, and destination were reviewed." },
    ],
    url_checks: qrAnalysis.hidden_redirect ? [{ domain: qrAnalysis.destination_url, score, checks: [{ label: "Status", result: "QR destination reviewed locally" }] }] : [],
    qr_analysis: qrAnalysis,
    call_analysis: { emotion: "Not analyzed", pressure_score: 0, live_warning: score >= 70 },
    what_we_found: tamper.tamper_detected ? `${tamper.headline || tamper.change_status}: ${tamper.explanation || tamper.summary}` : `QR payment review for recipient ${qrAnalysis.upi_id}, merchant ${qrAnalysis.merchant}, amount ${qrAnalysis.amount}, note ${qrAnalysis.note}.`,
    why_dangerous: tamper.tamper_detected ? (tamper.explanation || tamper.summary) : (qrAnalysis.risk_signals?.length ? `Risk signals: ${qrAnalysis.risk_signals.slice(0, 4).join("; ")}.` : "Recipient reputation is unknown. Verify the payee inside your UPI app before paying."),
    how_sure: `${confidence}% confidence based on local QR payload checks.`,
    local_review: true,
  };
}

export { getVerifiedQrBaseline, saveVerifiedQrBaseline, OWNERSHIP_DISCLAIMER };
