const SUSPICIOUS_UPI_TERMS = ["fake", "refund", "support", "verify", "kyc", "helpdesk", "customer"];
const PRESSURE_TERMS = ["kyc", "refund", "verify", "blocked", "fee", "urgent", "registration"];
const MERCHANT_SUSPICIOUS_TERMS = ["refund", "support", "kyc", "verification", "bank", "helpdesk"];
const UPI_ID_PATTERN = /^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z][a-zA-Z0-9.\-_]{2,}$/;
const HANDLE_PATTERN = /^[a-zA-Z][a-zA-Z0-9.\-_]{2,}$/;

function clamp(value) {
  return Math.max(0, Math.min(99, value));
}

async function sha256Prefix(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 8)
    .toUpperCase();
}

function parseUpiFields(text) {
  const raw = text.trim();
  const url = new URL(raw);
  const upiId = url.searchParams.get("pa") || "";
  const merchant = url.searchParams.get("pn") || "";
  const amount = url.searchParams.get("am") || "";
  const note = url.searchParams.get("tn") || "";
  const [, , upiHandle = ""] = upiId.split("@");
  return {
    raw,
    scheme: url.protocol.replace(":", ""),
    host: url.host,
    pathname: url.pathname,
    upiId,
    merchant,
    amount,
    note,
    upiHandle,
    destinationUrl: url.protocol === "http:" || url.protocol === "https:" ? raw : "",
    hiddenRedirect: url.protocol === "http:" || url.protocol === "https:",
  };
}

function inspectUrlLocal(rawUrl) {
  let url = rawUrl.trim();
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { score: 30, checks: [{ label: "URL format", result: "Invalid URL" }] };
  }
  const domain = parsed.hostname.toLowerCase();
  let score = 12;
  const checks = [];
  if (parsed.protocol !== "https:") {
    score += 15;
    checks.push({ label: "No HTTPS", result: "Risky" });
  }
  if (/[0-9]/.test(domain)) {
    score += 12;
    checks.push({ label: "Digits in domain", result: "Suspicious" });
  }
  if (domain.includes("-")) {
    score += 8;
    checks.push({ label: "Hyphenated domain", result: "Review carefully" });
  }
  if (/\.(xyz|top|click|shop|info|loan|work)$/i.test(domain)) {
    score += 15;
    checks.push({ label: "Risky TLD", result: "Common in throwaway sites" });
  }
  for (const fake of ["amaz0n", "paytm-login", "sbi-verify", "hdfc-verify"]) {
    if (domain.includes(fake)) {
      score += 22;
      checks.push({ label: "Lookalike brand", result: "Possible impersonation" });
      break;
    }
  }
  if (!checks.length) checks.push({ label: "Basic URL checks", result: "No obvious red flags" });
  return { score: clamp(score), domain, checks };
}

export function countLocalPayeeReports(upiId) {
  try {
    const cases = JSON.parse(localStorage.getItem("bharatshield_cases") || "[]");
    const upiKey = (upiId || "").trim().toLowerCase();
    if (!upiKey) return 0;
    return cases.filter((item) => {
      const qrUpi = String(item.ai_result?.qr_analysis?.upi_id || "").trim().toLowerCase();
      if (qrUpi && qrUpi === upiKey) return true;
      const input = String(item.input || "").trim().toLowerCase();
      return input.startsWith("upi://") && input.includes(`pa=${upiKey}`);
    }).length;
  } catch {
    return 0;
  }
}

export async function inspectQrPayloadLocal(text) {
  try {
    const fields = parseUpiFields(text);
    const {
      raw,
      scheme,
      host,
      pathname,
      upiId,
      merchant,
      amount,
      note,
      upiHandle,
      destinationUrl,
      hiddenRedirect,
    } = fields;
    const loweredPayload = [raw, upiId, merchant, note].join(" ").toLowerCase();
    const normalized = [scheme, upiId, merchant, amount, note, host, pathname].join("|").toLowerCase();
    const fingerprint = `BS-QR-${await sha256Prefix(normalized)}`;
    const checks = [];
    const riskSignals = [];
    let score = 0;
    let handleUnusual = false;

    if (scheme === "upi") {
      checks.push({ label: "Payload", result: "Valid UPI payment intent" });
    } else if (scheme === "http" || scheme === "https") {
      checks.push({ label: "Payload", result: "Website link inside QR" });
      const urlInspection = inspectUrlLocal(raw);
      score += urlInspection.score;
      riskSignals.push("QR opens a website link");
      checks.push({ label: "Destination URL", result: destinationUrl });
      if (urlInspection.score >= 45) riskSignals.push("Suspicious destination URL detected");
      for (const check of urlInspection.checks.slice(0, 3)) {
        checks.push({ label: `URL ${check.label}`, result: check.result });
      }
    } else if (raw) {
      checks.push({ label: "Payload", result: "Non-UPI QR content" });
      score += 6;
    }

    if (upiId) {
      const upiValid = UPI_ID_PATTERN.test(upiId);
      checks.push({ label: "Recipient", result: upiId });
      checks.push({ label: "UPI format", result: upiValid ? "Valid structure" : "Invalid or unusual" });
      if (!upiValid) {
        score += 18;
        riskSignals.push("Recipient UPI format is unusual");
      }
      if (SUSPICIOUS_UPI_TERMS.some((term) => upiId.toLowerCase().includes(term))) {
        score += 24;
        riskSignals.push("Recipient name contains support/refund/KYC terms");
      }
      handleUnusual = Boolean(upiHandle) && (
        !HANDLE_PATTERN.test(upiHandle)
        || SUSPICIOUS_UPI_TERMS.some((term) => upiHandle.toLowerCase().includes(term))
      );
      if (handleUnusual) {
        score += 14;
        riskSignals.push("UPI provider handle is malformed or unusual");
      }
    } else if (scheme === "upi") {
      score += 22;
      riskSignals.push("UPI QR has no recipient field");
    }

    if (amount) {
      checks.push({ label: "Amount", result: `INR ${amount}` });
      const amountValue = Number.parseFloat(amount);
      if (!Number.isFinite(amountValue)) {
        score += 8;
        riskSignals.push("Amount is not a clean number");
      } else if (amountValue >= 5000) {
        score += 16;
        riskSignals.push("High payment amount");
      } else if (amountValue >= 1000) {
        score += 10;
        riskSignals.push("Moderate payment amount");
      }
    } else {
      checks.push({ label: "Amount", result: "Not prefilled" });
    }

    if (merchant) {
      checks.push({ label: "Merchant name", result: merchant });
      if (MERCHANT_SUSPICIOUS_TERMS.some((term) => merchant.toLowerCase().includes(term))) {
        score += 20;
        riskSignals.push("Merchant name uses refund/support/KYC terms");
      }
    } else {
      checks.push({ label: "Merchant name", result: "Not provided" });
    }

    if (note) {
      checks.push({ label: "Payment note", result: note });
      if (PRESSURE_TERMS.some((term) => note.toLowerCase().includes(term))) {
        score += 22;
        riskSignals.push("Payment note contains pressure or verification terms");
      }
    } else {
      checks.push({ label: "Payment note", result: "Not provided" });
    }

    if (["otp", "pin", "password"].some((term) => loweredPayload.includes(term))) {
      score += 26;
      riskSignals.push("QR payload references OTP/PIN/password");
    }

    const previousReports = countLocalPayeeReports(upiId);
    if (previousReports) {
      score += Math.min(30, 12 + previousReports * 6);
      riskSignals.push(`Recipient matched ${previousReports} previous BharatSHIELD case(s)`);
    }
    checks.push({ label: "Previous BharatSHIELD reports", result: String(previousReports) });
    checks.push({ label: "QR fingerprint", result: fingerprint });

    const recipientSpecificSuspicion = previousReports > 0 || (
      Boolean(upiId) && (
        SUSPICIOUS_UPI_TERMS.some((term) => upiId.toLowerCase().includes(term))
        || handleUnusual
      )
    );

    let reputation;
    if (recipientSpecificSuspicion) {
      reputation = "Suspicious";
      checks.push({ label: "Recipient reputation", result: "Suspicious pattern" });
    } else if (upiId && riskSignals.length) {
      reputation = "Review";
      checks.push({ label: "Recipient reputation", result: "Needs manual verification" });
    } else if (upiId) {
      reputation = "Unknown";
      checks.push({ label: "Recipient reputation", result: "Unknown — not verified safe" });
    } else {
      reputation = "Not applicable";
    }

    return {
      score: clamp(score),
      upi_id: upiId || "Not found",
      merchant: merchant || "Not found",
      amount: amount || "Not found",
      note: note || "Not found",
      destination_url: destinationUrl || "Not found",
      recipient_reputation: reputation,
      previous_reports: previousReports,
      fingerprint,
      risk_signals: riskSignals,
      hidden_redirect: hiddenRedirect,
      checks,
    };
  } catch {
    return null;
  }
}

export async function buildLocalQrAnalysisResult(text) {
  const qrAnalysis = await inspectQrPayloadLocal(text);
  if (!qrAnalysis) throw new Error("Could not parse QR payload.");

  const score = qrAnalysis.score;
  const risk = score >= 75 ? "Critical" : score >= 55 ? "High" : score >= 30 ? "Medium" : "Low";
  const confidence = score === 0 ? 62 : clamp(Math.max(55, Math.min(98, score + 12)));
  const signals = qrAnalysis.risk_signals.map((reason) => ({ label: "QR payment", reason }));

  return {
    score,
    risk,
    confidence,
    rule_score: score,
    url_score: qrAnalysis.hidden_redirect ? score : null,
    safety_score: 100 - score,
    scam_type: qrAnalysis.upi_id !== "Not found" ? (score >= 55 ? "UPI QR Fraud Risk" : "UPI QR Review") : "QR Review",
    signals,
    recommendations: [
      "Verify recipient, merchant, amount, and purpose inside your UPI app before paying.",
      "Never share OTP, UPI PIN, passwords, or card details.",
      qrAnalysis.recipient_reputation === "Unknown"
        ? "Unknown recipient — not verified safe. Confirm payee identity before payment."
        : "Do not approve payment if the sender is pressuring you.",
    ],
    reason_breakdown: [
      { label: "Message language", score: 0, why: "QR payload language was reviewed locally." },
      { label: "Urgency and pressure", score: PRESSURE_TERMS.some((term) => `${qrAnalysis.note}`.toLowerCase().includes(term)) ? 82 : 16, why: "Payment note pressure terms are reviewed." },
      { label: "Credential risk", score: qrAnalysis.risk_signals.some((item) => /otp|pin|password/i.test(item)) ? 92 : 12, why: "Checks for OTP, PIN, and password references." },
      { label: "URL / QR risk", score: Math.max(score, qrAnalysis.hidden_redirect ? 45 : score), why: "UPI payload, amount, merchant, and destination URL were reviewed." },
    ],
    url_checks: qrAnalysis.hidden_redirect
      ? [{ domain: qrAnalysis.destination_url, score, checks: [{ label: "Status", result: "QR destination reviewed locally" }] }]
      : [],
    qr_analysis: qrAnalysis,
    call_analysis: { emotion: "Not analyzed", pressure_score: 0, live_warning: score >= 70 },
    what_we_found: `QR payment review for recipient ${qrAnalysis.upi_id}, merchant ${qrAnalysis.merchant}, amount ${qrAnalysis.amount}, note ${qrAnalysis.note}.`,
    why_dangerous: qrAnalysis.risk_signals.length
      ? `Risk signals: ${qrAnalysis.risk_signals.slice(0, 4).join("; ")}.`
      : "Recipient reputation is unknown. Verify the payee inside your UPI app before paying.",
    how_sure: `${confidence}% confidence based on local QR payload checks.`,
    local_review: true,
  };
}
