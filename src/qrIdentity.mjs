const PHONE_UPI_LOCAL_PATTERN = /^\d{8,}$/;

export const OWNERSHIP_DISCLAIMER =
  "BharatSHIELD cannot independently prove bank-account ownership from a QR payload alone.";

export function normalizePayeeName(name) {
  const decoded = decodeURIComponent(name || "").trim();
  return decoded.replace(/\s+/g, " ").toLowerCase();
}

export function displayPayeeName(name) {
  try {
    const decoded = decodeURIComponent(name || "").trim();
    return decoded.replace(/\s+/g, " ") || "Not found";
  } catch {
    return String(name || "").trim() || "Not found";
  }
}

export function extractPhoneFromUpi(upiId) {
  const [local = ""] = (upiId || "").split("@");
  const digits = local.replace(/\D/g, "");
  if (PHONE_UPI_LOCAL_PATTERN.test(local) && digits.length >= 10) {
    return digits.slice(-10);
  }
  return null;
}

export async function buildIdentityFingerprint(upiId, merchant, amount, note, destinationUrl = "") {
  const normalized = [
    (upiId || "").trim().toLowerCase(),
    normalizePayeeName(merchant),
    (amount || "").trim(),
    (note || "").trim().toLowerCase(),
    destinationUrl && destinationUrl !== "Not found" ? destinationUrl.trim().toLowerCase() : "",
  ].join("|");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized));
  const prefix = Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 8)
    .toUpperCase();
  return `BS-QR-${prefix}`;
}

export async function buildIdentityRecord(upiId, merchant, amount, note, destinationUrl = "") {
  const upiValid = /^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z][a-zA-Z0-9.\-_]{2,}$/.test(upiId || "");
  const phone = extractPhoneFromUpi(upiId);
  let paymentNote = "Not found";
  try {
    paymentNote = note ? decodeURIComponent(note).trim() : "Not found";
  } catch {
    paymentNote = note || "Not found";
  }
  return {
    recipient_name: displayPayeeName(merchant),
    recipient_name_normalized: normalizePayeeName(merchant),
    upi_id: upiId || "Not found",
    upi_id_normalized: (upiId || "").trim().toLowerCase(),
    phone_number: phone || "Not found",
    amount: amount || "Not found",
    amount_normalized: (amount || "").trim(),
    payment_note: paymentNote,
    note_normalized: (note || "").trim().toLowerCase(),
    destination_url: destinationUrl || "Not found",
    fingerprint: await buildIdentityFingerprint(upiId, merchant, amount, note, destinationUrl),
    payload_consistent: upiValid && Boolean(upiId),
    verified_at: null,
    user_verified: false,
  };
}

function consistencyState(identity, userVerified = false) {
  if (userVerified) return "User Verified Baseline";
  if (identity.payload_consistent) return "Payload Consistent";
  return "Unknown — Not Independently Verified";
}

export function compareIdentity(current, baseline) {
  if (!baseline) {
    return {
      tamper_detected: false,
      change_status: "No Verified Baseline",
      severity: "none",
      summary: "No previously user-verified QR baseline found for comparison.",
      changes: [],
      previous: null,
      current,
      headline: "",
      explanation: "",
    };
  }

  if (current.fingerprint === baseline.fingerprint) {
    return {
      tamper_detected: false,
      change_status: "Matches Verified Baseline",
      severity: "none",
      summary: "Current QR matches the previously user-verified QR baseline.",
      changes: [],
      previous: baseline,
      current,
      headline: "",
      explanation: "",
    };
  }

  const upiChanged = current.upi_id_normalized !== baseline.upi_id_normalized;
  const nameChanged = current.recipient_name_normalized !== baseline.recipient_name_normalized;
  const amountChanged = current.amount_normalized !== baseline.amount_normalized;
  const noteChanged = current.note_normalized !== baseline.note_normalized;
  const urlChanged = (
    current.destination_url !== baseline.destination_url
    && current.destination_url !== "Not found"
    && baseline.destination_url !== "Not found"
  );

  const changes = [];
  if (upiChanged) changes.push({ field: "Recipient / UPI ID", previous: baseline.upi_id, current: current.upi_id });
  if (nameChanged) changes.push({ field: "Recipient Name", previous: baseline.recipient_name, current: current.recipient_name });
  if (amountChanged) changes.push({ field: "Amount", previous: baseline.amount, current: current.amount });
  if (noteChanged) changes.push({ field: "Payment Note", previous: baseline.payment_note, current: current.payment_note });
  if (urlChanged) changes.push({ field: "Destination URL", previous: baseline.destination_url, current: current.destination_url });

  let changeStatus = "Payload Changed";
  let severity = amountChanged ? "medium" : "low";
  let headline = "QR Payload Changed";
  if (upiChanged && nameChanged) {
    changeStatus = "Recipient Identity Changed";
    severity = "high";
    headline = "Recipient Identity Changed";
  } else if (upiChanged) {
    changeStatus = "Recipient Changed";
    severity = "medium";
    headline = "QR Tampering / Recipient Change Detected";
  } else if (nameChanged) {
    changeStatus = "Payee Name Changed";
    severity = "medium";
    headline = "Payee Name Changed";
  }

  const explanation = upiChanged || nameChanged
    ? "The recipient information encoded in this QR differs from the previously verified QR."
    : "This QR payload differs from the previously user-verified QR baseline.";

  return {
    tamper_detected: changes.length > 0,
    change_status: changeStatus,
    severity,
    summary: explanation,
    changes,
    previous: baseline,
    current,
    headline,
    explanation,
  };
}

export function tamperRiskBoost(tamper) {
  if (!tamper?.tamper_detected) return 0;
  let boost = 0;
  if (tamper.change_status === "Recipient Identity Changed") boost += 35;
  else if (tamper.change_status === "Recipient Changed") boost += 25;
  else if (tamper.change_status === "Payee Name Changed") boost += 15;
  else if (tamper.change_status === "Payload Changed") boost += 10;

  for (const change of tamper.changes || []) {
    if (change.field === "Amount") {
      const previous = Number.parseFloat(String(change.previous).replace(/[^\d.]/g, ""));
      const current = Number.parseFloat(String(change.current).replace(/[^\d.]/g, ""));
      if (Number.isFinite(current) && current >= 5000 && current > (previous || 0)) boost += 16;
      else if (Number.isFinite(current) && current >= 1000 && current > (previous || 0)) boost += 10;
    }
  }
  return boost;
}

export function buildIdentityCheck(identity, tamper, userVerified = false) {
  const checks = {
    recipient_name: identity.payload_consistent && identity.recipient_name !== "Not found",
    upi_id: identity.payload_consistent,
    phone_number: identity.phone_number !== "Not found",
    fingerprint: Boolean(identity.fingerprint),
  };
  if (tamper.tamper_detected) {
    if (["Recipient Changed", "Recipient Identity Changed"].includes(tamper.change_status)) checks.upi_id = false;
    if (["Payee Name Changed", "Recipient Identity Changed"].includes(tamper.change_status)) checks.recipient_name = false;
  }
  return {
    recipient_name: identity.recipient_name,
    upi_id: identity.upi_id,
    phone_number: identity.phone_number,
    amount: identity.amount,
    payment_note: identity.payment_note,
    fingerprint: identity.fingerprint,
    consistency_state: consistencyState(identity, userVerified),
    checks,
    ownership_disclaimer: OWNERSHIP_DISCLAIMER,
    tamper,
  };
}

const VERIFIED_QR_KEY = "bharatshield_verified_qr";

export function getVerifiedQrBaseline() {
  try {
    const raw = localStorage.getItem(VERIFIED_QR_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function saveVerifiedQrBaseline(identity) {
  const baseline = {
    ...identity,
    user_verified: true,
    verified_at: new Date().toISOString(),
  };
  localStorage.setItem(VERIFIED_QR_KEY, JSON.stringify(baseline));
  return baseline;
}
