import hashlib
import re
from typing import Any
from urllib.parse import unquote

PHONE_UPI_LOCAL_PATTERN = re.compile(r"^\d{8,}$")
UPI_ID_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z][a-zA-Z0-9.\-_]{2,}$")

OWNERSHIP_DISCLAIMER = (
    "BharatSHIELD cannot independently prove bank-account ownership from a QR payload alone."
)


def normalize_payee_name(name: str) -> str:
    decoded = unquote(name or "").strip()
    collapsed = re.sub(r"\s+", " ", decoded)
    return collapsed.lower()


def display_payee_name(name: str) -> str:
    decoded = unquote(name or "").strip()
    return re.sub(r"\s+", " ", decoded) or "Not found"


def extract_phone_from_upi(upi_id: str) -> str | None:
    local, _, _ = (upi_id or "").partition("@")
    digits = re.sub(r"\D", "", local)
    if PHONE_UPI_LOCAL_PATTERN.fullmatch(local or "") and len(digits) >= 10:
        return digits[-10:]
    return None


def build_identity_fingerprint(
    upi_id: str,
    merchant: str,
    amount: str,
    note: str,
    destination_url: str = "",
) -> str:
    normalized = "|".join([
        (upi_id or "").strip().lower(),
        normalize_payee_name(merchant),
        (amount or "").strip(),
        (note or "").strip().lower(),
        (destination_url or "").strip().lower() if destination_url not in {"", "Not found"} else "",
    ])
    return "BS-QR-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:8].upper()


def build_identity_record(
    upi_id: str,
    merchant: str,
    amount: str,
    note: str,
    destination_url: str = "",
) -> dict[str, Any]:
    display_name = display_payee_name(merchant)
    phone = extract_phone_from_upi(upi_id)
    upi_valid = bool(UPI_ID_PATTERN.match(upi_id or ""))
    return {
        "recipient_name": display_name,
        "recipient_name_normalized": normalize_payee_name(merchant),
        "upi_id": upi_id or "Not found",
        "upi_id_normalized": (upi_id or "").strip().lower(),
        "phone_number": phone or "Not found",
        "amount": amount or "Not found",
        "amount_normalized": (amount or "").strip(),
        "payment_note": unquote(note).strip() if note else "Not found",
        "note_normalized": (note or "").strip().lower(),
        "destination_url": destination_url or "Not found",
        "fingerprint": build_identity_fingerprint(upi_id, merchant, amount, note, destination_url),
        "payload_consistent": upi_valid and bool(upi_id),
    }


def consistency_state(identity: dict[str, Any], user_verified: bool = False) -> str:
    if user_verified:
        return "User Verified Baseline"
    if identity.get("payload_consistent"):
        return "Payload Consistent"
    if identity.get("upi_id") and identity.get("upi_id") != "Not found":
        return "Unknown — Not Independently Verified"
    return "Unknown — Not Independently Verified"


def compare_identity(current: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    if not baseline:
        return {
            "tamper_detected": False,
            "change_status": "No Verified Baseline",
            "severity": "none",
            "summary": "No previously user-verified QR baseline found for comparison.",
            "changes": [],
            "previous": None,
            "current": current,
            "headline": "",
            "explanation": "",
        }

    if current.get("fingerprint") == baseline.get("fingerprint"):
        return {
            "tamper_detected": False,
            "change_status": "Matches Verified Baseline",
            "severity": "none",
            "summary": "Current QR matches the previously user-verified QR baseline.",
            "changes": [],
            "previous": baseline,
            "current": current,
            "headline": "",
            "explanation": "",
        }

    upi_changed = current.get("upi_id_normalized") != baseline.get("upi_id_normalized")
    name_changed = current.get("recipient_name_normalized") != baseline.get("recipient_name_normalized")
    amount_changed = current.get("amount_normalized") != baseline.get("amount_normalized")
    note_changed = current.get("note_normalized") != baseline.get("note_normalized")
    url_changed = (
        current.get("destination_url") not in {"", "Not found", baseline.get("destination_url")}
        and baseline.get("destination_url") not in {"", "Not found"}
        and current.get("destination_url") != baseline.get("destination_url")
    )

    changes: list[dict[str, str]] = []
    if upi_changed:
        changes.append({
            "field": "Recipient / UPI ID",
            "previous": baseline.get("upi_id") or "Not found",
            "current": current.get("upi_id") or "Not found",
        })
    if name_changed:
        changes.append({
            "field": "Recipient Name",
            "previous": baseline.get("recipient_name") or "Not found",
            "current": current.get("recipient_name") or "Not found",
        })
    if amount_changed:
        changes.append({
            "field": "Amount",
            "previous": baseline.get("amount") or "Not found",
            "current": current.get("amount") or "Not found",
        })
    if note_changed:
        changes.append({
            "field": "Payment Note",
            "previous": baseline.get("payment_note") or "Not found",
            "current": current.get("payment_note") or "Not found",
        })
    if url_changed:
        changes.append({
            "field": "Destination URL",
            "previous": baseline.get("destination_url") or "Not found",
            "current": current.get("destination_url") or "Not found",
        })

    if upi_changed and name_changed:
        change_status = "Recipient Identity Changed"
        severity = "high"
        headline = "Recipient Identity Changed"
    elif upi_changed:
        change_status = "Recipient Changed"
        severity = "medium"
        headline = "QR Tampering / Recipient Change Detected"
    elif name_changed:
        change_status = "Payee Name Changed"
        severity = "medium"
        headline = "Payee Name Changed"
    elif amount_changed or note_changed or url_changed:
        change_status = "Payload Changed"
        severity = "low" if not amount_changed else "medium"
        headline = "QR Payload Changed"
    else:
        change_status = "Payload Changed"
        severity = "low"
        headline = "QR Payload Changed"

    explanation = (
        "The recipient information encoded in this QR differs from the previously verified QR."
        if upi_changed or name_changed
        else "This QR payload differs from the previously user-verified QR baseline."
    )

    return {
        "tamper_detected": bool(changes),
        "change_status": change_status,
        "severity": severity,
        "summary": explanation,
        "changes": changes,
        "previous": baseline,
        "current": current,
        "headline": headline,
        "explanation": explanation,
    }


def tamper_risk_boost(tamper: dict[str, Any]) -> int:
    if not tamper.get("tamper_detected"):
        return 0
    severity = tamper.get("severity", "none")
    status = tamper.get("change_status", "")
    boost = 0
    if status == "Recipient Identity Changed":
        boost += 35
    elif status == "Recipient Changed":
        boost += 25
    elif status == "Payee Name Changed":
        boost += 15
    elif status == "Payload Changed":
        boost += 10
    for change in tamper.get("changes", []):
        if change.get("field") == "Amount":
            try:
                previous = float(str(change.get("previous", "0")).replace("INR", "").strip())
                current = float(str(change.get("current", "0")).replace("INR", "").strip())
            except ValueError:
                previous = 0
                current = 0
            if current >= 5000 and current > previous:
                boost += 16
            elif current >= 1000 and current > previous:
                boost += 10
    if severity == "high":
        boost = max(boost, 35)
    return boost


def build_identity_check(
    identity: dict[str, Any],
    tamper: dict[str, Any],
    user_verified: bool = False,
) -> dict[str, Any]:
    checks = {
        "recipient_name": identity.get("payload_consistent") and identity.get("recipient_name") != "Not found",
        "upi_id": identity.get("payload_consistent"),
        "phone_number": identity.get("phone_number") not in {None, "", "Not found"},
        "fingerprint": bool(identity.get("fingerprint")),
    }
    if tamper.get("tamper_detected"):
        if tamper.get("change_status") in {"Recipient Changed", "Recipient Identity Changed"}:
            checks["upi_id"] = False
        if tamper.get("change_status") in {"Payee Name Changed", "Recipient Identity Changed"}:
            checks["recipient_name"] = False

    return {
        "recipient_name": identity.get("recipient_name"),
        "upi_id": identity.get("upi_id"),
        "phone_number": identity.get("phone_number"),
        "amount": identity.get("amount"),
        "payment_note": identity.get("payment_note"),
        "fingerprint": identity.get("fingerprint"),
        "consistency_state": consistency_state(identity, user_verified=user_verified),
        "checks": checks,
        "ownership_disclaimer": OWNERSHIP_DISCLAIMER,
        "tamper": tamper,
    }
