import unittest
from pathlib import Path
import sys
import types
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import fastapi  # noqa: F401
except ImportError:
    fastapi_module = types.ModuleType("fastapi")

    class _FastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            pass

        def middleware(self, *args, **kwargs):
            return lambda func: func

        def get(self, *args, **kwargs):
            return lambda func: func

        def post(self, *args, **kwargs):
            return lambda func: func

    class _HTTPException(Exception):
        def __init__(self, status_code=500, detail=""):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    fastapi_module.FastAPI = _FastAPI
    fastapi_module.Depends = lambda dependency=None: dependency
    fastapi_module.Header = lambda default=None: default
    fastapi_module.HTTPException = _HTTPException
    fastapi_module.Request = object
    sys.modules["fastapi"] = fastapi_module

    responses_module = types.ModuleType("fastapi.responses")
    responses_module.JSONResponse = lambda *args, **kwargs: {"args": args, "kwargs": kwargs}
    sys.modules["fastapi.responses"] = responses_module

    middleware_module = types.ModuleType("fastapi.middleware")
    cors_module = types.ModuleType("fastapi.middleware.cors")
    cors_module.CORSMiddleware = object
    sys.modules["fastapi.middleware"] = middleware_module
    sys.modules["fastapi.middleware.cors"] = cors_module

try:
    import pydantic  # noqa: F401
except ImportError:
    pydantic_module = types.ModuleType("pydantic")
    pydantic_module.BaseModel = object
    pydantic_module.Field = lambda default=None, **kwargs: default
    sys.modules["pydantic"] = pydantic_module

import main


class QRAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(__file__).resolve().parent / ".testdata"
        self.tmp.mkdir(exist_ok=True)
        main.DB_PATH = self.tmp / f"test_bharatshield_{uuid.uuid4().hex}.db"
        main.init_db()

    def tearDown(self):
        try:
            main.DB_PATH.unlink(missing_ok=True)
        except PermissionError:
            pass

    def test_case_a_numeric_upi_is_not_suspicious_by_itself(self):
        result = main.inspect_qr_payload("upi://pay?pa=9876543210@upi&pn=Rahul&am=200&tn=Lunch")

        self.assertEqual(result["upi_id"], "9876543210@upi")
        self.assertEqual(result["merchant"], "Rahul")
        self.assertEqual(result["amount"], "200")
        self.assertEqual(result["note"], "Lunch")
        self.assertIn(result["recipient_reputation"], {"Unknown", "Review"})
        self.assertNotEqual(result["recipient_reputation"], "Suspicious")
        self.assertFalse(any("mobile-number" in signal.lower() for signal in result["risk_signals"]))
        self.assertLess(result["score"], 45)

    def test_case_b_kyc_note_raises_risk(self):
        safe = main.inspect_qr_payload("upi://pay?pa=9876543210@upi&pn=Rahul&am=200&tn=Lunch")
        risky = main.inspect_qr_payload("upi://pay?pa=9876543210@upi&pn=Rahul&am=200&tn=KYC verification")

        self.assertGreater(risky["score"], safe["score"])
        self.assertIn("Payment note contains pressure or verification terms", risky["risk_signals"])

    def test_case_c_refund_support_payload_is_high_risk(self):
        result = main.inspect_qr_payload(
            "upi://pay?pa=refund-support@upi&pn=Refund Support&am=4999&tn=Urgent refund verification"
        )

        self.assertGreaterEqual(result["score"], 70)
        self.assertEqual(result["recipient_reputation"], "Suspicious")
        self.assertIn("Recipient name contains support/refund/KYC terms", result["risk_signals"])
        self.assertIn("Merchant name uses refund/support/KYC terms", result["risk_signals"])
        self.assertIn("Payment note contains pressure or verification terms", result["risk_signals"])

    def test_case_d_changed_recipient_updates_report(self):
        result = main.inspect_qr_payload(
            "upi://pay?pa=someoneelse@upi&pn=Refund Support&am=4999&tn=Urgent refund verification"
        )

        self.assertEqual(result["upi_id"], "someoneelse@upi")
        self.assertEqual(result["merchant"], "Refund Support")
        self.assertNotIn("Recipient name contains support/refund/KYC terms", result["risk_signals"])
        self.assertIn("Merchant name uses refund/support/KYC terms", result["risk_signals"])
        self.assertIn("Payment note contains pressure or verification terms", result["risk_signals"])

    def test_case_e_same_qr_second_scan_shows_previous_report(self):
        payload = "upi://pay?pa=refund-support@upi&pn=Refund Support&am=4999&tn=Urgent refund verification"
        first = main.inspect_qr_payload(payload)
        main.save_security_case(
            {
                "case_id": "BS-TEST",
                "owner": "tester@example.com",
                "type": "UPI QR Fraud Risk",
                "channel": "qr",
                "input": payload,
                "ai_result": {"score": first["score"], "risk": "High", "confidence": 90, "qr_analysis": first},
            }
        )

        second = main.inspect_qr_payload(payload)
        self.assertGreaterEqual(second["previous_reports"], 1)
        self.assertTrue(any("previous BharatSHIELD case" in signal for signal in second["risk_signals"]))

    def test_sequential_production_payloads_update_current_qr_fields(self):
        first = main.inspect_qr_payload("upi://pay?pa=7903687480@ptaxis&pn=JASHMANDEEP%20KAUR")
        second = main.inspect_qr_payload("upi://pay?pa=9056086377@ptaxis&pn=JASHMANDEEP%20KAUR")
        third = main.inspect_qr_payload(
            "upi://pay?pa=refund-support@upi&pn=Refund%20Support&am=4999&tn=Urgent%20KYC%20verification"
        )

        self.assertEqual(first["upi_id"], "7903687480@ptaxis")
        self.assertEqual(second["upi_id"], "9056086377@ptaxis")
        self.assertEqual(third["upi_id"], "refund-support@upi")
        self.assertEqual(third["merchant"], "Refund Support")
        self.assertEqual(third["amount"], "4999")
        self.assertEqual(third["note"], "Urgent KYC verification")
        self.assertNotIn("Recipient name contains support/refund/KYC terms", first["risk_signals"])
        self.assertNotIn("Recipient name contains support/refund/KYC terms", second["risk_signals"])
        self.assertIn("Recipient name contains support/refund/KYC terms", third["risk_signals"])
        self.assertGreater(third["score"], first["score"])
        self.assertGreater(third["score"], second["score"])

    def test_unknown_recipient_is_not_marked_safe(self):
        result = main.inspect_qr_payload("upi://pay?pa=9876543210@upi&pn=Rahul&am=200&tn=Lunch")
        self.assertEqual(result["recipient_reputation"], "Unknown")
        self.assertNotIn("Safe", result["recipient_reputation"])


if __name__ == "__main__":
    unittest.main()
