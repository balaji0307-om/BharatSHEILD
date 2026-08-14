import unittest
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import main


BASELINE_PAYLOAD = "upi://pay?pa=9876543210@upi&pn=Rahul Sharma&am=500&tn=Payment"


class QRTamperTests(unittest.TestCase):
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

    def _verified_baseline(self):
        first = main.inspect_qr_payload(BASELINE_PAYLOAD)
        return {**first["identity"], "user_verified": True}

    def test_a_payload_consistent_no_tamper(self):
        result = main.inspect_qr_payload(BASELINE_PAYLOAD)

        self.assertEqual(result["identity_check"]["consistency_state"], "Payload Consistent")
        self.assertFalse(result["tamper_check"]["tamper_detected"])
        self.assertEqual(result["tamper_check"]["change_status"], "No Verified Baseline")
        self.assertEqual(result["upi_id"], "9876543210@upi")
        self.assertEqual(result["merchant"], "Rahul Sharma")

    def test_b_recipient_changed(self):
        baseline = self._verified_baseline()
        result = main.inspect_qr_payload(
            "upi://pay?pa=9056086377@upi&pn=Rahul Sharma&am=500&tn=Payment",
            baseline,
        )

        self.assertTrue(result["tamper_check"]["tamper_detected"])
        self.assertEqual(result["tamper_check"]["change_status"], "Recipient Changed")
        self.assertEqual(result["tamper_check"]["severity"], "medium")
        change_fields = {item["field"] for item in result["tamper_check"]["changes"]}
        self.assertIn("Recipient / UPI ID", change_fields)

    def test_c_payee_name_changed(self):
        baseline = self._verified_baseline()
        result = main.inspect_qr_payload(
            "upi://pay?pa=9876543210@upi&pn=Amit Kumar&am=500&tn=Payment",
            baseline,
        )

        self.assertTrue(result["tamper_check"]["tamper_detected"])
        self.assertEqual(result["tamper_check"]["change_status"], "Payee Name Changed")
        change_fields = {item["field"] for item in result["tamper_check"]["changes"]}
        self.assertIn("Recipient Name", change_fields)

    def test_d_identity_and_amount_changed_high_severity(self):
        baseline = self._verified_baseline()
        result = main.inspect_qr_payload(
            "upi://pay?pa=9056086377@upi&pn=Amit Kumar&am=5000&tn=Payment",
            baseline,
        )

        self.assertTrue(result["tamper_check"]["tamper_detected"])
        self.assertEqual(result["tamper_check"]["change_status"], "Recipient Identity Changed")
        self.assertEqual(result["tamper_check"]["severity"], "high")
        change_fields = {item["field"] for item in result["tamper_check"]["changes"]}
        self.assertIn("Recipient / UPI ID", change_fields)
        self.assertIn("Recipient Name", change_fields)
        self.assertIn("Amount", change_fields)
        self.assertGreaterEqual(result["score"], 35)


if __name__ == "__main__":
    unittest.main()
