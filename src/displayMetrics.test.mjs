import assert from "node:assert/strict";
import { buildMetricDisplay } from "./displayMetrics.mjs";

const missingQrMetrics = buildMetricDisplay({
  mode: "qr",
  activeAnalysisMode: null,
  loading: false,
  displayResult: {
    mode: "qr",
    risk: "Unable to verify",
    score: null,
    confidence: null,
    rule_score: null,
    url_score: null,
    safety_score: null,
    qr_analysis: {
      upi_id: "9876543210@upi",
      merchant: "Rahul",
      amount: "200",
      note: "Lunch",
    },
  },
});

assert.equal(missingQrMetrics.scoreDisplay, "N/A");
assert.equal(missingQrMetrics.confidenceDisplay, "N/A");
assert.equal(missingQrMetrics.ruleScoreDisplay, "N/A");
assert.equal(missingQrMetrics.urlScoreDisplay, "Not applicable");
assert.equal(missingQrMetrics.safetyScoreDisplay, "N/A");
assert.equal(missingQrMetrics.liveShieldStatus, "Risk unavailable");

const validQrMetrics = buildMetricDisplay({
  mode: "qr",
  activeAnalysisMode: null,
  loading: false,
  displayResult: {
    mode: "qr",
    risk: "High",
    score: 84,
    confidence: 91,
    rule_score: 88,
    url_score: 72,
    safety_score: 16,
    qr_analysis: {
      upi_id: "refund-support@upi",
      merchant: "Refund Support",
      amount: "4999",
      note: "Urgent KYC verification",
      destination_url: "https://refund.example",
    },
  },
});

assert.equal(validQrMetrics.scoreDisplay, "84%");
assert.equal(validQrMetrics.confidenceDisplay, "91%");
assert.equal(validQrMetrics.ruleScoreDisplay, "88%");
assert.equal(validQrMetrics.urlScoreDisplay, "72%");
assert.equal(validQrMetrics.safetyScoreDisplay, "16");

const switchedToQrBeforeNewResult = buildMetricDisplay({
  mode: "qr",
  activeAnalysisMode: null,
  loading: false,
  displayResult: null,
});

assert.equal(switchedToQrBeforeNewResult.liveShieldStatus, "Monitoring");
assert.equal(switchedToQrBeforeNewResult.urlScoreDisplay, "N/A");
