export function numericValue(value) {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function formatPercent(value, fallback = "N/A") {
  const parsed = numericValue(value);
  return parsed === null ? fallback : `${parsed}%`;
}

export function formatMetric(value, fallback = "N/A") {
  const parsed = numericValue(value);
  return parsed === null ? fallback : String(parsed);
}

export function buildMetricDisplay({ displayResult, mode, activeAnalysisMode, loading }) {
  const isAnalyzing = Boolean(loading && activeAnalysisMode === mode);

  if (isAnalyzing) {
    return {
      scoreValue: null,
      gaugeScore: 18,
      scoreDisplay: "Analyzing",
      confidenceDisplay: "Analyzing",
      ruleScoreDisplay: "Analyzing",
      urlScoreDisplay: "Analyzing",
      safetyScoreDisplay: "Analyzing",
      liveShieldStatus: "Analyzing",
    };
  }

  if (!displayResult) {
    return {
      scoreValue: 0,
      gaugeScore: 18,
      scoreDisplay: "0%",
      confidenceDisplay: "Not applicable",
      ruleScoreDisplay: "Not applicable",
      urlScoreDisplay: "Not applicable",
      safetyScoreDisplay: "Not applicable",
      liveShieldStatus: "Monitoring",
    };
  }

  const isQrResult = displayResult.mode === "qr" || Boolean(displayResult.qr_analysis);
  const scoreValue = numericValue(displayResult.score);
  const safetyValue = numericValue(displayResult.safety_score);
  const ruleValue = numericValue(displayResult.rule_score);
  const urlValue = numericValue(displayResult.url_score);
  const hasUrlChecks = Array.isArray(displayResult.url_checks) && displayResult.url_checks.length > 0;
  const destinationUrl = displayResult.qr_analysis?.destination_url;
  const hasQrDestination = displayResult.qr_analysis?.hidden_redirect === true
    || (typeof destinationUrl === "string" && destinationUrl !== "Not found" && destinationUrl.length > 0);

  const scoreDisplay = scoreValue === null ? "Unable" : formatPercent(scoreValue);
  const confidenceDisplay = formatPercent(displayResult.confidence, "Not applicable");
  const ruleScoreDisplay = ruleValue !== null
    ? formatPercent(ruleValue)
    : isQrResult
      ? "Not applicable"
      : scoreValue !== null
        ? `${Math.max(14, scoreValue - 2)}%`
        : "Not applicable";
  const urlScoreDisplay = urlValue !== null
    ? formatPercent(urlValue)
    : hasUrlChecks
      ? formatPercent(Math.max(...displayResult.url_checks.map((item) => numericValue(item.score) ?? 0)))
      : isQrResult && !hasQrDestination
        ? "Not applicable"
        : "Not applicable";

  return {
    scoreValue,
    gaugeScore: scoreValue ?? 18,
    scoreDisplay,
    confidenceDisplay,
    ruleScoreDisplay,
    urlScoreDisplay,
    safetyScoreDisplay: safetyValue === null ? "Not applicable" : formatMetric(safetyValue),
    liveShieldStatus: scoreValue === null ? "Risk unavailable" : `${scoreDisplay} threat detected`,
  };
}
