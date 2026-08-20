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
      confidenceDisplay: "N/A",
      ruleScoreDisplay: "N/A",
      urlScoreDisplay: "N/A",
      safetyScoreDisplay: "N/A",
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

  const scoreDisplay = scoreValue === null ? "N/A" : formatPercent(scoreValue);
  const confidenceDisplay = formatPercent(displayResult.confidence);
  const ruleScoreDisplay = ruleValue !== null
    ? formatPercent(ruleValue)
    : isQrResult
      ? "N/A"
      : scoreValue !== null
        ? `${Math.max(14, scoreValue - 2)}%`
        : "N/A";
  const urlScoreDisplay = urlValue !== null
    ? formatPercent(urlValue)
    : hasUrlChecks
      ? formatPercent(Math.max(...displayResult.url_checks.map((item) => numericValue(item.score) ?? 0)))
      : isQrResult && !hasQrDestination
        ? "Not applicable"
        : "N/A";

  return {
    scoreValue,
    gaugeScore: scoreValue ?? 18,
    scoreDisplay,
    confidenceDisplay,
    ruleScoreDisplay,
    urlScoreDisplay,
    safetyScoreDisplay: formatMetric(safetyValue),
    liveShieldStatus: scoreValue === null ? "Risk unavailable" : `${scoreDisplay} threat detected`,
  };
}
