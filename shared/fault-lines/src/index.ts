// Top-level entry: current fault-line + forecasting + policy-recommendation API.
// Extracted from mnemom-api/src/fault-lines/ during UC-11b (ADR-025).

export { extractFaultLines } from "./extractor.js";
export { forecastRisks } from "./forecaster.js";
export { recommendPolicy } from "./recommender.js";
export { buildForecastPrompt, buildRecommendationPrompt } from "./prompts.js";

export type { RecommendationConstraints } from "./prompts.js";

export type {
  FaultLine,
  FaultLineClassification,
  FaultLineSummary,
  FaultLineAlignment,
  FaultLineAnalysis,
  ValueDivergence,
  FleetCoherenceResult,
  FailureMode,
  FailureModeType,
  RiskTolerance,
  RiskForecast,
  TaskContext,
  ReasoningStep,
  ForecastSummary,
  PolicyRecommendation,
  LLMCaller,
} from "./types.js";
