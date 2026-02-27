export { extractFaultLines } from './extractor.js';
export { forecastRisks } from './forecaster.js';
export { recommendPolicy } from './recommender.js';
export { buildForecastPrompt, buildRecommendationPrompt } from './prompts.js';

export type { RecommendationConstraints } from './prompts.js';

export type {
  FaultLine,
  FaultLineClassification,
  FaultLineSummary,
  FaultLineAnalysis,
  Severity,
  ValueDivergence,
  FleetCoherenceResult,
  AgentCard,
  FailureMode,
  FailureModeType,
  RiskTolerance,
  RiskForecast,
  TaskContext,
  ReasoningStep,
  ForecastSummary,
  PolicyRecommendation,
  LLMCaller,
} from './types.js';
