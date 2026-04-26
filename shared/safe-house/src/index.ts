export { runL1Detection, applySessionMultiplier } from './detector.js';
export type { L1Result } from './detector.js';
export { preprocessForDetection } from './preprocessor.js';
export type { PreprocessResult } from './preprocessor.js';
export { detectLanguage, hasNativeL1Support, SUPPORTED_L1_LANGUAGES } from './lang-detect.js';
export { MULTILINGUAL_SIGNALS } from './i18n-signals.js';
export { decorateMessage, buildQuarantineNotification } from './decorator.js';
export { scanDLP, hasDLPMatches, redactDLPMatches } from './dlp.js';
export { buildSHAnalysisPrompt, THREAT_CATEGORY_DESCRIPTIONS } from './prompts.js';
export { buildSHUserPrompt, parseL2Response, mergeL1AndL2, buildThreatContextForAIP, buildPreemptiveNudgeContent } from './prompts.js';
export { buildSHExitAnalysisPrompt, buildSHExitUserPrompt, SH_EXIT_THREAT_DESCRIPTIONS } from './prompts.js';
export type {
  ThreatType, SafeHouseMode, SafeHouseVerdict, TrustTier, SourceType, SurfaceKind,
  ThreatDetection, SafeHouseDecision, AnnotatedMessage, QuarantineNotification,
  SafeHouseConfig, SessionRiskState, ContentSurface, SafeHouseThreatPattern, DLPMatch,
  ScreenSurfaces, TrustedSourceBuckets, L1Options,
} from './types.js';
export { sourceTypeToSurface } from './types.js';
export type { L2Result, PreemptiveNudge } from './types.js';
export { DEFAULT_SAFE_HOUSE_CONFIG } from './types.js';
export { computeMinHash, estimateSimilarity, serializeMinHash, deserializeMinHash, isSimilarToPattern, computeBandHashes } from './fingerprint.js';
export {
  compileRecipeFromRpcRow, buildRecipeIndex,
  CANONICAL_DOORS, CANONICAL_THREAT_TYPES, CANONICAL_VARIANT_CLASSES,
  CANONICAL_SEVERITIES_P, CANONICAL_DETECTORS, CANONICAL_OPERATORS, RECIPE_SCOPES,
} from './recipes.js';
export type {
  CanonicalDoor, CanonicalThreatType, CanonicalVariantClass,
  CanonicalSeverity, CanonicalDetector, CanonicalOperator, RecipeScope,
  RecipeRpcRow, RpcTier1, RpcTier1Condition, RpcTier2, RpcTier2Check, RpcParsedContent,
  CompiledCondition, CompiledTier1, CompiledTier2, CompiledTier2Check,
  CompiledRecipe, RecipeIndex,
} from './recipes.js';
export {
  evaluateRecipesTier1,
  buildDetectorScoresFromThreats,
  collectTier2Checks,
  buildRecipeTier2PromptFragment,
  parseRecipeTier2Response,
  serializeRecipeTelemetry,
  DEFAULT_RECIPE_EVAL_CONFIG,
} from './recipes-evaluator.js';
export type {
  RecipeMode, RecipeEvalConfig, DetectorScores,
  MatchedCondition, SkippedCondition, ConditionSkipReason,
  Tier1Hit, Tier1Result,
  Tier2Check, Tier2CheckResult, Tier2CheckSkipReason, Tier2Result,
  RecipeTelemetry, ThreatLike,
} from './recipes-evaluator.js';
