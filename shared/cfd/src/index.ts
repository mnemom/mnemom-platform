export { runL1Detection, applySessionMultiplier } from './detector.js';
export { detectLanguage, hasNativeL1Support, SUPPORTED_L1_LANGUAGES } from './lang-detect.js';
export { MULTILINGUAL_SIGNALS } from './i18n-signals.js';
export { decorateMessage, buildQuarantineNotification } from './decorator.js';
export { scanDLP, hasDLPMatches, redactDLPMatches } from './dlp.js';
export { buildCFDAnalysisPrompt, THREAT_CATEGORY_DESCRIPTIONS } from './prompts.js';
export { buildCFDUserPrompt, parseL2Response, mergeL1AndL2, buildThreatContextForAIP, buildPreemptiveNudgeContent } from './prompts.js';
export type {
  ThreatType, CFDMode, CFDVerdict, TrustTier, SourceType,
  ThreatDetection, CFDDecision, AnnotatedMessage, QuarantineNotification,
  CFDConfig, SessionRiskState, ContentSurface, CFDThreatPattern, DLPMatch,
  SourceTrustRule,
} from './types.js';
export type { L2Result, PreemptiveNudge } from './types.js';
export { DEFAULT_CFD_CONFIG } from './types.js';
export { computeMinHash, estimateSimilarity, serializeMinHash, deserializeMinHash, isSimilarToPattern } from './fingerprint.js';
