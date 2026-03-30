export { runL1Detection, applySessionMultiplier } from './detector.js';
export { decorateMessage, buildQuarantineNotification } from './decorator.js';
export { scanDLP, hasDLPMatches } from './dlp.js';
export { buildCFDAnalysisPrompt, THREAT_CATEGORY_DESCRIPTIONS } from './prompts.js';
export type {
  ThreatType, CFDMode, CFDVerdict, TrustTier, SourceType,
  ThreatDetection, CFDDecision, AnnotatedMessage, QuarantineNotification,
  CFDConfig, SessionRiskState, ContentSurface, CFDThreatPattern, DLPMatch,
} from './types.js';
export { DEFAULT_CFD_CONFIG } from './types.js';
