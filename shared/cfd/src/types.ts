// Threat categories
export type ThreatType =
  | 'prompt_injection'
  | 'indirect_injection'
  | 'social_engineering'
  | 'bec_fraud'
  | 'agent_spoofing'
  | 'hijack_attempt'
  | 'data_exfiltration'
  | 'privilege_escalation'
  | 'pii_in_inbound';

// CFD operating modes
export type CFDMode = 'disabled' | 'simulate' | 'observe' | 'enforce';

// Verdict after evaluation
export type CFDVerdict = 'pass' | 'warn' | 'quarantine' | 'block';

// Trust tier for message source
export type TrustTier = 'high' | 'medium' | 'low' | 'unknown';

// Source type of inbound content
export type SourceType = 'user_message' | 'tool_result' | 'agent_message' | 'email' | 'api' | 'system_prompt' | 'outbound' | 'canary' | 'unknown';

// A single detected threat
export interface ThreatDetection {
  type: ThreatType;
  confidence: number;        // 0.0 - 1.0
  reasoning: string;
  matched_pattern?: string;  // for L1 pattern matches
}

// Full CFD evaluation result
export interface CFDDecision {
  verdict: CFDVerdict;
  overall_risk: number;      // 0.0 - 1.0
  threats: ThreatDetection[];
  l1_score: number;
  l2_score?: number;         // undefined until Phase 1 (Haiku)
  session_multiplier: number;
  quarantine_id?: string;    // set when verdict is quarantine or block
  detection_layer: 'l1' | 'l2' | 'l3';
  duration_ms: number;
}

// Annotated message (WARN mode output)
export interface AnnotatedMessage {
  content: string;           // full decorated XML string to replace original
  original: string;          // original unmodified content
  verdict: CFDVerdict;
  quarantine_ref?: string;
}

// Quarantine notification (BLOCK mode output)
export interface QuarantineNotification {
  xml: string;               // full XML notification string
  quarantine_id: string;
  threat_type: ThreatType;
  confidence: number;
  apparent_sender?: string;
}

export interface SourceTrustRule {
  source_pattern: string;       // e.g. "email:*@company.com" or "agent:smolt-xxx"
  trust_tier: 'verified' | 'known' | 'unknown' | 'untrusted';
  risk_multiplier: number;      // 0.0 (fully trusted) to 2.0 (extra suspicious)
}

// CFD configuration (from cfd_configs table)
export interface CFDConfig {
  mode: CFDMode;
  thresholds: {
    warn: number;           // default 0.6
    quarantine: number;     // default 0.8
    block: number;          // default 0.95
  };
  screen_surfaces: SourceType[];
  trusted_sources: SourceTrustRule[];
}

export const DEFAULT_CFD_CONFIG: CFDConfig = {
  mode: 'disabled',
  thresholds: { warn: 0.6, quarantine: 0.8, block: 0.95 },
  screen_surfaces: ['user_message'],
  trusted_sources: [] as SourceTrustRule[],
};

// Session risk state (stored in KV)
export interface SessionRiskState {
  session_id: string;
  agent_id: string;
  window_scores: Array<{ score: number; threat_type?: ThreatType; timestamp: number }>;
  session_threat_level: 'low' | 'medium' | 'high';
  escalation_triggered: boolean;
  last_updated: number;
}

// Content surface to evaluate
export interface ContentSurface {
  content: string;
  source_type: SourceType;
  apparent_sender?: string;
  trust_tier?: TrustTier;
}

// Threat pattern from cfd_threat_patterns table
export interface CFDThreatPattern {
  id: string;
  threat_type: ThreatType;
  label: 'malicious' | 'benign';
  content: string;
  minhash?: string;
}

// DLP match result
export interface DLPMatch {
  type: 'credit_card' | 'ssn' | 'api_key' | 'pem_key' | 'password_field' | 'oauth_token';
  value_masked: string;    // e.g. "****-****-****-1234"
  offset: number;
}

// Result from L2 LLM analysis
export interface L2Result {
  threats: ThreatDetection[];
  overall_risk: number;
  recommendation: CFDVerdict;
  raw_response: string;
}

// Pre-emptive nudge content for injection into enforcement channel
export interface PreemptiveNudge {
  nudge_content: string;
  threat_type: ThreatType;
  cfd_score: number;
  pre_emptive: true;
}
