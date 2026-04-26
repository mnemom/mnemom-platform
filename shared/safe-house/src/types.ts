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

// Safe House operating modes (ADR-037 unified Protection Card canonical form).
// Unified with alignment-card `integrity.enforcement_mode` plus `off`.
//   off     — detection skipped entirely (cost/speed/non-applicability)
//   observe — detectors run, signals logged, no request-path action
//   nudge   — detectors run; matches attach an advisory annotation to the
//             agent's context and an X-Safe-House-Advisory response header,
//             but the request proceeds
//   enforce — detectors run synchronously; matches block the request
export type SafeHouseMode = 'off' | 'observe' | 'nudge' | 'enforce';

// Verdict after evaluation. Note: 'nudge' is a verdict-equivalent in nudge
// mode — detector tripped, advisory attached, message proceeded.
export type SafeHouseVerdict = 'pass' | 'warn' | 'nudge' | 'quarantine' | 'block';

// Trust tier for message source
export type TrustTier = 'high' | 'medium' | 'low' | 'unknown';

// Source type of inbound content. Used by detectors to tune confidence per
// surface (e.g. indirect-injection patterns are weighted differently in tool
// results vs. user messages). Decoupled from screen_surfaces (the four
// directional gates from ADR-037); a SourceType maps to one of those gates
// via sourceTypeToSurface().
export type SourceType = 'user_message' | 'tool_result' | 'agent_message' | 'email' | 'api' | 'system_prompt' | 'outbound' | 'canary' | 'unknown';

// A single detected threat
export interface ThreatDetection {
  type: ThreatType;
  confidence: number;        // 0.0 - 1.0
  reasoning: string;
  matched_pattern?: string;  // for L1 pattern matches
}

// Options for runL1Detection
export interface L1Options {
  /** Surface type of the content — affects indirect injection pattern confidence */
  surface?: SourceType;
}

// Full Safe House evaluation result
export interface SafeHouseDecision {
  verdict: SafeHouseVerdict;
  overall_risk: number;            // 0.0 - 1.0
  threats: ThreatDetection[];
  detector_scores: Record<string, number | null>; // keyed by detector name; null = did not run
  detection_sources: string[];     // detectors with positive signal contribution
  session_multiplier: number;
  quarantine_id?: string;          // set when verdict is quarantine or block
  duration_ms: number;
}

// Annotated message (WARN mode output)
export interface AnnotatedMessage {
  content: string;           // full decorated XML string to replace original
  original: string;          // original unmodified content
  verdict: SafeHouseVerdict;
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

// ADR-037: trusted_sources are typed buckets, validated against a deny-list
// at write time in mnemom-api. The gateway reads them as straight string[].
export interface TrustedSourceBuckets {
  domains: string[];     // DNS name or host:port
  agent_ids: string[];   // mnm-* Mnemom agent IDs
  ip_ranges: string[];   // IPv4/IPv6 CIDR
}

// ADR-037: screened surfaces are direction-named bools.
export interface ScreenSurfaces {
  incoming: boolean;        // prompt/message reaching the agent
  outgoing: boolean;        // agent's generated response
  tool_calls: boolean;      // arguments to tool invocations
  tool_responses: boolean;  // values returned by tools
}

// Map a legacy SourceType to the ADR-037 surface gate it falls under.
// Used by dispatchers that already classify content as a SourceType to
// decide whether the corresponding surface is enabled in screen_surfaces.
export type SurfaceKind = keyof ScreenSurfaces;
export function sourceTypeToSurface(type: SourceType): SurfaceKind {
  switch (type) {
    case 'user_message':
    case 'system_prompt':
    case 'email':
    case 'api':
      return 'incoming';
    case 'agent_message':
    case 'outbound':
      return 'outgoing';
    case 'tool_result':
      return 'tool_responses';
    case 'canary':
    case 'unknown':
    default:
      // Conservative: unknown classifications go through the incoming gate.
      return 'incoming';
  }
}

// Safe House configuration — ADR-037 canonical Protection Card shape (the
// gateway-facing slice; the full UnifiedProtectionCard adds card_version,
// agent_id, _composition).
export interface SafeHouseConfig {
  mode: SafeHouseMode;
  thresholds: {
    warn: number;
    quarantine: number;
    block: number;
  };
  screen_surfaces: ScreenSurfaces;
  trusted_sources: TrustedSourceBuckets;
}

export const DEFAULT_SAFE_HOUSE_CONFIG: SafeHouseConfig = {
  mode: 'off',
  thresholds: { warn: 0.6, quarantine: 0.8, block: 0.95 },
  screen_surfaces: { incoming: true, outgoing: true, tool_calls: true, tool_responses: true },
  trusted_sources: { domains: [], agent_ids: [], ip_ranges: [] },
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

// Threat pattern from sh_threat_patterns table
export interface SafeHouseThreatPattern {
  id: string;
  threat_type: ThreatType;
  label: 'malicious' | 'benign';
  content: string;
  minhash?: string;
  pattern_family?: string;
}

// DLP match result
export interface DLPMatch {
  type: 'credit_card' | 'ssn' | 'api_key' | 'pem_key' | 'password_field' | 'oauth_token'
      | 'email' | 'phone' | 'ipv4' | 'db_connection';
  value_masked: string;    // e.g. "****-****-****-1234"
  offset: number;
}

// Result from L2 LLM analysis
export interface L2Result {
  threats: ThreatDetection[];
  overall_risk: number;
  recommendation: SafeHouseVerdict;
  raw_response: string;
}

// Pre-emptive nudge content for injection into enforcement channel
export interface PreemptiveNudge {
  nudge_content: string;
  threat_type: ThreatType;
  sh_score: number;
  pre_emptive: true;
}
