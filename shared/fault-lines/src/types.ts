// ============================================================================
// Fault Line Types (Phase 4.1)
// ============================================================================

// ===== INTERIM: will be imported from @mnemom/agent-alignment-protocol@0.6.0 =====
export type FaultLineClassification = 'resolvable' | 'priority_mismatch' | 'incompatible' | 'complementary';

export interface FaultLine {
  id: string;
  value: string;
  classification: FaultLineClassification;
  severity: 'critical' | 'high' | 'medium' | 'low';
  agents_declaring: string[];
  agents_missing: string[];
  agents_conflicting: string[];
  impact_score: number;
  resolution_hint: string;
  affects_capabilities: string[];
}

export interface FaultLineSummary {
  total: number;
  resolvable: number;
  priority_mismatch: number;
  incompatible: number;
  complementary: number;
  critical_count: number;
}

export interface FaultLineAlignment {
  id: string;
  fault_line_ids: string[];
  minority_agents: string[];
  majority_agents: string[];
  alignment_score: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}

export interface FaultLineAnalysis {
  analysis_id: string;
  fleet_score: number;
  fault_lines: FaultLine[];
  alignments: FaultLineAlignment[];
  summary: FaultLineSummary;
}

export interface ValueDivergence {
  value: string;
  agents_declaring: string[];
  agents_missing: string[];
  agents_conflicting: string[];
  impact_on_fleet_score: number;
}

export interface FleetCoherenceResult {
  fleet_score: number;
  min_pair_score: number;
  max_pair_score: number;
  agent_count: number;
  pair_count: number;
  pairwise_matrix: Array<{
    agent_a: string;
    agent_b: string;
    result: { score: number; compatible: boolean; value_alignment: { matched: string[]; unmatched: string[]; conflicts: unknown[] } };
  }>;
  outliers: Array<{ agent_id: string; agent_mean_score: number; fleet_mean_score: number; deviation: number; primary_conflicts: string[] }>;
  clusters: Array<{ cluster_id: number; agent_ids: string[]; internal_coherence: number; shared_values: string[]; distinguishing_values: string[] }>;
  divergence_report: ValueDivergence[];
  agent_summaries: Array<{ agent_id: string; mean_score: number; compatible_count: number; conflict_count: number; cluster_id: number; is_outlier: boolean }>;
}
// ===== END INTERIM =====

// ============================================================================
// Risk Forecast Types (Phase 4.2)
// ============================================================================

export type FailureModeType =
  | 'escalation_conflict'
  | 'capability_gap'
  | 'value_override'
  | 'coordination_deadlock'
  | 'trust_erosion';

export type RiskTolerance = 'conservative' | 'moderate' | 'aggressive';

export interface FailureMode {
  mode: FailureModeType;
  description: string;
  probability: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  triggered_by: string[];
  affected_agents: string[];
  mitigation_available: boolean;
}

export interface TaskContext {
  description: string;
  action_type: string;
  tools?: string[];
  duration_hours?: number;
}

export interface RiskForecast {
  forecast_id: string;
  fault_line_analysis_id: string;
  failure_modes: FailureMode[];
  overall_risk_level: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
}

// ============================================================================
// Policy Recommendation Types (Phase 4.3)
// ============================================================================

export interface ReasoningStep {
  step: number;
  action: string;
  rationale: string;
  fault_lines_addressed: string[];
}

export interface ForecastSummary {
  failure_modes_addressed: number;
  failure_modes_total: number;
  residual_risk_level: 'critical' | 'high' | 'medium' | 'low';
}

export interface PolicyRecommendation {
  recommendation_id: string;
  policy: unknown; // Policy type from @mnemom/policy-engine — kept generic to avoid circular dep
  reasoning_chain: ReasoningStep[];
  confidence: number;
  forecast_summary: ForecastSummary;
  validation: { valid: boolean; errors: Array<{ path: string; message: string }> };
}

// ============================================================================
// LLM Interface Types
// ============================================================================

export interface LLMCaller {
  call(system: string, user: string): Promise<string>;
}

