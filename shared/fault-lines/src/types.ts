// ============================================================================
// Fault Line Types (Phase 4.1)
// ============================================================================

export type FaultLineClassification = 'resolvable' | 'priority_mismatch' | 'incompatible';
export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface FaultLine {
  id: string;
  value: string;
  classification: FaultLineClassification;
  severity: Severity;
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
  critical_count: number;
}

export interface FaultLineAnalysis {
  team_id: string;
  analysis_id: string;
  fleet_score: number;
  fault_lines: FaultLine[];
  summary: FaultLineSummary;
}

// ============================================================================
// Coherence Input Types (from AAP E-05 checkFleetCoherence)
// ============================================================================

export interface ValueDivergence {
  value: string;
  agent_a: string;
  agent_b: string;
  divergence_score: number;
  details?: string;
}

export interface FleetCoherenceResult {
  fleet_score: number;
  pairwise_scores: Array<{
    agent_a: string;
    agent_b: string;
    score: number;
  }>;
  value_divergences: ValueDivergence[];
  outliers: string[];
  clusters: Array<{
    agents: string[];
    shared_values: string[];
  }>;
}

export interface AgentCard {
  agent_id: string;
  values?: {
    declared?: string[];
    definitions?: Record<string, {
      name?: string;
      description?: string;
      priority?: number;
      conflicts_with?: string[];
    }>;
  };
  autonomy_envelope?: {
    bounded_actions?: string[];
    forbidden_actions?: string[];
  };
  extensions?: Record<string, unknown>;
}

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
  severity: Severity;
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
  overall_risk_level: Severity;
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
  residual_risk_level: Severity;
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
