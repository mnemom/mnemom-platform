// ============================================================================
// Policy DSL Types
// ============================================================================

export interface PolicyMeta {
  schema_version: string;
  name: string;
  description?: string;
  scope: 'org' | 'agent';
}

export interface CapabilityMapping {
  description?: string;
  tools: string[];
  card_actions: string[];
}

export interface ForbiddenRule {
  pattern: string;
  reason: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface EscalationTrigger {
  condition: string;
  action: 'escalate' | 'warn' | 'deny';
  reason: string;
}

export interface PolicyDefaults {
  unmapped_tool_action: 'allow' | 'deny' | 'warn';
  unmapped_severity: 'critical' | 'high' | 'medium' | 'low';
  fail_open: boolean;
  enforcement_mode?: 'warn' | 'enforce' | 'off';
  grace_period_hours?: number;
}

export interface Policy {
  meta: PolicyMeta;
  capability_mappings: Record<string, CapabilityMapping>;
  forbidden: ForbiddenRule[];
  escalation_triggers: EscalationTrigger[];
  defaults: PolicyDefaults;
}

// ============================================================================
// Evaluation Types
// ============================================================================

/**
 * AAP 1.0.x-shaped alignment card. Retained so callers that still hand the
 * evaluator an AAP-shape object (pre-UC-8 path) keep working. The evaluator
 * itself reads bounded_actions from both card.autonomy (unified) and
 * card.autonomy_envelope (AAP) via the fallback chain.
 */
export interface AlignmentCard {
  card_id?: string;
  version?: string;
  principal?: {
    name?: string;
    type?: string;
    organization?: string;
  };
  values?: {
    declared?: string[];
    definitions?: Record<string, string>;
  };
  autonomy_envelope?: {
    bounded_actions?: string[];
    forbidden_actions?: string[];
    escalation_triggers?: Array<{
      condition: string;
      action?: string;
    }>;
  };
  audit_commitment?: {
    log_level?: string;
    retention_days?: number;
    access_policy?: string;
  };
  extensions?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * UC-8 unified alignment card shape. Superset of AlignmentCard — includes
 * capabilities + enforcement + autonomy (not autonomy_envelope). Consumers
 * derive the evaluator-facing Policy via extractPolicyFromCard.
 */
export interface UnifiedAlignmentCard {
  card_version?: string;
  card_id?: string;
  agent_id?: string;
  issued_at?: string;
  expires_at?: string | null;
  principal?: Record<string, unknown>;
  values?: {
    declared?: string[];
    definitions?: Record<string, unknown>;
    conflicts_with?: string[];
  };
  conscience?: {
    mode?: 'augment' | 'replace';
    values?: Array<{ type: string; content: string; severity?: string }>;
  };
  integrity?: {
    enforcement_mode?: 'observe' | 'nudge' | 'enforce';
  };
  autonomy?: {
    bounded_actions?: string[];
    forbidden_actions?: string[];
    escalation_triggers?: Array<{ condition: string; action?: string; reason?: string }>;
    max_autonomous_value?: { amount: number; currency?: string };
  };
  /** Legacy AAP shape — read as fallback by the evaluator. */
  autonomy_envelope?: AlignmentCard['autonomy_envelope'];
  capabilities?: Record<string, {
    description?: string;
    tools: string[];
    required_actions: string[];
  }>;
  enforcement?: {
    forbidden_tools?: Array<{ pattern: string; reason: string; severity: 'critical' | 'high' | 'medium' | 'low' }>;
    unmapped_tool_action?: 'allow' | 'deny' | 'warn';
    fail_open?: boolean;
    mode?: 'off' | 'warn' | 'enforce';
    grace_period_hours?: number;
  };
  audit?: Record<string, unknown>;
  extensions?: Record<string, unknown>;
  _composition?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface ToolReference {
  name: string;
}

/**
 * UC-8 evaluator input: a single unified card + tools.
 *
 * The pre-UC-8 `policy` field is gone — the evaluator derives it from the
 * card's capabilities + enforcement + autonomy sections via
 * extractPolicyFromCard.
 *
 * `transactionGuardrails` is an optional ephemeral per-request policy that
 * INTERSECTS with the derived policy (transactions can only restrict,
 * never expand). Used by the gateway for X-Transaction-* header overrides.
 */
export interface EvaluationInput {
  context: 'cicd' | 'gateway' | 'observer';
  card: UnifiedAlignmentCard;
  tools: ToolReference[];
  transactionGuardrails?: Policy;
  dryRun?: boolean;
}

export interface PolicyViolation {
  type: 'forbidden' | 'capability_exceeded' | 'unmapped_denied';
  tool: string;
  capability?: string;
  rule?: string;
  reason: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface PolicyWarning {
  type: 'unmapped_tool' | 'escalation_triggered';
  tool: string;
  reason: string;
}

export interface CoverageReport {
  total_card_actions: number;
  mapped_card_actions: string[];
  unmapped_card_actions: string[];
  coverage_pct: number;
}

export interface CardGap {
  tool: string;
  capability: string;
  missing_card_actions: string[];
  reason: string;
}

export interface EvaluationResult {
  verdict: 'pass' | 'fail' | 'warn';
  violations: PolicyViolation[];
  warnings: PolicyWarning[];
  card_gaps: CardGap[];
  coverage: CoverageReport;
  policy_id: string;
  policy_version: number;
  evaluated_at: string;
  context: string;
  duration_ms: number;
}

// ============================================================================
// Merge Types
// ============================================================================

export interface PolicyData {
  orgPolicy: Policy | null;
  agentPolicy: Policy | null;
  exempt: boolean;
}

// ============================================================================
// Validation Types
// ============================================================================

export interface ValidationError {
  path: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
}
