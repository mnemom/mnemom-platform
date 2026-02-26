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

export interface ToolReference {
  name: string;
}

export interface EvaluationInput {
  context: 'cicd' | 'gateway' | 'observer';
  policy: Policy;
  card: AlignmentCard;
  tools: ToolReference[];
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

export interface EvaluationResult {
  verdict: 'pass' | 'fail' | 'warn';
  violations: PolicyViolation[];
  warnings: PolicyWarning[];
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
