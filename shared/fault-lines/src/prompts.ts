import type {
  FaultLine,
  TaskContext,
  FailureMode,
  FailureModeType,
} from './types.js';

// ============================================================================
// Recommendation Constraints
// ============================================================================

export interface RecommendationConstraints {
  enforcement_mode?: 'warn' | 'enforce';
  allow_unmapped_tools?: boolean;
  preserve_existing_policy?: boolean;
}

// ============================================================================
// Prompt Builders
// ============================================================================

const VALID_FAILURE_MODES: FailureModeType[] = [
  'escalation_conflict',
  'capability_gap',
  'value_override',
  'coordination_deadlock',
  'trust_erosion',
];

const FAILURE_MODE_SCHEMA = `{
  "mode": "escalation_conflict | capability_gap | value_override | coordination_deadlock | trust_erosion",
  "description": "string — concise explanation of how this failure could manifest",
  "probability": "number — between 0 and 1 inclusive",
  "severity": "critical | high | medium | low",
  "triggered_by": ["fault_line_id_1", "..."],
  "affected_agents": ["agent_id_1", "..."],
  "mitigation_available": "boolean"
}`;

const POLICY_SCHEMA = `{
  "meta": {
    "schema_version": "string",
    "name": "string",
    "description": "string (optional)",
    "scope": "org | agent"
  },
  "capability_mappings": {
    "<capability_name>": {
      "description": "string (optional)",
      "tools": ["tool_pattern_1", "..."],
      "card_actions": ["action_1", "..."]
    }
  },
  "forbidden": [
    {
      "pattern": "string — tool glob pattern",
      "reason": "string",
      "severity": "critical | high | medium | low"
    }
  ],
  "escalation_triggers": [
    {
      "condition": "string — e.g. tool_matches('pattern')",
      "action": "escalate | warn | deny",
      "reason": "string"
    }
  ],
  "defaults": {
    "unmapped_tool_action": "allow | deny | warn",
    "unmapped_severity": "critical | high | medium | low",
    "fail_open": "boolean",
    "enforcement_mode": "warn | enforce | off (optional)",
    "grace_period_hours": "number (optional)"
  }
}`;

/**
 * Build a prompt pair for forecasting failure modes from fault lines.
 */
export function buildForecastPrompt(
  faultLines: FaultLine[],
  taskContext: TaskContext
): { system: string; user: string } {
  const system = `You are a risk forecasting engine. Your job is to analyze fault lines between AI agents and predict potential failure modes.

You MUST respond with ONLY a valid JSON array of failure mode objects. No markdown, no explanation, no wrapping — just the raw JSON array.

Each failure mode object must match this schema exactly:
${FAILURE_MODE_SCHEMA}

Rules:
- probability MUST be a number between 0 and 1 inclusive.
- mode MUST be one of: ${VALID_FAILURE_MODES.join(', ')}.
- severity MUST be one of: critical, high, medium, low.
- triggered_by MUST reference fault line IDs from the provided data.
- affected_agents MUST reference agent IDs from the provided fault line data.
- mitigation_available should be true if the fault line classification is "resolvable", false for "incompatible", and your judgment for "priority_mismatch".
- Output between 1 and ${Math.max(faultLines.length * 2, 3)} failure modes.
- Deduplicate: do not output two objects with the same mode value.`;

  const faultLineData = faultLines.map((fl) => ({
    id: fl.id,
    value: fl.value,
    classification: fl.classification,
    severity: fl.severity,
    agents_declaring: fl.agents_declaring,
    agents_missing: fl.agents_missing,
    agents_conflicting: fl.agents_conflicting,
    impact_score: fl.impact_score,
    resolution_hint: fl.resolution_hint,
    affects_capabilities: fl.affects_capabilities,
  }));

  const user = `Analyze the following fault lines and task context to predict failure modes.

## Fault Lines
${JSON.stringify(faultLineData, null, 2)}

## Task Context
- Description: ${taskContext.description}
- Action type: ${taskContext.action_type}
- Tools: ${taskContext.tools?.join(', ') ?? 'none specified'}
- Duration: ${taskContext.duration_hours ?? 'unspecified'} hours

Respond with ONLY a JSON array of failure mode objects.`;

  return { system, user };
}

/**
 * Build a prompt pair for generating policy recommendations from fault lines and failure modes.
 */
export function buildRecommendationPrompt(
  faultLines: FaultLine[],
  failureModes: FailureMode[],
  taskContext: TaskContext,
  constraints?: RecommendationConstraints
): { system: string; user: string } {
  const enforcementMode = constraints?.enforcement_mode ?? 'warn';
  const allowUnmapped = constraints?.allow_unmapped_tools ?? true;
  const preserveExisting = constraints?.preserve_existing_policy ?? false;

  const system = `You are a policy recommendation engine. Your job is to generate a valid Policy JSON that mitigates predicted failure modes arising from fault lines between AI agents.

You MUST respond with ONLY a valid JSON object with two top-level keys: "policy" and "reasoning_chain". No markdown, no explanation, no wrapping — just the raw JSON object.

The "policy" value must match this Policy DSL schema exactly:
${POLICY_SCHEMA}

The "reasoning_chain" value must be a JSON array of reasoning step objects:
[
  {
    "step": 1,
    "action": "string — what the policy change does",
    "rationale": "string — why this change mitigates the risk",
    "fault_lines_addressed": ["fault_line_id_1", "..."]
  }
]

Policy generation rules:
- enforcement_mode in defaults should be "${enforcementMode}".
- unmapped_tool_action should be "${allowUnmapped ? 'warn' : 'deny'}".
- ${preserveExisting ? 'Preserve existing policy structure where possible — only add rules, do not remove.' : 'Generate a complete policy from scratch.'}
- Every failure mode with probability >= 0.5 MUST be addressed by at least one policy rule.
- forbidden rules should target tools involved in high-severity failure modes.
- escalation_triggers should use tool_matches('pattern') condition syntax.
- schema_version must be "1.0".
- Each reasoning step must reference which fault lines it addresses.`;

  const faultLineData = faultLines.map((fl) => ({
    id: fl.id,
    value: fl.value,
    classification: fl.classification,
    severity: fl.severity,
    affects_capabilities: fl.affects_capabilities,
    resolution_hint: fl.resolution_hint,
  }));

  const failureModeData = failureModes.map((fm) => ({
    mode: fm.mode,
    description: fm.description,
    probability: fm.probability,
    severity: fm.severity,
    triggered_by: fm.triggered_by,
    affected_agents: fm.affected_agents,
    mitigation_available: fm.mitigation_available,
  }));

  const user = `Generate a policy recommendation to mitigate the following risks.

## Fault Lines
${JSON.stringify(faultLineData, null, 2)}

## Predicted Failure Modes
${JSON.stringify(failureModeData, null, 2)}

## Task Context
- Description: ${taskContext.description}
- Action type: ${taskContext.action_type}
- Tools: ${taskContext.tools?.join(', ') ?? 'none specified'}
- Duration: ${taskContext.duration_hours ?? 'unspecified'} hours

## Constraints
- Enforcement mode: ${enforcementMode}
- Allow unmapped tools: ${allowUnmapped}
- Preserve existing policy: ${preserveExisting}

Respond with ONLY a JSON object containing "policy" and "reasoning_chain" keys.`;

  return { system, user };
}
