import type {
  FaultLine,
  FailureMode,
  TaskContext,
  PolicyRecommendation,
  ReasoningStep,
  ForecastSummary,
  Severity,
  LLMCaller,
} from './types.js';

// ============================================================================
// Policy Recommender (Phase 4.3)
// ============================================================================

/**
 * Generate a valid Policy object that mitigates predicted risks.
 *
 * Orchestration:
 *  1. Build a deterministic fallback policy (always available).
 *  2. If an LLM caller is provided, attempt to generate a refined policy via
 *     the LLM, validated and retried up to 2 times.
 *  3. Assemble reasoning chain and forecast summary.
 */
export async function recommendPolicy(
  faultLines: FaultLine[],
  failureModes: FailureMode[],
  taskContext: TaskContext,
  constraints: {
    enforcement_mode?: 'warn' | 'enforce';
    allow_unmapped_tools?: boolean;
    preserve_existing_policy?: boolean;
  },
  llm?: LLMCaller,
  validatePolicy?: (policy: unknown) => { valid: boolean; errors: Array<{ path: string; message: string }> },
): Promise<PolicyRecommendation> {
  // ---- Step 1: Deterministic fallback policy (always computed) ----
  const fallbackPolicy = buildDeterministicPolicy(faultLines, constraints);
  const fallbackReasoning = buildDeterministicReasoning(faultLines);

  let policy: unknown = fallbackPolicy;
  let reasoning: ReasoningStep[] = fallbackReasoning;
  let confidence = 0.6;
  let validation: { valid: boolean; errors: Array<{ path: string; message: string }> } = { valid: true, errors: [] };

  // ---- Step 2: LLM-enhanced path ----
  if (llm) {
    const llmResult = await attemptLLMPolicy(
      faultLines,
      failureModes,
      taskContext,
      constraints,
      llm,
      validatePolicy,
    );

    if (llmResult) {
      policy = llmResult.policy;
      reasoning = llmResult.reasoning;
      confidence = 0.9;
      validation = llmResult.validation;
    }
  }

  // If no LLM or LLM failed, validate the fallback if validator is provided
  if (confidence < 0.9 && validatePolicy) {
    validation = validatePolicy(policy);
  }

  // ---- Step 3: Forecast summary ----
  const forecastSummary = buildForecastSummary(faultLines, failureModes, confidence);

  // ---- Step 4: Assemble recommendation ----
  const inputKey = faultLines.map((fl) => fl.id).join(',') + '|' + taskContext.description;
  const recommendationId = `pr-${deterministicHex(inputKey, 12)}`;

  return {
    recommendation_id: recommendationId,
    policy,
    reasoning_chain: reasoning,
    confidence,
    forecast_summary: forecastSummary,
    validation,
  };
}

// ============================================================================
// Deterministic fallback policy builder
// ============================================================================

interface DeterministicPolicy {
  meta: {
    schema_version: string;
    name: string;
    description: string;
    scope: 'agent';
  };
  capability_mappings: Record<string, { description: string; tools: string[]; card_actions: string[] }>;
  forbidden: Array<{ pattern: string; reason: string; severity: 'critical' | 'high' | 'medium' | 'low' }>;
  escalation_triggers: Array<{ condition: string; action: 'escalate' | 'warn' | 'deny'; reason: string }>;
  defaults: {
    unmapped_tool_action: 'allow' | 'deny' | 'warn';
    unmapped_severity: 'medium';
    fail_open: true;
    enforcement_mode: 'warn' | 'enforce';
  };
}

function buildDeterministicPolicy(
  faultLines: FaultLine[],
  constraints: {
    enforcement_mode?: 'warn' | 'enforce';
    allow_unmapped_tools?: boolean;
  },
): DeterministicPolicy {
  const capabilityMappings: Record<string, { description: string; tools: string[]; card_actions: string[] }> = {};
  const forbidden: Array<{ pattern: string; reason: string; severity: 'critical' | 'high' | 'medium' | 'low' }> = [];
  const escalationTriggers: Array<{ condition: string; action: 'escalate' | 'warn' | 'deny'; reason: string }> = [];

  for (const fl of faultLines) {
    switch (fl.classification) {
      case 'incompatible': {
        // Add forbidden rules for the conflicting value's capabilities
        for (const cap of fl.affects_capabilities) {
          forbidden.push({
            pattern: cap,
            reason: `Incompatible fault line "${fl.value}": ${fl.resolution_hint}`,
            severity: fl.severity,
          });
        }
        break;
      }

      case 'priority_mismatch': {
        // Add escalation triggers
        for (const cap of fl.affects_capabilities) {
          escalationTriggers.push({
            condition: `tool_matches('${cap}')`,
            action: 'escalate',
            reason: `Priority mismatch on "${fl.value}": ${fl.resolution_hint}`,
          });
        }
        break;
      }

      case 'resolvable': {
        // Add capability mappings with the missing bounded_actions
        const capName = `auto_${fl.id.replace(/[^a-zA-Z0-9_]/g, '_')}`;
        capabilityMappings[capName] = {
          description: `Auto-mapped for resolvable fault line "${fl.value}"`,
          tools: fl.affects_capabilities.length > 0 ? fl.affects_capabilities : ['*'],
          card_actions: fl.affects_capabilities.length > 0 ? fl.affects_capabilities : [fl.value],
        };
        break;
      }
    }
  }

  return {
    meta: {
      schema_version: '1.0',
      name: 'auto-recommended',
      description: 'Auto-generated policy from fault line analysis',
      scope: 'agent' as const,
    },
    capability_mappings: capabilityMappings,
    forbidden,
    escalation_triggers: escalationTriggers,
    defaults: {
      unmapped_tool_action: constraints.allow_unmapped_tools ? 'warn' as const : 'deny' as const,
      unmapped_severity: 'medium' as const,
      fail_open: true,
      enforcement_mode: constraints.enforcement_mode ?? 'warn' as const,
    },
  };
}

// ============================================================================
// Deterministic reasoning builder
// ============================================================================

function buildDeterministicReasoning(faultLines: FaultLine[]): ReasoningStep[] {
  const steps: ReasoningStep[] = [];
  let stepNum = 1;

  const incompatible = faultLines.filter((fl) => fl.classification === 'incompatible');
  const priorityMismatch = faultLines.filter((fl) => fl.classification === 'priority_mismatch');
  const resolvable = faultLines.filter((fl) => fl.classification === 'resolvable');

  if (incompatible.length > 0) {
    steps.push({
      step: stepNum++,
      action: 'Add forbidden rules for incompatible fault lines',
      rationale: `${incompatible.length} incompatible fault line(s) require blocking conflicting capabilities to prevent value violations.`,
      fault_lines_addressed: incompatible.map((fl) => fl.id),
    });
  }

  if (priorityMismatch.length > 0) {
    steps.push({
      step: stepNum++,
      action: 'Add escalation triggers for priority mismatches',
      rationale: `${priorityMismatch.length} priority mismatch(es) require human escalation when affected capabilities are invoked.`,
      fault_lines_addressed: priorityMismatch.map((fl) => fl.id),
    });
  }

  if (resolvable.length > 0) {
    steps.push({
      step: stepNum++,
      action: 'Add capability mappings for resolvable fault lines',
      rationale: `${resolvable.length} resolvable fault line(s) addressed by mapping missing bounded_actions to capabilities.`,
      fault_lines_addressed: resolvable.map((fl) => fl.id),
    });
  }

  return steps;
}

// ============================================================================
// LLM-enhanced policy generation
// ============================================================================

interface LLMPolicyResult {
  policy: unknown;
  reasoning: ReasoningStep[];
  validation: { valid: boolean; errors: Array<{ path: string; message: string }> };
}

async function attemptLLMPolicy(
  faultLines: FaultLine[],
  failureModes: FailureMode[],
  taskContext: TaskContext,
  constraints: {
    enforcement_mode?: 'warn' | 'enforce';
    allow_unmapped_tools?: boolean;
    preserve_existing_policy?: boolean;
  },
  llm: LLMCaller,
  validatePolicy?: (policy: unknown) => { valid: boolean; errors: Array<{ path: string; message: string }> },
): Promise<LLMPolicyResult | null> {
  const { buildRecommendationPrompt } = await import('./prompts.js');
  const { system, user } = buildRecommendationPrompt(faultLines, failureModes, taskContext, constraints);

  const MAX_RETRIES = 2;
  let currentUserPrompt = user;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const response = await llm.call(system, currentUserPrompt);
      const parsed = parseJSONFromResponse(response);

      if (!parsed) {
        // Could not extract JSON — retry with guidance
        currentUserPrompt = user + '\n\nYour previous response did not contain valid JSON. Please respond with a JSON object wrapped in ```json ... ``` code fences.';
        continue;
      }

      const validation = validatePolicy
        ? validatePolicy(parsed)
        : { valid: true, errors: [] as Array<{ path: string; message: string }> };

      if (validation.valid) {
        const reasoning = parseReasoningChain(response);
        return { policy: parsed, reasoning, validation };
      }

      // Validation failed — feed errors back for retry
      const errorContext = validation.errors
        .map((e) => `  - ${e.path}: ${e.message}`)
        .join('\n');
      currentUserPrompt = user + `\n\nYour previous policy had validation errors:\n${errorContext}\n\nPlease fix these errors and return a corrected policy JSON.`;
    } catch {
      // LLM call failed — try again or give up
      continue;
    }
  }

  // All retries exhausted — return null to trigger fallback
  return null;
}

// ============================================================================
// Response parsing helpers
// ============================================================================

function parseJSONFromResponse(response: string): unknown | null {
  // Try extracting JSON from ```json ... ``` fenced block
  const fencedMatch = response.match(/```json\s*([\s\S]*?)```/);
  if (fencedMatch) {
    try {
      return JSON.parse(fencedMatch[1].trim());
    } catch {
      // Fall through to raw parse
    }
  }

  // Try parsing the entire response as JSON (find first { to last })
  const firstBrace = response.indexOf('{');
  const lastBrace = response.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    try {
      return JSON.parse(response.slice(firstBrace, lastBrace + 1));
    } catch {
      // Could not parse
    }
  }

  return null;
}

function parseReasoningChain(response: string): ReasoningStep[] {
  // Attempt to find a reasoning_chain array in the response
  const chainMatch = response.match(/"reasoning_chain"\s*:\s*(\[[\s\S]*?\])/);
  if (chainMatch) {
    try {
      const chain = JSON.parse(chainMatch[1]) as ReasoningStep[];
      if (Array.isArray(chain)) {
        return chain;
      }
    } catch {
      // Fall through
    }
  }

  return [];
}

// ============================================================================
// Forecast summary
// ============================================================================

function buildForecastSummary(
  faultLines: FaultLine[],
  failureModes: FailureMode[],
  confidence: number,
): ForecastSummary {
  // Count failure modes that have mitigation available (addressed by our policy)
  const addressed = failureModes.filter((fm) => fm.mitigation_available).length;
  const total = failureModes.length;

  // Compute residual risk from unaddressed failure modes
  const unaddressed = failureModes.filter((fm) => !fm.mitigation_available);
  const residualRiskLevel = computeResidualRisk(unaddressed, faultLines, confidence);

  return {
    failure_modes_addressed: addressed,
    failure_modes_total: total,
    residual_risk_level: residualRiskLevel,
  };
}

function computeResidualRisk(
  unaddressedModes: FailureMode[],
  faultLines: FaultLine[],
  confidence: number,
): Severity {
  if (unaddressedModes.length === 0) {
    return 'low';
  }

  // If any unaddressed mode is critical, residual risk is critical
  if (unaddressedModes.some((fm) => fm.severity === 'critical')) {
    return 'critical';
  }

  // If any unaddressed mode is high severity or confidence is low
  if (unaddressedModes.some((fm) => fm.severity === 'high') || confidence < 0.7) {
    return 'high';
  }

  // If we have multiple unaddressed modes or incompatible fault lines remain
  const incompatibleCount = faultLines.filter((fl) => fl.classification === 'incompatible').length;
  if (unaddressedModes.length > 2 || incompatibleCount > 0) {
    return 'medium';
  }

  return 'low';
}

// ============================================================================
// Utility
// ============================================================================

function deterministicHex(input: string, length: number): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(length, '0').slice(0, length);
}
