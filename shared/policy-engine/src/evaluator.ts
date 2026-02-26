import { toolMatchesPattern, toolMatchesAny } from './glob.js';
import type {
  EvaluationInput,
  EvaluationResult,
  PolicyViolation,
  PolicyWarning,
  CoverageReport,
  CapabilityMapping,
} from './types.js';

/**
 * Evaluate a set of tools against a policy and alignment card.
 * Pure, synchronous function with zero I/O.
 */
export function evaluatePolicy(input: EvaluationInput): EvaluationResult {
  const start = Date.now();
  const { policy, card, tools, context } = input;

  const violations: PolicyViolation[] = [];
  const warnings: PolicyWarning[] = [];
  const boundedActions = new Set(card.autonomy_envelope?.bounded_actions ?? []);

  for (const tool of tools) {
    const toolName = tool.name;

    // 1. Check forbidden rules
    const forbiddenMatch = policy.forbidden.find((rule) =>
      toolMatchesPattern(toolName, rule.pattern)
    );
    if (forbiddenMatch) {
      violations.push({
        type: 'forbidden',
        tool: toolName,
        rule: forbiddenMatch.pattern,
        reason: forbiddenMatch.reason,
        severity: forbiddenMatch.severity,
      });
      // Continue checking other rules — a tool can trigger multiple violations
    }

    // 2. Find capability mapping
    const mapping = findCapabilityMapping(toolName, policy.capability_mappings);

    if (mapping) {
      // Tool is mapped — check that the capability's card_actions exist in bounded_actions
      const missingActions = mapping.cardActions.filter((a) => !boundedActions.has(a));
      if (missingActions.length > 0) {
        violations.push({
          type: 'capability_exceeded',
          tool: toolName,
          capability: mapping.capabilityName,
          reason: `Tool "${toolName}" maps to capability "${mapping.capabilityName}" which requires card actions [${missingActions.join(', ')}] not in bounded_actions`,
          severity: 'high',
        });
      }
    } else {
      // Tool is unmapped — apply defaults
      const action = policy.defaults.unmapped_tool_action;
      if (action === 'deny') {
        violations.push({
          type: 'unmapped_denied',
          tool: toolName,
          reason: `Tool "${toolName}" has no capability mapping and unmapped_tool_action is "deny"`,
          severity: policy.defaults.unmapped_severity,
        });
      } else if (action === 'warn') {
        warnings.push({
          type: 'unmapped_tool',
          tool: toolName,
          reason: `Tool "${toolName}" has no capability mapping`,
        });
      }
      // action === 'allow' — silently pass
    }

    // 3. Check escalation triggers
    for (const trigger of policy.escalation_triggers) {
      if (matchesEscalationCondition(toolName, trigger.condition)) {
        if (trigger.action === 'deny') {
          violations.push({
            type: 'forbidden',
            tool: toolName,
            rule: trigger.condition,
            reason: trigger.reason,
            severity: 'high',
          });
        } else {
          // 'escalate' or 'warn'
          warnings.push({
            type: 'escalation_triggered',
            tool: toolName,
            reason: trigger.reason,
          });
        }
      }
    }
  }

  // Compute coverage
  const coverage = computeCoverage(boundedActions, policy.capability_mappings);

  // Determine verdict
  const hasCriticalOrHigh = violations.some(
    (v) => v.severity === 'critical' || v.severity === 'high'
  );
  const hasAnyViolation = violations.length > 0;

  let verdict: 'pass' | 'fail' | 'warn';
  if (hasCriticalOrHigh) {
    verdict = 'fail';
  } else if (hasAnyViolation || warnings.length > 0) {
    verdict = 'warn';
  } else {
    verdict = 'pass';
  }

  return {
    verdict,
    violations,
    warnings,
    coverage,
    policy_id: policy.meta.name,
    policy_version: 1,
    evaluated_at: new Date().toISOString(),
    context,
    duration_ms: Date.now() - start,
  };
}

// ============================================================================
// Internal helpers
// ============================================================================

interface MappingMatch {
  capabilityName: string;
  cardActions: string[];
}

function findCapabilityMapping(
  toolName: string,
  mappings: Record<string, CapabilityMapping>
): MappingMatch | null {
  for (const [name, mapping] of Object.entries(mappings)) {
    if (toolMatchesAny(toolName, mapping.tools)) {
      return { capabilityName: name, cardActions: mapping.card_actions };
    }
  }
  return null;
}

/**
 * Simple condition evaluation for escalation triggers.
 * Supports: tool_matches('pattern')
 */
function matchesEscalationCondition(toolName: string, condition: string): boolean {
  const match = condition.match(/^tool_matches\(['"](.+)['"]\)$/);
  if (match) {
    return toolMatchesPattern(toolName, match[1]);
  }
  return false;
}

function computeCoverage(
  boundedActions: Set<string>,
  mappings: Record<string, CapabilityMapping>
): CoverageReport {
  const allCardActions = Array.from(boundedActions);

  // Collect all card_actions that have at least one mapping
  const mappedSet = new Set<string>();
  for (const mapping of Object.values(mappings)) {
    for (const action of mapping.card_actions) {
      if (boundedActions.has(action)) {
        mappedSet.add(action);
      }
    }
  }

  const mapped = Array.from(mappedSet);
  const unmapped = allCardActions.filter((a) => !mappedSet.has(a));

  return {
    total_card_actions: allCardActions.length,
    mapped_card_actions: mapped,
    unmapped_card_actions: unmapped,
    coverage_pct: allCardActions.length > 0 ? (mapped.length / allCardActions.length) * 100 : 100,
  };
}
