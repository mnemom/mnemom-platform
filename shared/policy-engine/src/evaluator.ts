import { toolMatchesPattern, toolMatchesAny } from './glob.js';
import { extractPolicyFromCard } from './card-policy.js';
import { mergeTransactionGuardrails } from './merge.js';
import type {
  EvaluationInput,
  EvaluationResult,
  PolicyViolation,
  PolicyWarning,
  CardGap,
  CoverageReport,
  CapabilityMapping,
} from './types.js';

/**
 * UC-8 — evaluate tools against a unified alignment card.
 *
 * Pure, synchronous, zero I/O. The evaluator:
 *   1. Derives a Policy from the card via extractPolicyFromCard.
 *   2. If transactionGuardrails is provided, intersects via
 *      mergeTransactionGuardrails (ephemeral, can only restrict).
 *   3. Walks the tools list, checking forbidden rules, capability mappings,
 *      and escalation triggers against the effective policy.
 *
 * Dual-shape aware on bounded_actions: prefers autonomy.bounded_actions
 * (unified) with fallback to autonomy_envelope.bounded_actions (legacy).
 */
export function evaluatePolicy(input: EvaluationInput): EvaluationResult {
  const start = Date.now();
  const { card, tools, context, transactionGuardrails } = input;

  // Derive the policy from the card, then layer ephemeral txn guardrails.
  const derivedPolicy = extractPolicyFromCard(card);
  const policy = transactionGuardrails
    ? mergeTransactionGuardrails(derivedPolicy, transactionGuardrails)
    : derivedPolicy;

  const violations: PolicyViolation[] = [];
  const warnings: PolicyWarning[] = [];
  const cardGaps: CardGap[] = [];
  const boundedActions = new Set(
    card.autonomy?.bounded_actions
      ?? card.autonomy_envelope?.bounded_actions
      ?? [],
  );

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

        // In observer context, record card gaps for Phase 3 remediation
        if (context === 'observer') {
          cardGaps.push({
            tool: toolName,
            capability: mapping.capabilityName,
            missing_card_actions: missingActions,
            reason: `Card missing actions [${missingActions.join(', ')}] required by capability "${mapping.capabilityName}"`,
          });
        }
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
    card_gaps: cardGaps,
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
