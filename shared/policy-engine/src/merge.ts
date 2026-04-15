import type { Policy, PolicyDefaults } from './types.js';

// ============================================================================
// UC-8 — mergePolicies was removed. Org+agent policy merging now happens at
// storage time in mnemom-api's composition engine (the canonical alignment
// card is pre-merged). Callers that previously ran
//   mergePolicies(orgPolicy, agentPolicy, isExempt)
// should now fetch the canonical card and call evaluatePolicy({card, tools});
// the evaluator derives a Policy via extractPolicyFromCard.
//
// mergeTransactionGuardrails (below) stays because transaction guardrails are
// ephemeral per-request overrides that don't live in the card.
// ============================================================================

// ----------------------------------------------------------------------------
// Shared merge helpers (used by mergeTransactionGuardrails + historical
// mergePolicies). Left as private functions in this module so the
// transaction path can reuse them.
// ----------------------------------------------------------------------------

function mergeForbidden(
  org: Policy['forbidden'],
  agent: Policy['forbidden']
): Policy['forbidden'] {
  const seen = new Set<string>();
  const merged: Policy['forbidden'] = [];
  for (const rule of [...org, ...agent]) {
    if (!seen.has(rule.pattern)) {
      seen.add(rule.pattern);
      merged.push({ ...rule });
    }
  }
  return merged;
}

const STRENGTH_ORDER: Record<string, number> = {
  allow: 0,
  warn: 1,
  deny: 2,
};

const SEVERITY_ORDER: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function stronger(orgVal: string, agentVal: string, order: Record<string, number>): string {
  const orgStrength = order[orgVal] ?? 0;
  const agentStrength = order[agentVal] ?? 0;
  return agentStrength >= orgStrength ? agentVal : orgVal;
}

// ============================================================================
// Transaction guardrail merge (intersection semantics)
// ============================================================================

const ENFORCEMENT_ORDER: Record<string, number> = {
  off: 0,
  warn: 1,
  enforce: 2,
};

/**
 * Merge a base policy with transaction-scoped guardrails.
 *
 * Unlike {@link mergePolicies} which uses union semantics for capability
 * mappings (agent adds, can't remove), this function uses INTERSECTION
 * semantics — the transaction can only RESTRICT, never expand.
 *
 * Merge rules:
 * - capability_mappings: intersection (only capabilities in BOTH survive)
 * - forbidden: union (transaction adds MORE forbidden rules)
 * - escalation_triggers: concatenation (base first, then transaction)
 * - defaults: transaction cannot weaken — same floor semantics as org merge
 * - meta: `{base.name}+txn-guardrails`, preserving base scope & schema_version
 */
export function mergeTransactionGuardrails(
  basePolicy: Policy,
  txnPolicy: Policy
): Policy {
  return {
    meta: {
      schema_version: basePolicy.meta.schema_version,
      name: `${basePolicy.meta.name}+txn-guardrails`,
      scope: basePolicy.meta.scope,
      description: basePolicy.meta.description,
    },

    // Intersection: only capabilities present in BOTH remain
    capability_mappings: intersectCapabilityMappings(
      basePolicy.capability_mappings,
      txnPolicy.capability_mappings
    ),

    // Union: transaction adds more forbidden rules
    forbidden: mergeForbidden(basePolicy.forbidden, txnPolicy.forbidden),

    // Concat: base triggers first, then transaction
    escalation_triggers: [
      ...basePolicy.escalation_triggers,
      ...txnPolicy.escalation_triggers,
    ],

    // Base is floor: transaction can strengthen but not weaken
    defaults: mergeTransactionDefaults(basePolicy.defaults, txnPolicy.defaults),
  };
}

function intersectCapabilityMappings(
  base: Policy['capability_mappings'],
  txn: Policy['capability_mappings']
): Policy['capability_mappings'] {
  const merged: Policy['capability_mappings'] = {};

  for (const [name, baseMapping] of Object.entries(base)) {
    const txnMapping = txn[name];
    // Only capabilities present in BOTH survive
    if (!txnMapping) continue;

    const toolSet = new Set(baseMapping.tools);
    const intersectedTools = txnMapping.tools.filter((t) => toolSet.has(t));

    const actionSet = new Set(baseMapping.card_actions);
    const intersectedActions = txnMapping.card_actions.filter((a) => actionSet.has(a));

    // If intersection results in empty tools or card_actions, drop the capability
    if (intersectedTools.length === 0 || intersectedActions.length === 0) continue;

    merged[name] = {
      description: baseMapping.description,
      tools: intersectedTools,
      card_actions: intersectedActions,
    };
  }

  return merged;
}

function mergeTransactionDefaults(
  base: PolicyDefaults,
  txn: PolicyDefaults
): PolicyDefaults {
  const merged: PolicyDefaults = {
    // Transaction can strengthen (allow→warn, warn→deny) but not weaken
    unmapped_tool_action: stronger(
      base.unmapped_tool_action,
      txn.unmapped_tool_action,
      STRENGTH_ORDER
    ) as PolicyDefaults['unmapped_tool_action'],

    // Transaction can escalate severity but not reduce it
    unmapped_severity: stronger(
      base.unmapped_severity,
      txn.unmapped_severity,
      SEVERITY_ORDER
    ) as PolicyDefaults['unmapped_severity'],

    // Transaction cannot weaken fail_open (base false → stays false)
    fail_open: base.fail_open ? txn.fail_open : false,
  };

  // enforcement_mode: use the stronger value (warn < enforce; ignore 'off')
  const baseMode = base.enforcement_mode;
  const txnMode = txn.enforcement_mode;
  if (baseMode || txnMode) {
    merged.enforcement_mode = stronger(
      baseMode ?? 'off',
      txnMode ?? 'off',
      ENFORCEMENT_ORDER
    ) as PolicyDefaults['enforcement_mode'];
  }

  return merged;
}
