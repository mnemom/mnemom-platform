/**
 * UC-8 — Extract a policy-evaluator-shaped view from a unified alignment card.
 *
 * The unified card (per ADR-008) folds what used to be a separate CLPI
 * policy into its own `capabilities` + `enforcement` sections, plus the
 * `autonomy.escalation_triggers` array. This helper produces the
 * pre-UC-4 `Policy` shape from a canonical unified card so the evaluator
 * (which still operates on `Policy` internally) doesn't need to know
 * about the new shape.
 *
 * Consumers:
 *   - evaluatePolicy() — reads the card, extracts, evaluates.
 *   - Gateway / observer hot paths — pre-UC-8 they did
 *     fetchPolicyForAgent + mergePolicies; now they pass the canonical
 *     card directly and the evaluator does the extraction.
 *
 * Shape-tolerance: the extractor handles both unified (autonomy.*,
 * enforcement.forbidden_tools) and pre-UC-4 AAP (autonomy_envelope.*,
 * policy-side forbidden) shapes. Callers during migration can pass
 * either; new callers should pass unified.
 */
import type {
  Policy,
  CapabilityMapping,
  ForbiddenRule,
  EscalationTrigger,
  PolicyDefaults,
  UnifiedAlignmentCard,
} from './types.js';

export function extractPolicyFromCard(card: UnifiedAlignmentCard): Policy {
  const c = card as Record<string, any>;

  // Capabilities: card.capabilities (unified) first, fall back to none.
  // The card schema uses `required_actions`; policy-engine's CapabilityMapping
  // uses `card_actions`. Rename here.
  const capability_mappings: Record<string, CapabilityMapping> = {};
  const cardCaps = (c.capabilities ?? {}) as Record<string, any>;
  for (const [name, entry] of Object.entries(cardCaps)) {
    if (!entry || typeof entry !== 'object') continue;
    const e = entry as Record<string, any>;
    capability_mappings[name] = {
      description: typeof e.description === 'string' ? e.description : undefined,
      tools: Array.isArray(e.tools) ? e.tools.filter((t): t is string => typeof t === 'string') : [],
      // Unified uses required_actions; some tests may use card_actions for legacy.
      card_actions: Array.isArray(e.required_actions)
        ? e.required_actions.filter((a): a is string => typeof a === 'string')
        : (Array.isArray(e.card_actions)
            ? e.card_actions.filter((a): a is string => typeof a === 'string')
            : []),
    };
  }

  // Forbidden tools: card.enforcement.forbidden_tools (unified)
  const enforcement = (c.enforcement ?? {}) as Record<string, any>;
  const forbidden: ForbiddenRule[] = Array.isArray(enforcement.forbidden_tools)
    ? enforcement.forbidden_tools
        .filter((f: any) => f && typeof f.pattern === 'string')
        .map((f: any): ForbiddenRule => ({
          pattern: f.pattern,
          reason: typeof f.reason === 'string' ? f.reason : 'forbidden by card',
          severity: (f.severity as ForbiddenRule['severity']) || 'high',
        }))
    : [];

  // Escalation triggers: card.autonomy.escalation_triggers (unified) fallback
  // to card.autonomy_envelope.escalation_triggers (AAP legacy).
  const autonomy = (c.autonomy ?? c.autonomy_envelope ?? {}) as Record<string, any>;
  const triggersRaw = Array.isArray(autonomy.escalation_triggers)
    ? autonomy.escalation_triggers
    : [];
  const escalation_triggers: EscalationTrigger[] = triggersRaw
    .filter((t: any) => t && typeof t.condition === 'string')
    .map((t: any): EscalationTrigger => ({
      condition: t.condition,
      action: (t.action as EscalationTrigger['action']) || 'escalate',
      reason: typeof t.reason === 'string' ? t.reason : '',
    }));

  // Defaults: card.enforcement.{unmapped_tool_action, fail_open, mode, grace_period_hours}
  // unmapped_severity is derived from unmapped_tool_action:
  //   deny  → high   (explicit denial is a hard violation)
  //   warn  → medium (caller is asking for awareness, not rejection)
  //   allow → low    (informational only)
  const unmappedAction = (enforcement.unmapped_tool_action as PolicyDefaults['unmapped_tool_action']) || 'allow';
  const unmappedSeverity: PolicyDefaults['unmapped_severity'] =
    unmappedAction === 'deny' ? 'high'
    : unmappedAction === 'warn' ? 'medium'
    : 'low';
  const defaults: PolicyDefaults = {
    unmapped_tool_action: unmappedAction,
    unmapped_severity: unmappedSeverity,
    fail_open: enforcement.fail_open !== false,
    enforcement_mode: (enforcement.mode as PolicyDefaults['enforcement_mode']) || 'warn',
    grace_period_hours: typeof enforcement.grace_period_hours === 'number'
      ? enforcement.grace_period_hours
      : undefined,
  };

  // Policy meta: derive a name/scope that's legible in audit logs.
  const cardId = typeof c.card_id === 'string' ? c.card_id : 'card';
  return {
    meta: {
      schema_version: typeof c.card_version === 'string' ? c.card_version : '2026-04-15',
      name: `${cardId}/derived`,
      description: 'Extracted from unified alignment card (UC-8)',
      scope: 'agent',
    },
    capability_mappings,
    forbidden,
    escalation_triggers,
    defaults,
  };
}
