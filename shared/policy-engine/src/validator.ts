import type { Policy, ValidationResult, ValidationError } from './types.js';

const VALID_SCOPES = ['org', 'agent'];
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];
const VALID_ACTIONS = ['allow', 'deny', 'warn'];
const VALID_ESCALATION_ACTIONS = ['escalate', 'warn', 'deny'];

/**
 * Validate a policy object against the schema.
 * Returns a ValidationResult with any structural errors.
 */
export function validatePolicySchema(policy: unknown): ValidationResult {
  const errors: ValidationError[] = [];

  if (!policy || typeof policy !== 'object') {
    return { valid: false, errors: [{ path: '', message: 'Policy must be a non-null object' }] };
  }

  const p = policy as Record<string, unknown>;

  // meta
  validateMeta(p.meta, errors);

  // capability_mappings
  validateCapabilityMappings(p.capability_mappings, errors);

  // forbidden
  validateForbidden(p.forbidden, errors);

  // escalation_triggers
  validateEscalationTriggers(p.escalation_triggers, errors);

  // defaults
  validateDefaults(p.defaults, errors);

  return { valid: errors.length === 0, errors };
}

// ============================================================================
// Section validators
// ============================================================================

function validateMeta(meta: unknown, errors: ValidationError[]): void {
  if (!meta || typeof meta !== 'object') {
    errors.push({ path: 'meta', message: 'meta is required and must be an object' });
    return;
  }

  const m = meta as Record<string, unknown>;

  if (typeof m.schema_version !== 'string' || !m.schema_version) {
    errors.push({ path: 'meta.schema_version', message: 'schema_version is required and must be a non-empty string' });
  }

  if (typeof m.name !== 'string' || !m.name) {
    errors.push({ path: 'meta.name', message: 'name is required and must be a non-empty string' });
  }

  if (m.description !== undefined && typeof m.description !== 'string') {
    errors.push({ path: 'meta.description', message: 'description must be a string if provided' });
  }

  if (typeof m.scope !== 'string' || !VALID_SCOPES.includes(m.scope)) {
    errors.push({ path: 'meta.scope', message: `scope must be one of: ${VALID_SCOPES.join(', ')}` });
  }
}

function validateCapabilityMappings(mappings: unknown, errors: ValidationError[]): void {
  if (mappings === undefined) {
    // Optional — empty mappings are fine
    return;
  }

  if (!mappings || typeof mappings !== 'object' || Array.isArray(mappings)) {
    errors.push({ path: 'capability_mappings', message: 'capability_mappings must be an object' });
    return;
  }

  const m = mappings as Record<string, unknown>;

  for (const [name, value] of Object.entries(m)) {
    const prefix = `capability_mappings.${name}`;

    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      errors.push({ path: prefix, message: 'must be an object' });
      continue;
    }

    const cap = value as Record<string, unknown>;

    if (!Array.isArray(cap.tools) || cap.tools.length === 0) {
      errors.push({ path: `${prefix}.tools`, message: 'tools must be a non-empty array of strings' });
    } else if (!cap.tools.every((t: unknown) => typeof t === 'string')) {
      errors.push({ path: `${prefix}.tools`, message: 'all tools entries must be strings' });
    }

    if (!Array.isArray(cap.card_actions) || cap.card_actions.length === 0) {
      errors.push({ path: `${prefix}.card_actions`, message: 'card_actions must be a non-empty array of strings' });
    } else if (!cap.card_actions.every((a: unknown) => typeof a === 'string')) {
      errors.push({ path: `${prefix}.card_actions`, message: 'all card_actions entries must be strings' });
    }
  }
}

function validateForbidden(forbidden: unknown, errors: ValidationError[]): void {
  if (forbidden === undefined) return;

  if (!Array.isArray(forbidden)) {
    errors.push({ path: 'forbidden', message: 'forbidden must be an array' });
    return;
  }

  for (let i = 0; i < forbidden.length; i++) {
    const prefix = `forbidden[${i}]`;
    const rule = forbidden[i];

    if (!rule || typeof rule !== 'object') {
      errors.push({ path: prefix, message: 'must be an object' });
      continue;
    }

    if (typeof rule.pattern !== 'string' || !rule.pattern) {
      errors.push({ path: `${prefix}.pattern`, message: 'pattern is required and must be a non-empty string' });
    }

    if (typeof rule.reason !== 'string' || !rule.reason) {
      errors.push({ path: `${prefix}.reason`, message: 'reason is required and must be a non-empty string' });
    }

    if (typeof rule.severity !== 'string' || !VALID_SEVERITIES.includes(rule.severity)) {
      errors.push({ path: `${prefix}.severity`, message: `severity must be one of: ${VALID_SEVERITIES.join(', ')}` });
    }
  }
}

function validateEscalationTriggers(triggers: unknown, errors: ValidationError[]): void {
  if (triggers === undefined) return;

  if (!Array.isArray(triggers)) {
    errors.push({ path: 'escalation_triggers', message: 'escalation_triggers must be an array' });
    return;
  }

  for (let i = 0; i < triggers.length; i++) {
    const prefix = `escalation_triggers[${i}]`;
    const trigger = triggers[i];

    if (!trigger || typeof trigger !== 'object') {
      errors.push({ path: prefix, message: 'must be an object' });
      continue;
    }

    if (typeof trigger.condition !== 'string' || !trigger.condition) {
      errors.push({ path: `${prefix}.condition`, message: 'condition is required and must be a non-empty string' });
    }

    if (typeof trigger.action !== 'string' || !VALID_ESCALATION_ACTIONS.includes(trigger.action)) {
      errors.push({ path: `${prefix}.action`, message: `action must be one of: ${VALID_ESCALATION_ACTIONS.join(', ')}` });
    }

    if (typeof trigger.reason !== 'string' || !trigger.reason) {
      errors.push({ path: `${prefix}.reason`, message: 'reason is required and must be a non-empty string' });
    }
  }
}

function validateDefaults(defaults: unknown, errors: ValidationError[]): void {
  if (!defaults || typeof defaults !== 'object') {
    errors.push({ path: 'defaults', message: 'defaults is required and must be an object' });
    return;
  }

  const d = defaults as Record<string, unknown>;

  if (typeof d.unmapped_tool_action !== 'string' || !VALID_ACTIONS.includes(d.unmapped_tool_action)) {
    errors.push({ path: 'defaults.unmapped_tool_action', message: `must be one of: ${VALID_ACTIONS.join(', ')}` });
  }

  if (typeof d.unmapped_severity !== 'string' || !VALID_SEVERITIES.includes(d.unmapped_severity)) {
    errors.push({ path: 'defaults.unmapped_severity', message: `must be one of: ${VALID_SEVERITIES.join(', ')}` });
  }

  if (typeof d.fail_open !== 'boolean') {
    errors.push({ path: 'defaults.fail_open', message: 'must be a boolean' });
  }

  if (d.enforcement_mode !== undefined) {
    const validModes = ['warn', 'enforce', 'off'];
    if (typeof d.enforcement_mode !== 'string' || !validModes.includes(d.enforcement_mode)) {
      errors.push({ path: 'defaults.enforcement_mode', message: `must be one of: ${validModes.join(', ')}` });
    }
  }

  if (d.grace_period_hours !== undefined) {
    if (typeof d.grace_period_hours !== 'number' || d.grace_period_hours < 0) {
      errors.push({ path: 'defaults.grace_period_hours', message: 'must be a non-negative number' });
    }
  }
}
