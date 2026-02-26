import { describe, it, expect } from 'vitest';
import { validatePolicySchema } from '../src/validator';
import type { Policy } from '../src/types';

function makeValidPolicy(): Policy {
  return {
    meta: { schema_version: '1.0', name: 'test-policy', scope: 'org' },
    capability_mappings: {
      web_fetch: {
        tools: ['WebFetch'],
        card_actions: ['web_fetch'],
      },
    },
    forbidden: [
      { pattern: 'mcp__*__delete*', reason: 'No deletion', severity: 'critical' },
    ],
    escalation_triggers: [
      { condition: "tool_matches('*pay*')", action: 'escalate', reason: 'Payment tools' },
    ],
    defaults: {
      unmapped_tool_action: 'warn',
      unmapped_severity: 'medium',
      fail_open: true,
    },
  };
}

describe('validatePolicySchema', () => {
  it('validates a correct policy', () => {
    const result = validatePolicySchema(makeValidPolicy());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('rejects null input', () => {
    const result = validatePolicySchema(null);
    expect(result.valid).toBe(false);
  });

  it('rejects non-object input', () => {
    const result = validatePolicySchema('not an object');
    expect(result.valid).toBe(false);
  });

  describe('meta validation', () => {
    it('requires meta section', () => {
      const policy = { ...makeValidPolicy(), meta: undefined };
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'meta')).toBe(true);
    });

    it('requires schema_version', () => {
      const policy = makeValidPolicy();
      (policy.meta as any).schema_version = '';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'meta.schema_version')).toBe(true);
    });

    it('requires name', () => {
      const policy = makeValidPolicy();
      (policy.meta as any).name = '';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'meta.name')).toBe(true);
    });

    it('requires valid scope', () => {
      const policy = makeValidPolicy();
      (policy.meta as any).scope = 'invalid';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'meta.scope')).toBe(true);
    });

    it('allows optional description', () => {
      const policy = makeValidPolicy();
      policy.meta.description = 'A test policy';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(true);
    });
  });

  describe('capability_mappings validation', () => {
    it('allows missing capability_mappings (optional)', () => {
      const policy = makeValidPolicy();
      delete (policy as any).capability_mappings;
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(true);
    });

    it('requires tools array in each mapping', () => {
      const policy = makeValidPolicy();
      (policy.capability_mappings.web_fetch as any).tools = [];
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path.includes('tools'))).toBe(true);
    });

    it('requires card_actions array in each mapping', () => {
      const policy = makeValidPolicy();
      (policy.capability_mappings.web_fetch as any).card_actions = [];
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path.includes('card_actions'))).toBe(true);
    });

    it('requires string values in tools array', () => {
      const policy = makeValidPolicy();
      (policy.capability_mappings.web_fetch as any).tools = [123];
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
    });
  });

  describe('forbidden validation', () => {
    it('allows missing forbidden (optional)', () => {
      const policy = makeValidPolicy();
      delete (policy as any).forbidden;
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(true);
    });

    it('requires pattern in forbidden rules', () => {
      const policy = makeValidPolicy();
      (policy.forbidden[0] as any).pattern = '';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
    });

    it('requires valid severity in forbidden rules', () => {
      const policy = makeValidPolicy();
      (policy.forbidden[0] as any).severity = 'ultra';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
    });
  });

  describe('escalation_triggers validation', () => {
    it('allows missing escalation_triggers (optional)', () => {
      const policy = makeValidPolicy();
      delete (policy as any).escalation_triggers;
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(true);
    });

    it('requires condition in triggers', () => {
      const policy = makeValidPolicy();
      (policy.escalation_triggers[0] as any).condition = '';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
    });

    it('requires valid action in triggers', () => {
      const policy = makeValidPolicy();
      (policy.escalation_triggers[0] as any).action = 'invalid';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
    });
  });

  describe('defaults validation', () => {
    it('requires defaults section', () => {
      const policy = { ...makeValidPolicy(), defaults: undefined };
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'defaults')).toBe(true);
    });

    it('requires valid unmapped_tool_action', () => {
      const policy = makeValidPolicy();
      (policy.defaults as any).unmapped_tool_action = 'invalid';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
    });

    it('requires valid unmapped_severity', () => {
      const policy = makeValidPolicy();
      (policy.defaults as any).unmapped_severity = 'extreme';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
    });

    it('requires boolean fail_open', () => {
      const policy = makeValidPolicy();
      (policy.defaults as any).fail_open = 'yes';
      const result = validatePolicySchema(policy);
      expect(result.valid).toBe(false);
    });
  });

  describe('reports multiple errors', () => {
    it('collects all errors in one pass', () => {
      const result = validatePolicySchema({
        meta: { schema_version: '', name: '' },
        defaults: {},
      });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(2);
    });
  });
});
