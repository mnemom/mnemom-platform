import { describe, it, expect } from 'vitest';
import { loadFromYAML, toYAML } from '../src/yaml';
import type { Policy } from '../src/types';

const samplePolicy: Policy = {
  meta: {
    schema_version: '1.0',
    name: 'test-policy',
    description: 'A test policy',
    scope: 'org',
  },
  capability_mappings: {
    code_review: {
      description: 'Review code',
      tools: ['read_file', 'grep'],
      card_actions: ['code_review'],
    },
  },
  forbidden: [
    {
      pattern: 'delete_production_*',
      reason: 'No production deletions',
      severity: 'critical',
    },
  ],
  escalation_triggers: [
    {
      condition: 'pii_detected',
      action: 'escalate',
      reason: 'PII found',
    },
  ],
  defaults: {
    unmapped_tool_action: 'deny',
    unmapped_severity: 'high',
    fail_open: false,
  },
};

const sampleYAML = `meta:
  schema_version: "1.0"
  name: test-policy
  description: A test policy
  scope: org
capability_mappings:
  code_review:
    description: Review code
    tools:
      - read_file
      - grep
    card_actions:
      - code_review
forbidden:
  - pattern: delete_production_*
    reason: No production deletions
    severity: critical
escalation_triggers:
  - condition: pii_detected
    action: escalate
    reason: PII found
defaults:
  unmapped_tool_action: deny
  unmapped_severity: high
  fail_open: false
`;

describe('YAML support', () => {
  it('should parse YAML into a Policy', () => {
    const policy = loadFromYAML(sampleYAML);
    expect(policy.meta.name).toBe('test-policy');
    expect(policy.meta.scope).toBe('org');
    expect(policy.forbidden).toHaveLength(1);
    expect(policy.forbidden[0].severity).toBe('critical');
    expect(policy.escalation_triggers).toHaveLength(1);
    expect(policy.defaults.fail_open).toBe(false);
  });

  it('should serialize a Policy to YAML', () => {
    const yamlStr = toYAML(samplePolicy);
    expect(yamlStr).toContain('name: test-policy');
    expect(yamlStr).toContain('scope: org');
    expect(yamlStr).toContain('delete_production_*');
    expect(yamlStr).toContain('fail_open: false');
  });

  it('should roundtrip Policy -> YAML -> Policy', () => {
    const yamlStr = toYAML(samplePolicy);
    const parsed = loadFromYAML(yamlStr);
    expect(parsed).toEqual(samplePolicy);
  });

  it('should roundtrip YAML -> Policy -> YAML -> Policy', () => {
    const policy = loadFromYAML(sampleYAML);
    const yamlStr = toYAML(policy);
    const reparsed = loadFromYAML(yamlStr);
    expect(reparsed).toEqual(policy);
  });
});
