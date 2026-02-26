import { describe, it, expect } from 'vitest';
import { mergePolicies } from '../src/merge';
import type { Policy } from '../src/types';

function makeOrgPolicy(overrides?: Partial<Policy>): Policy {
  return {
    meta: { schema_version: '1.0', name: 'org-baseline', scope: 'org' },
    capability_mappings: {
      web_fetch: {
        tools: ['WebFetch', 'WebSearch'],
        card_actions: ['web_fetch'],
      },
      file_system: {
        tools: ['Read', 'Write'],
        card_actions: ['file_read'],
      },
    },
    forbidden: [
      { pattern: 'mcp__*__delete*', reason: 'No deletion at org level', severity: 'critical' },
    ],
    escalation_triggers: [
      { condition: "tool_matches('*payment*')", action: 'escalate', reason: 'Payment requires approval' },
    ],
    defaults: {
      unmapped_tool_action: 'warn',
      unmapped_severity: 'medium',
      fail_open: true,
    },
    ...overrides,
  };
}

function makeAgentPolicy(overrides?: Partial<Policy>): Policy {
  return {
    meta: { schema_version: '1.0', name: 'agent-custom', scope: 'agent' },
    capability_mappings: {
      code_execution: {
        tools: ['Bash'],
        card_actions: ['code_execution'],
      },
    },
    forbidden: [],
    escalation_triggers: [
      { condition: "tool_matches('*deploy*')", action: 'warn', reason: 'Deploy needs review' },
    ],
    defaults: {
      unmapped_tool_action: 'allow',
      unmapped_severity: 'low',
      fail_open: true,
    },
    ...overrides,
  };
}

describe('mergePolicies', () => {
  it('returns null when both policies are null', () => {
    expect(mergePolicies(null, null, false)).toBeNull();
  });

  it('returns org policy when no agent policy', () => {
    const org = makeOrgPolicy();
    const result = mergePolicies(org, null, false);
    expect(result).toEqual(org);
  });

  it('returns agent policy when no org policy', () => {
    const agent = makeAgentPolicy();
    const result = mergePolicies(null, agent, false);
    expect(result).toEqual(agent);
  });

  it('returns agent policy when exempt from org', () => {
    const org = makeOrgPolicy();
    const agent = makeAgentPolicy();
    const result = mergePolicies(org, agent, true);
    expect(result).toEqual(agent);
  });

  describe('capability_mappings merge', () => {
    it('unions org and agent capability mappings', () => {
      const result = mergePolicies(makeOrgPolicy(), makeAgentPolicy(), false)!;
      expect(Object.keys(result.capability_mappings)).toContain('web_fetch');
      expect(Object.keys(result.capability_mappings)).toContain('file_system');
      expect(Object.keys(result.capability_mappings)).toContain('code_execution');
    });

    it('unions tool patterns for overlapping capabilities', () => {
      const agent = makeAgentPolicy({
        capability_mappings: {
          web_fetch: {
            tools: ['mcp__browser__*'],
            card_actions: ['web_browse'],
          },
        },
      });
      const result = mergePolicies(makeOrgPolicy(), agent, false)!;
      expect(result.capability_mappings.web_fetch.tools).toContain('WebFetch');
      expect(result.capability_mappings.web_fetch.tools).toContain('WebSearch');
      expect(result.capability_mappings.web_fetch.tools).toContain('mcp__browser__*');
      expect(result.capability_mappings.web_fetch.card_actions).toContain('web_fetch');
      expect(result.capability_mappings.web_fetch.card_actions).toContain('web_browse');
    });
  });

  describe('forbidden merge', () => {
    it('unions forbidden rules, org always enforced', () => {
      const agent = makeAgentPolicy({
        forbidden: [{ pattern: 'mcp__*__drop*', reason: 'No drop', severity: 'high' }],
      });
      const result = mergePolicies(makeOrgPolicy(), agent, false)!;
      expect(result.forbidden).toHaveLength(2);
      expect(result.forbidden[0].pattern).toBe('mcp__*__delete*');
      expect(result.forbidden[1].pattern).toBe('mcp__*__drop*');
    });

    it('deduplicates forbidden rules by pattern', () => {
      const agent = makeAgentPolicy({
        forbidden: [{ pattern: 'mcp__*__delete*', reason: 'Agent also forbids', severity: 'high' }],
      });
      const result = mergePolicies(makeOrgPolicy(), agent, false)!;
      expect(result.forbidden).toHaveLength(1);
      // Org rule wins (first seen)
      expect(result.forbidden[0].reason).toBe('No deletion at org level');
    });
  });

  describe('escalation_triggers merge', () => {
    it('concatenates triggers, org first then agent', () => {
      const result = mergePolicies(makeOrgPolicy(), makeAgentPolicy(), false)!;
      expect(result.escalation_triggers).toHaveLength(2);
      expect(result.escalation_triggers[0].reason).toBe('Payment requires approval');
      expect(result.escalation_triggers[1].reason).toBe('Deploy needs review');
    });
  });

  describe('defaults merge', () => {
    it('agent can strengthen unmapped_tool_action (allow→warn stays warn from org)', () => {
      // Org says warn, agent says allow → org wins (floor)
      const result = mergePolicies(makeOrgPolicy(), makeAgentPolicy(), false)!;
      expect(result.defaults.unmapped_tool_action).toBe('warn');
    });

    it('agent can strengthen unmapped_tool_action (warn→deny)', () => {
      const agent = makeAgentPolicy({
        defaults: { unmapped_tool_action: 'deny', unmapped_severity: 'high', fail_open: true },
      });
      const result = mergePolicies(makeOrgPolicy(), agent, false)!;
      expect(result.defaults.unmapped_tool_action).toBe('deny');
    });

    it('agent cannot weaken fail_open (org false stays false)', () => {
      const org = makeOrgPolicy({
        defaults: { unmapped_tool_action: 'warn', unmapped_severity: 'medium', fail_open: false },
      });
      const agent = makeAgentPolicy({
        defaults: { unmapped_tool_action: 'warn', unmapped_severity: 'medium', fail_open: true },
      });
      const result = mergePolicies(org, agent, false)!;
      expect(result.defaults.fail_open).toBe(false);
    });

    it('agent can escalate severity but not reduce', () => {
      // Org says medium, agent says low → org wins (floor)
      const result = mergePolicies(makeOrgPolicy(), makeAgentPolicy(), false)!;
      expect(result.defaults.unmapped_severity).toBe('medium');

      // Agent says critical → agent wins (stronger)
      const agent2 = makeAgentPolicy({
        defaults: { unmapped_tool_action: 'deny', unmapped_severity: 'critical', fail_open: true },
      });
      const result2 = mergePolicies(makeOrgPolicy(), agent2, false)!;
      expect(result2.defaults.unmapped_severity).toBe('critical');
    });
  });

  describe('merged meta', () => {
    it('combines policy names', () => {
      const result = mergePolicies(makeOrgPolicy(), makeAgentPolicy(), false)!;
      expect(result.meta.name).toBe('org-baseline+agent-custom');
      expect(result.meta.scope).toBe('agent');
    });

    it('uses org schema version', () => {
      const result = mergePolicies(makeOrgPolicy(), makeAgentPolicy(), false)!;
      expect(result.meta.schema_version).toBe('1.0');
    });
  });
});
