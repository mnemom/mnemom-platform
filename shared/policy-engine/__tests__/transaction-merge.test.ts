import { describe, it, expect } from 'vitest';
import { mergeTransactionGuardrails } from '../src/merge';
import type { Policy } from '../src/types';

function makeBasePolicy(overrides?: Partial<Policy>): Policy {
  return {
    meta: { schema_version: '1.0', name: 'base-policy', scope: 'org' },
    capability_mappings: {
      web_fetch: {
        description: 'Web access tools',
        tools: ['WebFetch', 'WebSearch'],
        card_actions: ['web_fetch', 'web_browse'],
      },
      file_system: {
        description: 'File system access',
        tools: ['Read', 'Write'],
        card_actions: ['file_read', 'file_write'],
      },
    },
    forbidden: [
      { pattern: 'mcp__*__delete*', reason: 'No deletion allowed', severity: 'critical' },
      { pattern: 'mcp__*__drop*', reason: 'No drop allowed', severity: 'high' },
    ],
    escalation_triggers: [
      { condition: "tool_matches('*payment*')", action: 'escalate', reason: 'Payment requires approval' },
    ],
    defaults: {
      unmapped_tool_action: 'warn',
      unmapped_severity: 'medium',
      fail_open: false,
      enforcement_mode: 'warn',
    },
    ...overrides,
  };
}

function makeTxnPolicy(overrides?: Partial<Policy>): Policy {
  return {
    meta: { schema_version: '1.0', name: 'txn-scope', scope: 'agent' },
    capability_mappings: {
      web_fetch: {
        description: 'Restricted web access',
        tools: ['WebFetch'],
        card_actions: ['web_fetch'],
      },
      file_system: {
        description: 'Read-only file access',
        tools: ['Read'],
        card_actions: ['file_read'],
      },
    },
    forbidden: [
      { pattern: 'Bash', reason: 'No shell in transaction', severity: 'high' },
    ],
    escalation_triggers: [
      { condition: "tool_matches('*admin*')", action: 'deny', reason: 'Admin tools blocked in txn' },
    ],
    defaults: {
      unmapped_tool_action: 'deny',
      unmapped_severity: 'high',
      fail_open: false,
      enforcement_mode: 'enforce',
    },
    ...overrides,
  };
}

describe('mergeTransactionGuardrails', () => {
  describe('capability_mappings intersection', () => {
    it('keeps only capabilities present in BOTH policies', () => {
      const base = makeBasePolicy({
        capability_mappings: {
          web_fetch: {
            tools: ['WebFetch'],
            card_actions: ['web_fetch'],
          },
          file_system: {
            tools: ['Read'],
            card_actions: ['file_read'],
          },
          code_execution: {
            tools: ['Bash'],
            card_actions: ['code_execution'],
          },
        },
      });
      const txn = makeTxnPolicy({
        capability_mappings: {
          web_fetch: {
            tools: ['WebFetch'],
            card_actions: ['web_fetch'],
          },
          file_system: {
            tools: ['Read'],
            card_actions: ['file_read'],
          },
        },
      });

      const result = mergeTransactionGuardrails(base, txn);

      expect(Object.keys(result.capability_mappings)).toContain('web_fetch');
      expect(Object.keys(result.capability_mappings)).toContain('file_system');
      expect(Object.keys(result.capability_mappings)).not.toContain('code_execution');
    });

    it('intersects tools within shared capabilities (only common tools)', () => {
      const result = mergeTransactionGuardrails(makeBasePolicy(), makeTxnPolicy());

      // Base web_fetch has [WebFetch, WebSearch], txn has [WebFetch] → intersection is [WebFetch]
      expect(result.capability_mappings.web_fetch.tools).toEqual(['WebFetch']);
      // Base file_system has [Read, Write], txn has [Read] → intersection is [Read]
      expect(result.capability_mappings.file_system.tools).toEqual(['Read']);
    });

    it('intersects card_actions within shared capabilities', () => {
      const result = mergeTransactionGuardrails(makeBasePolicy(), makeTxnPolicy());

      // Base web_fetch has [web_fetch, web_browse], txn has [web_fetch] → intersection is [web_fetch]
      expect(result.capability_mappings.web_fetch.card_actions).toEqual(['web_fetch']);
      // Base file_system has [file_read, file_write], txn has [file_read] → intersection is [file_read]
      expect(result.capability_mappings.file_system.card_actions).toEqual(['file_read']);
    });

    it('drops capabilities whose intersection yields empty tools or card_actions', () => {
      const base = makeBasePolicy({
        capability_mappings: {
          web_fetch: {
            tools: ['WebFetch'],
            card_actions: ['web_fetch'],
          },
          code_execution: {
            tools: ['Bash'],
            card_actions: ['code_execution'],
          },
        },
      });
      const txn = makeTxnPolicy({
        capability_mappings: {
          web_fetch: {
            tools: ['WebFetch'],
            card_actions: ['web_fetch'],
          },
          code_execution: {
            // No overlap with base tools
            tools: ['mcp__sandbox__exec'],
            card_actions: ['code_execution'],
          },
        },
      });

      const result = mergeTransactionGuardrails(base, txn);

      expect(Object.keys(result.capability_mappings)).toContain('web_fetch');
      // code_execution dropped because tools intersection is empty
      expect(Object.keys(result.capability_mappings)).not.toContain('code_execution');
    });
  });

  describe('forbidden rules union', () => {
    it('adds transaction forbidden rules to base rules', () => {
      const result = mergeTransactionGuardrails(makeBasePolicy(), makeTxnPolicy());

      // Base has 2 rules, txn has 1 unique rule → 3 total
      expect(result.forbidden).toHaveLength(3);
      const patterns = result.forbidden.map((r) => r.pattern);
      expect(patterns).toContain('mcp__*__delete*');
      expect(patterns).toContain('mcp__*__drop*');
      expect(patterns).toContain('Bash');
    });

    it('deduplicates forbidden rules by pattern (base wins)', () => {
      const txn = makeTxnPolicy({
        forbidden: [
          { pattern: 'mcp__*__delete*', reason: 'Txn also forbids deletes', severity: 'high' },
        ],
      });

      const result = mergeTransactionGuardrails(makeBasePolicy(), txn);

      const deleteRules = result.forbidden.filter((r) => r.pattern === 'mcp__*__delete*');
      expect(deleteRules).toHaveLength(1);
      // Base version wins because it appears first
      expect(deleteRules[0].reason).toBe('No deletion allowed');
      expect(deleteRules[0].severity).toBe('critical');
    });
  });

  describe('escalation_triggers concatenation', () => {
    it('places base triggers first, then transaction triggers', () => {
      const result = mergeTransactionGuardrails(makeBasePolicy(), makeTxnPolicy());

      expect(result.escalation_triggers).toHaveLength(2);
      expect(result.escalation_triggers[0].reason).toBe('Payment requires approval');
      expect(result.escalation_triggers[0].action).toBe('escalate');
      expect(result.escalation_triggers[1].reason).toBe('Admin tools blocked in txn');
      expect(result.escalation_triggers[1].action).toBe('deny');
    });
  });

  describe('defaults — cannot weaken', () => {
    it('transaction can strengthen unmapped_tool_action (warn→deny) but not weaken (deny→warn)', () => {
      // Base has warn, txn has deny → strengthened to deny
      const result = mergeTransactionGuardrails(makeBasePolicy(), makeTxnPolicy());
      expect(result.defaults.unmapped_tool_action).toBe('deny');

      // Reverse: base has deny, txn has warn → stays deny (cannot weaken)
      const strongBase = makeBasePolicy({
        defaults: {
          unmapped_tool_action: 'deny',
          unmapped_severity: 'medium',
          fail_open: false,
        },
      });
      const weakTxn = makeTxnPolicy({
        defaults: {
          unmapped_tool_action: 'warn',
          unmapped_severity: 'medium',
          fail_open: false,
        },
      });
      const result2 = mergeTransactionGuardrails(strongBase, weakTxn);
      expect(result2.defaults.unmapped_tool_action).toBe('deny');
    });

    it('transaction cannot weaken fail_open (base false stays false)', () => {
      // Base has fail_open: false, txn has fail_open: true → stays false
      const base = makeBasePolicy({
        defaults: {
          unmapped_tool_action: 'warn',
          unmapped_severity: 'medium',
          fail_open: false,
        },
      });
      const txn = makeTxnPolicy({
        defaults: {
          unmapped_tool_action: 'warn',
          unmapped_severity: 'medium',
          fail_open: true,
        },
      });

      const result = mergeTransactionGuardrails(base, txn);
      expect(result.defaults.fail_open).toBe(false);
    });

    it('enforcement_mode uses the stronger value', () => {
      // Base has warn, txn has enforce → enforce
      const result = mergeTransactionGuardrails(makeBasePolicy(), makeTxnPolicy());
      expect(result.defaults.enforcement_mode).toBe('enforce');

      // Reverse: base has enforce, txn has warn → stays enforce
      const strongBase = makeBasePolicy({
        defaults: {
          unmapped_tool_action: 'warn',
          unmapped_severity: 'medium',
          fail_open: false,
          enforcement_mode: 'enforce',
        },
      });
      const weakTxn = makeTxnPolicy({
        defaults: {
          unmapped_tool_action: 'warn',
          unmapped_severity: 'medium',
          fail_open: false,
          enforcement_mode: 'warn',
        },
      });
      const result2 = mergeTransactionGuardrails(strongBase, weakTxn);
      expect(result2.defaults.enforcement_mode).toBe('enforce');
    });
  });

  describe('meta', () => {
    it('sets name to {base.name}+txn-guardrails and preserves base scope and schema_version', () => {
      const result = mergeTransactionGuardrails(makeBasePolicy(), makeTxnPolicy());

      expect(result.meta.name).toBe('base-policy+txn-guardrails');
      expect(result.meta.scope).toBe('org');
      expect(result.meta.schema_version).toBe('1.0');
      expect(result.meta.description).toBeUndefined();
    });
  });
});
