import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '../src/evaluator';
import type { Policy, AlignmentCard, EvaluationInput } from '../src/types';

// ============================================================================
// Test fixtures
// ============================================================================

function makePolicy(overrides?: Partial<Policy>): Policy {
  return {
    meta: { schema_version: '1.0', name: 'test-policy', scope: 'org' },
    capability_mappings: {
      web_fetch: {
        description: 'Web browsing',
        tools: ['WebFetch', 'WebSearch', 'mcp__browser__*'],
        card_actions: ['web_fetch'],
      },
      file_system: {
        tools: ['Read', 'Write', 'Edit', 'Glob'],
        card_actions: ['file_read', 'file_write'],
      },
      code_execution: {
        tools: ['Bash', 'mcp__*__evaluate_script'],
        card_actions: ['code_execution'],
      },
    },
    forbidden: [
      { pattern: 'mcp__*__delete*', reason: 'Destructive deletion forbidden', severity: 'critical' },
    ],
    escalation_triggers: [
      { condition: "tool_matches('*payment*')", action: 'escalate', reason: 'Payment tools require approval' },
    ],
    defaults: {
      unmapped_tool_action: 'warn',
      unmapped_severity: 'medium',
      fail_open: true,
    },
    ...overrides,
  };
}

function makeCard(overrides?: Partial<AlignmentCard>): AlignmentCard {
  return {
    autonomy_envelope: {
      bounded_actions: ['web_fetch', 'file_read', 'file_write', 'code_execution'],
    },
    ...overrides,
  };
}

function makeInput(overrides?: Partial<EvaluationInput>): EvaluationInput {
  return {
    context: 'observer',
    policy: makePolicy(),
    card: makeCard(),
    tools: [{ name: 'Read' }, { name: 'WebFetch' }],
    ...overrides,
  };
}

// ============================================================================
// Tests
// ============================================================================

describe('evaluatePolicy', () => {
  describe('pass verdict', () => {
    it('passes when all tools are mapped and within bounded_actions', () => {
      const result = evaluatePolicy(makeInput());
      expect(result.verdict).toBe('pass');
      expect(result.violations).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
    });

    it('passes with wildcard-matched tools', () => {
      const result = evaluatePolicy(makeInput({
        tools: [{ name: 'mcp__browser__navigate_page' }],
      }));
      expect(result.verdict).toBe('pass');
      expect(result.violations).toHaveLength(0);
    });

    it('passes with unmapped tools when default is allow', () => {
      const result = evaluatePolicy(makeInput({
        policy: makePolicy({ defaults: { unmapped_tool_action: 'allow', unmapped_severity: 'medium', fail_open: true } }),
        tools: [{ name: 'SomeUnknownTool' }],
      }));
      expect(result.verdict).toBe('pass');
      expect(result.warnings).toHaveLength(0);
    });
  });

  describe('warn verdict', () => {
    it('warns on unmapped tools when default is warn', () => {
      const result = evaluatePolicy(makeInput({
        tools: [{ name: 'SomeUnknownTool' }],
      }));
      expect(result.verdict).toBe('warn');
      expect(result.warnings).toHaveLength(1);
      expect(result.warnings[0].type).toBe('unmapped_tool');
      expect(result.warnings[0].tool).toBe('SomeUnknownTool');
    });

    it('warns on escalation trigger match', () => {
      const result = evaluatePolicy(makeInput({
        tools: [{ name: 'process_payment_stripe' }],
      }));
      expect(result.verdict).toBe('warn');
      expect(result.warnings.some((w) => w.type === 'escalation_triggered')).toBe(true);
    });

    it('warns on low/medium severity violations only', () => {
      const result = evaluatePolicy(makeInput({
        policy: makePolicy({
          defaults: { unmapped_tool_action: 'deny', unmapped_severity: 'low', fail_open: true },
        }),
        tools: [{ name: 'UnknownTool' }],
      }));
      expect(result.verdict).toBe('warn');
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].severity).toBe('low');
    });
  });

  describe('fail verdict', () => {
    it('fails on forbidden tool match', () => {
      const result = evaluatePolicy(makeInput({
        tools: [{ name: 'mcp__fs__delete_file' }],
      }));
      expect(result.verdict).toBe('fail');
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].type).toBe('forbidden');
      expect(result.violations[0].severity).toBe('critical');
    });

    it('fails on capability_exceeded — tool mapped but card_action missing', () => {
      const result = evaluatePolicy(makeInput({
        card: makeCard({
          autonomy_envelope: {
            bounded_actions: ['file_read'],  // no code_execution
          },
        }),
        tools: [{ name: 'Bash' }],
      }));
      expect(result.verdict).toBe('fail');
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].type).toBe('capability_exceeded');
      expect(result.violations[0].capability).toBe('code_execution');
    });

    it('fails on unmapped tool when default is deny with high severity', () => {
      const result = evaluatePolicy(makeInput({
        policy: makePolicy({
          defaults: { unmapped_tool_action: 'deny', unmapped_severity: 'high', fail_open: true },
        }),
        tools: [{ name: 'UnknownDangerousTool' }],
      }));
      expect(result.verdict).toBe('fail');
      expect(result.violations[0].type).toBe('unmapped_denied');
    });

    it('fails on escalation trigger with deny action', () => {
      const result = evaluatePolicy(makeInput({
        policy: makePolicy({
          escalation_triggers: [
            { condition: "tool_matches('*dangerous*')", action: 'deny', reason: 'Blocked' },
          ],
        }),
        tools: [{ name: 'super_dangerous_tool' }],
      }));
      expect(result.verdict).toBe('fail');
    });
  });

  describe('multiple tools', () => {
    it('evaluates all tools and aggregates results', () => {
      const result = evaluatePolicy(makeInput({
        tools: [
          { name: 'Read' },           // pass — mapped
          { name: 'UnknownTool' },     // warn — unmapped
          { name: 'mcp__fs__delete_file' }, // fail — forbidden
        ],
      }));
      expect(result.verdict).toBe('fail');
      expect(result.violations.length).toBeGreaterThanOrEqual(1);
      expect(result.warnings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('coverage report', () => {
    it('reports full coverage when all card actions are mapped', () => {
      const result = evaluatePolicy(makeInput());
      expect(result.coverage.coverage_pct).toBe(100);
      expect(result.coverage.unmapped_card_actions).toHaveLength(0);
    });

    it('reports partial coverage with unmapped card actions', () => {
      const result = evaluatePolicy(makeInput({
        card: makeCard({
          autonomy_envelope: {
            bounded_actions: ['web_fetch', 'file_read', 'file_write', 'code_execution', 'database_access'],
          },
        }),
      }));
      expect(result.coverage.unmapped_card_actions).toContain('database_access');
      expect(result.coverage.coverage_pct).toBeLessThan(100);
    });

    it('reports 100% coverage when card has no bounded_actions', () => {
      const result = evaluatePolicy(makeInput({
        card: makeCard({ autonomy_envelope: { bounded_actions: [] } }),
      }));
      expect(result.coverage.coverage_pct).toBe(100);
      expect(result.coverage.total_card_actions).toBe(0);
    });
  });

  describe('result metadata', () => {
    it('includes policy name and context', () => {
      const result = evaluatePolicy(makeInput({ context: 'gateway' }));
      expect(result.policy_id).toBe('test-policy');
      expect(result.context).toBe('gateway');
    });

    it('includes evaluated_at timestamp', () => {
      const result = evaluatePolicy(makeInput());
      expect(result.evaluated_at).toBeTruthy();
      expect(() => new Date(result.evaluated_at)).not.toThrow();
    });

    it('includes duration_ms', () => {
      const result = evaluatePolicy(makeInput());
      expect(typeof result.duration_ms).toBe('number');
      expect(result.duration_ms).toBeGreaterThanOrEqual(0);
    });
  });
});
