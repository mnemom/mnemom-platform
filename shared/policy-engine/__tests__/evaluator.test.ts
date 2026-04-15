import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '../src/evaluator';
import type {
  Policy,
  UnifiedAlignmentCard,
  EvaluationInput,
} from '../src/types';

// ============================================================================
// UC-8 test fixtures — evaluator now takes a unified card, not a Policy.
// makeCard() produces a card whose extracted policy is equivalent to what
// the pre-UC-8 makePolicy() used to provide, so behavioural assertions are
// preserved after the signature change.
// ============================================================================

function makeCard(overrides?: Partial<UnifiedAlignmentCard>): UnifiedAlignmentCard {
  return {
    card_id: 'ac-test',
    card_version: '2026-04-15',
    autonomy: {
      bounded_actions: ['web_fetch', 'file_read', 'file_write', 'code_execution'],
      escalation_triggers: [
        { condition: "tool_matches('*payment*')", action: 'escalate', reason: 'Payment tools require approval' },
      ],
    },
    capabilities: {
      web_fetch: {
        description: 'Web browsing',
        tools: ['WebFetch', 'WebSearch', 'mcp__browser__*'],
        required_actions: ['web_fetch'],
      },
      file_system: {
        tools: ['Read', 'Write', 'Edit', 'Glob'],
        required_actions: ['file_read', 'file_write'],
      },
      code_execution: {
        tools: ['Bash', 'mcp__*__evaluate_script'],
        required_actions: ['code_execution'],
      },
    },
    enforcement: {
      forbidden_tools: [
        { pattern: 'mcp__*__delete*', reason: 'Destructive deletion forbidden', severity: 'critical' },
      ],
      unmapped_tool_action: 'warn',
      fail_open: true,
    },
    ...overrides,
  };
}

function makeInput(overrides?: Partial<EvaluationInput>): EvaluationInput {
  return {
    context: 'observer',
    card: makeCard(),
    tools: [{ name: 'Read' }, { name: 'WebFetch' }],
    ...overrides,
  };
}

// ============================================================================
// Tests
// ============================================================================

describe('evaluatePolicy (UC-8)', () => {
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
      const card = makeCard();
      card.enforcement!.unmapped_tool_action = 'allow';
      const result = evaluatePolicy(makeInput({
        card,
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
          autonomy: {
            bounded_actions: ['file_read'],  // no code_execution
            escalation_triggers: [],
          },
        }),
        tools: [{ name: 'Bash' }],
      }));
      expect(result.verdict).toBe('fail');
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].type).toBe('capability_exceeded');
      expect(result.violations[0].capability).toBe('code_execution');
    });

    it('fails on escalation trigger with deny action', () => {
      const card = makeCard({
        autonomy: {
          bounded_actions: ['web_fetch', 'file_read', 'file_write', 'code_execution'],
          escalation_triggers: [
            { condition: "tool_matches('*dangerous*')", action: 'deny', reason: 'Blocked' },
          ],
        },
      });
      const result = evaluatePolicy(makeInput({
        card,
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
          autonomy: {
            bounded_actions: ['web_fetch', 'file_read', 'file_write', 'code_execution', 'database_access'],
            escalation_triggers: [],
          },
        }),
      }));
      expect(result.coverage.unmapped_card_actions).toContain('database_access');
      expect(result.coverage.coverage_pct).toBeLessThan(100);
    });

    it('reports 100% coverage when card has no bounded_actions', () => {
      const result = evaluatePolicy(makeInput({
        card: makeCard({ autonomy: { bounded_actions: [], escalation_triggers: [] } }),
      }));
      expect(result.coverage.coverage_pct).toBe(100);
      expect(result.coverage.total_card_actions).toBe(0);
    });
  });

  describe('card_gaps', () => {
    it('populates card_gaps for capability_exceeded in observer context', () => {
      const result = evaluatePolicy(makeInput({
        context: 'observer',
        card: makeCard({
          autonomy: { bounded_actions: ['file_read'], escalation_triggers: [] },
        }),
        tools: [{ name: 'Bash' }],
      }));
      expect(result.card_gaps).toHaveLength(1);
      expect(result.card_gaps[0].tool).toBe('Bash');
      expect(result.card_gaps[0].capability).toBe('code_execution');
      expect(result.card_gaps[0].missing_card_actions).toContain('code_execution');
    });

    it('returns empty card_gaps in gateway context', () => {
      const result = evaluatePolicy(makeInput({
        context: 'gateway',
        card: makeCard({
          autonomy: { bounded_actions: ['file_read'], escalation_triggers: [] },
        }),
        tools: [{ name: 'Bash' }],
      }));
      expect(result.card_gaps).toHaveLength(0);
    });

    it('returns empty card_gaps in cicd context', () => {
      const result = evaluatePolicy(makeInput({
        context: 'cicd',
        card: makeCard({
          autonomy: { bounded_actions: ['file_read'], escalation_triggers: [] },
        }),
        tools: [{ name: 'Bash' }],
      }));
      expect(result.card_gaps).toHaveLength(0);
    });

    it('returns empty card_gaps when no capability violations', () => {
      const result = evaluatePolicy(makeInput({ context: 'observer' }));
      expect(result.card_gaps).toHaveLength(0);
    });
  });

  describe('result metadata', () => {
    it('includes derived policy id (from card_id) and context', () => {
      const result = evaluatePolicy(makeInput({ context: 'gateway' }));
      expect(result.policy_id).toBe('ac-test/derived');
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

  describe('legacy AAP shape (autonomy_envelope) still readable', () => {
    it('evaluates when card uses autonomy_envelope instead of autonomy', () => {
      // Simulates a pre-UC-4 card passed through mapUnifiedCardToAAP.
      // The evaluator falls back to autonomy_envelope.bounded_actions when
      // autonomy is absent.
      const card: UnifiedAlignmentCard = {
        card_id: 'ac-legacy',
        autonomy_envelope: {
          bounded_actions: ['web_fetch'],
          escalation_triggers: [],
        },
        capabilities: {
          web_fetch: { tools: ['WebFetch'], required_actions: ['web_fetch'] },
        },
        enforcement: { unmapped_tool_action: 'allow', fail_open: true },
      };
      const result = evaluatePolicy({
        context: 'gateway',
        card,
        tools: [{ name: 'WebFetch' }],
      });
      expect(result.verdict).toBe('pass');
    });
  });

  describe('transactionGuardrails (ephemeral overrides)', () => {
    it('intersects capability_mappings with transaction guardrails', () => {
      // The card maps WebFetch → web_fetch capability. A txn guardrail
      // restricts web_fetch to a single tool. Result: only the txn-allowed
      // tool is mapped; others go through the card's forbidden/warn path.
      const txnPolicy: Policy = {
        meta: { schema_version: '1.0', name: 'txn', scope: 'agent' },
        capability_mappings: {
          web_fetch: {
            tools: ['WebFetch'],  // restricts to WebFetch only
            card_actions: ['web_fetch'],
          },
        },
        forbidden: [],
        escalation_triggers: [],
        defaults: {
          unmapped_tool_action: 'warn',
          unmapped_severity: 'medium',
          fail_open: true,
        },
      };
      const result = evaluatePolicy(makeInput({
        tools: [{ name: 'WebFetch' }],
        transactionGuardrails: txnPolicy,
      }));
      expect(result.verdict).toBe('pass');
    });

    it('txn guardrail can add more forbidden rules (union)', () => {
      const txnPolicy: Policy = {
        meta: { schema_version: '1.0', name: 'txn', scope: 'agent' },
        capability_mappings: {
          web_fetch: { tools: ['WebFetch'], card_actions: ['web_fetch'] },
          file_system: { tools: ['Read', 'Write', 'Edit', 'Glob'], card_actions: ['file_read', 'file_write'] },
          code_execution: { tools: ['Bash'], card_actions: ['code_execution'] },
        },
        forbidden: [
          { pattern: 'Bash', reason: 'Txn forbids Bash', severity: 'critical' },
        ],
        escalation_triggers: [],
        defaults: {
          unmapped_tool_action: 'warn',
          unmapped_severity: 'medium',
          fail_open: true,
        },
      };
      const result = evaluatePolicy(makeInput({
        tools: [{ name: 'Bash' }],
        transactionGuardrails: txnPolicy,
      }));
      expect(result.verdict).toBe('fail');
      expect(result.violations.some((v) => v.type === 'forbidden')).toBe(true);
    });
  });
});
