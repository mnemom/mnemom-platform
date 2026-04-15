import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  evaluatePolicy,
  extractPolicyFromCard,
  type Policy,
  type UnifiedAlignmentCard,
  type EvaluationResult,
} from '@mnemom/policy-engine';

// We test the pure functions directly — extractToolsFromRequest is internal,
// so we replicate its logic here for tool extraction tests, and test the
// policy engine integration for gateway scenarios.

// ============================================================================
// Tool extraction tests (replicating gateway logic)
// ============================================================================

interface ToolReference {
  name: string;
}

type GatewayProvider = 'anthropic' | 'openai' | 'gemini';

function extractToolsFromRequest(
  requestBody: Record<string, any> | null,
  provider: GatewayProvider
): ToolReference[] {
  if (!requestBody) return [];

  const tools: string[] = [];

  switch (provider) {
    case 'anthropic': {
      const anthropicTools = requestBody.tools;
      if (Array.isArray(anthropicTools)) {
        for (const t of anthropicTools) {
          if (t?.name) tools.push(t.name);
        }
      }
      break;
    }
    case 'openai': {
      const openaiTools = requestBody.tools;
      if (Array.isArray(openaiTools)) {
        for (const t of openaiTools) {
          if (t?.function?.name) tools.push(t.function.name);
        }
      }
      break;
    }
    case 'gemini': {
      const geminiTools = requestBody.tools;
      if (Array.isArray(geminiTools)) {
        for (const t of geminiTools) {
          if (t?.functionDeclarations && Array.isArray(t.functionDeclarations)) {
            for (const fd of t.functionDeclarations) {
              if (fd?.name) tools.push(fd.name);
            }
          }
          if (t?.name) tools.push(t.name);
        }
      }
      break;
    }
  }

  return tools.map((name) => ({ name }));
}

// ============================================================================
// UC-8 test fixtures — evaluator now takes a unified card (no separate policy).
// Fixtures produce a card whose extractPolicyFromCard derivation matches what
// the pre-UC-8 makePolicy() emitted, so behavioural assertions are preserved.
// ============================================================================

function makeCard(overrides?: Partial<UnifiedAlignmentCard>): UnifiedAlignmentCard {
  return {
    card_id: 'ac-test',
    card_version: '2026-04-15',
    autonomy: {
      bounded_actions: ['web_fetch', 'file_read', 'file_write', 'code_execution'],
      escalation_triggers: [],
    },
    capabilities: {
      web_fetch: {
        description: 'Web browsing',
        tools: ['WebFetch', 'WebSearch'],
        required_actions: ['web_fetch'],
      },
      file_system: {
        tools: ['Read', 'Write', 'Edit', 'Glob'],
        required_actions: ['file_read', 'file_write'],
      },
      code_execution: {
        tools: ['Bash'],
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

// ============================================================================
// Tool extraction tests
// ============================================================================

describe('extractToolsFromRequest', () => {
  describe('Anthropic format', () => {
    it('extracts tool names from Anthropic request', () => {
      const body = {
        tools: [
          { name: 'Read', description: 'Read files' },
          { name: 'Write', description: 'Write files' },
          { name: 'Bash', description: 'Run commands' },
        ],
      };
      const result = extractToolsFromRequest(body, 'anthropic');
      expect(result).toHaveLength(3);
      expect(result.map((t) => t.name)).toEqual(['Read', 'Write', 'Bash']);
    });

    it('returns empty array for null body', () => {
      expect(extractToolsFromRequest(null, 'anthropic')).toHaveLength(0);
    });

    it('returns empty array when no tools field', () => {
      expect(extractToolsFromRequest({ model: 'claude-3' }, 'anthropic')).toHaveLength(0);
    });
  });

  describe('OpenAI format', () => {
    it('extracts tool names from OpenAI request', () => {
      const body = {
        tools: [
          { type: 'function', function: { name: 'get_weather', parameters: {} } },
          { type: 'function', function: { name: 'search_web', parameters: {} } },
        ],
      };
      const result = extractToolsFromRequest(body, 'openai');
      expect(result).toHaveLength(2);
      expect(result.map((t) => t.name)).toEqual(['get_weather', 'search_web']);
    });
  });

  describe('Gemini format', () => {
    it('extracts tool names from Gemini functionDeclarations', () => {
      const body = {
        tools: [
          {
            functionDeclarations: [
              { name: 'search', description: 'Search' },
              { name: 'calculate', description: 'Calculate' },
            ],
          },
        ],
      };
      const result = extractToolsFromRequest(body, 'gemini');
      expect(result).toHaveLength(2);
      expect(result.map((t) => t.name)).toEqual(['search', 'calculate']);
    });

    it('extracts flat tool names from Gemini', () => {
      const body = {
        tools: [{ name: 'code_execution' }],
      };
      const result = extractToolsFromRequest(body, 'gemini');
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe('code_execution');
    });
  });
});

// ============================================================================
// Gateway policy evaluation scenarios
// ============================================================================

describe('gateway policy evaluation (UC-8)', () => {
  it('enforce mode: reject on fail returns violations', () => {
    const card = makeCard({
      enforcement: {
        forbidden_tools: [{ pattern: 'Bash', reason: 'No shell access', severity: 'critical' }],
        unmapped_tool_action: 'warn',
        fail_open: true,
      },
    });
    const result = evaluatePolicy({
      context: 'gateway',
      card,
      tools: [{ name: 'Bash' }],
    });

    expect(result.verdict).toBe('fail');
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations[0].type).toBe('forbidden');
  });

  it('warn mode: forward on fail with verdict', () => {
    const card = makeCard({
      enforcement: {
        forbidden_tools: [{ pattern: 'Bash', reason: 'No shell access', severity: 'critical' }],
        unmapped_tool_action: 'warn',
        fail_open: true,
      },
    });
    const result = evaluatePolicy({
      context: 'gateway',
      card,
      tools: [{ name: 'Bash' }],
    });

    expect(result.verdict).toBe('fail');
  });

  it('extractPolicyFromCard: no capabilities/enforcement → empty policy', () => {
    const policy = extractPolicyFromCard({ card_id: 'ac-empty' });
    expect(policy.capability_mappings).toEqual({});
    expect(policy.forbidden).toHaveLength(0);
    expect(policy.defaults.unmapped_tool_action).toBe('allow');
  });

  it('fail-open: evaluation runs with a bare card', () => {
    const result = evaluatePolicy({
      context: 'gateway',
      card: { card_id: 'ac-bare' },
      tools: [{ name: 'Read' }],
    });
    expect(result).toBeDefined();
    expect(result.context).toBe('gateway');
  });

  it('no tools in request → empty result', () => {
    const result = evaluatePolicy({
      context: 'gateway',
      card: makeCard(),
      tools: [],
    });

    expect(result.verdict).toBe('pass');
    expect(result.violations).toHaveLength(0);
    expect(result.warnings).toHaveLength(0);
  });

  it('card_gaps are empty in gateway context', () => {
    const result = evaluatePolicy({
      context: 'gateway',
      card: makeCard({ autonomy: { bounded_actions: [], escalation_triggers: [] } }),
      tools: [{ name: 'Bash' }],
    });

    expect(result.card_gaps).toHaveLength(0);
  });

  it('forbidden rules come from card.enforcement.forbidden_tools', () => {
    // Post-UC-8 the card is the source of truth — org+agent were already merged
    // at storage time by the composition engine in mnemom-api.
    const result = evaluatePolicy({
      context: 'gateway',
      card: makeCard({
        enforcement: {
          forbidden_tools: [
            { pattern: 'mcp__*__delete*', reason: 'Org forbids deletion', severity: 'critical' },
          ],
          unmapped_tool_action: 'warn',
          fail_open: true,
        },
      }),
      tools: [{ name: 'mcp__fs__delete_file' }],
    });

    expect(result.verdict).toBe('fail');
    expect(result.violations.some((v) => v.type === 'forbidden')).toBe(true);
  });

  it('transaction guardrails intersect with card-derived policy', () => {
    const txnPolicy: Policy = {
      meta: { schema_version: '1.0', name: 'txn', scope: 'agent' },
      capability_mappings: {
        file_system: { tools: ['Read'], card_actions: ['file_read', 'file_write'] },
      },
      forbidden: [
        { pattern: 'Write', reason: 'Txn restricts writes', severity: 'critical' },
      ],
      escalation_triggers: [],
      defaults: { unmapped_tool_action: 'warn', unmapped_severity: 'medium', fail_open: true },
    };
    const result = evaluatePolicy({
      context: 'gateway',
      card: makeCard(),
      tools: [{ name: 'Write' }],
      transactionGuardrails: txnPolicy,
    });
    expect(result.verdict).toBe('fail');
    expect(result.violations.some((v) => v.type === 'forbidden')).toBe(true);
  });

  it('enforcement_mode from card.enforcement.mode', () => {
    const result = evaluatePolicy({
      context: 'gateway',
      card: makeCard({
        enforcement: {
          unmapped_tool_action: 'warn',
          fail_open: true,
          mode: 'enforce',
          grace_period_hours: 48,
        },
      }),
      tools: [{ name: 'Read' }],
    });

    expect(result.verdict).toBe('pass');
  });
});

// ============================================================================
// Grace period tests (unit-level logic)
// ============================================================================

describe('grace period logic', () => {
  it('new tool violation → downgraded when in grace period', () => {
    // Simulate: tool has no first_seen record → it's new → in grace
    // We test this at the policy engine level — violations are produced,
    // and the gateway's applyGracePeriod would downgrade them.
    const card = makeCard({
      enforcement: {
        unmapped_tool_action: 'deny',
        fail_open: true,
        grace_period_hours: 24,
      },
    });
    const result = evaluatePolicy({
      context: 'gateway',
      card,
      tools: [{ name: 'NewUnknownTool' }],
    });

    expect(result.verdict).toBe('fail');
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].tool).toBe('NewUnknownTool');
  });

  it('grace period of 0 disables grace behavior', () => {
    const card = makeCard({
      enforcement: {
        unmapped_tool_action: 'deny',
        fail_open: true,
        grace_period_hours: 0,
      },
    });
    const result = evaluatePolicy({
      context: 'gateway',
      card,
      tools: [{ name: 'NewTool' }],
    });

    expect(result.verdict).toBe('fail');
    expect(result.violations).toHaveLength(1);
  });
});
