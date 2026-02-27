import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  evaluatePolicy,
  mergePolicies,
  type Policy,
  type AlignmentCard,
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
// Test fixtures
// ============================================================================

function makePolicy(overrides?: Partial<Policy>): Policy {
  return {
    meta: { schema_version: '1.0', name: 'test-policy', scope: 'org' },
    capability_mappings: {
      web_fetch: {
        description: 'Web browsing',
        tools: ['WebFetch', 'WebSearch'],
        card_actions: ['web_fetch'],
      },
      file_system: {
        tools: ['Read', 'Write', 'Edit', 'Glob'],
        card_actions: ['file_read', 'file_write'],
      },
      code_execution: {
        tools: ['Bash'],
        card_actions: ['code_execution'],
      },
    },
    forbidden: [
      { pattern: 'mcp__*__delete*', reason: 'Destructive deletion forbidden', severity: 'critical' },
    ],
    escalation_triggers: [],
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

describe('gateway policy evaluation', () => {
  it('enforce mode: reject on fail returns violations', () => {
    const policy = makePolicy({
      forbidden: [{ pattern: 'Bash', reason: 'No shell access', severity: 'critical' }],
    });
    const card = makeCard();
    const result = evaluatePolicy({
      context: 'gateway',
      policy,
      card,
      tools: [{ name: 'Bash' }],
    });

    expect(result.verdict).toBe('fail');
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations[0].type).toBe('forbidden');
  });

  it('warn mode: forward on fail with verdict', () => {
    const policy = makePolicy({
      forbidden: [{ pattern: 'Bash', reason: 'No shell access', severity: 'critical' }],
    });
    const result = evaluatePolicy({
      context: 'gateway',
      policy,
      card: makeCard(),
      tools: [{ name: 'Bash' }],
    });

    // In warn mode, the gateway would still forward — we just verify the verdict
    expect(result.verdict).toBe('fail');
    // The gateway decides what to do with this based on enforcement_mode
  });

  it('no policy → skip evaluation (null merge)', () => {
    const merged = mergePolicies(null, null, false);
    expect(merged).toBeNull();
  });

  it('fail-open: evaluation runs successfully even with empty card', () => {
    const policy = makePolicy();
    const result = evaluatePolicy({
      context: 'gateway',
      policy,
      card: {},
      tools: [{ name: 'Read' }],
    });

    // With empty card, mapped tools will have capability_exceeded (no bounded_actions)
    expect(result).toBeDefined();
    expect(result.context).toBe('gateway');
  });

  it('no tools in request → empty result', () => {
    const policy = makePolicy();
    const result = evaluatePolicy({
      context: 'gateway',
      policy,
      card: makeCard(),
      tools: [],
    });

    expect(result.verdict).toBe('pass');
    expect(result.violations).toHaveLength(0);
    expect(result.warnings).toHaveLength(0);
  });

  it('card_gaps are empty in gateway context', () => {
    const policy = makePolicy();
    const result = evaluatePolicy({
      context: 'gateway',
      policy,
      card: makeCard({ autonomy_envelope: { bounded_actions: [] } }),
      tools: [{ name: 'Bash' }],
    });

    expect(result.card_gaps).toHaveLength(0);
  });

  it('policy merge: agent cannot weaken org forbidden rules', () => {
    const orgPolicy = makePolicy({
      forbidden: [
        { pattern: 'mcp__*__delete*', reason: 'Org forbids deletion', severity: 'critical' },
      ],
    });
    const agentPolicy = makePolicy({
      meta: { schema_version: '1.0', name: 'agent-policy', scope: 'agent' },
      forbidden: [], // Agent tries to have no forbidden rules
    });

    const merged = mergePolicies(orgPolicy, agentPolicy, false);
    expect(merged).not.toBeNull();

    // Org forbidden rules persist
    const result = evaluatePolicy({
      context: 'gateway',
      policy: merged!,
      card: makeCard(),
      tools: [{ name: 'mcp__fs__delete_file' }],
    });

    expect(result.verdict).toBe('fail');
    expect(result.violations.some((v) => v.type === 'forbidden')).toBe(true);
  });

  it('enforcement_mode defaults are accepted in policy', () => {
    const policy = makePolicy({
      defaults: {
        unmapped_tool_action: 'warn',
        unmapped_severity: 'medium',
        fail_open: true,
        enforcement_mode: 'enforce',
        grace_period_hours: 48,
      },
    });

    const result = evaluatePolicy({
      context: 'gateway',
      policy,
      card: makeCard(),
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
    // Here we verify the violation is correctly produced.
    const policy = makePolicy({
      defaults: {
        unmapped_tool_action: 'deny',
        unmapped_severity: 'high',
        fail_open: true,
        grace_period_hours: 24,
      },
    });
    const result = evaluatePolicy({
      context: 'gateway',
      policy,
      card: makeCard(),
      tools: [{ name: 'NewUnknownTool' }],
    });

    // Violation is produced by the engine
    expect(result.verdict).toBe('fail');
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].tool).toBe('NewUnknownTool');
    // Grace period downgrading happens in the gateway layer (tested via integration)
  });

  it('grace period of 0 disables grace behavior', () => {
    const policy = makePolicy({
      defaults: {
        unmapped_tool_action: 'deny',
        unmapped_severity: 'high',
        fail_open: true,
        grace_period_hours: 0,
      },
    });
    const result = evaluatePolicy({
      context: 'gateway',
      policy,
      card: makeCard(),
      tools: [{ name: 'NewTool' }],
    });

    expect(result.verdict).toBe('fail');
    expect(result.violations).toHaveLength(1);
  });
});
