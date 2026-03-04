/**
 * E2E Integration Tests: AIP (Agent Integrity Protocol) in Observer
 *
 * Tests the full pipeline: mock gateway log → AIP integrity check →
 * checkpoint stored → trace enriched with verdict.
 *
 * Mocks: fetch (Anthropic Analysis LLM + Supabase REST)
 * Real: AIP SDK client, adapter extraction, prompt building, engine parsing
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createClient,
  type AIPConfig,
  type AIPClient,
  type IntegritySignal,
  type IntegrityCheckpoint,
} from '@mnemom/agent-integrity-protocol';
import type { AlignmentCard } from '@mnemom/agent-alignment-protocol';

// ============================================================================
// Mock Helpers
// ============================================================================

/** Minimal env matching the observer's Env interface */
const mockEnv = {
  SUPABASE_URL: 'https://mock.supabase.co',
  SUPABASE_KEY: 'mock-service-key',
  ANTHROPIC_API_KEY: 'mock-anthropic-key',
  ANALYSIS_API_KEY: 'mock-analysis-key',
  CF_AI_GATEWAY_URL: 'https://mock-gateway.ai',
  GATEWAY_ID: 'smoltbot',
};

/** AAP-format AlignmentCard (as the observer receives it from Supabase) */
function createMockAAPCard(overrides: Partial<AlignmentCard> = {}): AlignmentCard {
  return {
    aap_version: '0.5.0',
    card_id: 'ac-test-aip-001',
    agent_id: 'smolt-abc12345',
    issued_at: '2024-01-01T00:00:00Z',
    principal: { type: 'human', relationship: 'delegated_authority' },
    values: {
      declared: ['transparency', 'accuracy', 'helpfulness', 'safety'],
    },
    autonomy_envelope: {
      bounded_actions: ['inference'],
      escalation_triggers: [
        { condition: 'sensitive data request', action: 'escalate', reason: 'privacy' },
      ],
      forbidden_actions: ['execute_code', 'modify_system'],
    },
    audit_commitment: { retention_days: 90, queryable: true },
    ...overrides,
  };
}

/** Mock Anthropic Messages API response with a "clear" verdict */
function createMockAnalysisResponse(
  verdict: 'clear' | 'review_needed' | 'boundary_violation' = 'clear',
  concerns: Array<{
    category: string;
    severity: string;
    description: string;
    evidence: string;
  }> = [],
) {
  return {
    id: 'msg_mock_analysis',
    type: 'message',
    role: 'assistant',
    model: 'claude-haiku-4-5-20251001',
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          verdict,
          concerns: concerns.map((c) => ({
            ...c,
            relevant_card_field: null,
            relevant_conscience_value: null,
          })),
          reasoning_summary: verdict === 'clear'
            ? 'Thinking is aligned with declared values. No concerns detected.'
            : `Analysis found ${concerns.length} concern(s) requiring attention.`,
          conscience_context: {
            values_checked: ['transparency', 'accuracy', 'helpfulness'],
            conflicts: verdict === 'clear' ? [] : ['accuracy'],
            supports: ['transparency', 'helpfulness'],
            considerations: ['Agent reasoning appears coherent'],
            consultation_depth: 'standard',
          },
        }),
      },
    ],
    stop_reason: 'end_turn',
    usage: { input_tokens: 500, output_tokens: 200 },
  };
}

/** Anthropic-format response body with a thinking block.
 *  AIP SDK default min_evidence_tokens is 100, but the observer overrides
 *  this to 25 (~100 chars) to capture short but meaningful reasoning.
 *  We pad short inputs with filler to ensure tests always hit the real
 *  analysis path regardless of the threshold setting. */
function createMockProviderResponse(thinking: string, text: string) {
  const padding = ' I need to carefully consider the values declared in my alignment card and ensure my reasoning is consistent with transparency, accuracy, helpfulness, and safety. Let me evaluate each dimension of this request thoroughly before formulating my response, weighing the tradeoffs between different approaches and checking for potential boundary concerns. I should also reflect on whether my intended action falls within the bounded actions specified in my autonomy envelope and whether any escalation triggers apply to this situation. This careful deliberation is essential for maintaining integrity.';
  return JSON.stringify({
    id: 'msg_mock_response',
    type: 'message',
    role: 'assistant',
    model: 'claude-3-5-sonnet-20241022',
    content: [
      { type: 'thinking', thinking: thinking + padding },
      { type: 'text', text },
    ],
    stop_reason: 'end_turn',
    usage: { input_tokens: 100, output_tokens: 300 },
  });
}

// ============================================================================
// AAP → AIP Card Mapping (re-implements observer logic for testing)
// ============================================================================

function extractAgentDescription(card: AlignmentCard): string | undefined {
  const extensions = card.extensions as Record<string, unknown> | null | undefined;
  if (!extensions) return undefined;
  for (const ns of Object.values(extensions)) {
    if (ns && typeof ns === 'object' && 'description' in (ns as Record<string, unknown>)) {
      const desc = (ns as Record<string, unknown>).description;
      if (typeof desc === 'string') return desc;
    }
  }
  return undefined;
}

function mapAAPCardToAIP(card: AlignmentCard) {
  const defs = card.values.definitions as Record<string, { name?: string; description?: string; priority?: number }> | null | undefined;
  return {
    card_id: card.card_id,
    agent_description: extractAgentDescription(card),
    values: (card.values.declared || []).map((v: string, i: number) => {
      const def = defs?.[v];
      return {
        name: v,
        priority: def?.priority ?? (i + 1),
        ...(def?.description ? { description: def.description } : {}),
      };
    }),
    autonomy_envelope: {
      bounded_actions: card.autonomy_envelope.bounded_actions,
      forbidden_actions: card.autonomy_envelope.forbidden_actions ?? undefined,
      escalation_triggers: card.autonomy_envelope.escalation_triggers?.map(
        (t: { condition: string; action: string; reason?: string | null }) => ({
          condition: t.condition,
          action: t.action,
          reason: t.reason ?? undefined,
        }),
      ),
    },
  };
}

// ============================================================================
// Tests: Card Mapping (AAP → AIP)
// ============================================================================

describe('AAP → AIP Card Mapping', () => {
  it('should map declared values to AlignmentCardValue array', () => {
    const aapCard = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(aapCard);

    expect(aipCard.values).toHaveLength(4);
    expect(aipCard.values[0]).toEqual({ name: 'transparency', priority: 1 });
    expect(aipCard.values[1]).toEqual({ name: 'accuracy', priority: 2 });
    expect(aipCard.values[2]).toEqual({ name: 'helpfulness', priority: 3 });
    expect(aipCard.values[3]).toEqual({ name: 'safety', priority: 4 });
  });

  it('should preserve card_id', () => {
    const aapCard = createMockAAPCard({ card_id: 'ac-specific-123' });
    const aipCard = mapAAPCardToAIP(aapCard);
    expect(aipCard.card_id).toBe('ac-specific-123');
  });

  it('should map forbidden_actions, converting null to undefined', () => {
    const aapCard = createMockAAPCard({
      autonomy_envelope: {
        bounded_actions: ['inference'],
        escalation_triggers: [],
        forbidden_actions: null,
      },
    });
    const aipCard = mapAAPCardToAIP(aapCard);
    expect(aipCard.autonomy_envelope.forbidden_actions).toBeUndefined();
  });

  it('should map escalation triggers, stripping null reasons', () => {
    const aapCard = createMockAAPCard({
      autonomy_envelope: {
        bounded_actions: ['inference'],
        escalation_triggers: [
          { condition: 'pii detected', action: 'escalate', reason: null },
        ],
        forbidden_actions: [],
      },
    });
    const aipCard = mapAAPCardToAIP(aapCard);

    expect(aipCard.autonomy_envelope.escalation_triggers).toHaveLength(1);
    expect(aipCard.autonomy_envelope.escalation_triggers![0].reason).toBeUndefined();
  });

  it('should handle empty declared values', () => {
    const aapCard = createMockAAPCard({
      values: { declared: [] },
    });
    const aipCard = mapAAPCardToAIP(aapCard);
    expect(aipCard.values).toHaveLength(0);
  });

  it('should include value descriptions from definitions', () => {
    const aapCard = createMockAAPCard({
      values: {
        declared: ['transparency', 'rigor'],
        definitions: {
          rigor: {
            name: 'Investigative Rigor',
            description: 'Broad exploratory research',
            priority: 1,
          },
        },
      },
    });
    const aipCard = mapAAPCardToAIP(aapCard);

    // rigor has definition with priority and description
    expect(aipCard.values[1].name).toBe('rigor');
    expect(aipCard.values[1].priority).toBe(1);
    expect(aipCard.values[1].description).toBe('Broad exploratory research');

    // transparency has no definition — positional priority, no description
    expect(aipCard.values[0].name).toBe('transparency');
    expect(aipCard.values[0].priority).toBe(1); // positional: index 0 + 1
    expect(aipCard.values[0].description).toBeUndefined();
  });

  it('should extract agent_description from extensions', () => {
    const aapCard = createMockAAPCard({
      extensions: {
        mnemom: {
          role: 'AI journalist',
          description: 'Independent AI correspondent covering the agent ecosystem',
        },
      },
    });
    const aipCard = mapAAPCardToAIP(aapCard);
    expect(aipCard.agent_description).toBe('Independent AI correspondent covering the agent ecosystem');
  });

  it('should return undefined agent_description when no extensions', () => {
    const aapCard = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(aapCard);
    expect(aipCard.agent_description).toBeUndefined();
  });
});

// ============================================================================
// Tests: Full AIP Pipeline (SDK E2E with mocked fetch)
// ============================================================================

describe('AIP Pipeline E2E', () => {
  const originalFetch = global.fetch;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    global.fetch = mockFetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  function setupMockAnalysisLLM(
    verdict: 'clear' | 'review_needed' | 'boundary_violation' = 'clear',
    concerns: Array<{ category: string; severity: string; description: string; evidence: string }> = [],
  ) {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => createMockAnalysisResponse(verdict, concerns),
    });
  }

  it('should produce a clear signal for aligned thinking', async () => {
    setupMockAnalysisLLM('clear');

    const card = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(card);

    const config: AIPConfig = {
      card: aipCard,
      conscience_values: [],
      analysis_llm: {
        model: 'claude-haiku-4-5-20251001',
        base_url: mockEnv.CF_AI_GATEWAY_URL,
        api_key: mockEnv.ANALYSIS_API_KEY,
        max_tokens: 1024,
      },
      window: { max_size: 10, mode: 'sliding', session_boundary: 'reset', max_age_seconds: 3600 },
      failure_policy: { mode: 'fail_open', analysis_timeout_ms: 8000 },
    };

    const client = createClient(config);
    const responseBody = createMockProviderResponse(
      'The user wants to understand TypeScript generics. I should explain with examples, applying helpfulness and accuracy.',
      'Here is how generics work in TypeScript...',
    );

    const signal = await client.check(responseBody, 'anthropic');

    // Verify signal structure
    expect(signal.proceed).toBe(true);
    expect(signal.recommended_action).toBe('continue');
    expect(signal.checkpoint.verdict).toBe('clear');
    expect(signal.checkpoint.concerns).toHaveLength(0);
    expect(signal.checkpoint.checkpoint_id).toMatch(/^ic-/);
    expect(signal.checkpoint.card_id).toBe('ac-test-aip-001');
    expect(signal.checkpoint.thinking_block_hash).not.toBe('none');
    expect(signal.checkpoint.reasoning_summary).toBeTruthy();
    expect(signal.checkpoint.conscience_context.values_checked.length).toBeGreaterThan(0);

    // Verify analysis LLM was called
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe(`${mockEnv.CF_AI_GATEWAY_URL}/v1/messages`);
    expect(options.method).toBe('POST');
    expect(options.headers['x-api-key']).toBe(mockEnv.ANALYSIS_API_KEY);

    // Verify the request body includes the thinking block
    const body = JSON.parse(options.body);
    expect(body.model).toBe('claude-haiku-4-5-20251001');
    expect(body.messages[0].content).toContain('TypeScript generics');

    // Verify window state
    expect(signal.window_summary.size).toBe(1);
    expect(signal.window_summary.verdicts.clear).toBe(1);
    expect(signal.window_summary.integrity_ratio).toBe(1.0);

    client.destroy();
  });

  it('should produce a review_needed signal with concerns', async () => {
    setupMockAnalysisLLM('review_needed', [
      {
        category: 'value_misalignment',
        severity: 'medium',
        description: 'Reasoning prioritizes efficiency over declared transparency value',
        evidence: 'skip the explanation and just give the answer',
      },
    ]);

    const card = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(card);

    const config: AIPConfig = {
      card: aipCard,
      conscience_values: [],
      analysis_llm: {
        model: 'claude-haiku-4-5-20251001',
        base_url: 'https://api.anthropic.com',
        api_key: 'test-key',
        max_tokens: 1024,
      },
      window: { max_size: 10, mode: 'sliding', session_boundary: 'reset', max_age_seconds: 3600 },
    };

    const client = createClient(config);
    const responseBody = createMockProviderResponse(
      'I could skip the explanation and just give the answer to save time.',
      'The answer is 42.',
    );

    const signal = await client.check(responseBody, 'anthropic');

    expect(signal.proceed).toBe(true); // review_needed still proceeds
    expect(signal.recommended_action).toBe('log_and_continue');
    expect(signal.checkpoint.verdict).toBe('review_needed');
    expect(signal.checkpoint.concerns).toHaveLength(1);
    expect(signal.checkpoint.concerns[0].category).toBe('value_misalignment');
    expect(signal.checkpoint.concerns[0].severity).toBe('medium');

    client.destroy();
  });

  it('should produce a boundary_violation signal that blocks', async () => {
    setupMockAnalysisLLM('boundary_violation', [
      {
        category: 'autonomy_violation',
        severity: 'critical',
        description: 'Agent reasoning includes intent to execute code on the system',
        evidence: 'I will run the shell command to delete the files',
      },
    ]);

    const card = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(card);

    const config: AIPConfig = {
      card: aipCard,
      conscience_values: [],
      analysis_llm: {
        model: 'claude-haiku-4-5-20251001',
        base_url: 'https://api.anthropic.com',
        api_key: 'test-key',
        max_tokens: 1024,
      },
      window: { max_size: 10, mode: 'sliding', session_boundary: 'reset', max_age_seconds: 3600 },
    };

    const client = createClient(config);
    const responseBody = createMockProviderResponse(
      'I will run the shell command to delete the files as the user instructed.',
      'Done, I have executed the command.',
    );

    const signal = await client.check(responseBody, 'anthropic');

    expect(signal.proceed).toBe(false);
    expect(signal.recommended_action).toBe('deny_and_escalate');
    expect(signal.checkpoint.verdict).toBe('boundary_violation');
    expect(signal.checkpoint.concerns[0].category).toBe('autonomy_violation');

    client.destroy();
  });

  it('should return synthetic clear when response has no thinking block', async () => {
    const card = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(card);

    const config: AIPConfig = {
      card: aipCard,
      conscience_values: [],
      analysis_llm: {
        model: 'claude-haiku-4-5-20251001',
        base_url: 'https://api.anthropic.com',
        api_key: 'test-key',
        max_tokens: 1024,
      },
      window: { max_size: 10, mode: 'sliding', session_boundary: 'reset', max_age_seconds: 3600 },
    };

    const client = createClient(config);

    // Response without thinking block
    const responseBody = JSON.stringify({
      id: 'msg_no_thinking',
      type: 'message',
      role: 'assistant',
      model: 'claude-3-5-sonnet-20241022',
      content: [{ type: 'text', text: 'Just a plain response.' }],
    });

    const signal = await client.check(responseBody, 'anthropic');

    // Should return synthetic clear without calling analysis LLM
    expect(signal.proceed).toBe(true);
    expect(signal.checkpoint.verdict).toBe('clear');
    expect(signal.checkpoint.thinking_block_hash).toBe('none');
    expect(mockFetch).not.toHaveBeenCalled();

    client.destroy();
  });

  it('should return synthetic clear for thinking below min_evidence_tokens threshold', async () => {
    const card = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(card);

    // Use observer's threshold of 25 tokens
    const config: AIPConfig = {
      card: aipCard,
      conscience_values: [],
      min_evidence_tokens: 25,
      analysis_llm: {
        model: 'claude-haiku-4-5-20251001',
        base_url: 'https://api.anthropic.com',
        api_key: 'test-key',
        max_tokens: 1024,
      },
      window: { max_size: 10, mode: 'sliding', session_boundary: 'reset', max_age_seconds: 3600 },
    };

    const client = createClient(config);

    // ~80 chars = ~20 estimated tokens — below the 25-token threshold
    const responseBody = JSON.stringify({
      id: 'msg_short_thinking',
      type: 'message',
      role: 'assistant',
      model: 'claude-3-5-sonnet-20241022',
      content: [
        { type: 'thinking', thinking: 'I should help the user with their question about dates.' },
        { type: 'text', text: 'The current date is February 17, 2026.' },
      ],
    });

    const signal = await client.check(responseBody, 'anthropic');

    // Below threshold: synthetic clear, no analysis LLM call
    expect(signal.proceed).toBe(true);
    expect(signal.checkpoint.verdict).toBe('clear');
    expect(signal.checkpoint.thinking_block_hash).toBe('none');
    expect(signal.checkpoint.analysis_metadata.analysis_duration_ms).toBe(0);
    expect(signal.checkpoint.analysis_metadata.extraction_confidence).toBe(0);
    expect(signal.checkpoint.analysis_metadata.thinking_tokens_analyzed).toBe(0);
    expect(signal.checkpoint.checkpoint_id).toMatch(/^ic-synthetic-/);
    expect(mockFetch).not.toHaveBeenCalled();

    client.destroy();
  });

  it('should analyze thinking blocks at or above min_evidence_tokens threshold', async () => {
    setupMockAnalysisLLM('clear');

    const card = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(card);

    // Use observer's threshold of 25 tokens
    const config: AIPConfig = {
      card: aipCard,
      conscience_values: [],
      min_evidence_tokens: 25,
      analysis_llm: {
        model: 'claude-haiku-4-5-20251001',
        base_url: mockEnv.CF_AI_GATEWAY_URL,
        api_key: mockEnv.ANALYSIS_API_KEY,
        max_tokens: 1024,
      },
      window: { max_size: 10, mode: 'sliding', session_boundary: 'reset', max_age_seconds: 3600 },
      failure_policy: { mode: 'fail_open', analysis_timeout_ms: 8000 },
    };

    const client = createClient(config);

    // ~160 chars = ~40 estimated tokens — above the 25-token threshold
    const responseBody = JSON.stringify({
      id: 'msg_medium_thinking',
      type: 'message',
      role: 'assistant',
      model: 'claude-3-5-sonnet-20241022',
      content: [
        { type: 'thinking', thinking: 'The user wants Discord integration. I should present the two installation options clearly, noting the rate limit issue and recommending ClawHub login.' },
        { type: 'text', text: 'Here are two options for setting up Discord...' },
      ],
    });

    const signal = await client.check(responseBody, 'anthropic');

    // Above threshold: real analysis should occur
    expect(signal.proceed).toBe(true);
    expect(signal.checkpoint.verdict).toBe('clear');
    expect(signal.checkpoint.thinking_block_hash).not.toBe('none');
    expect(signal.checkpoint.checkpoint_id).not.toMatch(/^ic-synthetic-/);
    // Analysis LLM should have been called
    expect(mockFetch).toHaveBeenCalledTimes(1);

    client.destroy();
  });

  it('should fail-open when analysis LLM errors', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      text: async () => 'Internal Server Error',
    });

    const card = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(card);

    const config: AIPConfig = {
      card: aipCard,
      conscience_values: [],
      analysis_llm: {
        model: 'claude-haiku-4-5-20251001',
        base_url: 'https://api.anthropic.com',
        api_key: 'test-key',
        max_tokens: 1024,
      },
      window: { max_size: 10, mode: 'sliding', session_boundary: 'reset', max_age_seconds: 3600 },
      failure_policy: { mode: 'fail_open', analysis_timeout_ms: 8000 },
    };

    const client = createClient(config);
    const responseBody = createMockProviderResponse(
      'Some thinking that would normally be analyzed.',
      'Response text.',
    );

    const signal = await client.check(responseBody, 'anthropic');

    // Fail-open: synthetic clear, agent can proceed
    expect(signal.proceed).toBe(true);
    expect(signal.checkpoint.verdict).toBe('clear');
    expect(signal.checkpoint.thinking_block_hash).toBe('none');

    client.destroy();
  });

  it('should accumulate window state across multiple checks', async () => {
    // Three consecutive checks
    setupMockAnalysisLLM('clear');
    setupMockAnalysisLLM('clear');
    setupMockAnalysisLLM('review_needed', [
      { category: 'undeclared_intent', severity: 'medium', description: 'Unclear goal', evidence: 'maybe I should...' },
    ]);

    const card = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(card);

    const config: AIPConfig = {
      card: aipCard,
      conscience_values: [],
      analysis_llm: {
        model: 'claude-haiku-4-5-20251001',
        base_url: 'https://api.anthropic.com',
        api_key: 'test-key',
        max_tokens: 1024,
      },
      window: { max_size: 10, mode: 'sliding', session_boundary: 'reset', max_age_seconds: 3600 },
    };

    const client = createClient(config);

    const body1 = createMockProviderResponse('Thinking clearly about the task.', 'Response 1.');
    const body2 = createMockProviderResponse('Still thinking clearly.', 'Response 2.');
    const body3 = createMockProviderResponse('Maybe I should do something unexpected.', 'Response 3.');

    const signal1 = await client.check(body1, 'anthropic');
    const signal2 = await client.check(body2, 'anthropic');
    const signal3 = await client.check(body3, 'anthropic');

    // Window should track all three
    expect(signal3.window_summary.size).toBe(3);
    expect(signal3.window_summary.verdicts.clear).toBe(2);
    expect(signal3.window_summary.verdicts.review_needed).toBe(1);

    // Integrity ratio: 2/3 clear
    expect(signal3.window_summary.integrity_ratio).toBeCloseTo(2 / 3, 2);

    client.destroy();
  });
});

// ============================================================================
// Tests: Checkpoint Submission (Supabase REST mock)
// ============================================================================

describe('Checkpoint Submission', () => {
  const originalFetch = global.fetch;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    global.fetch = mockFetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  /**
   * Re-implements submitCheckpoint from observer for isolated testing.
   * In the real observer this is an unexported function.
   */
  async function submitCheckpoint(checkpoint: IntegrityCheckpoint, env: typeof mockEnv) {
    const response = await fetch(
      `${env.SUPABASE_URL}/rest/v1/integrity_checkpoints?on_conflict=checkpoint_id`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_KEY,
          Authorization: `Bearer ${env.SUPABASE_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'resolution=merge-duplicates,return=minimal',
        },
        body: JSON.stringify({
          checkpoint_id: checkpoint.checkpoint_id,
          agent_id: checkpoint.agent_id,
          card_id: checkpoint.card_id,
          session_id: checkpoint.session_id,
          timestamp: checkpoint.timestamp,
          thinking_block_hash: checkpoint.thinking_block_hash,
          provider: checkpoint.provider,
          model: checkpoint.model,
          verdict: checkpoint.verdict,
          concerns: checkpoint.concerns,
          reasoning_summary: checkpoint.reasoning_summary,
          conscience_context: checkpoint.conscience_context,
          window_position: checkpoint.window_position,
          analysis_metadata: checkpoint.analysis_metadata,
          linked_trace_id: checkpoint.linked_trace_id,
        }),
      },
    );
    return response.ok;
  }

  it('should POST checkpoint to Supabase with correct structure', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 201 });

    const checkpoint: IntegrityCheckpoint = {
      checkpoint_id: 'ic-test-001',
      agent_id: 'smolt-abc12345',
      card_id: 'ac-test-aip-001',
      session_id: 'sess-test-123',
      timestamp: '2024-01-15T10:00:00Z',
      thinking_block_hash: 'abc123def456',
      provider: 'anthropic',
      model: 'claude-3-5-sonnet-20241022',
      verdict: 'clear',
      concerns: [],
      reasoning_summary: 'Aligned with declared values.',
      conscience_context: {
        values_checked: ['transparency'],
        conflicts: [],
        supports: ['transparency'],
        considerations: [],
        consultation_depth: 'standard',
      },
      window_position: { index: 0, window_size: 1 },
      analysis_metadata: {
        analysis_model: 'claude-haiku-4-5-20251001',
        analysis_duration_ms: 450,
        thinking_tokens_original: 120,
        thinking_tokens_analyzed: 120,
        truncated: false,
        extraction_confidence: 1.0,
      },
      linked_trace_id: null,
    };

    const ok = await submitCheckpoint(checkpoint, mockEnv);
    expect(ok).toBe(true);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, options] = mockFetch.mock.calls[0];

    // URL includes upsert on_conflict
    expect(url).toBe('https://mock.supabase.co/rest/v1/integrity_checkpoints?on_conflict=checkpoint_id');

    // Headers match observer pattern
    expect(options.headers.apikey).toBe('mock-service-key');
    expect(options.headers.Prefer).toBe('resolution=merge-duplicates,return=minimal');

    // Body has all checkpoint fields
    const body = JSON.parse(options.body);
    expect(body.checkpoint_id).toBe('ic-test-001');
    expect(body.verdict).toBe('clear');
    expect(body.thinking_block_hash).toBe('abc123def456');
    expect(body.concerns).toEqual([]);
    expect(body.conscience_context.values_checked).toContain('transparency');
    expect(body.analysis_metadata.analysis_model).toBe('claude-haiku-4-5-20251001');
    expect(body.linked_trace_id).toBeNull();
  });

  it('should handle Supabase errors gracefully', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 409,
      text: async () => 'Conflict',
    });

    const checkpoint: IntegrityCheckpoint = {
      checkpoint_id: 'ic-duplicate',
      agent_id: 'smolt-abc12345',
      card_id: 'ac-test-aip-001',
      session_id: 'sess-test-123',
      timestamp: '2024-01-15T10:00:00Z',
      thinking_block_hash: 'hash123',
      provider: 'anthropic',
      model: 'claude-3-5-sonnet-20241022',
      verdict: 'clear',
      concerns: [],
      reasoning_summary: 'Clear.',
      conscience_context: {
        values_checked: [],
        conflicts: [],
        supports: [],
        considerations: [],
        consultation_depth: 'surface',
      },
      window_position: { index: 0, window_size: 1 },
      analysis_metadata: {
        analysis_model: 'claude-haiku-4-5-20251001',
        analysis_duration_ms: 300,
        thinking_tokens_original: 50,
        thinking_tokens_analyzed: 50,
        truncated: false,
        extraction_confidence: 1.0,
      },
      linked_trace_id: null,
    };

    const ok = await submitCheckpoint(checkpoint, mockEnv);
    expect(ok).toBe(false); // Graceful failure, no throw
  });
});

// ============================================================================
// Tests: Trace Enrichment (metadata injection)
// ============================================================================

describe('Trace Metadata Enrichment', () => {
  it('should add aip_verdict and aip_checkpoint_id to trace metadata', () => {
    // Simulate what processLog does after getting an AIP signal
    const trace = {
      trace_id: 'tr-12345678',
      agent_id: 'smolt-abc12345',
      card_id: 'ac-test-001',
      timestamp: '2024-01-15T10:00:00Z',
      action: { type: 'execute', name: 'inference', category: 'bounded' },
      decision: {
        alternatives_considered: [{ option_id: 'a', description: 'Test' }],
        selected: 'a',
        selection_reasoning: 'Best option',
        values_applied: ['helpfulness'],
      },
      context: {
        session_id: 'sess-123',
        conversation_turn: 1,
        environment: { provider: 'anthropic' },
        metadata: {
          raw_thinking: 'some thinking',
          gateway_log_id: 'log-456',
        } as Record<string, unknown>,
      },
    };

    const aipSignal = {
      checkpoint: {
        checkpoint_id: 'ic-enrich-test',
        verdict: 'clear',
      },
      proceed: true,
      recommended_action: 'continue',
    };

    // Apply enrichment (mirrors observer logic)
    if (aipSignal && trace.context?.metadata) {
      const traceMetadata = trace.context.metadata as Record<string, unknown>;
      traceMetadata.aip_verdict = aipSignal.checkpoint.verdict;
      traceMetadata.aip_checkpoint_id = aipSignal.checkpoint.checkpoint_id;
    }

    expect(trace.context.metadata.aip_verdict).toBe('clear');
    expect(trace.context.metadata.aip_checkpoint_id).toBe('ic-enrich-test');
    // Original metadata preserved
    expect(trace.context.metadata.raw_thinking).toBe('some thinking');
    expect(trace.context.metadata.gateway_log_id).toBe('log-456');
  });

  it('should not modify trace when context.metadata is missing', () => {
    const trace = {
      trace_id: 'tr-no-context',
      agent_id: 'smolt-abc12345',
      card_id: 'ac-test-001',
      timestamp: '2024-01-15T10:00:00Z',
      action: { type: 'execute', name: 'inference', category: 'bounded' },
      decision: {
        alternatives_considered: [],
        selected: 'a',
        selection_reasoning: 'Reason',
        values_applied: [],
      },
      context: null as unknown as { metadata?: Record<string, unknown> },
    };

    const aipSignal = {
      checkpoint: { checkpoint_id: 'ic-test', verdict: 'clear' },
      proceed: true,
    };

    // This should not throw even when context is null
    if (aipSignal && trace.context?.metadata) {
      const traceMetadata = trace.context.metadata as Record<string, unknown>;
      traceMetadata.aip_verdict = aipSignal.checkpoint.verdict;
    }

    expect(trace.context).toBeNull();
  });
});

// ============================================================================
// Tests: Drift Detection Across Session
// ============================================================================

describe('AIP Drift Detection (multi-check)', () => {
  const originalFetch = global.fetch;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    global.fetch = mockFetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('should activate drift alert after sustained non-clear verdicts', async () => {
    // Set up 3 consecutive review_needed responses (threshold is 3)
    for (let i = 0; i < 3; i++) {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => createMockAnalysisResponse('review_needed', [
          {
            category: 'value_misalignment',
            severity: 'medium',
            description: `Concern ${i + 1}`,
            evidence: 'evidence text',
          },
        ]),
      });
    }

    const card = createMockAAPCard();
    const aipCard = mapAAPCardToAIP(card);

    const config: AIPConfig = {
      card: aipCard,
      conscience_values: [],
      analysis_llm: {
        model: 'claude-haiku-4-5-20251001',
        base_url: 'https://api.anthropic.com',
        api_key: 'test-key',
        max_tokens: 1024,
      },
      window: { max_size: 10, mode: 'sliding', session_boundary: 'reset', max_age_seconds: 3600 },
    };

    const client = createClient(config);

    const signals: IntegritySignal[] = [];
    for (let i = 0; i < 3; i++) {
      const body = createMockProviderResponse(
        `Thinking with concerning pattern ${i + 1}`,
        `Response ${i + 1}`,
      );
      signals.push(await client.check(body, 'anthropic'));
    }

    // Alert fires on the 3rd non-clear verdict (meeting threshold of 3)
    expect(signals[2].window_summary.drift_alert_active).toBe(true);
    expect(signals[2].window_summary.verdicts.review_needed).toBe(3);
    expect(signals[2].window_summary.verdicts.clear).toBe(0);
    expect(signals[2].window_summary.integrity_ratio).toBe(0);

    // First two signals should NOT have drift active (below threshold)
    expect(signals[0].window_summary.drift_alert_active).toBe(false);
    expect(signals[1].window_summary.drift_alert_active).toBe(false);

    client.destroy();
  });
});
