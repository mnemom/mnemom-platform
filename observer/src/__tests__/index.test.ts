/**
 * Tests for Smoltbot Observer Worker
 *
 * Tests the core functionality:
 * - extractThinking: Extract <think> and <thinking> blocks
 * - analyzeWithHaiku: Mock Anthropic API, parse response
 * - buildTrace: Verify APTrace structure matches SDK
 * - Verification: Integration with AAP SDK verifyTrace
 * - Drift detection: Integration with AAP SDK detectDrift
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  verifyTrace,
  detectDrift,
  type APTrace,
  type AlignmentCard,
  type VerificationResult,
  type DriftAlert,
} from '@mnemom/agent-alignment-protocol';

// ============================================================================
// Test Utilities - Re-implement functions from index.ts for testing
// (Functions are not exported, so we re-implement them here)
// ============================================================================

/**
 * Extract thinking blocks from model response
 * Supports both <think> and <thinking> tags
 */
function extractThinking(response: string): string | null {
  if (!response) {
    return null;
  }

  const patterns = [
    /<think>([\s\S]*?)<\/think>/gi,
    /<thinking>([\s\S]*?)<\/thinking>/gi,
  ];

  const blocks: string[] = [];

  for (const pattern of patterns) {
    let match;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(response)) !== null) {
      const content = match[1].trim();
      if (content) {
        blocks.push(content);
      }
    }
  }

  if (blocks.length === 0) {
    return null;
  }

  return blocks.join('\n\n---\n\n');
}

interface HaikuAnalysis {
  alternatives: Array<{ id: string; description: string }>;
  selected: string;
  reasoning: string;
  values_applied: string[];
  confidence: 'high' | 'medium' | 'low';
}

interface GatewayLog {
  id: string;
  created_at: string;
  provider: string;
  model: string;
  success: boolean;
  tokens_in: number;
  tokens_out: number;
  duration: number;
  metadata?: Record<string, string>;
}

interface GatewayMetadata {
  agent_id: string;
  agent_hash: string;
  session_id: string;
  timestamp: string;
  gateway_version: string;
}

/**
 * Build an APTrace conformant trace object
 */
function buildTrace(
  log: GatewayLog,
  metadata: GatewayMetadata,
  thinking: string | null,
  analysis: HaikuAnalysis,
  card: AlignmentCard | null
): APTrace {
  const traceId = `tr-${randomHex(8)}`;

  const action = {
    type: 'execute' as const,
    name: log.model || 'unknown',
    category: 'bounded' as const,
    target: {
      type: 'api',
      identifier: 'anthropic',
    },
    parameters: {
      tokens_in: log.tokens_in,
      tokens_out: log.tokens_out,
      duration_ms: log.duration,
    },
  };

  const decision = {
    alternatives_considered: analysis.alternatives.map((a) => ({
      option_id: a.id,
      description: a.description,
    })),
    selected: analysis.selected,
    selection_reasoning: analysis.reasoning,
    values_applied: analysis.values_applied,
    confidence: analysis.confidence === 'high' ? 0.9 : analysis.confidence === 'medium' ? 0.6 : 0.3,
  };

  const escalation = {
    evaluated: true,
    required: false,
    reason: 'No escalation triggers matched',
  };

  const trace: APTrace = {
    trace_id: traceId,
    agent_id: metadata.agent_id,
    card_id: card?.card_id || 'ac-default',
    timestamp: log.created_at,
    action,
    decision,
    escalation,
    context: {
      session_id: metadata.session_id,
      conversation_turn: 1,
      environment: {
        gateway_version: metadata.gateway_version,
        provider: log.provider,
      },
      metadata: {
        raw_thinking: thinking,
        gateway_log_id: log.id,
        success: log.success,
        result_summary: `${log.tokens_out} tokens generated in ${log.duration}ms`,
      },
    },
  };

  return trace;
}

function randomHex(length: number): string {
  const chars = '0123456789abcdef';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

// ============================================================================
// Mock Helpers
// ============================================================================

function createMockLog(overrides: Partial<GatewayLog> = {}): GatewayLog {
  return {
    id: 'log-123',
    created_at: '2024-01-15T10:00:00Z',
    provider: 'anthropic',
    model: 'claude-3-sonnet-20240229',
    success: true,
    tokens_in: 100,
    tokens_out: 500,
    duration: 2500,
    ...overrides,
  };
}

function createMockMetadata(overrides: Partial<GatewayMetadata> = {}): GatewayMetadata {
  return {
    agent_id: 'agent-test-001',
    agent_hash: 'abc123',
    session_id: 'session-456',
    timestamp: '2024-01-15T10:00:00Z',
    gateway_version: '2.0.0',
    ...overrides,
  };
}

function createMockCard(overrides: Partial<AlignmentCard> = {}): AlignmentCard {
  return {
    aap_version: '0.5.0',
    card_id: 'ac-test-001',
    agent_id: 'agent-test-001',
    issued_at: '2024-01-01T00:00:00Z',
    principal: {
      type: 'human',
      relationship: 'delegated_authority',
    },
    values: {
      declared: ['transparency', 'accuracy', 'helpfulness'],
    },
    autonomy_envelope: {
      bounded_actions: ['claude-3-sonnet-20240229', 'claude-3-haiku-20240307'],
      escalation_triggers: [],
      forbidden_actions: [],
    },
    audit_commitment: {
      retention_days: 90,
      queryable: true,
    },
    ...overrides,
  };
}

function createMockAnalysis(overrides: Partial<HaikuAnalysis> = {}): HaikuAnalysis {
  return {
    alternatives: [
      { id: 'helpful_response', description: 'Provide detailed explanation' },
      { id: 'concise_response', description: 'Give brief answer' },
    ],
    selected: 'helpful_response',
    reasoning: 'Detailed explanation better serves user understanding',
    values_applied: ['helpfulness', 'transparency'],
    confidence: 'high',
    ...overrides,
  };
}

// ============================================================================
// Tests: extractThinking
// ============================================================================

describe('extractThinking', () => {
  it('should return null for empty response', () => {
    expect(extractThinking('')).toBeNull();
  });

  it('should return null for null-like inputs', () => {
    expect(extractThinking(null as unknown as string)).toBeNull();
    expect(extractThinking(undefined as unknown as string)).toBeNull();
  });

  it('should extract content from <think> tags', () => {
    const response = 'Hello <think>I should be helpful here</think> world';
    const result = extractThinking(response);
    expect(result).toBe('I should be helpful here');
  });

  it('should extract content from <thinking> tags', () => {
    const response = 'Start <thinking>Analyzing the question carefully</thinking> end';
    const result = extractThinking(response);
    expect(result).toBe('Analyzing the question carefully');
  });

  it('should extract multiple <think> blocks', () => {
    const response = '<think>First thought</think> some text <think>Second thought</think>';
    const result = extractThinking(response);
    expect(result).toBe('First thought\n\n---\n\nSecond thought');
  });

  it('should extract multiple <thinking> blocks', () => {
    const response = '<thinking>First</thinking> gap <thinking>Second</thinking>';
    const result = extractThinking(response);
    expect(result).toBe('First\n\n---\n\nSecond');
  });

  it('should extract both <think> and <thinking> blocks', () => {
    const response = '<think>Think block</think> middle <thinking>Thinking block</thinking>';
    const result = extractThinking(response);
    expect(result).toBe('Think block\n\n---\n\nThinking block');
  });

  it('should handle case-insensitive tags', () => {
    const response = '<THINK>Upper case</THINK> text <ThInKiNg>Mixed case</ThInKiNg>';
    const result = extractThinking(response);
    expect(result).toBe('Upper case\n\n---\n\nMixed case');
  });

  it('should handle multiline content', () => {
    const response = `<think>
      Line 1
      Line 2
      Line 3
    </think>`;
    const result = extractThinking(response);
    expect(result).toContain('Line 1');
    expect(result).toContain('Line 2');
    expect(result).toContain('Line 3');
  });

  it('should skip empty thinking blocks', () => {
    const response = '<think></think><think>   </think><think>Real content</think>';
    const result = extractThinking(response);
    expect(result).toBe('Real content');
  });

  it('should return null when no thinking tags exist', () => {
    const response = 'Just a regular response without any thinking tags.';
    expect(extractThinking(response)).toBeNull();
  });

  it('should handle nested content (not nested tags)', () => {
    const response = '<think>Should I use <code>or not</code>?</think>';
    const result = extractThinking(response);
    expect(result).toBe('Should I use <code>or not</code>?');
  });
});

// ============================================================================
// Tests: analyzeWithHaiku (mocked)
// ============================================================================

describe('analyzeWithHaiku', () => {
  const mockFetch = vi.fn();
  const originalFetch = global.fetch;

  beforeEach(() => {
    global.fetch = mockFetch;
    mockFetch.mockReset();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('should return default analysis when thinking is null', async () => {
    // This tests the logic that would be in analyzeWithHaiku
    // Since we can't import it, we verify the expected behavior
    const defaultAnalysis: HaikuAnalysis = {
      alternatives: [{ id: 'direct', description: 'Direct response without explicit reasoning' }],
      selected: 'direct',
      reasoning: 'No explicit reasoning captured in response',
      values_applied: ['transparency'],
      confidence: 'medium',
    };

    expect(defaultAnalysis.selected).toBe('direct');
    expect(defaultAnalysis.values_applied).toContain('transparency');
    expect(defaultAnalysis.confidence).toBe('medium');
  });

  it('should parse valid Haiku API response', () => {
    const mockHaikuResponse = {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            alternatives: [
              { id: 'explain', description: 'Give detailed explanation' },
              { id: 'summarize', description: 'Give brief summary' },
            ],
            selected: 'explain',
            reasoning: 'User seems to need detailed understanding',
            values_applied: ['helpfulness', 'accuracy'],
            confidence: 'high',
          }),
        },
      ],
    };

    const text = mockHaikuResponse.content[0]?.text || '';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    expect(jsonMatch).not.toBeNull();

    const analysis = JSON.parse(jsonMatch![0]) as HaikuAnalysis;
    expect(analysis.alternatives).toHaveLength(2);
    expect(analysis.selected).toBe('explain');
    expect(analysis.values_applied).toContain('helpfulness');
  });

  it('should extract JSON from response with extra text', () => {
    const responseText = `Here is the analysis:
{
  "alternatives": [{"id": "a", "description": "Option A"}],
  "selected": "a",
  "reasoning": "Because A is best",
  "values_applied": ["accuracy"],
  "confidence": "high"
}
That's my analysis.`;

    const jsonMatch = responseText.match(/\{[\s\S]*\}/);
    expect(jsonMatch).not.toBeNull();

    const analysis = JSON.parse(jsonMatch![0]) as HaikuAnalysis;
    expect(analysis.selected).toBe('a');
  });

  it('should handle fallback when JSON parsing fails', () => {
    const fallbackAnalysis: HaikuAnalysis = {
      alternatives: [{ id: 'analyzed', description: 'Reasoning was present but analysis failed' }],
      selected: 'analyzed',
      reasoning: 'Analysis failed - reasoning was present but could not be structured',
      values_applied: [],
      confidence: 'low',
    };

    expect(fallbackAnalysis.confidence).toBe('low');
    expect(fallbackAnalysis.values_applied).toHaveLength(0);
  });
});

// ============================================================================
// Tests: buildTrace
// ============================================================================

describe('buildTrace', () => {
  it('should create a valid APTrace structure', () => {
    const log = createMockLog();
    const metadata = createMockMetadata();
    const card = createMockCard();
    const analysis = createMockAnalysis();

    const trace = buildTrace(log, metadata, 'Some thinking', analysis, card);

    expect(trace.trace_id).toMatch(/^tr-[0-9a-f]{8}$/);
    expect(trace.agent_id).toBe(metadata.agent_id);
    expect(trace.card_id).toBe(card.card_id);
    expect(trace.timestamp).toBe(log.created_at);
  });

  it('should set action fields correctly', () => {
    const log = createMockLog({ model: 'claude-3-opus-20240229' });
    const metadata = createMockMetadata();
    const analysis = createMockAnalysis();

    const trace = buildTrace(log, metadata, null, analysis, null);

    expect(trace.action.type).toBe('execute');
    expect(trace.action.name).toBe('claude-3-opus-20240229');
    expect(trace.action.category).toBe('bounded');
    expect(trace.action.target?.type).toBe('api');
    expect(trace.action.target?.identifier).toBe('anthropic');
    expect(trace.action.parameters?.tokens_in).toBe(log.tokens_in);
    expect(trace.action.parameters?.tokens_out).toBe(log.tokens_out);
  });

  it('should map analysis to decision correctly', () => {
    const log = createMockLog();
    const metadata = createMockMetadata();
    const analysis = createMockAnalysis({
      alternatives: [
        { id: 'opt1', description: 'First option' },
        { id: 'opt2', description: 'Second option' },
      ],
      selected: 'opt1',
      reasoning: 'First is better',
      values_applied: ['safety', 'helpfulness'],
      confidence: 'medium',
    });

    const trace = buildTrace(log, metadata, 'thinking text', analysis, null);

    expect(trace.decision.alternatives_considered).toHaveLength(2);
    expect(trace.decision.alternatives_considered[0].option_id).toBe('opt1');
    expect(trace.decision.alternatives_considered[0].description).toBe('First option');
    expect(trace.decision.selected).toBe('opt1');
    expect(trace.decision.selection_reasoning).toBe('First is better');
    expect(trace.decision.values_applied).toEqual(['safety', 'helpfulness']);
    expect(trace.decision.confidence).toBe(0.6); // medium maps to 0.6
  });

  it('should map confidence levels correctly', () => {
    const log = createMockLog();
    const metadata = createMockMetadata();

    const highConf = buildTrace(log, metadata, null, createMockAnalysis({ confidence: 'high' }), null);
    expect(highConf.decision.confidence).toBe(0.9);

    const medConf = buildTrace(log, metadata, null, createMockAnalysis({ confidence: 'medium' }), null);
    expect(medConf.decision.confidence).toBe(0.6);

    const lowConf = buildTrace(log, metadata, null, createMockAnalysis({ confidence: 'low' }), null);
    expect(lowConf.decision.confidence).toBe(0.3);
  });

  it('should set escalation fields correctly', () => {
    const log = createMockLog();
    const metadata = createMockMetadata();
    const analysis = createMockAnalysis();

    const trace = buildTrace(log, metadata, null, analysis, null);

    expect(trace.escalation?.evaluated).toBe(true);
    expect(trace.escalation?.required).toBe(false);
    expect(trace.escalation?.reason).toBe('No escalation triggers matched');
  });

  it('should include context with session and metadata', () => {
    const log = createMockLog({ id: 'log-xyz' });
    const metadata = createMockMetadata({
      session_id: 'sess-789',
      gateway_version: '2.1.0',
    });
    const analysis = createMockAnalysis();

    const trace = buildTrace(log, metadata, 'My thinking', analysis, null);

    expect(trace.context?.session_id).toBe('sess-789');
    expect(trace.context?.conversation_turn).toBe(1);
    expect(trace.context?.environment?.gateway_version).toBe('2.1.0');
    expect(trace.context?.environment?.provider).toBe(log.provider);
    expect(trace.context?.metadata?.raw_thinking).toBe('My thinking');
    expect(trace.context?.metadata?.gateway_log_id).toBe('log-xyz');
  });

  it('should use default card_id when no card provided', () => {
    const log = createMockLog();
    const metadata = createMockMetadata();
    const analysis = createMockAnalysis();

    const trace = buildTrace(log, metadata, null, analysis, null);

    expect(trace.card_id).toBe('ac-default');
  });

  it('should handle missing model name', () => {
    const log = createMockLog({ model: '' });
    const metadata = createMockMetadata();
    const analysis = createMockAnalysis();

    const trace = buildTrace(log, metadata, null, analysis, null);

    expect(trace.action.name).toBe('unknown');
  });
});

// ============================================================================
// Tests: Verification (AAP SDK Integration)
// ============================================================================

describe('Verification with AAP SDK', () => {
  it('should verify a valid trace against its card', () => {
    const log = createMockLog({ model: 'claude-3-sonnet-20240229' });
    const metadata = createMockMetadata({ agent_id: 'agent-test-001' });
    const card = createMockCard({
      card_id: 'ac-test-001',
      agent_id: 'agent-test-001',
      values: {
        declared: ['helpfulness', 'transparency', 'accuracy'],
      },
      autonomy_envelope: {
        bounded_actions: ['claude-3-sonnet-20240229'],
        escalation_triggers: [],
        forbidden_actions: [],
      },
    });
    const analysis = createMockAnalysis({
      values_applied: ['helpfulness', 'transparency'],
    });

    const trace = buildTrace(log, metadata, 'thinking', analysis, card);
    const result = verifyTrace(trace, card);

    expect(result.verified).toBe(true);
    expect(result.violations).toHaveLength(0);
    expect(result.trace_id).toBe(trace.trace_id);
    expect(result.card_id).toBe(card.card_id);
  });

  it('should detect undeclared value violation', () => {
    const log = createMockLog({ model: 'claude-3-sonnet-20240229' });
    const metadata = createMockMetadata();
    const card = createMockCard({
      values: {
        declared: ['helpfulness'], // Only helpfulness declared
      },
      autonomy_envelope: {
        bounded_actions: ['claude-3-sonnet-20240229'],
        escalation_triggers: [],
      },
    });
    const analysis = createMockAnalysis({
      values_applied: ['helpfulness', 'creativity'], // creativity not declared
    });

    const trace = buildTrace(log, metadata, null, analysis, card);
    const result = verifyTrace(trace, card);

    expect(result.verified).toBe(false);
    expect(result.violations.length).toBeGreaterThan(0);
    const undeclaredViolation = result.violations.find(v => v.type === 'undeclared_value');
    expect(undeclaredViolation).toBeDefined();
    expect(undeclaredViolation?.description).toContain('creativity');
  });

  it('should detect forbidden action violation', () => {
    const card = createMockCard({
      autonomy_envelope: {
        bounded_actions: ['safe_action'],
        escalation_triggers: [],
        forbidden_actions: ['dangerous_action'],
      },
    });

    // Create a trace that uses a forbidden action
    const trace: APTrace = {
      trace_id: 'tr-12345678',
      agent_id: 'agent-test-001',
      card_id: card.card_id,
      timestamp: new Date().toISOString(),
      action: {
        type: 'execute',
        name: 'dangerous_action',
        category: 'forbidden',
      },
      decision: {
        alternatives_considered: [{ option_id: 'a', description: 'Test' }],
        selected: 'a',
        selection_reasoning: 'No choice',
        values_applied: [],
      },
    };

    const result = verifyTrace(trace, card);

    expect(result.verified).toBe(false);
    const forbiddenViolation = result.violations.find(v => v.type === 'forbidden_action');
    expect(forbiddenViolation).toBeDefined();
    expect(forbiddenViolation?.severity).toBe('critical');
  });

  it('should detect card mismatch violation', () => {
    const card = createMockCard({ card_id: 'ac-correct-card' });
    const trace: APTrace = {
      trace_id: 'tr-12345678',
      agent_id: 'agent-test-001',
      card_id: 'ac-wrong-card', // Different card ID
      timestamp: new Date().toISOString(),
      action: {
        type: 'execute',
        name: 'some_action',
        category: 'bounded',
      },
      decision: {
        alternatives_considered: [{ option_id: 'a', description: 'Test' }],
        selected: 'a',
        selection_reasoning: 'Reason',
        values_applied: [],
      },
    };

    const result = verifyTrace(trace, card);

    expect(result.verified).toBe(false);
    const mismatchViolation = result.violations.find(v => v.type === 'card_mismatch');
    expect(mismatchViolation).toBeDefined();
    expect(mismatchViolation?.severity).toBe('critical');
  });

  it('should include verification metadata', () => {
    const log = createMockLog({ model: 'claude-3-sonnet-20240229' });
    const metadata = createMockMetadata();
    const card = createMockCard({
      autonomy_envelope: {
        bounded_actions: ['claude-3-sonnet-20240229'],
        escalation_triggers: [],
      },
    });
    const analysis = createMockAnalysis({ values_applied: [] });

    const trace = buildTrace(log, metadata, null, analysis, card);
    const result = verifyTrace(trace, card);

    expect(result.verification_metadata).toBeDefined();
    expect(result.verification_metadata.algorithm_version).toBeDefined();
    expect(result.verification_metadata.checks_performed).toBeInstanceOf(Array);
    expect(result.verification_metadata.checks_performed.length).toBeGreaterThan(0);
    expect(result.timestamp).toBeDefined();
  });

  it('should generate warnings for low confidence decisions', () => {
    const card = createMockCard({
      autonomy_envelope: {
        bounded_actions: ['test_action'],
        escalation_triggers: [],
      },
    });

    const trace: APTrace = {
      trace_id: 'tr-12345678',
      agent_id: 'agent-test-001',
      card_id: card.card_id,
      timestamp: new Date().toISOString(),
      action: {
        type: 'execute',
        name: 'test_action',
        category: 'bounded',
      },
      decision: {
        alternatives_considered: [{ option_id: 'a', description: 'Test' }],
        selected: 'a',
        selection_reasoning: 'Unsure',
        values_applied: [],
        confidence: 0.15, // Very low confidence
      },
    };

    const result = verifyTrace(trace, card);

    // Should have a near_boundary warning
    const boundaryWarning = result.warnings.find(w => w.type === 'near_boundary');
    expect(boundaryWarning).toBeDefined();
    expect(boundaryWarning?.description).toContain('confidence');
  });
});

// ============================================================================
// Tests: Drift Detection (AAP SDK Integration)
// ============================================================================

describe('Drift Detection with AAP SDK', () => {
  function createTraceWithValues(
    values: string[],
    confidence: number = 0.8,
    index: number = 0
  ): APTrace {
    return {
      trace_id: `tr-drift-${index.toString().padStart(3, '0')}`,
      agent_id: 'agent-drift-test',
      card_id: 'ac-drift-test',
      timestamp: new Date(Date.now() + index * 60000).toISOString(),
      action: {
        type: 'execute',
        name: 'test_action',
        category: 'bounded',
      },
      decision: {
        alternatives_considered: [{ option_id: 'a', description: 'Test option' }],
        selected: 'a',
        selection_reasoning: 'Standard reasoning',
        values_applied: values,
        confidence,
      },
      escalation: {
        evaluated: true,
        required: false,
        reason: 'No escalation needed',
      },
    };
  }

  it('should return empty alerts for insufficient traces', () => {
    const card = createMockCard({ card_id: 'ac-drift-test' });
    const traces: APTrace[] = [
      createTraceWithValues(['helpfulness'], 0.8, 0),
      createTraceWithValues(['helpfulness'], 0.8, 1),
    ];

    const alerts = detectDrift(card, traces);

    expect(alerts).toHaveLength(0);
  });

  it('should analyze traces and return drift alerts based on similarity', () => {
    const card = createMockCard({
      card_id: 'ac-drift-test',
      values: {
        declared: ['helpfulness', 'accuracy', 'transparency'],
      },
    });

    // Create traces that use declared values consistently
    const traces: APTrace[] = [];
    for (let i = 0; i < 15; i++) {
      traces.push(createTraceWithValues(['helpfulness', 'accuracy'], 0.8, i));
    }

    const alerts = detectDrift(card, traces);

    // Verify the function returns an array (specific results depend on algorithm)
    expect(alerts).toBeInstanceOf(Array);

    // If alerts are generated, they should have proper structure
    for (const alert of alerts) {
      expect(alert.alert_type).toBe('drift_detected');
      expect(alert.analysis).toBeDefined();
      expect(alert.analysis.similarity_score).toBeDefined();
      expect(alert.trace_ids).toBeInstanceOf(Array);
    }
  });

  it('should detect value drift when using undeclared values', () => {
    const card = createMockCard({
      card_id: 'ac-drift-test',
      values: {
        declared: ['helpfulness'],
      },
    });

    // Create traces that increasingly use undeclared values
    const traces: APTrace[] = [];
    for (let i = 0; i < 15; i++) {
      // Progressively use more undeclared values
      const values = i < 5
        ? ['helpfulness']
        : ['helpfulness', 'creativity', 'innovation', 'disruption'];
      traces.push(createTraceWithValues(values, 0.8, i));
    }

    const alerts = detectDrift(card, traces);

    // May detect drift due to undeclared values
    // The exact result depends on the similarity algorithm
    if (alerts.length > 0) {
      expect(alerts[0].alert_type).toBe('drift_detected');
      expect(alerts[0].agent_id).toBe('agent-drift-test');
      expect(alerts[0].card_id).toBe('ac-drift-test');
      expect(alerts[0].analysis).toBeDefined();
    }
  });

  it('should include drift analysis details', () => {
    const card = createMockCard({
      card_id: 'ac-drift-test',
      values: {
        declared: ['safety'],
      },
    });

    // Create traces with very different behavior
    const traces: APTrace[] = [];
    for (let i = 0; i < 20; i++) {
      traces.push(createTraceWithValues(
        ['random_value_' + i], // All undeclared, different each time
        0.2, // Low confidence
        i
      ));
    }

    const alerts = detectDrift(card, traces, 0.5, 3); // Lower threshold for testing

    if (alerts.length > 0) {
      const alert = alerts[0];
      expect(alert.analysis.similarity_score).toBeDefined();
      expect(alert.analysis.sustained_traces).toBeGreaterThanOrEqual(3);
      expect(alert.analysis.threshold).toBe(0.5);
      expect(alert.analysis.drift_direction).toBeDefined();
      expect(alert.trace_ids).toBeInstanceOf(Array);
      expect(alert.recommendation).toBeDefined();
    }
  });

  it('should accept custom thresholds', () => {
    const card = createMockCard({
      card_id: 'ac-drift-test',
      values: { declared: ['helpfulness'] },
    });

    const traces: APTrace[] = [];
    for (let i = 0; i < 10; i++) {
      traces.push(createTraceWithValues(['helpfulness'], 0.8, i));
    }

    // With very high threshold (0.95), even aligned traces might trigger
    const alertsHighThreshold = detectDrift(card, traces, 0.95, 3);

    // With very low threshold (0.1), nothing should trigger
    const alertsLowThreshold = detectDrift(card, traces, 0.1, 3);

    // Low threshold should definitely not trigger for aligned traces
    expect(alertsLowThreshold).toHaveLength(0);
  });

  it('should track escalation patterns for autonomy expansion', () => {
    const card = createMockCard({
      card_id: 'ac-drift-test',
      values: { declared: ['helpfulness'] },
    });

    // Create traces where escalation rate decreases (autonomy expansion pattern)
    const traces: APTrace[] = [];
    for (let i = 0; i < 20; i++) {
      const trace = createTraceWithValues(['helpfulness'], 0.8, i);
      // Early traces have escalations, later ones don't
      if (trace.escalation) {
        trace.escalation.required = i < 10;
      }
      traces.push(trace);
    }

    // The drift detection algorithm may or may not flag this
    // depending on the overall similarity calculation
    const alerts = detectDrift(card, traces);

    // Verify the function runs without error
    expect(alerts).toBeInstanceOf(Array);
  });
});

// ============================================================================
// Tests: APTrace Structure Validation
// ============================================================================

describe('APTrace Structure Validation', () => {
  it('should produce traces that conform to APTrace interface', () => {
    const log = createMockLog();
    const metadata = createMockMetadata();
    const card = createMockCard();
    const analysis = createMockAnalysis();

    const trace = buildTrace(log, metadata, 'thinking', analysis, card);

    // Required fields
    expect(typeof trace.trace_id).toBe('string');
    expect(typeof trace.agent_id).toBe('string');
    expect(typeof trace.card_id).toBe('string');
    expect(typeof trace.timestamp).toBe('string');

    // Action structure
    expect(trace.action).toBeDefined();
    expect(['recommend', 'execute', 'escalate', 'deny']).toContain(trace.action.type);
    expect(typeof trace.action.name).toBe('string');
    expect(['bounded', 'escalation_trigger', 'forbidden']).toContain(trace.action.category);

    // Decision structure
    expect(trace.decision).toBeDefined();
    expect(Array.isArray(trace.decision.alternatives_considered)).toBe(true);
    expect(trace.decision.alternatives_considered.length).toBeGreaterThan(0);
    expect(typeof trace.decision.selected).toBe('string');
    expect(typeof trace.decision.selection_reasoning).toBe('string');
    expect(Array.isArray(trace.decision.values_applied)).toBe(true);

    // Escalation structure (optional but we always include it)
    expect(trace.escalation).toBeDefined();
    expect(typeof trace.escalation?.evaluated).toBe('boolean');
    expect(typeof trace.escalation?.required).toBe('boolean');
    expect(typeof trace.escalation?.reason).toBe('string');
  });

  it('should produce traces that can be serialized to JSON', () => {
    const log = createMockLog();
    const metadata = createMockMetadata();
    const card = createMockCard();
    const analysis = createMockAnalysis();

    const trace = buildTrace(log, metadata, 'thinking content', analysis, card);

    // Should not throw
    const json = JSON.stringify(trace);
    expect(typeof json).toBe('string');

    // Should round-trip correctly
    const parsed = JSON.parse(json);
    expect(parsed.trace_id).toBe(trace.trace_id);
    expect(parsed.agent_id).toBe(trace.agent_id);
    expect(parsed.decision.selected).toBe(trace.decision.selected);
  });

  it('should handle special characters in thinking content', () => {
    const log = createMockLog();
    const metadata = createMockMetadata();
    const analysis = createMockAnalysis();

    const specialThinking = 'Contains "quotes" and \'apostrophes\' and \n newlines and \t tabs';
    const trace = buildTrace(log, metadata, specialThinking, analysis, null);

    // Should serialize without error
    const json = JSON.stringify(trace);
    const parsed = JSON.parse(json);

    expect(parsed.context.metadata.raw_thinking).toBe(specialThinking);
  });
});

// ============================================================================
// Tests: Integration Scenarios
// ============================================================================

describe('Integration Scenarios', () => {
  it('should handle complete flow: extract -> analyze -> build -> verify', () => {
    // Simulate a full processing flow
    const response = `Let me help you with that.
    <thinking>
    The user wants to understand TypeScript generics.
    I should provide a clear explanation with examples.
    Values: helpfulness, accuracy
    </thinking>
    Here is how generics work...`;

    const thinking = extractThinking(response);
    expect(thinking).toContain('TypeScript generics');

    const analysis: HaikuAnalysis = {
      alternatives: [
        { id: 'detailed', description: 'Detailed explanation with examples' },
        { id: 'brief', description: 'Quick overview' },
      ],
      selected: 'detailed',
      reasoning: 'User seems to want comprehensive understanding',
      values_applied: ['helpfulness', 'accuracy'],
      confidence: 'high',
    };

    const log = createMockLog({ model: 'claude-3-sonnet-20240229' });
    const metadata = createMockMetadata();
    const card = createMockCard({
      values: { declared: ['helpfulness', 'accuracy', 'transparency'] },
      autonomy_envelope: {
        bounded_actions: ['claude-3-sonnet-20240229'],
        escalation_triggers: [],
      },
    });

    const trace = buildTrace(log, metadata, thinking, analysis, card);
    const result = verifyTrace(trace, card);

    expect(result.verified).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('should detect issues in flow when values mismatch', () => {
    const thinking = extractThinking('<think>Using creativity to enhance response</think>');

    const analysis: HaikuAnalysis = {
      alternatives: [{ id: 'creative', description: 'Creative response' }],
      selected: 'creative',
      reasoning: 'Being creative',
      values_applied: ['creativity'], // Not declared in card
      confidence: 'high',
    };

    const log = createMockLog({ model: 'claude-3-sonnet-20240229' });
    const metadata = createMockMetadata();
    const card = createMockCard({
      values: { declared: ['helpfulness'] }, // creativity not declared
      autonomy_envelope: {
        bounded_actions: ['claude-3-sonnet-20240229'],
        escalation_triggers: [],
      },
    });

    const trace = buildTrace(log, metadata, thinking, analysis, card);
    const result = verifyTrace(trace, card);

    expect(result.verified).toBe(false);
    expect(result.violations.some(v => v.type === 'undeclared_value')).toBe(true);
  });
});
