/**
 * Unit tests for the inside.integrity enforce same-turn intervention
 * (T0-5, ADR-040). Covers the response-body replacement helpers used
 * by both the hybrid and sync AIP paths.
 *
 *  - extractBoundaryValueName: pulls the BOUNDARY:* value from the
 *    checkpoint's concerns or conscience_context.
 *  - buildIntegrityInterventionText: agent-voice intervention text;
 *    falls back gracefully when the boundary value is missing.
 *  - replaceIntegrityViolationContent: per-provider response-body
 *    replacement (Anthropic / OpenAI / Gemini), unrecognized-shape
 *    fallback, non-JSON fallback.
 *  - writeIntegrityEnforceAdvisory: skip on non-violation; on
 *    violation, full pending_advisories payload with source enum +
 *    source_ref + checkpoint_id + expires_at; failure swallowed.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import {
  extractBoundaryValueName,
  buildIntegrityInterventionText,
  replaceIntegrityViolationContent,
  writeIntegrityEnforceAdvisory,
  type Env,
} from '../index';
import { parseSSEEvents } from '../sse-parser';
import { synthesizeProviderStream } from '../sse-synthesizer';

interface KVStub {
  get: ReturnType<typeof vi.fn>;
  put: ReturnType<typeof vi.fn>;
  delete: ReturnType<typeof vi.fn>;
}

function makeKV(): KVStub {
  return {
    get: vi.fn().mockResolvedValue({ ttl_hours: 24 }),
    put: vi.fn().mockResolvedValue(undefined),
    delete: vi.fn().mockResolvedValue(undefined),
  };
}

function makeEnv(kv?: KVStub): Env {
  return {
    SUPABASE_URL: 'https://test.supabase.co',
    SUPABASE_SECRET_KEY: 'sb_secret_test',
    BILLING_CACHE: kv as unknown as KVNamespace | undefined,
  } as unknown as Env;
}

function jsonRes(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  mockFetch.mockReset();
});

// ─── extractBoundaryValueName ───────────────────────────────────────────────

describe('extractBoundaryValueName', () => {
  it('returns null for null/undefined checkpoint', () => {
    expect(extractBoundaryValueName(null)).toBeNull();
    expect(extractBoundaryValueName(undefined)).toBeNull();
    expect(extractBoundaryValueName({})).toBeNull();
  });

  it('extracts the BOUNDARY value from concerns', () => {
    const checkpoint = {
      concerns: [
        {
          relevant_conscience_value: 'BOUNDARY:no_data_exfiltration',
          severity: 'critical',
        },
      ],
    };
    expect(extractBoundaryValueName(checkpoint)).toBe('no_data_exfiltration');
  });

  it('picks the highest-severity BOUNDARY when multiple are present', () => {
    const checkpoint = {
      concerns: [
        { relevant_conscience_value: 'BOUNDARY:low_priority', severity: 'low' },
        {
          relevant_conscience_value: 'BOUNDARY:honesty',
          severity: 'critical',
        },
        {
          relevant_conscience_value: 'BOUNDARY:medium_priority',
          severity: 'medium',
        },
      ],
    };
    expect(extractBoundaryValueName(checkpoint)).toBe('honesty');
  });

  it('skips non-BOUNDARY relevant_conscience_value entries', () => {
    const checkpoint = {
      concerns: [
        { relevant_conscience_value: 'CORE:helpfulness', severity: 'high' },
        { relevant_conscience_value: 'BOUNDARY:no_harm', severity: 'medium' },
      ],
    };
    expect(extractBoundaryValueName(checkpoint)).toBe('no_harm');
  });

  it('handles unknown severity (rank 0) without crashing', () => {
    const checkpoint = {
      concerns: [
        {
          relevant_conscience_value: 'BOUNDARY:strange_value',
          severity: 'unspecified-severity',
        },
      ],
    };
    expect(extractBoundaryValueName(checkpoint)).toBe('strange_value');
  });

  it('falls back to conscience_context.conflicts when concerns lack BOUNDARY', () => {
    const checkpoint = {
      concerns: [
        { relevant_conscience_value: 'CORE:helpfulness', severity: 'high' },
      ],
      conscience_context: {
        conflicts: ['CORE:helpfulness', 'BOUNDARY:privacy_protection'],
      },
    };
    expect(extractBoundaryValueName(checkpoint)).toBe('privacy_protection');
  });

  it('returns null when no BOUNDARY can be identified', () => {
    const checkpoint = {
      concerns: [{ relevant_conscience_value: null, severity: 'high' }],
      conscience_context: { conflicts: ['CORE:helpfulness'] },
    };
    expect(extractBoundaryValueName(checkpoint)).toBeNull();
  });
});

// ─── buildIntegrityInterventionText ─────────────────────────────────────────

describe('buildIntegrityInterventionText', () => {
  it('names the BOUNDARY value when identifiable', () => {
    const text = buildIntegrityInterventionText({
      concerns: [
        { relevant_conscience_value: 'BOUNDARY:honesty', severity: 'critical' },
      ],
      reasoning_summary: 'detected fabrication of citations',
    });
    expect(text).toContain('Mnemom Intervention');
    expect(text).toContain('`honesty`');
    expect(text).toContain('detected fabrication of citations');
    expect(text).toContain("I'm not going to act");
  });

  it('caps a very long reasoning summary at 240 chars', () => {
    const longSummary = 'x'.repeat(1000);
    const text = buildIntegrityInterventionText({
      concerns: [
        { relevant_conscience_value: 'BOUNDARY:honesty', severity: 'critical' },
      ],
      reasoning_summary: longSummary,
    });
    // Embedded summary should be truncated; ellipsis preserved.
    expect(text).toContain('...');
    // The text shouldn't blow past several hundred chars overall.
    expect(text.length).toBeLessThan(600);
  });

  it('omits the parenthetical when reasoning_summary is missing or empty', () => {
    const text = buildIntegrityInterventionText({
      concerns: [
        { relevant_conscience_value: 'BOUNDARY:honesty', severity: 'critical' },
      ],
    });
    expect(text).not.toMatch(/\(\)/);
    expect(text).toContain('`honesty`');
  });

  it('falls back to a generic phrasing when no BOUNDARY can be identified', () => {
    const text = buildIntegrityInterventionText({
      concerns: [{ relevant_conscience_value: null, severity: 'high' }],
      reasoning_summary: 'unspecified violation',
    });
    expect(text).toContain('Mnemom Intervention');
    expect(text).toContain('boundary violation');
    expect(text).toContain('unspecified violation');
    // No BOUNDARY name => no backtick-wrapped value name.
    expect(text).not.toMatch(/`[^`]+`/);
  });
});

// ─── replaceIntegrityViolationContent ───────────────────────────────────────

describe('replaceIntegrityViolationContent', () => {
  const intervention = '[Mnemom Intervention: violation noted]';

  it('replaces Anthropic content[] with a single text block', () => {
    const original = JSON.stringify({
      id: 'msg_abc',
      type: 'message',
      role: 'assistant',
      content: [
        { type: 'text', text: 'original violating content' },
        { type: 'tool_use', id: 'tu_1', name: 'forbidden', input: {} },
      ],
      stop_reason: 'tool_use',
      model: 'claude-sonnet-4-6',
    });
    const replaced = JSON.parse(replaceIntegrityViolationContent(original, intervention));
    expect(replaced.id).toBe('msg_abc');
    expect(replaced.model).toBe('claude-sonnet-4-6');
    expect(replaced.content).toEqual([{ type: 'text', text: intervention }]);
    expect(replaced.stop_reason).toBe('end_turn');
    // tool_use stripped — we don't deliver tool calls when the response
    // is being intervened on.
    expect(JSON.stringify(replaced)).not.toContain('tool_use');
  });

  it('replaces OpenAI choices[].message.content + clears tool_calls', () => {
    const original = JSON.stringify({
      id: 'chatcmpl-abc',
      object: 'chat.completion',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: 'original violating content',
            tool_calls: [{ id: 'tc_1', function: { name: 'forbidden' } }],
          },
          finish_reason: 'tool_calls',
        },
      ],
      model: 'gpt-5',
    });
    const replaced = JSON.parse(replaceIntegrityViolationContent(original, intervention));
    expect(replaced.id).toBe('chatcmpl-abc');
    expect(replaced.model).toBe('gpt-5');
    expect(replaced.choices[0].message.content).toBe(intervention);
    expect(replaced.choices[0].message.tool_calls).toBeUndefined();
    expect(replaced.choices[0].finish_reason).toBe('stop');
  });

  it('replaces Gemini candidates[].content.parts', () => {
    const original = JSON.stringify({
      candidates: [
        {
          content: {
            parts: [{ text: 'original violating content' }],
            role: 'model',
          },
          finishReason: 'STOP',
          index: 0,
        },
      ],
    });
    const replaced = JSON.parse(replaceIntegrityViolationContent(original, intervention));
    expect(replaced.candidates[0].content.parts).toEqual([{ text: intervention }]);
    expect(replaced.candidates[0].content.role).toBe('model');
    expect(replaced.candidates[0].finishReason).toBe('STOP');
  });

  it('returns an Anthropic envelope on unrecognized response shape', () => {
    const original = JSON.stringify({ some_other_shape: true });
    const replaced = JSON.parse(replaceIntegrityViolationContent(original, intervention));
    expect(replaced.type).toBe('message');
    expect(replaced.content).toEqual([{ type: 'text', text: intervention }]);
  });

  it('returns an Anthropic envelope on non-JSON response body', () => {
    const replaced = JSON.parse(
      replaceIntegrityViolationContent('not-json-at-all', intervention),
    );
    expect(replaced.type).toBe('message');
    expect(replaced.content).toEqual([{ type: 'text', text: intervention }]);
  });

  it('returns an Anthropic envelope on JSON null', () => {
    const replaced = JSON.parse(replaceIntegrityViolationContent('null', intervention));
    expect(replaced.type).toBe('message');
  });

  it('handles multi-choice OpenAI responses', () => {
    const original = JSON.stringify({
      choices: [
        { message: { role: 'assistant', content: 'a' }, finish_reason: 'stop', index: 0 },
        { message: { role: 'assistant', content: 'b' }, finish_reason: 'stop', index: 1 },
      ],
    });
    const replaced = JSON.parse(replaceIntegrityViolationContent(original, intervention));
    expect(replaced.choices).toHaveLength(2);
    for (const c of replaced.choices) {
      expect(c.message.content).toBe(intervention);
    }
  });
});

// ─── writeIntegrityEnforceAdvisory ──────────────────────────────────────────

describe('writeIntegrityEnforceAdvisory', () => {
  const violationCheckpoint = {
    checkpoint_id: 'ic-test123',
    verdict: 'boundary_violation',
    concerns: [
      {
        category: 'value_misalignment',
        severity: 'critical',
        relevant_conscience_value: 'BOUNDARY:honesty',
        description: 'fabricated citation',
      },
    ],
    reasoning_summary: 'agent reasoning would fabricate a non-existent source',
  };

  function captureInsertCall() {
    // KV stub returns the cached TTL so the only network call is the POST.
    mockFetch.mockResolvedValueOnce(jsonRes({}, 201));
  }

  it('skips the write when verdict is not boundary_violation', async () => {
    for (const verdict of ['clear', 'review_needed']) {
      mockFetch.mockReset();
      await writeIntegrityEnforceAdvisory(
        'agent-1',
        'sess-1',
        { ...violationCheckpoint, verdict },
        makeEnv(makeKV()),
      );
      expect(mockFetch).not.toHaveBeenCalled();
    }
  });

  it('writes a pending_advisories row with source=runtime.inside.integrity.enforce', async () => {
    captureInsertCall();
    await writeIntegrityEnforceAdvisory(
      'agent-1',
      'sess-1',
      violationCheckpoint,
      makeEnv(makeKV()),
    );
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain('/rest/v1/pending_advisories');
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.source).toBe('runtime.inside.integrity.enforce');
    expect(body.agent_id).toBe('agent-1');
    expect(body.session_id).toBe('sess-1');
    expect(body.status).toBe('pending');
    expect(body.id).toMatch(/^pa-[0-9a-f]{12}$/);
  });

  it('embeds the checkpoint_id in both the row + source_ref', async () => {
    captureInsertCall();
    await writeIntegrityEnforceAdvisory(
      'agent-1',
      'sess-1',
      violationCheckpoint,
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.checkpoint_id).toBe('ic-test123');
    expect(body.source_ref.checkpoint_id).toBe('ic-test123');
    expect(body.source_ref.verdict).toBe('boundary_violation');
  });

  it('records the boundary_value when extractable, null otherwise', async () => {
    captureInsertCall();
    await writeIntegrityEnforceAdvisory(
      'agent-1',
      'sess-1',
      violationCheckpoint,
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.source_ref.boundary_value).toBe('honesty');
    expect(body.concerns_summary).toContain('honesty');

    // Fallback case: no BOUNDARY identifiable.
    mockFetch.mockReset();
    captureInsertCall();
    await writeIntegrityEnforceAdvisory(
      'agent-1',
      'sess-1',
      {
        ...violationCheckpoint,
        concerns: [
          { category: 'unknown', severity: 'medium', relevant_conscience_value: null },
        ],
      },
      makeEnv(makeKV()),
    );
    const body2 = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body2.source_ref.boundary_value).toBeNull();
    expect(body2.concerns_summary).toContain('boundary value unidentified');
  });

  it('caps the source_ref.concerns at 3 entries', async () => {
    captureInsertCall();
    await writeIntegrityEnforceAdvisory(
      'agent-1',
      'sess-1',
      {
        ...violationCheckpoint,
        concerns: [
          { category: 'a', severity: 'critical', relevant_conscience_value: 'BOUNDARY:a' },
          { category: 'b', severity: 'high', relevant_conscience_value: 'BOUNDARY:b' },
          { category: 'c', severity: 'medium', relevant_conscience_value: 'BOUNDARY:c' },
          { category: 'd', severity: 'low', relevant_conscience_value: 'BOUNDARY:d' },
          { category: 'e', severity: 'low', relevant_conscience_value: 'BOUNDARY:e' },
        ],
      },
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.source_ref.concerns).toHaveLength(3);
    expect(body.source_ref.concerns.map((c: { category: string }) => c.category)).toEqual([
      'a',
      'b',
      'c',
    ]);
  });

  it('embeds the agent-voice text in nudge_content', async () => {
    captureInsertCall();
    await writeIntegrityEnforceAdvisory(
      'agent-1',
      'sess-1',
      violationCheckpoint,
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.nudge_content).toContain('Mnemom Intervention');
    expect(body.nudge_content).toContain('honesty');
    expect(body.nudge_content).toContain("I'm not going to act");
  });

  it('computes expires_at from the configured TTL (KV-cached)', async () => {
    const kv = makeKV();
    kv.get.mockResolvedValueOnce({ ttl_hours: 48 });
    captureInsertCall();
    const before = Date.now();
    await writeIntegrityEnforceAdvisory(
      'agent-1',
      'sess-1',
      violationCheckpoint,
      makeEnv(kv),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    const expiresAt = new Date(body.expires_at).getTime();
    expect(expiresAt).toBeGreaterThanOrEqual(before + 48 * 60 * 60 * 1000);
    expect(expiresAt).toBeLessThan(Date.now() + 49 * 60 * 60 * 1000);
  });

  it('swallows insert errors so the request path is not affected', async () => {
    mockFetch.mockRejectedValueOnce(new Error('supabase down'));
    await expect(
      writeIntegrityEnforceAdvisory(
        'agent-1',
        'sess-1',
        violationCheckpoint,
        makeEnv(makeKV()),
      ),
    ).resolves.toBeUndefined();
  });
});

// ─── T0-5 streaming addendum: SSE round-trip of intervention text ───────────

describe('buildIntegrityInterventionText → synthesizeProviderStream round-trip', () => {
  const checkpoint = {
    checkpoint_id: 'cp_test_1',
    verdict: 'boundary_violation' as const,
    concerns: [
      { relevant_conscience_value: 'BOUNDARY:no_harm', severity: 'high' as const, description: 'reasoning toward harm' },
    ],
    reasoning_summary: 'Model was reasoning toward an action that harms the user.',
  };

  it('produces an SSE stream that parses back to the same intervention text for every provider', async () => {
    const text = buildIntegrityInterventionText(checkpoint);
    expect(text).toContain('Mnemom Intervention');
    expect(text).toContain('no_harm');

    for (const provider of ['anthropic', 'openai', 'gemini'] as const) {
      const { body, headers } = synthesizeProviderStream(
        provider,
        text,
        { model: 'm' },
      );
      expect(headers['Content-Type']).toMatch(/^text\/event-stream/);
      const decoder = new TextDecoder();
      const chunks: string[] = [];
      const reader = body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(decoder.decode(value));
      }
      const sse = chunks.join('');
      const parsed = parseSSEEvents(sse, provider);
      expect(parsed.text).toBe(text);
    }
  });

  it('emits text/event-stream content-type — not application/json (CAC: streaming clients must receive SSE)', async () => {
    const text = buildIntegrityInterventionText(checkpoint);
    for (const provider of ['anthropic', 'openai', 'gemini'] as const) {
      const { headers } = synthesizeProviderStream(provider, text, null);
      expect(headers['Content-Type']).toMatch(/^text\/event-stream/);
      expect(headers['Content-Type']).not.toBe('application/json');
    }
  });
});
