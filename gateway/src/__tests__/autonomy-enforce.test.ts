/**
 * Unit tests for the inside.autonomy enforce same-turn intervention
 * (T0-4, ADR-040). Covers:
 *
 *  - buildAutonomyEnforceResponse: per-provider response shape, text
 *    content names violations + rule_id, model echo, content-type.
 *  - writeAutonomyEnforceAdvisory: skip on non-fail verdict; on fail,
 *    full pending_advisories payload with source enum + source_ref +
 *    expires_at; failure-swallowed.
 *
 * The full request-path 403→200 swap is exercised via the existing
 * worker.fetch suite once the integration test is added; this file
 * focuses on the helper contracts that drive correctness.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import {
  buildAutonomyEnforceResponse,
  buildAutonomyInterventionText,
  writeAutonomyEnforceAdvisory,
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

function makeEvalResult(
  overrides: Partial<{
    verdict: string;
    violations: Array<{
      tool_name?: string;
      type?: string;
      reason?: string;
      rule_id?: string;
      severity?: string;
    }>;
  }> = {},
) {
  return {
    verdict: 'fail',
    violations: [
      {
        tool_name: 'delete_data',
        type: 'forbidden_tool',
        reason: 'destructive operation not permitted',
        rule_id: 'rule_no_destructive',
        severity: 'critical',
      },
    ],
    ...overrides,
  };
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

// ─── buildAutonomyEnforceResponse ───────────────────────────────────────────

describe('buildAutonomyEnforceResponse', () => {
  describe('Anthropic', () => {
    it('returns the Messages API non-stream shape with intervention text', () => {
      const evalResult = makeEvalResult();
      const { body, contentType } = buildAutonomyEnforceResponse(
        'anthropic',
        evalResult,
        { model: 'claude-sonnet-4-6' },
      );
      expect(contentType).toBe('application/json');
      const parsed = JSON.parse(body);
      expect(parsed.type).toBe('message');
      expect(parsed.role).toBe('assistant');
      expect(parsed.id).toMatch(/^msg_mn-[0-9a-f]{16}$/);
      expect(parsed.model).toBe('claude-sonnet-4-6');
      expect(parsed.stop_reason).toBe('end_turn');
      expect(Array.isArray(parsed.content)).toBe(true);
      expect(parsed.content[0].type).toBe('text');
      expect(parsed.content[0].text).toContain('Mnemom Intervention');
      expect(parsed.content[0].text).toContain('delete_data');
      expect(parsed.content[0].text).toContain('rule_no_destructive');
      expect(parsed.content[0].text).toContain('destructive operation not permitted');
    });

    it('falls back to "unknown" model when the request omits it', () => {
      const { body } = buildAutonomyEnforceResponse(
        'anthropic',
        makeEvalResult(),
        null,
      );
      expect(JSON.parse(body).model).toBe('unknown');
    });
  });

  describe('OpenAI', () => {
    it('returns the Chat Completions shape with assistant content', () => {
      const evalResult = makeEvalResult();
      const { body, contentType } = buildAutonomyEnforceResponse(
        'openai',
        evalResult,
        { model: 'gpt-5' },
      );
      expect(contentType).toBe('application/json');
      const parsed = JSON.parse(body);
      expect(parsed.object).toBe('chat.completion');
      expect(parsed.id).toMatch(/^chatcmpl-mn-[0-9a-f]{16}$/);
      expect(parsed.model).toBe('gpt-5');
      expect(parsed.choices[0].message.role).toBe('assistant');
      expect(parsed.choices[0].finish_reason).toBe('stop');
      expect(parsed.choices[0].message.content).toContain('Mnemom Intervention');
      expect(parsed.choices[0].message.content).toContain('delete_data');
      expect(typeof parsed.created).toBe('number');
    });
  });

  describe('Gemini', () => {
    it('returns the generateContent shape with model role', () => {
      const evalResult = makeEvalResult();
      const { body, contentType } = buildAutonomyEnforceResponse(
        'gemini',
        evalResult,
        { model: 'gemini-2.5-pro' },
      );
      expect(contentType).toBe('application/json');
      const parsed = JSON.parse(body);
      expect(parsed.candidates[0].content.role).toBe('model');
      expect(parsed.candidates[0].finishReason).toBe('STOP');
      expect(parsed.candidates[0].content.parts[0].text).toContain(
        'Mnemom Intervention',
      );
      expect(parsed.candidates[0].content.parts[0].text).toContain('delete_data');
    });
  });

  describe('text composition', () => {
    it('lists multiple violations with rule_ids', () => {
      const evalResult = makeEvalResult({
        violations: [
          { tool_name: 'delete_data', reason: 'destructive', rule_id: 'r1' },
          { tool_name: 'send_email', reason: 'unauthorized', rule_id: 'r2' },
        ],
      });
      const { body } = buildAutonomyEnforceResponse(
        'anthropic',
        evalResult,
        null,
      );
      const text = JSON.parse(body).content[0].text;
      expect(text).toContain('delete_data');
      expect(text).toContain('send_email');
      expect(text).toContain('r1');
      expect(text).toContain('r2');
    });

    it('caps the violation list at 3 entries', () => {
      const evalResult = makeEvalResult({
        violations: [
          { tool_name: 'a', reason: 'x' },
          { tool_name: 'b', reason: 'x' },
          { tool_name: 'c', reason: 'x' },
          { tool_name: 'd', reason: 'x' },
          { tool_name: 'e', reason: 'x' },
        ],
      });
      const { body } = buildAutonomyEnforceResponse(
        'openai',
        evalResult,
        null,
      );
      const content = JSON.parse(body).choices[0].message.content;
      expect(content).toContain('`a`');
      expect(content).toContain('`b`');
      expect(content).toContain('`c`');
      expect(content).not.toContain('`d`');
      expect(content).not.toContain('`e`');
    });

    it('handles a violation without rule_id or reason', () => {
      const evalResult = makeEvalResult({
        violations: [{ tool_name: 'mystery_tool', type: 'forbidden_tool' }],
      });
      const { body } = buildAutonomyEnforceResponse('anthropic', evalResult, null);
      const text = JSON.parse(body).content[0].text;
      expect(text).toContain('mystery_tool');
      expect(text).toContain('forbidden_tool');
      expect(text).not.toContain('(rule:');
    });

    it('uses singular "tool" copy for one violation, plural for many', () => {
      const single = JSON.parse(
        buildAutonomyEnforceResponse(
          'anthropic',
          makeEvalResult({ violations: [{ tool_name: 'a', reason: 'x' }] }),
          null,
        ).body,
      ).content[0].text;
      expect(single).toMatch(/the following tool:/);

      const many = JSON.parse(
        buildAutonomyEnforceResponse(
          'anthropic',
          makeEvalResult({
            violations: [
              { tool_name: 'a', reason: 'x' },
              { tool_name: 'b', reason: 'x' },
            ],
          }),
          null,
        ).body,
      ).content[0].text;
      expect(many).toMatch(/the following tools:/);
    });
  });
});

// ─── writeAutonomyEnforceAdvisory ───────────────────────────────────────────

describe('writeAutonomyEnforceAdvisory', () => {
  function captureInsertCall() {
    // Sequence: TTL fetch (cached so no fetch) → advisory POST.
    // KV stub returns { ttl_hours: 24 } from get(), so first network call
    // is the POST.
    mockFetch.mockResolvedValueOnce(jsonRes({}, 201));
  }

  it('skips the write when verdict is not fail', async () => {
    for (const verdict of ['pass', 'warn']) {
      mockFetch.mockReset();
      await writeAutonomyEnforceAdvisory(
        'agent-1',
        'sess-1',
        makeEvalResult({ verdict }),
        makeEnv(makeKV()),
      );
      expect(mockFetch).not.toHaveBeenCalled();
    }
  });

  it('writes a pending_advisories row with source=runtime.inside.autonomy.enforce', async () => {
    captureInsertCall();
    await writeAutonomyEnforceAdvisory(
      'agent-1',
      'sess-1',
      makeEvalResult(),
      makeEnv(makeKV()),
    );
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain('/rest/v1/pending_advisories');
    const init2 = init as RequestInit;
    expect(init2.method).toBe('POST');
    const body = JSON.parse(init2.body as string);
    expect(body.source).toBe('runtime.inside.autonomy.enforce');
    expect(body.agent_id).toBe('agent-1');
    expect(body.session_id).toBe('sess-1');
    expect(body.status).toBe('pending');
    expect(body.id).toMatch(/^pa-[0-9a-f]{12}$/);
    expect(body.checkpoint_id).toBeUndefined();
  });

  it('captures violations in source_ref (capped at 3)', async () => {
    captureInsertCall();
    await writeAutonomyEnforceAdvisory(
      'agent-1',
      'sess-1',
      makeEvalResult({
        violations: [
          { tool_name: 'a', type: 'forbidden_tool', rule_id: 'r1', severity: 'critical' },
          { tool_name: 'b', type: 'forbidden_tool', rule_id: 'r2', severity: 'high' },
          { tool_name: 'c', type: 'forbidden_tool', rule_id: 'r3', severity: 'high' },
          { tool_name: 'd', type: 'forbidden_tool', rule_id: 'r4', severity: 'low' },
        ],
      }),
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.source_ref.violations).toHaveLength(3);
    expect(body.source_ref.violations.map((v: { tool_name: string }) => v.tool_name)).toEqual(['a', 'b', 'c']);
    expect(body.source_ref.verdict).toBe('fail');
  });

  it('embeds the agent-facing text in nudge_content + summary', async () => {
    captureInsertCall();
    await writeAutonomyEnforceAdvisory(
      'agent-1',
      'sess-1',
      makeEvalResult({
        violations: [
          { tool_name: 'delete_data', reason: 'destructive', rule_id: 'r1' },
        ],
      }),
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.nudge_content).toContain('Mnemom advisory');
    expect(body.nudge_content).toContain('delete_data');
    expect(body.nudge_content).toContain('destructive');
    expect(body.concerns_summary).toContain('Inside.autonomy refused');
    expect(body.concerns_summary).toContain('delete_data');
  });

  it('computes expires_at from the configured TTL (KV-cached)', async () => {
    const kv = makeKV();
    kv.get.mockResolvedValueOnce({ ttl_hours: 72 });
    captureInsertCall();
    const before = Date.now();
    await writeAutonomyEnforceAdvisory(
      'agent-1',
      'sess-1',
      makeEvalResult(),
      makeEnv(kv),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    const expiresAt = new Date(body.expires_at).getTime();
    expect(expiresAt).toBeGreaterThanOrEqual(before + 72 * 60 * 60 * 1000);
    expect(expiresAt).toBeLessThan(Date.now() + 73 * 60 * 60 * 1000);
  });

  it('swallows insert errors so the request path is not affected', async () => {
    mockFetch.mockRejectedValueOnce(new Error('supabase down'));
    await expect(
      writeAutonomyEnforceAdvisory(
        'agent-1',
        'sess-1',
        makeEvalResult(),
        makeEnv(makeKV()),
      ),
    ).resolves.toBeUndefined();
  });

  it('handles empty violations array gracefully', async () => {
    captureInsertCall();
    await writeAutonomyEnforceAdvisory(
      'agent-1',
      'sess-1',
      { verdict: 'fail', violations: [] },
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.nudge_content).toContain('unspecified');
    expect(body.source_ref.violations).toEqual([]);
  });
});

// ─── buildAutonomyInterventionText (T0-4 streaming addendum) ────────────────

describe('buildAutonomyInterventionText', () => {
  it('returns the same text the buffered builder embeds in its body', () => {
    const evalResult = makeEvalResult();
    const text = buildAutonomyInterventionText(evalResult);
    const buffered = JSON.parse(
      buildAutonomyEnforceResponse('anthropic', evalResult, null).body,
    );
    expect(text).toBe(buffered.content[0].text);
  });

  it('feeds synthesizeProviderStream so the SSE round-trips with the same text', async () => {
    for (const provider of ['anthropic', 'openai', 'gemini'] as const) {
      const evalResult = makeEvalResult();
      const text = buildAutonomyInterventionText(evalResult);
      const { body } = synthesizeProviderStream(provider, text, { model: 'm' });
      const decoder = new TextDecoder();
      const chunks: string[] = [];
      const reader = body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(decoder.decode(value));
      }
      const parsed = parseSSEEvents(chunks.join(''), provider);
      expect(parsed.text).toBe(text);
    }
  });
});
