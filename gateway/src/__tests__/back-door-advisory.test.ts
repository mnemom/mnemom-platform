/**
 * Unit tests for the back-door redaction + advisory writer (T0-6,
 * ADR-040). Covers:
 *
 *  - applyBackDoorRedaction: per-provider response-body walk +
 *    redaction; non-JSON fallback; unrecognized-shape no-op; aggregated
 *    matches across multiple text segments.
 *  - writeBackDoorAdvisory: skip when no matches, skip on observe mode,
 *    fires on nudge + enforce, payload shape + counts + threat types,
 *    expires_at arithmetic, error swallowed.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import {
  applyBackDoorRedaction,
  writeBackDoorAdvisory,
  type Env,
} from '../index';
import type { DLPMatch } from '@mnemom/safe-house';

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

// ─── applyBackDoorRedaction ─────────────────────────────────────────────────

describe('applyBackDoorRedaction', () => {
  it('redacts an email inside an Anthropic content[] text block', () => {
    // Note: scanDLP filters obvious placeholder domains
    // (example.com, test@*, @localhost) so the test uses a domain
    // that the production detector would actually flag.
    const original = JSON.stringify({
      id: 'msg_abc',
      type: 'message',
      role: 'assistant',
      content: [
        { type: 'text', text: 'Reach out to alice@acme-corp.io for details.' },
      ],
      stop_reason: 'end_turn',
    });
    const result = applyBackDoorRedaction(original);
    expect(result.modified).toBe(true);
    expect(result.matches.length).toBeGreaterThan(0);
    const parsed = JSON.parse(result.body);
    expect(parsed.id).toBe('msg_abc'); // shape preserved
    expect(parsed.content[0].text).toContain('[EMAIL REDACTED]');
    expect(parsed.content[0].text).not.toContain('alice@acme-corp.io');
  });

  it('leaves clean Anthropic responses untouched (modified=false)', () => {
    const original = JSON.stringify({
      type: 'message',
      content: [{ type: 'text', text: 'Just a benign answer.' }],
    });
    const result = applyBackDoorRedaction(original);
    expect(result.modified).toBe(false);
    expect(result.matches).toEqual([]);
    expect(result.body).toBe(original);
  });

  it('redacts only text blocks, leaves tool_use blocks untouched', () => {
    const original = JSON.stringify({
      type: 'message',
      content: [
        { type: 'text', text: 'My email is bob@corp.io' },
        { type: 'tool_use', id: 'tu_1', name: 'search', input: { q: 'x' } },
      ],
    });
    const result = applyBackDoorRedaction(original);
    expect(result.modified).toBe(true);
    const parsed = JSON.parse(result.body);
    expect(parsed.content[0].text).toContain('[EMAIL REDACTED]');
    expect(parsed.content[1]).toEqual({
      type: 'tool_use',
      id: 'tu_1',
      name: 'search',
      input: { q: 'x' },
    });
  });

  it('redacts OpenAI choices[].message.content', () => {
    const original = JSON.stringify({
      id: 'chatcmpl-abc',
      object: 'chat.completion',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: 'My SSN is 123-45-6789, dont share',
          },
          finish_reason: 'stop',
        },
      ],
    });
    const result = applyBackDoorRedaction(original);
    expect(result.modified).toBe(true);
    const parsed = JSON.parse(result.body);
    expect(parsed.choices[0].message.content).toContain('[SSN REDACTED]');
    expect(parsed.choices[0].message.content).not.toContain('123-45-6789');
    expect(parsed.choices[0].finish_reason).toBe('stop'); // preserved
  });

  it('redacts Gemini candidates[].content.parts[].text', () => {
    const original = JSON.stringify({
      candidates: [
        {
          content: {
            parts: [
              { text: 'Card: 4111111111111111 here' },
              { text: 'Plus an email: foo@bar.com' },
            ],
            role: 'model',
          },
          finishReason: 'STOP',
        },
      ],
    });
    const result = applyBackDoorRedaction(original);
    expect(result.modified).toBe(true);
    const parsed = JSON.parse(result.body);
    expect(parsed.candidates[0].content.parts[0].text).toContain('[CARD REDACTED]');
    expect(parsed.candidates[0].content.parts[1].text).toContain('[EMAIL REDACTED]');
    expect(parsed.candidates[0].content.role).toBe('model');
  });

  it('aggregates matches across multiple text segments', () => {
    const original = JSON.stringify({
      content: [
        { type: 'text', text: 'Email: a@x.com' },
        { type: 'text', text: 'Phone: 555-123-4567' },
      ],
    });
    const result = applyBackDoorRedaction(original);
    expect(result.modified).toBe(true);
    const types = new Set(result.matches.map((m) => m.type));
    expect(types.has('email')).toBe(true);
    expect(types.has('phone')).toBe(true);
  });

  it('falls back to raw-text redaction on non-JSON body', () => {
    const original = 'plain text with email a@b.com inline';
    const result = applyBackDoorRedaction(original);
    expect(result.modified).toBe(true);
    expect(result.body).toContain('[EMAIL REDACTED]');
  });

  it('returns no-op for unrecognized JSON shape', () => {
    const original = JSON.stringify({ some_other_envelope: { foo: 1 } });
    const result = applyBackDoorRedaction(original);
    expect(result.modified).toBe(false);
    expect(result.matches).toEqual([]);
    expect(result.body).toBe(original);
  });

  it('returns no-op for null JSON', () => {
    const result = applyBackDoorRedaction('null');
    expect(result.modified).toBe(false);
  });
});

// ─── writeBackDoorAdvisory ──────────────────────────────────────────────────

function makeMatch(type: DLPMatch['type'], offset = 0): DLPMatch {
  return { type, value_masked: '****', offset };
}

describe('writeBackDoorAdvisory', () => {
  function captureInsertCall() {
    mockFetch.mockResolvedValueOnce(jsonRes({}, 201));
  }

  it('skips entirely when there are no matches', async () => {
    await writeBackDoorAdvisory(
      'agent-1',
      'sess-1',
      { matches: [], mode: 'enforce' },
      makeEnv(makeKV()),
    );
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('skips on observe and off (no advisory under detection-only modes)', async () => {
    for (const mode of ['observe', 'off']) {
      mockFetch.mockReset();
      await writeBackDoorAdvisory(
        'agent-1',
        'sess-1',
        { matches: [makeMatch('email')], mode },
        makeEnv(makeKV()),
      );
      expect(mockFetch).not.toHaveBeenCalled();
    }
  });

  it('writes a pending_advisories row with source=runtime.back_door.modification on nudge', async () => {
    captureInsertCall();
    await writeBackDoorAdvisory(
      'agent-1',
      'sess-1',
      { matches: [makeMatch('email')], mode: 'nudge' },
      makeEnv(makeKV()),
    );
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain('/rest/v1/pending_advisories');
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.source).toBe('runtime.back_door.modification');
    expect(body.agent_id).toBe('agent-1');
    expect(body.session_id).toBe('sess-1');
    expect(body.status).toBe('pending');
    expect(body.id).toMatch(/^pa-[0-9a-f]{12}$/);
    // Back door has no integrity checkpoint to reference.
    expect(body.checkpoint_id).toBeUndefined();
  });

  it('also fires on enforce', async () => {
    captureInsertCall();
    await writeBackDoorAdvisory(
      'agent-1',
      'sess-1',
      { matches: [makeMatch('email')], mode: 'enforce' },
      makeEnv(makeKV()),
    );
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('aggregates threat_types + counts in source_ref', async () => {
    captureInsertCall();
    await writeBackDoorAdvisory(
      'agent-1',
      'sess-1',
      {
        matches: [
          makeMatch('email', 0),
          makeMatch('email', 50),
          makeMatch('phone', 100),
          makeMatch('ssn', 200),
        ],
        mode: 'enforce',
      },
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.source_ref.mode).toBe('enforce');
    expect(body.source_ref.modification_count).toBe(4);
    expect(new Set(body.source_ref.threat_types)).toEqual(
      new Set(['email', 'phone', 'ssn']),
    );
    expect(body.source_ref.counts).toEqual({ email: 2, phone: 1, ssn: 1 });
  });

  it('embeds the agent-facing text in nudge_content + summary', async () => {
    captureInsertCall();
    await writeBackDoorAdvisory(
      'agent-1',
      'sess-1',
      {
        matches: [makeMatch('email'), makeMatch('phone')],
        mode: 'nudge',
      },
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.nudge_content).toContain('Mnemom advisory');
    expect(body.nudge_content).toContain('redacted 2');
    expect(body.nudge_content).toContain('email');
    expect(body.nudge_content).toContain('phone');
    expect(body.nudge_content).toContain("don't reference");
    expect(body.concerns_summary).toContain('Back-door redacted 2');
  });

  it('uses singular vs plural copy correctly', async () => {
    captureInsertCall();
    await writeBackDoorAdvisory(
      'agent-1',
      'sess-1',
      { matches: [makeMatch('email')], mode: 'nudge' },
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.nudge_content).toMatch(/redacted 1 sensitive item /);
    expect(body.concerns_summary).toMatch(/redacted 1 item /);
  });

  it('computes expires_at from the configured TTL (KV-cached)', async () => {
    const kv = makeKV();
    kv.get.mockResolvedValueOnce({ ttl_hours: 12 });
    captureInsertCall();
    const before = Date.now();
    await writeBackDoorAdvisory(
      'agent-1',
      'sess-1',
      { matches: [makeMatch('email')], mode: 'enforce' },
      makeEnv(kv),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    const expiresAt = new Date(body.expires_at).getTime();
    expect(expiresAt).toBeGreaterThanOrEqual(before + 12 * 60 * 60 * 1000);
    expect(expiresAt).toBeLessThan(Date.now() + 13 * 60 * 60 * 1000);
  });

  it('swallows insert errors so the request path is not affected', async () => {
    mockFetch.mockRejectedValueOnce(new Error('supabase down'));
    await expect(
      writeBackDoorAdvisory(
        'agent-1',
        'sess-1',
        { matches: [makeMatch('email')], mode: 'enforce' },
        makeEnv(makeKV()),
      ),
    ).resolves.toBeUndefined();
  });
});
