/**
 * Unit tests for writeIntegrityNudgeAdvisory (T0-11, ADR-040).
 *
 * The nudge-mode counterpart to T0-5's writeIntegrityEnforceAdvisory.
 * Same payload shape; differs in:
 *   - source = 'runtime.inside.integrity.nudge' (vs '.enforce')
 *   - agent-voice text framing ("noticed" vs "intervened")
 *   - text says "Review my approach and self-correct" rather than
 *     "I'm not going to act on that"
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import { writeIntegrityNudgeAdvisory, type Env } from '../index';

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

const violationCheckpoint = {
  checkpoint_id: 'ic-nudge1',
  verdict: 'boundary_violation',
  concerns: [
    {
      category: 'value_misalignment',
      severity: 'medium',
      relevant_conscience_value: 'BOUNDARY:privacy',
      description: 'considered sharing user PII',
    },
  ],
  reasoning_summary: 'agent reasoning leaned toward sharing user PII',
};

beforeEach(() => {
  mockFetch.mockReset();
});

describe('writeIntegrityNudgeAdvisory', () => {
  function captureInsertCall() {
    mockFetch.mockResolvedValueOnce(jsonRes({}, 201));
  }

  it('skips when verdict is not boundary_violation', async () => {
    for (const verdict of ['clear', 'review_needed']) {
      mockFetch.mockReset();
      await writeIntegrityNudgeAdvisory(
        'agent-1',
        'sess-1',
        { ...violationCheckpoint, verdict },
        makeEnv(makeKV()),
      );
      expect(mockFetch).not.toHaveBeenCalled();
    }
  });

  it('writes a pending_advisories row with source=runtime.inside.integrity.nudge', async () => {
    captureInsertCall();
    await writeIntegrityNudgeAdvisory(
      'agent-1',
      'sess-1',
      violationCheckpoint,
      makeEnv(makeKV()),
    );
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain('/rest/v1/pending_advisories');
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.source).toBe('runtime.inside.integrity.nudge');
    expect(body.agent_id).toBe('agent-1');
    expect(body.session_id).toBe('sess-1');
    expect(body.status).toBe('pending');
    expect(body.id).toMatch(/^pa-[0-9a-f]{12}$/);
  });

  it('uses nudge-style framing (not enforce) in nudge_content', async () => {
    captureInsertCall();
    await writeIntegrityNudgeAdvisory(
      'agent-1',
      'sess-1',
      violationCheckpoint,
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.nudge_content).toContain('Mnemom advisory');
    expect(body.nudge_content).toContain('privacy');
    expect(body.nudge_content).toContain('Review my approach');
    expect(body.nudge_content).toContain('self-correct');
    // Critical: should NOT use the enforce-mode "I'm not going to act on that" framing
    expect(body.nudge_content).not.toContain("I'm not going to act");
    expect(body.nudge_content).not.toContain('original response was prevented');
  });

  it('embeds the checkpoint_id in row + source_ref', async () => {
    captureInsertCall();
    await writeIntegrityNudgeAdvisory(
      'agent-1',
      'sess-1',
      violationCheckpoint,
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.checkpoint_id).toBe('ic-nudge1');
    expect(body.source_ref.checkpoint_id).toBe('ic-nudge1');
    expect(body.source_ref.verdict).toBe('boundary_violation');
    expect(body.source_ref.boundary_value).toBe('privacy');
  });

  it('falls back to generic phrasing when no BOUNDARY can be identified', async () => {
    captureInsertCall();
    await writeIntegrityNudgeAdvisory(
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
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.source_ref.boundary_value).toBeNull();
    expect(body.concerns_summary).toContain('boundary value unidentified');
    // No backtick-wrapped value name in the generic case.
    expect(body.nudge_content).not.toMatch(/`[^`]+`/);
  });

  it('caps source_ref.concerns at 3 entries', async () => {
    captureInsertCall();
    await writeIntegrityNudgeAdvisory(
      'agent-1',
      'sess-1',
      {
        ...violationCheckpoint,
        concerns: [
          { category: 'a', severity: 'high', relevant_conscience_value: 'BOUNDARY:a' },
          { category: 'b', severity: 'medium', relevant_conscience_value: 'BOUNDARY:b' },
          { category: 'c', severity: 'medium', relevant_conscience_value: 'BOUNDARY:c' },
          { category: 'd', severity: 'low', relevant_conscience_value: 'BOUNDARY:d' },
        ],
      },
      makeEnv(makeKV()),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    expect(body.source_ref.concerns).toHaveLength(3);
  });

  it('computes expires_at from configured TTL', async () => {
    const kv = makeKV();
    kv.get.mockResolvedValueOnce({ ttl_hours: 36 });
    captureInsertCall();
    const before = Date.now();
    await writeIntegrityNudgeAdvisory(
      'agent-1',
      'sess-1',
      violationCheckpoint,
      makeEnv(kv),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[0][1] as RequestInit).body as string,
    );
    const expiresAt = new Date(body.expires_at).getTime();
    expect(expiresAt).toBeGreaterThanOrEqual(before + 36 * 60 * 60 * 1000);
    expect(expiresAt).toBeLessThan(Date.now() + 37 * 60 * 60 * 1000);
  });

  it('swallows insert errors so the request path is not affected', async () => {
    mockFetch.mockRejectedValueOnce(new Error('supabase down'));
    await expect(
      writeIntegrityNudgeAdvisory(
        'agent-1',
        'sess-1',
        violationCheckpoint,
        makeEnv(makeKV()),
      ),
    ).resolves.toBeUndefined();
  });
});
