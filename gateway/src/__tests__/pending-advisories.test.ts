/**
 * Unit tests for the front-door pending-advisory writer (T0-3, ADR-040).
 *
 * Calls the helpers directly with mocked global fetch + a stub KV
 * namespace. The same-turn enforce mechanism (input replacement) is
 * exercised by the existing index.test.ts suite — these tests cover
 * the cross-turn carryover write that T0-3 adds.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import {
  getPendingAdvisoryTtlHours,
  buildFrontDoorAdvisoryContent,
  writeFrontDoorAdvisory,
  type Env,
} from '../index';
import type { SafeHouseDecision, ThreatDetection } from '@mnemom/safe-house';

interface KVStub {
  get: ReturnType<typeof vi.fn>;
  put: ReturnType<typeof vi.fn>;
  delete: ReturnType<typeof vi.fn>;
}

function makeKV(): KVStub {
  return {
    get: vi.fn().mockResolvedValue(null),
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

function makeThreat(type: string, score = 0.8): ThreatDetection {
  return {
    type: type as ThreatDetection['type'],
    confidence: score,
    reasoning: `synthetic ${type} signal`,
    matched_pattern: `p-${type}`,
  };
}

function makeDecision(
  overrides: Partial<SafeHouseDecision> = {},
): SafeHouseDecision {
  return {
    verdict: 'block',
    overall_risk: 0.85,
    threats: [makeThreat('prompt_injection', 0.9)],
    detector_scores: { PatternMatcher: 0.85, SemanticAnalyzer: 0.75 },
    detection_sources: ['PatternMatcher', 'SemanticAnalyzer'],
    session_multiplier: 1.0,
    quarantine_id: 'q-abc12345',
    duration_ms: 42,
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

// ─── getPendingAdvisoryTtlHours ─────────────────────────────────────────────

describe('getPendingAdvisoryTtlHours', () => {
  it('returns the cached value when KV has a fresh entry', async () => {
    const kv = makeKV();
    kv.get.mockResolvedValueOnce({ ttl_hours: 48 });
    const ttl = await getPendingAdvisoryTtlHours(makeEnv(kv));
    expect(ttl).toBe(48);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('reads from Supabase + writes back to KV on cache miss', async () => {
    const kv = makeKV();
    mockFetch.mockResolvedValueOnce(
      jsonRes([{ pending_advisory_ttl_hours: 12 }]),
    );
    const ttl = await getPendingAdvisoryTtlHours(makeEnv(kv));
    expect(ttl).toBe(12);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect((mockFetch.mock.calls[0][0] as string)).toContain(
      '/rest/v1/platform_settings?id=eq.default',
    );
    expect(kv.put).toHaveBeenCalledTimes(1);
    const [putKey, putValue, putOptions] = kv.put.mock.calls[0];
    expect(putKey).toBe('platform:pending-advisory-ttl');
    expect(JSON.parse(putValue as string)).toEqual({ ttl_hours: 12 });
    expect((putOptions as { expirationTtl: number }).expirationTtl).toBe(3600);
  });

  it('falls back to 24h when Supabase returns an empty result', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes([]));
    expect(await getPendingAdvisoryTtlHours(makeEnv(makeKV()))).toBe(24);
  });

  it('falls back to 24h on a non-2xx Supabase response', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes('boom', 500));
    expect(await getPendingAdvisoryTtlHours(makeEnv(makeKV()))).toBe(24);
  });

  it('falls back to 24h on out-of-bound DB values (defensive)', async () => {
    // The DB CHECK constraint enforces 1..168, but the gateway must not
    // trust unbounded values: a future schema change or a corrupted row
    // shouldn't be able to make every advisory expire instantly or live
    // for years.
    for (const bad of [0, -5, 169, 99999, 24.5]) {
      mockFetch.mockResolvedValueOnce(
        jsonRes([{ pending_advisory_ttl_hours: bad }]),
      );
      expect(await getPendingAdvisoryTtlHours(makeEnv())).toBe(24);
    }
  });

  it('falls back to 24h when fetch throws', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network down'));
    expect(await getPendingAdvisoryTtlHours(makeEnv(makeKV()))).toBe(24);
  });

  it('survives a corrupt cache value', async () => {
    const kv = makeKV();
    kv.get.mockResolvedValueOnce({ ttl_hours: 'not a number' });
    mockFetch.mockResolvedValueOnce(
      jsonRes([{ pending_advisory_ttl_hours: 36 }]),
    );
    const ttl = await getPendingAdvisoryTtlHours(makeEnv(kv));
    expect(ttl).toBe(36);
  });

  it('still works when BILLING_CACHE is unbound (no caching)', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonRes([{ pending_advisory_ttl_hours: 6 }]),
    );
    const env = makeEnv();
    expect(await getPendingAdvisoryTtlHours(env)).toBe(6);
  });
});

// ─── buildFrontDoorAdvisoryContent ──────────────────────────────────────────

describe('buildFrontDoorAdvisoryContent', () => {
  it('renders a block verdict with threats joined', () => {
    const decision = makeDecision({
      verdict: 'block',
      threats: [
        makeThreat('prompt_injection'),
        makeThreat('jailbreak'),
        makeThreat('data_exfiltration'),
      ],
      overall_risk: 0.92,
    });
    const { text, summary } = buildFrontDoorAdvisoryContent(decision);
    expect(text).toContain('blocked');
    expect(text).toContain('prompt_injection');
    expect(text).toContain('jailbreak');
    expect(text).toContain('data_exfiltration');
    expect(text).toContain('0.92');
    expect(summary).toMatch(
      /^Front-door blocked: prompt_injection, jailbreak, data_exfiltration \(overall_risk=0\.92\)$/,
    );
  });

  it('renders a quarantine verdict', () => {
    const decision = makeDecision({
      verdict: 'quarantine',
      threats: [makeThreat('prompt_injection')],
    });
    const { text } = buildFrontDoorAdvisoryContent(decision);
    expect(text).toContain('quarantined');
    expect(text).not.toContain('blocked');
  });

  it('caps the threat list at 3 entries to keep the advisory readable', () => {
    const decision = makeDecision({
      threats: [
        makeThreat('prompt_injection'),
        makeThreat('jailbreak'),
        makeThreat('data_exfiltration'),
        makeThreat('other'),
        makeThreat('encoding_trick'),
      ],
    });
    const { text } = buildFrontDoorAdvisoryContent(decision);
    expect(text).toContain('prompt_injection');
    expect(text).toContain('jailbreak');
    expect(text).toContain('data_exfiltration');
    expect(text).not.toContain('encoding_trick');
  });

  it('handles an empty threats array gracefully', () => {
    const decision = makeDecision({ threats: [] });
    const { text, summary } = buildFrontDoorAdvisoryContent(decision);
    expect(text).toContain('unspecified');
    expect(summary).toContain('unspecified');
  });

  it('deduplicates repeated threat types', () => {
    const decision = makeDecision({
      threats: [
        makeThreat('prompt_injection'),
        makeThreat('prompt_injection'),
        makeThreat('jailbreak'),
      ],
    });
    const { summary } = buildFrontDoorAdvisoryContent(decision);
    // Only two distinct threat types, comma-separated.
    expect(summary.match(/prompt_injection/g)?.length).toBe(1);
  });
});

// ─── writeFrontDoorAdvisory ─────────────────────────────────────────────────

describe('writeFrontDoorAdvisory', () => {
  function captureInsertCall() {
    // Sequence: TTL fetch (200), advisory POST (201).
    mockFetch.mockResolvedValueOnce(
      jsonRes([{ pending_advisory_ttl_hours: 24 }]),
    );
    mockFetch.mockResolvedValueOnce(jsonRes({}, 201));
  }

  it('skips the write when verdict is pass / warn (no enforce semantics)', async () => {
    for (const verdict of ['pass', 'warn'] as const) {
      mockFetch.mockReset();
      const decision = makeDecision({ verdict });
      await writeFrontDoorAdvisory('agent-1', 'sess-1', decision, makeEnv());
      expect(mockFetch).not.toHaveBeenCalled();
    }
  });

  it('writes a pending_advisories row with source=runtime.front_door.enforce on block', async () => {
    captureInsertCall();
    const decision = makeDecision({ verdict: 'block' });
    await writeFrontDoorAdvisory('agent-1', 'sess-1', decision, makeEnv());

    expect(mockFetch).toHaveBeenCalledTimes(2);
    const insertCall = mockFetch.mock.calls[1];
    expect(insertCall[0]).toContain('/rest/v1/pending_advisories');
    const init = insertCall[1] as RequestInit;
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body.source).toBe('runtime.front_door.enforce');
    expect(body.agent_id).toBe('agent-1');
    expect(body.session_id).toBe('sess-1');
    expect(body.status).toBe('pending');
    expect(body.id).toMatch(/^pa-[0-9a-f]{12}$/);
    expect(body.checkpoint_id).toBeUndefined();
  });

  it('also fires on quarantine verdict', async () => {
    captureInsertCall();
    const decision = makeDecision({ verdict: 'quarantine' });
    await writeFrontDoorAdvisory('agent-1', 'sess-1', decision, makeEnv());
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('populates source_ref with quarantine_id, verdict, risk, threats, sources', async () => {
    captureInsertCall();
    const decision = makeDecision({
      verdict: 'block',
      quarantine_id: 'q-test123',
      overall_risk: 0.91,
      detection_sources: ['PatternMatcher'],
      threats: [makeThreat('prompt_injection'), makeThreat('jailbreak')],
    });
    await writeFrontDoorAdvisory('agent-1', 'sess-1', decision, makeEnv());

    const body = JSON.parse(
      (mockFetch.mock.calls[1][1] as RequestInit).body as string,
    );
    expect(body.source_ref).toEqual({
      quarantine_id: 'q-test123',
      verdict: 'block',
      overall_risk: 0.91,
      detection_sources: ['PatternMatcher'],
      threat_types: ['prompt_injection', 'jailbreak'],
    });
  });

  it('computes expires_at from the configured TTL', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonRes([{ pending_advisory_ttl_hours: 72 }]),
    );
    mockFetch.mockResolvedValueOnce(jsonRes({}, 201));
    const before = Date.now();
    await writeFrontDoorAdvisory(
      'agent-1',
      'sess-1',
      makeDecision({ verdict: 'block' }),
      makeEnv(),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[1][1] as RequestInit).body as string,
    );
    const expiresAt = new Date(body.expires_at).getTime();
    expect(expiresAt).toBeGreaterThanOrEqual(before + 72 * 60 * 60 * 1000);
    expect(expiresAt).toBeLessThan(Date.now() + 73 * 60 * 60 * 1000);
  });

  it('uses the 24h fallback TTL when platform_settings is unreachable', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes('boom', 500));
    mockFetch.mockResolvedValueOnce(jsonRes({}, 201));
    const before = Date.now();
    await writeFrontDoorAdvisory(
      'agent-1',
      'sess-1',
      makeDecision({ verdict: 'block' }),
      makeEnv(),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[1][1] as RequestInit).body as string,
    );
    const expiresAt = new Date(body.expires_at).getTime();
    expect(expiresAt).toBeGreaterThanOrEqual(before + 24 * 60 * 60 * 1000);
    expect(expiresAt).toBeLessThan(Date.now() + 25 * 60 * 60 * 1000);
  });

  it('embeds the agent-facing advisory text in nudge_content', async () => {
    captureInsertCall();
    await writeFrontDoorAdvisory(
      'agent-1',
      'sess-1',
      makeDecision({
        verdict: 'block',
        threats: [makeThreat('prompt_injection')],
      }),
      makeEnv(),
    );
    const body = JSON.parse(
      (mockFetch.mock.calls[1][1] as RequestInit).body as string,
    );
    expect(body.nudge_content).toContain('Mnemom advisory');
    expect(body.nudge_content).toContain('blocked');
    expect(body.nudge_content).toContain('prompt_injection');
    expect(body.concerns_summary).toContain('Front-door');
  });

  it('swallows insert errors so the request path is not affected', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonRes([{ pending_advisory_ttl_hours: 24 }]),
    );
    mockFetch.mockRejectedValueOnce(new Error('supabase down'));
    // Must not throw — the same-turn intervention is the actual
    // enforcement mechanism; this carryover row is informational.
    await expect(
      writeFrontDoorAdvisory(
        'agent-1',
        'sess-1',
        makeDecision({ verdict: 'block' }),
        makeEnv(),
      ),
    ).resolves.toBeUndefined();
  });
});
