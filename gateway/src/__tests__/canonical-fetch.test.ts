/**
 * UC-6 canonical-fetch tests (gateway).
 *
 * Exercises fetchCanonicalAlignmentCard + fetchCanonicalProtectionCard in
 * src/card-mappers.ts. Verifies KV-cache + needs_recompose bypass contract:
 *
 *   - KV hit → returns cached card; no Supabase fetch.
 *   - KV miss + DB hit + needs_recompose=false → returns card + populates KV.
 *   - KV miss + DB hit + needs_recompose=true → returns card; KV NOT touched.
 *   - KV miss + DB error (non-2xx) → null, KV untouched.
 *   - KV miss + DB hit but empty card_json → null, KV untouched.
 *   - KV absent from env (no BILLING_CACHE binding) → DB fetch; no throw.
 *
 * These contracts gate the "fallback rate decays to zero" check in the
 * UC-14 hardening list — the canonical path MUST be reliable enough that
 * no request falls back to the legacy lazy-merge path.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  fetchCanonicalAlignmentCard,
  fetchCanonicalProtectionCard,
} from '../card-mappers';

const SUPABASE_URL = 'https://test.supabase.co';
const AGENT_ID = 'mnm-canon-1';

function jsonOk(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
function textResp(status: number, body = ''): Response {
  return new Response(body, { status });
}

function makeKV() {
  return {
    get: vi.fn(),
    put: vi.fn().mockResolvedValue(undefined),
    delete: vi.fn().mockResolvedValue(undefined),
  } as any;
}

function makeEnv(withKV: boolean) {
  return {
    SUPABASE_URL,
    SUPABASE_KEY: 'test-key',
    BILLING_CACHE: withKV ? makeKV() : undefined,
  } as any;
}

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

beforeEach(() => {
  mockFetch.mockReset();
});

const alignmentCard = {
  card_version: '2026-04-15',
  agent_id: AGENT_ID,
  principal: { type: 'human', relationship: 'delegated_authority' },
  values: { declared: ['safety'] },
  autonomy: { bounded_actions: ['inference'], escalation_triggers: [] },
  audit: { retention_days: 30, queryable: false },
};
const protectionCard = {
  card_version: '2026-04-15',
  agent_id: AGENT_ID,
  mode: 'observe',
  thresholds: { warn: 0.6, quarantine: 0.8, block: 0.95 },
  screen_surfaces: ['user_message'],
  trusted_sources: [],
};

// ─── Alignment ────────────────────────────────────────────────────────────

describe('fetchCanonicalAlignmentCard', () => {
  it('returns the cached card on KV hit without touching Supabase', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(alignmentCard);

    const card = await fetchCanonicalAlignmentCard(AGENT_ID, env);
    expect(card).toEqual(alignmentCard);
    expect(env.BILLING_CACHE.get).toHaveBeenCalledWith(
      `canonical-align:${AGENT_ID}`,
      'json',
    );
    expect(mockFetch).not.toHaveBeenCalled();
    expect(env.BILLING_CACHE.put).not.toHaveBeenCalled();
  });

  it('on KV miss + DB hit + needs_recompose=false, returns card AND populates KV', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(null);
    mockFetch.mockResolvedValueOnce(
      jsonOk([{ card_json: alignmentCard, needs_recompose: false }]),
    );

    const card = await fetchCanonicalAlignmentCard(AGENT_ID, env);
    expect(card).toEqual(alignmentCard);

    // Verify the DB URL looked sensible
    const [url] = mockFetch.mock.calls[0];
    expect(typeof url).toBe('string');
    expect(url).toContain('/rest/v1/canonical_agent_cards');
    expect(url).toContain(`agent_id=eq.${AGENT_ID}`);

    // KV was populated
    expect(env.BILLING_CACHE.put).toHaveBeenCalledTimes(1);
    const [key, payload, opts] = env.BILLING_CACHE.put.mock.calls[0];
    expect(key).toBe(`canonical-align:${AGENT_ID}`);
    expect(JSON.parse(payload)).toEqual(alignmentCard);
    expect(opts).toEqual({ expirationTtl: 300 });
  });

  it('on KV miss + DB hit + needs_recompose=true, returns card but does NOT populate KV', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(null);
    mockFetch.mockResolvedValueOnce(
      jsonOk([{ card_json: alignmentCard, needs_recompose: true }]),
    );

    const card = await fetchCanonicalAlignmentCard(AGENT_ID, env);
    expect(card).toEqual(alignmentCard);
    expect(env.BILLING_CACHE.put).not.toHaveBeenCalled();
  });

  it('returns null when DB returns non-2xx (KV unchanged)', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(null);
    mockFetch.mockResolvedValueOnce(textResp(503, 'db down'));

    const card = await fetchCanonicalAlignmentCard(AGENT_ID, env);
    expect(card).toBeNull();
    expect(env.BILLING_CACHE.put).not.toHaveBeenCalled();
  });

  it('returns null when DB returns empty array', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(null);
    mockFetch.mockResolvedValueOnce(jsonOk([]));
    const card = await fetchCanonicalAlignmentCard(AGENT_ID, env);
    expect(card).toBeNull();
  });

  it('returns null when DB row has no card_json', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(null);
    mockFetch.mockResolvedValueOnce(jsonOk([{ needs_recompose: false }]));
    const card = await fetchCanonicalAlignmentCard(AGENT_ID, env);
    expect(card).toBeNull();
    expect(env.BILLING_CACHE.put).not.toHaveBeenCalled();
  });

  it('works when BILLING_CACHE binding is absent (no KV interaction)', async () => {
    const env = makeEnv(false);
    mockFetch.mockResolvedValueOnce(
      jsonOk([{ card_json: alignmentCard, needs_recompose: false }]),
    );
    const card = await fetchCanonicalAlignmentCard(AGENT_ID, env);
    expect(card).toEqual(alignmentCard);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

// ─── Protection ───────────────────────────────────────────────────────────

describe('fetchCanonicalProtectionCard', () => {
  it('returns the cached card on KV hit without touching Supabase', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(protectionCard);

    const card = await fetchCanonicalProtectionCard(AGENT_ID, env);
    expect(card).toEqual(protectionCard);
    expect(env.BILLING_CACHE.get).toHaveBeenCalledWith(
      `canonical-protect:${AGENT_ID}`,
      'json',
    );
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('on KV miss + DB hit + needs_recompose=false, returns card AND populates KV', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(null);
    mockFetch.mockResolvedValueOnce(
      jsonOk([{ card_json: protectionCard, needs_recompose: false }]),
    );
    const card = await fetchCanonicalProtectionCard(AGENT_ID, env);
    expect(card).toEqual(protectionCard);

    expect(env.BILLING_CACHE.put).toHaveBeenCalledTimes(1);
    expect(env.BILLING_CACHE.put.mock.calls[0][0]).toBe(`canonical-protect:${AGENT_ID}`);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain('/rest/v1/canonical_protection_cards');
  });

  it('on KV miss + DB hit + needs_recompose=true, returns card but does NOT populate KV', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(null);
    mockFetch.mockResolvedValueOnce(
      jsonOk([{ card_json: protectionCard, needs_recompose: true }]),
    );
    const card = await fetchCanonicalProtectionCard(AGENT_ID, env);
    expect(card).toEqual(protectionCard);
    expect(env.BILLING_CACHE.put).not.toHaveBeenCalled();
  });

  it('returns null on DB error', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(null);
    mockFetch.mockResolvedValueOnce(textResp(500, 'err'));
    const card = await fetchCanonicalProtectionCard(AGENT_ID, env);
    expect(card).toBeNull();
    expect(env.BILLING_CACHE.put).not.toHaveBeenCalled();
  });

  it('returns null when DB returns empty array', async () => {
    const env = makeEnv(true);
    env.BILLING_CACHE.get.mockResolvedValueOnce(null);
    mockFetch.mockResolvedValueOnce(jsonOk([]));
    const card = await fetchCanonicalProtectionCard(AGENT_ID, env);
    expect(card).toBeNull();
  });
});
