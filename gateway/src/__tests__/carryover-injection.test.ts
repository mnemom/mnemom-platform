/**
 * Unit tests for the T0-7 carryover-injection reader (ADR-040).
 *
 * Two functions under test, both exported from gateway/src/index.ts:
 *
 *   - injectPendingNudges: now reads from pending_advisories directly
 *     (not the enforcement_nudges compatibility view), filters by
 *     agent_id + session_id + non-expired, builds a generic header
 *     that wraps each advisory's already-formatted nudge_content,
 *     injects per provider.
 *   - markNudgesDelivered: now PATCHes pending_advisories with both
 *     id=eq.<id> AND status=eq.pending in the URL filter, so the
 *     UPDATE only fires when the row is still pending (atomic
 *     mark-consumed; double-mark becomes a no-op).
 *
 * Tests assert URL shape, body shape, and inject-into-system behavior
 * with mocked global fetch.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import {
  injectPendingNudges,
  markNudgesDelivered,
  type Env,
} from '../index';

function makeEnv(): Env {
  return {
    SUPABASE_URL: 'https://test.supabase.co',
    SUPABASE_SECRET_KEY: 'sb_secret_test',
  } as unknown as Env;
}

function jsonRes(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function nullRes(status = 204): Response {
  return new Response(null, { status });
}

beforeEach(() => {
  mockFetch.mockReset();
});

// ─── injectPendingNudges ────────────────────────────────────────────────────

describe('injectPendingNudges — gating', () => {
  it('returns [] when enforcement mode is observe (no inject)', async () => {
    const requestBody: Record<string, any> = {};
    const result = await injectPendingNudges(
      requestBody,
      'agent-1',
      'sess-1',
      'observe',
      makeEnv(),
      'anthropic',
    );
    expect(result).toEqual([]);
    expect(mockFetch).not.toHaveBeenCalled();
    expect(requestBody).toEqual({});
  });

  it('returns [] when enforcement mode is off', async () => {
    const result = await injectPendingNudges(
      {},
      'agent-1',
      null,
      'off',
      makeEnv(),
      'anthropic',
    );
    expect(result).toEqual([]);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('reads when enforcement mode is nudge', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes([]));
    await injectPendingNudges({}, 'agent-1', 'sess-1', 'nudge', makeEnv(), 'anthropic');
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('reads when enforcement mode is enforce', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes([]));
    await injectPendingNudges({}, 'agent-1', 'sess-1', 'enforce', makeEnv(), 'anthropic');
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('reads when includePreemptive is true even under observe', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes([]));
    await injectPendingNudges(
      {},
      'agent-1',
      'sess-1',
      'observe',
      makeEnv(),
      'anthropic',
      { includePreemptive: true },
    );
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

describe('injectPendingNudges — query construction', () => {
  it('queries pending_advisories directly (not the enforcement_nudges compat view)', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes([]));
    await injectPendingNudges({}, 'agent-1', null, 'nudge', makeEnv(), 'anthropic');
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain('/rest/v1/pending_advisories');
    expect(url).not.toContain('/rest/v1/enforcement_nudges');
  });

  it('filters by agent_id + status=pending + non-expired', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes([]));
    await injectPendingNudges({}, 'agent-1', null, 'nudge', makeEnv(), 'anthropic');
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain('agent_id=eq.agent-1');
    expect(url).toContain('status=eq.pending');
    // expires_at filter — "or=(expires_at.is.null,expires_at.gt.<now>)"
    // matches the compat view's "non-expired" semantics.
    expect(url).toContain('expires_at.is.null');
    expect(url).toContain('expires_at.gt.');
  });

  it('selects id + source + nudge_content', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes([]));
    await injectPendingNudges({}, 'agent-1', null, 'nudge', makeEnv(), 'anthropic');
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain('select=id,source,nudge_content');
  });

  it('orders by created_at ascending and caps at 5 rows', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes([]));
    await injectPendingNudges({}, 'agent-1', null, 'nudge', makeEnv(), 'anthropic');
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain('order=created_at.asc');
    expect(url).toContain('limit=5');
  });

  it('adds session filter when sessionId is provided (matching session OR null)', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes([]));
    await injectPendingNudges({}, 'agent-1', 'sess-abc', 'nudge', makeEnv(), 'anthropic');
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain('session_id.eq.sess-abc');
    expect(url).toContain('session_id.is.null');
  });

  it('omits session filter when sessionId is null (broader fan-out)', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes([]));
    await injectPendingNudges({}, 'agent-1', null, 'nudge', makeEnv(), 'anthropic');
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).not.toContain('session_id.eq.');
    // The expires_at OR-clause is still present, but no session OR-clause.
    const orClauses = (url.match(/[?&]or=/g) ?? []).length;
    expect(orClauses).toBe(1);
  });
});

describe('injectPendingNudges — injection + return', () => {
  function withAdvisories(rows: Array<{ id: string; source: string; nudge_content: string }>) {
    mockFetch.mockResolvedValueOnce(jsonRes(rows));
  }

  it('returns [] and skips injection when no advisories pending', async () => {
    withAdvisories([]);
    const requestBody: Record<string, any> = { messages: [{ role: 'user', content: 'hi' }] };
    const result = await injectPendingNudges(
      requestBody, 'agent-1', 'sess-1', 'nudge', makeEnv(), 'anthropic',
    );
    expect(result).toEqual([]);
    expect(requestBody.system).toBeUndefined();
  });

  it('builds the system prompt with the generic carryover header', async () => {
    withAdvisories([
      {
        id: 'pa-aaaa1111',
        source: 'runtime.front_door.enforce',
        nudge_content: '[Mnemom advisory: front-door blocked prompt_injection]',
      },
      {
        id: 'pa-bbbb2222',
        source: 'runtime.inside.integrity.enforce',
        nudge_content: '[Mnemom Intervention: BOUNDARY value `honesty` violated]',
      },
    ]);
    const requestBody: Record<string, any> = {};
    const result = await injectPendingNudges(
      requestBody, 'agent-1', 'sess-1', 'enforce', makeEnv(), 'anthropic',
    );
    expect(result).toEqual(['pa-aaaa1111', 'pa-bbbb2222']);
    const system = requestBody.system as string;
    expect(system).toContain('[Mnemom advisories from prior turns]');
    expect(system).toContain('front-door blocked prompt_injection');
    expect(system).toContain('BOUNDARY value `honesty` violated');
  });

  it('mixes sources without source-specific framing (each nudge_content speaks for itself)', async () => {
    // T0-3..T0-6's writers each produce their own agent-voice prefix
    // in nudge_content. The reader is source-agnostic — it just stacks
    // them in order.
    withAdvisories([
      { id: 'a', source: 'runtime.front_door.enforce', nudge_content: 'A' },
      { id: 'b', source: 'runtime.inside.autonomy.enforce', nudge_content: 'B' },
      { id: 'c', source: 'runtime.back_door.modification', nudge_content: 'C' },
    ]);
    const requestBody: Record<string, any> = {};
    await injectPendingNudges(
      requestBody, 'agent-1', null, 'enforce', makeEnv(), 'anthropic',
    );
    const system = requestBody.system as string;
    // Three carryover entries, in row order.
    expect(system.indexOf('A')).toBeLessThan(system.indexOf('B'));
    expect(system.indexOf('B')).toBeLessThan(system.indexOf('C'));
  });

  it('appends to an existing string system prompt rather than replacing it', async () => {
    withAdvisories([
      { id: 'pa-1', source: 'runtime.front_door.enforce', nudge_content: 'X' },
    ]);
    const requestBody: Record<string, any> = { system: 'You are a helpful assistant.' };
    await injectPendingNudges(
      requestBody, 'agent-1', null, 'enforce', makeEnv(), 'anthropic',
    );
    const system = requestBody.system as string;
    expect(system).toContain('You are a helpful assistant.');
    expect(system).toContain('X');
  });

  it('prepends an OpenAI system message when provider=openai', async () => {
    withAdvisories([
      { id: 'pa-1', source: 'runtime.front_door.enforce', nudge_content: 'NOTE' },
    ]);
    const requestBody: Record<string, any> = {
      messages: [{ role: 'user', content: 'hello' }],
    };
    await injectPendingNudges(
      requestBody, 'agent-1', null, 'enforce', makeEnv(), 'openai',
    );
    expect(requestBody.messages[0].role).toBe('system');
    expect(requestBody.messages[0].content).toContain('NOTE');
    expect(requestBody.messages[1].role).toBe('user');
  });

  it('returns [] and continues fail-open on supabase 5xx', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes('error', 500));
    const requestBody: Record<string, any> = {};
    const result = await injectPendingNudges(
      requestBody, 'agent-1', null, 'enforce', makeEnv(), 'anthropic',
    );
    expect(result).toEqual([]);
    expect(requestBody.system).toBeUndefined();
  });

  it('returns [] and continues fail-open on fetch exception', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network down'));
    const requestBody: Record<string, any> = {};
    const result = await injectPendingNudges(
      requestBody, 'agent-1', null, 'enforce', makeEnv(), 'anthropic',
    );
    expect(result).toEqual([]);
    expect(requestBody.system).toBeUndefined();
  });
});

// ─── markNudgesDelivered ────────────────────────────────────────────────────

describe('markNudgesDelivered — atomic mark-consumed', () => {
  it('skips entirely when there are no IDs', async () => {
    await markNudgesDelivered([], 'sess-1', makeEnv());
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('PATCHes pending_advisories (not enforcement_nudges) with id=eq + status=eq.pending atomic filter', async () => {
    mockFetch.mockResolvedValueOnce(nullRes(204));
    await markNudgesDelivered(['pa-aaaa1111'], 'sess-1', makeEnv());
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain('/rest/v1/pending_advisories');
    expect(url).not.toContain('/rest/v1/enforcement_nudges');
    expect(url).toContain('id=eq.pa-aaaa1111');
    expect(url).toContain('status=eq.pending');
    expect((init as RequestInit).method).toBe('PATCH');
  });

  it('writes the delivery payload (status, delivered_at, delivery_session_id)', async () => {
    mockFetch.mockResolvedValueOnce(nullRes(204));
    const before = Date.now();
    await markNudgesDelivered(['pa-bbbb2222'], 'sess-99', makeEnv());
    const init = mockFetch.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.status).toBe('delivered');
    expect(body.delivery_session_id).toBe('sess-99');
    const deliveredAt = new Date(body.delivered_at).getTime();
    expect(deliveredAt).toBeGreaterThanOrEqual(before);
    expect(deliveredAt).toBeLessThanOrEqual(Date.now() + 1000);
  });

  it('issues one PATCH per ID', async () => {
    mockFetch.mockResolvedValue(nullRes(204));
    await markNudgesDelivered(['pa-1', 'pa-2', 'pa-3'], 'sess-1', makeEnv());
    expect(mockFetch).toHaveBeenCalledTimes(3);
    const ids = mockFetch.mock.calls.map((call) => {
      const url = call[0] as string;
      return url.match(/id=eq\.([^&]+)/)?.[1];
    });
    expect(ids).toEqual(['pa-1', 'pa-2', 'pa-3']);
  });

  it('survives a 5xx without throwing (fail-open)', async () => {
    mockFetch.mockResolvedValueOnce(jsonRes('boom', 500));
    await expect(
      markNudgesDelivered(['pa-1'], 'sess-1', makeEnv()),
    ).resolves.toBeUndefined();
  });

  it('survives a fetch exception without throwing', async () => {
    mockFetch.mockRejectedValueOnce(new Error('network'));
    await expect(
      markNudgesDelivered(['pa-1'], 'sess-1', makeEnv()),
    ).resolves.toBeUndefined();
  });
});
