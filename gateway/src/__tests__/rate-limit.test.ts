/**
 * Tests for gateway rate limiting (per-IP, per-org, per-agent)
 *
 * Rate limiting uses BILLING_CACHE KV with minute-bucketed keys:
 *   rl:ip:{clientIp}:{minute}
 *   rl:agent:{agentHash}:{minute}
 *   rl:org:{accountId}:{minute}
 *
 * Functions are re-implemented here since they are not exported from index.ts.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// Re-implemented rate limiting functions from index.ts
// ============================================================================

const DEFAULT_RATE_LIMITS = {
  per_ip_rpm: 100,
  per_org_rpm: 1000,
  per_agent_rpm: 100,
};

async function checkRateLimitTier(
  kv: KVNamespace,
  key: string,
  limit: number,
): Promise<{ count: number; allowed: boolean }> {
  try {
    const current = parseInt((await kv.get(key)) || '0', 10);
    if (current >= limit) {
      return { count: current, allowed: false };
    }
    await kv.put(key, String(current + 1), { expirationTtl: 120 });
    return { count: current + 1, allowed: true };
  } catch {
    return { count: 0, allowed: true };
  }
}

function rateLimitResponse(
  tier: string, limit: number, minute: number
): Response {
  const resetAt = (minute + 1) * 60;
  const retryAfter = Math.max(1, resetAt - Math.floor(Date.now() / 1000));
  return new Response(
    JSON.stringify({
      error: 'Rate limit exceeded',
      type: 'rate_limit_error',
      tier,
      limit,
      retry_after: retryAfter,
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(retryAfter),
        'X-RateLimit-Limit': String(limit),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': String(resetAt),
      },
    },
  );
}

// ============================================================================
// Mock KV namespace
// ============================================================================

function createMockKV(store: Record<string, string> = {}): KVNamespace {
  return {
    get: vi.fn(async (key: string) => store[key] ?? null),
    put: vi.fn(async (key: string, value: string) => { store[key] = value; }),
    delete: vi.fn(),
    list: vi.fn(),
    getWithMetadata: vi.fn(),
  } as unknown as KVNamespace;
}

// ============================================================================
// Tests: checkRateLimitTier
// ============================================================================

describe('checkRateLimitTier', () => {
  it('allows request when under limit', async () => {
    const kv = createMockKV({ 'rl:ip:1.2.3.4:1000': '50' });
    const result = await checkRateLimitTier(kv, 'rl:ip:1.2.3.4:1000', 100);

    expect(result.allowed).toBe(true);
    expect(result.count).toBe(51);
    expect(kv.put).toHaveBeenCalledWith('rl:ip:1.2.3.4:1000', '51', { expirationTtl: 120 });
  });

  it('rejects request when at limit', async () => {
    const kv = createMockKV({ 'rl:ip:1.2.3.4:1000': '100' });
    const result = await checkRateLimitTier(kv, 'rl:ip:1.2.3.4:1000', 100);

    expect(result.allowed).toBe(false);
    expect(result.count).toBe(100);
    expect(kv.put).not.toHaveBeenCalled();
  });

  it('allows first request (no existing counter)', async () => {
    const kv = createMockKV();
    const result = await checkRateLimitTier(kv, 'rl:ip:5.6.7.8:2000', 100);

    expect(result.allowed).toBe(true);
    expect(result.count).toBe(1);
    expect(kv.put).toHaveBeenCalledWith('rl:ip:5.6.7.8:2000', '1', { expirationTtl: 120 });
  });

  it('fails open when KV throws', async () => {
    const kv = createMockKV();
    (kv.get as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('KV unavailable'));

    const result = await checkRateLimitTier(kv, 'rl:ip:1.2.3.4:1000', 100);

    expect(result.allowed).toBe(true);
    expect(result.count).toBe(0);
  });
});

// ============================================================================
// Tests: rateLimitResponse
// ============================================================================

describe('rateLimitResponse', () => {
  it('returns 429 with correct headers for per-IP limit', async () => {
    const minute = Math.floor(Date.now() / 60000);
    const response = rateLimitResponse('ip', 100, minute);

    expect(response.status).toBe(429);
    expect(response.headers.get('X-RateLimit-Limit')).toBe('100');
    expect(response.headers.get('X-RateLimit-Remaining')).toBe('0');
    expect(response.headers.get('X-RateLimit-Reset')).toBe(String((minute + 1) * 60));
    expect(response.headers.get('Retry-After')).toBeDefined();
    expect(parseInt(response.headers.get('Retry-After')!)).toBeGreaterThan(0);
    expect(parseInt(response.headers.get('Retry-After')!)).toBeLessThanOrEqual(60);

    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toBe('Rate limit exceeded');
    expect(body.type).toBe('rate_limit_error');
    expect(body.tier).toBe('ip');
    expect(body.limit).toBe(100);
  });

  it('returns correct tier for per-agent limit', async () => {
    const minute = Math.floor(Date.now() / 60000);
    const response = rateLimitResponse('agent', 100, minute);

    const body = await response.json() as Record<string, unknown>;
    expect(body.tier).toBe('agent');
    expect(body.limit).toBe(100);
  });

  it('returns correct tier for per-org limit', async () => {
    const minute = Math.floor(Date.now() / 60000);
    const response = rateLimitResponse('org', 5000, minute);

    expect(response.headers.get('X-RateLimit-Limit')).toBe('5000');
    const body = await response.json() as Record<string, unknown>;
    expect(body.tier).toBe('org');
    expect(body.limit).toBe(5000);
  });
});

// ============================================================================
// Tests: org-specific rate limit overrides
// ============================================================================

describe('org-specific rate limit overrides', () => {
  it('uses custom per_org_rpm from quotaContext.limits', async () => {
    const kv = createMockKV({ 'rl:org:ba-enterprise:1000': '999' });

    // Custom limit: 5000 rpm (enterprise override)
    const orgLimits = { per_org_rpm: 5000 };
    const orgLimit = orgLimits.per_org_rpm ?? DEFAULT_RATE_LIMITS.per_org_rpm;

    const result = await checkRateLimitTier(kv, 'rl:org:ba-enterprise:1000', orgLimit);

    // 999 < 5000, so allowed
    expect(result.allowed).toBe(true);
  });

  it('uses default when no org override', async () => {
    const kv = createMockKV({ 'rl:org:ba-free:1000': '999' });

    const orgLimits = {} as { per_org_rpm?: number };
    const orgLimit = orgLimits.per_org_rpm ?? DEFAULT_RATE_LIMITS.per_org_rpm;

    const result = await checkRateLimitTier(kv, 'rl:org:ba-free:1000', orgLimit);

    // 999 < 1000 (default), so allowed
    expect(result.allowed).toBe(true);
  });

  it('rejects when custom per_agent_rpm exceeded', async () => {
    const kv = createMockKV({ 'rl:agent:abc123:1000': '50' });

    const orgLimits = { per_agent_rpm: 50 };
    const agentLimit = orgLimits.per_agent_rpm ?? DEFAULT_RATE_LIMITS.per_agent_rpm;

    const result = await checkRateLimitTier(kv, 'rl:agent:abc123:1000', agentLimit);

    expect(result.allowed).toBe(false);
  });
});
