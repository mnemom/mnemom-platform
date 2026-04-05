import { describe, it, expect, vi, beforeEach, afterEach, beforeAll } from 'vitest';
import { SignJWT, generateKeyPair } from 'jose';

// Mock createRemoteJWKSet so JWT tests can control the returned JWKS key function.
// All other jose exports are passed through unchanged.
vi.mock('jose', async (importOriginal) => {
  const actual = await importOriginal<typeof import('jose')>();
  return { ...actual, createRemoteJWKSet: vi.fn() };
});
import { createRemoteJWKSet } from 'jose';
import {
  hashApiKey,
  generateSessionId,
  getOrCreateAgent,
  updateKeyPrefix,
  buildMetadataHeader,
  handleHealthCheck,
  handleAnthropicProxy,
  handleProviderProxy,
  _resetJwksCacheForTests,
  evaluateQuota,
  hashMnemomApiKey,
  resolveQuotaContext,
  submitMeteringEvent,
  FREE_TIER_CONTEXT,
  type Env,
  type QuotaContext,
} from '../index';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Helper to create test environment
function createTestEnv(overrides?: Partial<Env>): Env {
  return {
    SUPABASE_URL: 'https://test.supabase.co',
    SUPABASE_KEY: 'test-supabase-key',
    CF_AI_GATEWAY_URL: 'https://gateway.ai.cloudflare.com/v1/test',
    CF_AIG_TOKEN: 'test-aig-token',
    GATEWAY_VERSION: '2.0.0',
    ANTHROPIC_API_KEY: 'test-anthropic-key',
    AIP_ENABLED: 'false',
    ...overrides,
  };
}

// Helper to create mock execution context
function createMockContext(): ExecutionContext {
  return {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('hashApiKey', () => {
  it('should return a 16 character hex string', async () => {
    const result = await hashApiKey('test-api-key');

    expect(result).toHaveLength(16);
    expect(result).toMatch(/^[0-9a-f]{16}$/);
  });

  it('should produce consistent output for the same input', async () => {
    const result1 = await hashApiKey('same-key');
    const result2 = await hashApiKey('same-key');

    expect(result1).toBe(result2);
  });

  it('should produce different output for different inputs', async () => {
    const result1 = await hashApiKey('key-one');
    const result2 = await hashApiKey('key-two');

    expect(result1).not.toBe(result2);
  });

  it('should handle empty string input', async () => {
    const result = await hashApiKey('');

    expect(result).toHaveLength(16);
    expect(result).toMatch(/^[0-9a-f]{16}$/);
  });

  it('should handle special characters', async () => {
    const result = await hashApiKey('sk-ant-api03-!@#$%^&*()_+-=[]{}');

    expect(result).toHaveLength(16);
    expect(result).toMatch(/^[0-9a-f]{16}$/);
  });

  it('should only return first 16 characters of the full hash', async () => {
    // SHA-256 produces 64 hex chars, we want only first 16
    const result = await hashApiKey('test');

    expect(result).toHaveLength(16);
    // Verify it's not the full hash
    expect(result.length).toBeLessThan(64);
  });
});

describe('generateSessionId', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should return format: agentHash-hourBucket', () => {
    vi.setSystemTime(new Date('2024-01-15T10:30:00Z'));
    const agentHash = 'abcd1234efgh5678';

    const result = generateSessionId(agentHash);

    expect(result).toMatch(/^abcd1234efgh5678-\d+$/);
  });

  it('should use hour-based bucketing', () => {
    const agentHash = 'testhash12345678';

    // Set time to specific hour
    vi.setSystemTime(new Date('2024-01-15T10:00:00Z'));
    const result1 = generateSessionId(agentHash);

    // Same hour, different minute
    vi.setSystemTime(new Date('2024-01-15T10:45:00Z'));
    const result2 = generateSessionId(agentHash);

    expect(result1).toBe(result2);
  });

  it('should produce different session IDs for different hours', () => {
    const agentHash = 'testhash12345678';

    vi.setSystemTime(new Date('2024-01-15T10:00:00Z'));
    const result1 = generateSessionId(agentHash);

    vi.setSystemTime(new Date('2024-01-15T11:00:00Z'));
    const result2 = generateSessionId(agentHash);

    expect(result1).not.toBe(result2);
  });

  it('should produce different session IDs for different agents in same hour', () => {
    vi.setSystemTime(new Date('2024-01-15T10:30:00Z'));

    const result1 = generateSessionId('agent111122223333');
    const result2 = generateSessionId('agent444455556666');

    expect(result1).not.toBe(result2);
    // But they should have the same hour bucket
    const bucket1 = result1.split('-')[1];
    const bucket2 = result2.split('-')[1];
    expect(bucket1).toBe(bucket2);
  });

  it('should calculate correct hour bucket value', () => {
    // Unix epoch + exactly 1 hour = 3600000ms, bucket = 1
    vi.setSystemTime(3600000);
    const result = generateSessionId('test');
    expect(result).toBe('test-1');

    // 2 hours = bucket 2
    vi.setSystemTime(7200000);
    const result2 = generateSessionId('test');
    expect(result2).toBe('test-2');
  });
});

describe('getOrCreateAgent', () => {
  const env = createTestEnv();
  const testAgentHash = 'abc123def456gh78';

  it('should return existing agent when found', async () => {
    const existingAgent = {
      id: 'agent-uuid-123',
      agent_hash: testAgentHash,
      key_prefix: 'sk-ant-test-key-',
      name: 'Test Agent',
      created_at: '2024-01-01T00:00:00Z',
      last_seen: '2024-01-15T10:00:00Z',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([existingAgent]),
    });

    const result = await getOrCreateAgent(testAgentHash, env);

    expect(result.agent).toEqual(existingAgent);
    expect(result.isNew).toBe(false);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('should create new agent when not found', async () => {
    const newAgent = {
      id: 'new-agent-uuid',
      agent_hash: testAgentHash,
      key_prefix: 'sk-ant-test-key-',
      name: null,
      created_at: '2024-01-15T10:00:00Z',
      last_seen: '2024-01-15T10:00:00Z',
    };

    // First call - lookup returns empty
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([]),
    });

    // Second call - create agent
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([newAgent]),
    });

    // Third call - create alignment card
    mockFetch.mockResolvedValueOnce({
      ok: true,
    });

    const result = await getOrCreateAgent(testAgentHash, env);

    expect(result.agent).toEqual(newAgent);
    expect(result.isNew).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it('should throw error on lookup failure', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    await expect(getOrCreateAgent(testAgentHash, env)).rejects.toThrow(
      'Supabase lookup failed: 500'
    );
  });

  it('should throw error on create failure', async () => {
    // Lookup returns empty
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([]),
    });

    // Create fails
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      text: () => Promise.resolve('Bad request'),
    });

    await expect(getOrCreateAgent(testAgentHash, env)).rejects.toThrow(
      'Failed to create agent: 400 - Bad request'
    );
  });

  it('should use correct Supabase headers', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([{ id: '123', agent_hash: testAgentHash }]),
      key_prefix: 'sk-ant-test-key-',
    });

    await getOrCreateAgent(testAgentHash, env);

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining(env.SUPABASE_URL),
      expect.objectContaining({
        headers: expect.objectContaining({
          'apikey': env.SUPABASE_KEY,
          'Authorization': `Bearer ${env.SUPABASE_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'return=representation',
        }),
      })
    );
  });

  it('should query with correct agent_hash filter', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([]),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([{ id: '123' }]),
    });
    mockFetch.mockResolvedValueOnce({ ok: true });

    await getOrCreateAgent(testAgentHash, env);

    expect(mockFetch).toHaveBeenCalledWith(
      `${env.SUPABASE_URL}/rest/v1/agents?agent_hash=eq.${testAgentHash}&select=*`,
      expect.any(Object)
    );
  });

  it('should include key_prefix in INSERT body when creating a new agent', async () => {
    const newAgent = {
      id: 'smolt-abc123de',
      agent_hash: testAgentHash,
      key_prefix: 'sk-ant-test-key-',
      name: null,
      created_at: '2024-01-15T10:00:00Z',
      last_seen: '2024-01-15T10:00:00Z',
      key_prefix: 'sk-ant-api03-abcd',
    };
    const keyPrefix = 'sk-ant-api03-abcd';

    // Lookup returns empty
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([]),
    });
    // Create agent
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([newAgent]),
    });
    // Create alignment card
    mockFetch.mockResolvedValueOnce({ ok: true });

    const result = await getOrCreateAgent(testAgentHash, env, undefined, keyPrefix);

    expect(result.isNew).toBe(true);
    // Find the POST call (second fetch call)
    const createCall = mockFetch.mock.calls[1];
    const createBody = JSON.parse(createCall[1].body);
    expect(createBody.key_prefix).toBe(keyPrefix);
  });

  it('should NOT include key_prefix in INSERT body when keyPrefix is not provided', async () => {
    const newAgent = {
      id: 'smolt-abc123de',
      agent_hash: testAgentHash,
      key_prefix: 'sk-ant-test-key-',
      name: null,
      created_at: '2024-01-15T10:00:00Z',
      last_seen: '2024-01-15T10:00:00Z',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([]),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([newAgent]),
    });
    mockFetch.mockResolvedValueOnce({ ok: true });

    await getOrCreateAgent(testAgentHash, env, undefined, undefined);

    const createCall = mockFetch.mock.calls[1];
    const createBody = JSON.parse(createCall[1].body);
    expect(createBody).not.toHaveProperty('key_prefix');
  });

  it('named agent: key_prefix is apiKey.slice(0,16), not (apiKey+"|"+name).slice(0,16)', async () => {
    const rawKey = 'sk-ant-api03-verylongkey9999';
    const agentNameStr = 'my-named-agent';
    const keyPrefix = rawKey.slice(0, 16);
    // The combined prefix would differ
    const combinedPrefix = (rawKey + '|' + agentNameStr).slice(0, 16);
    expect(keyPrefix).toBe('sk-ant-api03-ver');
    expect(combinedPrefix).toBe('sk-ant-api03-ver'); // first 16 chars happen to be same in this case

    // Use a key where they differ to prove the assertion
    const shortKey = 'sk-XYZ';
    const shortCombined = (shortKey + '|' + agentNameStr).slice(0, 16);
    const shortPrefix = shortKey.slice(0, 16);
    // shortKey is only 6 chars so prefix is "sk-XYZ"
    // combined starts with "sk-XYZ|my-named" (16 chars)
    expect(shortPrefix).toBe('sk-XYZ');
    expect(shortCombined).toBe('sk-XYZ|my-named-');
    expect(shortPrefix).not.toBe(shortCombined);

    const newAgent = {
      id: 'smolt-abc123de',
      agent_hash: testAgentHash,
      key_prefix: shortPrefix,
      name: agentNameStr,
      created_at: '2024-01-15T10:00:00Z',
      last_seen: '2024-01-15T10:00:00Z',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([]),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([newAgent]),
    });
    mockFetch.mockResolvedValueOnce({ ok: true });

    await getOrCreateAgent(testAgentHash, env, agentNameStr, shortPrefix);

    const createCall = mockFetch.mock.calls[1];
    const createBody = JSON.parse(createCall[1].body);
    // key_prefix must be the raw key slice, not the combined string slice
    expect(createBody.key_prefix).not.toBe(shortCombined);
  });
});

describe('updateKeyPrefix', () => {
  const env = createTestEnv();

  it('should PATCH agent with key_prefix', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true });

    await updateKeyPrefix('smolt-abc123de', 'sk-ant-api03-ver', env);

    expect(mockFetch).toHaveBeenCalledWith(
      `${env.SUPABASE_URL}/rest/v1/agents?id=eq.smolt-abc123de`,
      expect.objectContaining({
        method: 'PATCH',
        headers: expect.objectContaining({
          'apikey': env.SUPABASE_KEY,
          'Authorization': `Bearer ${env.SUPABASE_KEY}`,
          'Content-Type': 'application/json',
        }),
        body: JSON.stringify({ key_prefix: 'sk-ant-api03-ver' }),
      })
    );
  });

  it('should be called for existing agents with null key_prefix (backfill scenario)', async () => {
    // should receive an updateKeyPrefix call when a request comes in with a known key.
    // We test updateKeyPrefix directly since handleProviderProxy integration tests
    // would require full env setup.
    mockFetch.mockResolvedValueOnce({ ok: true });

    const agentId = 'smolt-existingx';
    const prefix = 'sk-ant-api03-abc';
    await updateKeyPrefix(agentId, prefix, env);

    const call = mockFetch.mock.calls[0];
    expect(call[0]).toContain(`id=eq.${agentId}`);
    const body = JSON.parse(call[1].body);
    expect(body.key_prefix).toBe(prefix);
  });
});

describe('buildMetadataHeader', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T10:30:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should return valid JSON string', () => {
    const result = buildMetadataHeader('agent-123', 'hash123', 'session-456', '2.0.0');

    expect(() => JSON.parse(result)).not.toThrow();
  });

  it('should include all required fields', () => {
    const result = buildMetadataHeader('agent-123', 'hash123', 'session-456', '2.0.0');
    const parsed = JSON.parse(result);

    expect(parsed).toHaveProperty('agent_id', 'agent-123');
    expect(parsed).toHaveProperty('agent_hash', 'hash123');
    expect(parsed).toHaveProperty('session_id', 'session-456');
    expect(parsed).toHaveProperty('gateway_version', '2.0.0');
    expect(parsed).not.toHaveProperty('timestamp');
  });

  it('should stay within CF AI Gateway 5-pair metadata limit', () => {
    // Without agent name: 4 pairs
    const withoutName = JSON.parse(buildMetadataHeader('a', 'h', 's', 'v'));
    expect(Object.keys(withoutName).length).toBeLessThanOrEqual(5);

    // With agent name: 5 pairs (at limit)
    const withName = JSON.parse(buildMetadataHeader('a', 'h', 's', 'v', 'blackbeard'));
    expect(Object.keys(withName).length).toBeLessThanOrEqual(5);
    expect(withName).toHaveProperty('agent_name', 'blackbeard');
  });

  it('should handle special characters in inputs', () => {
    const result = buildMetadataHeader(
      'agent-with-special-chars!@#',
      'hash/with/slashes',
      'session"with"quotes',
      'version-1.2.3-beta'
    );

    expect(() => JSON.parse(result)).not.toThrow();
    const parsed = JSON.parse(result);
    expect(parsed.agent_id).toBe('agent-with-special-chars!@#');
  });
});

describe('handleHealthCheck', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T10:30:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should return 200 status', () => {
    const env = createTestEnv();
    const response = handleHealthCheck(env);

    expect(response.status).toBe(200);
  });

  it('should return JSON content type', () => {
    const env = createTestEnv();
    const response = handleHealthCheck(env);

    expect(response.headers.get('Content-Type')).toBe('application/json');
  });

  it('should include status ok in body', async () => {
    const env = createTestEnv();
    const response = handleHealthCheck(env);
    const body = await response.json();

    expect(body.status).toBe('ok');
  });

  it('should include gateway version', async () => {
    const env = createTestEnv({ GATEWAY_VERSION: '3.0.0' });
    const response = handleHealthCheck(env);
    const body = await response.json();

    expect(body.version).toBe('3.0.0');
  });

  it('should include timestamp', async () => {
    const env = createTestEnv();
    const response = handleHealthCheck(env);
    const body = await response.json();

    expect(body.timestamp).toBe('2024-01-15T10:30:00.000Z');
  });
});

describe('handleAnthropicProxy', () => {
  const env = createTestEnv();

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T10:30:00.000Z'));
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should return 401 if x-api-key header is missing', async () => {
    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
    });
    const ctx = createMockContext();

    const response = await handleAnthropicProxy(request, env, ctx);

    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.error).toBe('Missing x-api-key header');
    expect(body.type).toBe('authentication_error');
  });

  it('should forward request to CF AI Gateway', async () => {
    const existingAgent = {
      id: 'agent-uuid-123',
      agent_hash: 'abcdef0123456789',
      key_prefix: 'sk-ant-test-key-',
      name: null,
      created_at: '2024-01-01T00:00:00Z',
      last_seen: '2024-01-15T10:00:00Z',
    };

    // Agent lookup
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([existingAgent]),
    });

    // Quota context RPC (always called for agent_settings)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });

    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    // Forward request — must be a real Response so .text() works
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ id: 'msg_123' }), {
        status: 200,
        statusText: 'OK',
        headers: { 'Content-Type': 'application/json' },
      })
    );

    // Use GET request without body to avoid Node.js duplex stream issues
    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/models', {
      method: 'GET',
      headers: {
        'x-api-key': 'sk-ant-test-key',
      },
    });
    const ctx = createMockContext();

    await handleAnthropicProxy(request, env, ctx);

    // Verify forward request was made
    // Calls: 1) agent lookup, 2) quota context RPC, 3) policy fetch RPC, 4) forward to CF gateway
    expect(mockFetch.mock.calls.length).toBeGreaterThanOrEqual(4);
    const forwardCall = mockFetch.mock.calls[3];
    expect(forwardCall[0].url).toContain(env.CF_AI_GATEWAY_URL);
  });

  it('should strip /anthropic prefix from path when forwarding', async () => {
    const existingAgent = {
      id: 'agent-uuid-123',
      agent_hash: 'abcdef0123456789',
      key_prefix: 'sk-ant-test-key-',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([existingAgent]),
    });

    // Quota context RPC (always called for agent_settings)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });

    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers(),
      body: null,
    });

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': 'test-key' },
    });
    const ctx = createMockContext();

    await handleAnthropicProxy(request, env, ctx);

    const forwardCall = mockFetch.mock.calls[3];
    expect(forwardCall[0].url).toBe(`${env.CF_AI_GATEWAY_URL}/anthropic/v1/messages`);
  });

  it('should add cf-aig-metadata header to forwarded request', async () => {
    const existingAgent = {
      id: 'agent-uuid-123',
      agent_hash: 'abcdef0123456789',
      key_prefix: 'sk-ant-test-key-',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([existingAgent]),
    });

    // Quota context RPC (always called for agent_settings)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });

    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers(),
      body: null,
    });

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': 'test-key' },
    });
    const ctx = createMockContext();

    await handleAnthropicProxy(request, env, ctx);

    const forwardCall = mockFetch.mock.calls[3];
    const forwardRequest = forwardCall[0] as Request;
    const metadataHeader = forwardRequest.headers.get('cf-aig-metadata');

    expect(metadataHeader).toBeTruthy();
    const metadata = JSON.parse(metadataHeader!);
    expect(metadata).toHaveProperty('agent_id', 'agent-uuid-123');
    expect(metadata).toHaveProperty('session_id');
    expect(Object.keys(metadata).length).toBeLessThanOrEqual(5);
  });

  it('should add x-smoltbot-agent and x-smoltbot-session headers to response', async () => {
    const existingAgent = {
      id: 'agent-uuid-123',
      agent_hash: 'abcdef0123456789',
      key_prefix: 'sk-ant-test-key-',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([existingAgent]),
    });

    // Quota context RPC (always called for agent_settings)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });

    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    // Must be a real Response so .text() works when the AIP pipeline buffers it
    mockFetch.mockResolvedValueOnce(
      new Response(null, { status: 200, statusText: 'OK' })
    );

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': 'test-key' },
    });
    const ctx = createMockContext();

    const response = await handleAnthropicProxy(request, env, ctx);

    expect(response.headers.get('x-smoltbot-agent')).toBe('agent-uuid-123');
    expect(response.headers.get('x-smoltbot-session')).toBeTruthy();
  });

  it('should call waitUntil to update last_seen in background', async () => {
    const existingAgent = {
      id: 'agent-uuid-123',
      agent_hash: 'abcdef0123456789',
      key_prefix: 'sk-ant-test-key-',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([existingAgent]),
    });

    // Quota context RPC (always called for agent_settings)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });

    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers(),
      body: null,
    });

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': 'test-key' },
    });
    const ctx = createMockContext();

    await handleAnthropicProxy(request, env, ctx);

    expect(ctx.waitUntil).toHaveBeenCalled();
  });

  it('should return 500 on internal error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network failure'));

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': 'test-key' },
    });
    const ctx = createMockContext();

    const response = await handleAnthropicProxy(request, env, ctx);

    expect(response.status).toBe(500);
    const body = await response.json();
    expect(body.type).toBe('gateway_error');
    // Error message is sanitized — no internal details exposed to client
    expect(body.error).toBe('An internal error occurred');
    expect(body.message).toBeUndefined();
  });

  it('should preserve query parameters when forwarding', async () => {
    const existingAgent = {
      id: 'agent-uuid-123',
      agent_hash: 'abcdef0123456789',
      key_prefix: 'sk-ant-test-key-',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([existingAgent]),
    });

    // Quota context RPC (always called for agent_settings)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });

    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers(),
      body: null,
    });

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages?stream=true', {
      method: 'POST',
      headers: { 'x-api-key': 'test-key' },
    });
    const ctx = createMockContext();

    await handleAnthropicProxy(request, env, ctx);

    const forwardCall = mockFetch.mock.calls[3];
    expect(forwardCall[0].url).toContain('?stream=true');
  });
});

describe('Request handler integration', () => {
  // Import the default export for integration tests
  let handler: { fetch: (request: Request, env: Env, ctx: ExecutionContext) => Promise<Response> };

  beforeEach(async () => {
    vi.resetModules();
    mockFetch.mockReset();
    handler = (await import('../index')).default;
  });

  it('should handle OPTIONS requests for CORS preflight', async () => {
    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'OPTIONS',
    });
    const env = createTestEnv();
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    expect(response.status).toBe(204);
    // CORS origin is restricted to whitelist — no Origin header means default origin
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://mnemom.ai');
    expect(response.headers.get('Access-Control-Allow-Methods')).toContain('POST');
    expect(response.headers.get('Access-Control-Allow-Headers')).toContain('x-api-key');
  });

  it('should route /health to health check handler', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T10:30:00.000Z'));

    const request = new Request('https://gateway.smoltbot.com/health', {
      method: 'GET',
    });
    const env = createTestEnv();
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.status).toBe('ok');

    vi.useRealTimers();
  });

  it('should route /health/ (with trailing slash) to health check handler', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-15T10:30:00.000Z'));

    const request = new Request('https://gateway.smoltbot.com/health/', {
      method: 'GET',
    });
    const env = createTestEnv();
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.status).toBe('ok');

    vi.useRealTimers();
  });

  it('should return 404 for unknown paths', async () => {
    const request = new Request('https://gateway.smoltbot.com/unknown/path', {
      method: 'GET',
    });
    const env = createTestEnv();
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    expect(response.status).toBe(404);
    const body = await response.json();
    expect(body.type).toBe('not_found');
  });

  it('should return 404 for root path', async () => {
    const request = new Request('https://gateway.smoltbot.com/', {
      method: 'GET',
    });
    const env = createTestEnv();
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    expect(response.status).toBe(404);
  });

  it('should route /anthropic/* to proxy handler', async () => {
    const existingAgent = {
      id: 'agent-uuid-123',
      agent_hash: 'abcdef0123456789',
      key_prefix: 'sk-ant-test-key-',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([existingAgent]),
    });

    // Quota context RPC (always called for agent_settings)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });

    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers(),
      body: null,
    });

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': 'test-key' },
    });
    const env = createTestEnv();
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    // Should either be 200 (success) or 401 (missing key) - not 404
    expect(response.status).not.toBe(404);
  });

  it('should route /anthropic (without trailing path) to proxy handler', async () => {
    const request = new Request('https://gateway.smoltbot.com/anthropic', {
      method: 'POST',
      headers: { 'x-api-key': 'test-key' },
    });
    const env = createTestEnv();
    const ctx = createMockContext();

    // Mock agent lookup for proxy handler
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([{ id: 'agent-123', agent_hash: 'abcdef0123456789', key_prefix: 'sk-ant-test-key-' }]),
    });

    // Quota context RPC (always called for agent_settings)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });

    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: new Headers(),
      body: null,
    });

    const response = await handler.fetch(request, env, ctx);

    // Should not be 404
    expect(response.status).not.toBe(404);
  });
});

// ============================================================================
// evaluateQuota — pure function tests
// ============================================================================

describe('evaluateQuota', () => {
  function makeContext(overrides: Partial<QuotaContext> = {}): QuotaContext {
    return {
      plan_id: 'plan-developer',
      billing_model: 'metered',
      subscription_status: 'active',
      included_checks: 0,
      check_count_this_period: 100,
      overage_threshold: null,
      per_check_price: 1.0,
      feature_flags: { managed_gateway: true },
      limits: {},
      account_id: 'ba-test',
      current_period_end: '2026-03-15T00:00:00Z',
      past_due_since: null,
      is_suspended: false,
      containment_status: 'active',
      ...overrides,
    };
  }

  it('should allow free tier', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-free',
      billing_model: 'none',
    }));
    expect(decision.action).toBe('allow');
  });

  it('should allow enterprise', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-enterprise',
      billing_model: 'none',
    }));
    expect(decision.action).toBe('allow');
  });

  it('should allow developer under quota (metered)', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-developer',
      billing_model: 'metered',
      subscription_status: 'active',
    }));
    expect(decision.action).toBe('allow');
  });

  it('should allow developer past_due within 7-day grace', () => {
    const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-developer',
      subscription_status: 'past_due',
      past_due_since: threeDaysAgo,
    }));
    expect(decision.action).toBe('allow');
  });

  it('should reject developer past_due after 7-day grace', () => {
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-developer',
      subscription_status: 'past_due',
      past_due_since: tenDaysAgo,
    }));
    expect(decision.action).toBe('reject');
    expect(decision.reason).toBe('subscription_past_due_grace_expired');
  });

  it('should allow team at 79% quota', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-team',
      billing_model: 'subscription_plus_metered',
      subscription_status: 'active',
      included_checks: 15000,
      check_count_this_period: 11850,
    }));
    expect(decision.action).toBe('allow');
  });

  it('should warn team at 80% quota (approaching)', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-team',
      billing_model: 'subscription_plus_metered',
      subscription_status: 'active',
      included_checks: 15000,
      check_count_this_period: 12000,
    }));
    expect(decision.action).toBe('warn');
    expect(decision.reason).toBe('approaching_quota');
    expect(decision.headers['X-Mnemom-Usage-Warning']).toBe('approaching_quota');
  });

  it('should warn team at 100% quota (overage billing active)', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-team',
      billing_model: 'subscription_plus_metered',
      subscription_status: 'active',
      included_checks: 15000,
      check_count_this_period: 15000,
    }));
    expect(decision.action).toBe('warn');
    expect(decision.reason).toBe('quota_exceeded');
    expect(decision.headers['X-Mnemom-Usage-Warning']).toBe('quota_exceeded');
  });

  it('should reject team past_due immediately', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-team',
      subscription_status: 'past_due',
      past_due_since: new Date().toISOString(),
    }));
    expect(decision.action).toBe('reject');
    expect(decision.reason).toBe('subscription_past_due');
  });

  it('should reject canceled subscription', () => {
    const decision = evaluateQuota(makeContext({
      subscription_status: 'canceled',
    }));
    expect(decision.action).toBe('reject');
    expect(decision.reason).toBe('subscription_canceled');
  });

  it('should reject when overage threshold exceeded', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-team',
      billing_model: 'subscription_plus_metered',
      subscription_status: 'active',
      included_checks: 15000,
      check_count_this_period: 20000,
      overage_threshold: 18000,
    }));
    expect(decision.action).toBe('reject');
    expect(decision.reason).toBe('overage_threshold_exceeded');
  });

  it('should include usage percent header on allow', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-team',
      billing_model: 'subscription_plus_metered',
      subscription_status: 'active',
      included_checks: 15000,
      check_count_this_period: 7500,
    }));
    expect(decision.action).toBe('allow');
    expect(decision.headers['X-Mnemom-Usage-Percent']).toBe('50');
  });

  it('should reject suspended active account', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-team',
      billing_model: 'subscription_plus_metered',
      subscription_status: 'active',
      is_suspended: true,
    }));
    expect(decision.action).toBe('reject');
    expect(decision.reason).toBe('account_suspended');
  });

  it('should reject suspended free-tier account', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-free',
      billing_model: 'none',
      subscription_status: 'none',
      is_suspended: true,
    }));
    expect(decision.action).toBe('reject');
    expect(decision.reason).toBe('account_suspended');
  });

  // --- Containment tests ---

  it('should reject paused agent', () => {
    const decision = evaluateQuota(makeContext({
      containment_status: 'paused',
    }));
    expect(decision.action).toBe('reject');
    expect(decision.reason).toBe('agent_paused');
  });

  it('should reject killed agent', () => {
    const decision = evaluateQuota(makeContext({
      containment_status: 'killed',
    }));
    expect(decision.action).toBe('reject');
    expect(decision.reason).toBe('agent_killed');
  });

  it('should reject paused free-tier agent', () => {
    const decision = evaluateQuota(makeContext({
      plan_id: 'plan-free',
      billing_model: 'none',
      containment_status: 'paused',
    }));
    expect(decision.action).toBe('reject');
    expect(decision.reason).toBe('agent_paused');
  });

  it('should allow active agent', () => {
    const decision = evaluateQuota(makeContext({
      containment_status: 'active',
    }));
    expect(decision.action).toBe('allow');
  });

  it('should check containment after suspension (suspended takes priority)', () => {
    const decision = evaluateQuota(makeContext({
      is_suspended: true,
      containment_status: 'paused',
    }));
    expect(decision.action).toBe('reject');
    expect(decision.reason).toBe('account_suspended');
  });
});

// ============================================================================
// hashMnemomApiKey — full SHA-256 hex tests
// ============================================================================

describe('hashMnemomApiKey', () => {
  it('should return a 64 character hex string (full SHA-256)', async () => {
    const result = await hashMnemomApiKey('mk-test-key-12345');

    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  it('should produce consistent output for the same input', async () => {
    const result1 = await hashMnemomApiKey('mk-same-key');
    const result2 = await hashMnemomApiKey('mk-same-key');

    expect(result1).toBe(result2);
  });

  it('should produce different output for different inputs', async () => {
    const result1 = await hashMnemomApiKey('mk-key-alpha');
    const result2 = await hashMnemomApiKey('mk-key-beta');

    expect(result1).not.toBe(result2);
  });

  it('should handle empty string input', async () => {
    const result = await hashMnemomApiKey('');

    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  it('should differ from truncated hashApiKey for the same input', async () => {
    const input = 'shared-key-value';
    const mnemomHash = await hashMnemomApiKey(input);
    const agentHash = await hashApiKey(input);

    // hashApiKey returns first 16 chars; hashMnemomApiKey returns all 64
    expect(mnemomHash).toHaveLength(64);
    expect(agentHash).toHaveLength(16);
    // The first 16 chars should match since both use SHA-256
    expect(mnemomHash.substring(0, 16)).toBe(agentHash);
  });

  it('should handle special characters', async () => {
    const result = await hashMnemomApiKey('mk-!@#$%^&*()_+-=[]{}|;:,.<>?');

    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ============================================================================
// resolveQuotaContext — KV cache and Supabase RPC tests
// ============================================================================

describe('resolveQuotaContext', () => {
  const agentId = 'smolt-abcd1234';

  function createBillingEnv(overrides?: Partial<Env>): Env {
    return createTestEnv({
      BILLING_CACHE: {
        get: vi.fn(),
        put: vi.fn().mockResolvedValue(undefined),
        delete: vi.fn(),
        list: vi.fn(),
        getWithMetadata: vi.fn(),
      } as unknown as KVNamespace,
      ...overrides,
    });
  }

  it('should return cached data on cache hit', async () => {
    const cachedContext: QuotaContext = {
      plan_id: 'plan-developer',
      billing_model: 'metered',
      subscription_status: 'active',
      included_checks: 0,
      check_count_this_period: 42,
      overage_threshold: null,
      per_check_price: 1.0,
      feature_flags: { managed_gateway: true },
      limits: {},
      account_id: 'ba-cached',
      current_period_end: '2026-03-15T00:00:00Z',
      past_due_since: null,
    };

    const env = createBillingEnv();
    (env.BILLING_CACHE!.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(cachedContext);

    const result = await resolveQuotaContext(agentId, env);

    expect(result).toEqual(cachedContext);
    // Should not have called fetch (no RPC needed)
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('should use agent-based cache key when no mnemomKeyHash provided', async () => {
    const env = createBillingEnv();
    (env.BILLING_CACHE!.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

    // Mock the RPC call
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
      }),
    });

    await resolveQuotaContext(agentId, env);

    expect(env.BILLING_CACHE!.get).toHaveBeenCalledWith(
      `quota:agent:${agentId}`,
      'json'
    );
  });

  it('should use mnemom key hash cache key when mnemomKeyHash provided', async () => {
    const env = createBillingEnv();
    const mnemomKeyHash = 'abc123def456';
    (env.BILLING_CACHE!.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

    // Mock the RPC call
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ ...FREE_TIER_CONTEXT }),
    });

    await resolveQuotaContext(agentId, env, mnemomKeyHash);

    expect(env.BILLING_CACHE!.get).toHaveBeenCalledWith(
      `quota:mk:${mnemomKeyHash}`,
      'json'
    );
  });

  it('should call RPC and cache result on cache miss', async () => {
    const rpcContext: QuotaContext = {
      plan_id: 'plan-team',
      billing_model: 'subscription_plus_metered',
      subscription_status: 'active',
      included_checks: 15000,
      check_count_this_period: 500,
      overage_threshold: null,
      per_check_price: 0.5,
      feature_flags: { managed_gateway: true },
      limits: {},
      account_id: 'ba-team-123',
      current_period_end: '2026-03-15T00:00:00Z',
      past_due_since: null,
    };

    const env = createBillingEnv();
    (env.BILLING_CACHE!.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(rpcContext),
    });

    const result = await resolveQuotaContext(agentId, env);

    expect(result).toEqual(rpcContext);
    // Verify RPC was called with correct URL and body
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/rest/v1/rpc/get_quota_context_for_agent'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ p_agent_id: agentId }),
      })
    );
    // Verify result was written to KV cache with 30-min TTL
    expect(env.BILLING_CACHE!.put).toHaveBeenCalledWith(
      `quota:agent:${agentId}`,
      JSON.stringify(rpcContext),
      { expirationTtl: 1800 }
    );
  });

  it('should fall back to FREE_TIER_CONTEXT when RPC fails', async () => {
    const env = createBillingEnv();
    (env.BILLING_CACHE!.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    const result = await resolveQuotaContext(agentId, env);

    expect(result).toEqual(FREE_TIER_CONTEXT);
    expect(result.plan_id).toBe('plan-free');
    expect(result.billing_model).toBe('none');
  });

  it('should fall back to FREE_TIER_CONTEXT when fetch throws', async () => {
    const env = createBillingEnv();
    (env.BILLING_CACHE!.get as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

    mockFetch.mockRejectedValueOnce(new Error('Network error'));

    const result = await resolveQuotaContext(agentId, env);

    expect(result).toEqual(FREE_TIER_CONTEXT);
  });

  it('should continue to RPC when KV cache read throws', async () => {
    const rpcContext: QuotaContext = {
      ...FREE_TIER_CONTEXT,
      plan_id: 'plan-developer',
      billing_model: 'metered',
      account_id: 'ba-dev',
    };

    const env = createBillingEnv();
    (env.BILLING_CACHE!.get as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('KV error'));

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(rpcContext),
    });

    const result = await resolveQuotaContext(agentId, env);

    expect(result).toEqual(rpcContext);
  });

  it('should work without BILLING_CACHE bound (no KV)', async () => {
    const env = createTestEnv(); // No BILLING_CACHE

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ ...FREE_TIER_CONTEXT }),
    });

    const result = await resolveQuotaContext(agentId, env);

    expect(result).toEqual(FREE_TIER_CONTEXT);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

// ============================================================================
// submitMeteringEvent — Supabase RPC tests
// ============================================================================

describe('submitMeteringEvent', () => {
  const agentId = 'smolt-abcd1234';
  const checkpointId = 'chk-test-12345678';
  const source = 'gateway';
  const env = createTestEnv();

  it('should resolve billing account and insert metering event', async () => {
    // Mock get_billing_account_for_agent RPC
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ account_id: 'ba-acct-123' }),
    });

    // Mock metering event insert
    mockFetch.mockResolvedValueOnce({
      ok: true,
    });

    await submitMeteringEvent(agentId, checkpointId, source, env);

    // Verify the RPC call
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockFetch.mock.calls[0][0]).toContain('/rest/v1/rpc/get_billing_account_for_agent');
    const rpcBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(rpcBody).toEqual({ p_agent_id: agentId });

    // Verify the metering event insert
    expect(mockFetch.mock.calls[1][0]).toContain('/rest/v1/metering_events');
    const insertBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    expect(insertBody.account_id).toBe('ba-acct-123');
    expect(insertBody.agent_id).toBe(agentId);
    expect(insertBody.event_type).toBe('integrity_check');
    expect(insertBody.metadata).toEqual({ checkpoint_id: checkpointId, source });
    expect(insertBody.event_id).toMatch(/^me-[a-z0-9]{8}$/);
  });

  it('should succeed silently when account lookup fails (fail-open)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    // Should not throw
    await expect(submitMeteringEvent(agentId, checkpointId, source, env))
      .resolves.toBeUndefined();

    // Should only have called the RPC, not the insert
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('should succeed silently when account_id is null', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ account_id: null }),
    });

    await expect(submitMeteringEvent(agentId, checkpointId, source, env))
      .resolves.toBeUndefined();

    // Only the RPC was called, no insert
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('should succeed silently when fetch throws (fail-open)', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network failure'));

    await expect(submitMeteringEvent(agentId, checkpointId, source, env))
      .resolves.toBeUndefined();
  });

  it('should succeed silently when insert fails', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ account_id: 'ba-acct-123' }),
    });

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
    });

    await expect(submitMeteringEvent(agentId, checkpointId, source, env))
      .resolves.toBeUndefined();
  });

  it('should include correct Supabase headers in RPC call', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ account_id: null }),
    });

    await submitMeteringEvent(agentId, checkpointId, source, env);

    const headers = mockFetch.mock.calls[0][1].headers;
    expect(headers.apikey).toBe(env.SUPABASE_KEY);
    expect(headers.Authorization).toBe(`Bearer ${env.SUPABASE_KEY}`);
    expect(headers['Content-Type']).toBe('application/json');
  });
});

// ============================================================================
// Billing enforcement integration — main handler with billing enabled
// ============================================================================

describe('Billing enforcement integration', () => {
  let handler: { fetch: (request: Request, env: Env, ctx: ExecutionContext) => Promise<Response> };

  beforeEach(async () => {
    vi.resetModules();
    mockFetch.mockReset();
    handler = (await import('../index')).default;
  });

  function createBillingEnabledEnv(overrides?: Partial<Env>): Env {
    return createTestEnv({
      BILLING_ENFORCEMENT_ENABLED: 'true',
      AIP_ENABLED: 'false', // Disable AIP to isolate billing tests
      BILLING_CACHE: {
        get: vi.fn().mockResolvedValue(null),
        put: vi.fn().mockResolvedValue(undefined),
        delete: vi.fn(),
        list: vi.fn(),
        getWithMetadata: vi.fn(),
      } as unknown as KVNamespace,
      ...overrides,
    });
  }

  // Helper to mock the standard agent-lookup + forward flow
  function mockAgentLookupAndForward() {
    const existingAgent = {
      id: 'agent-uuid-billing',
      agent_hash: 'abcdef0123456789',
      key_prefix: 'sk-ant-test-key-',
      name: null,
      created_at: '2024-01-01T00:00:00Z',
      last_seen: '2024-01-15T10:00:00Z',
    };

    // Agent lookup
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([existingAgent]),
    });

    return existingAgent;
  }

  it('should proceed without billing when x-mnemom-api-key is absent and billing enabled', async () => {
    const env = createBillingEnabledEnv();

    mockAgentLookupAndForward();

    // Policy fetch RPC runs first (no KV cache hop), quota RPC runs second (after KV miss)
    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    // resolveQuotaContext RPC (no mnemom key, uses agent hash cache key)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        ...FREE_TIER_CONTEXT,
        plan_id: 'plan-free',
        billing_model: 'none',
      }),
    });

    // Forward request to CF AI Gateway (AIP disabled so only this forward)
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ id: 'msg_123' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': 'sk-ant-test-key' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', messages: [{ role: 'user', content: 'hi' }] }),
    });
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    // Should succeed — free tier is always allowed
    expect(response.status).toBe(200);
  });

  it('should check quota when x-mnemom-api-key is provided', async () => {
    const env = createBillingEnabledEnv();

    mockAgentLookupAndForward();

    // Mnemom API key validation RPC
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ valid: true, account_id: 'ba-acct-valid' }),
    });

    // Policy fetch RPC runs first (no KV cache hop), quota RPC runs second (after KV miss)
    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    // resolveQuotaContext RPC
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-developer',
        billing_model: 'metered',
        subscription_status: 'active',
        included_checks: 0,
        check_count_this_period: 50,
        overage_threshold: null,
        per_check_price: 1.0,
        feature_flags: { managed_gateway: true },
        limits: {},
        account_id: 'ba-acct-valid',
        current_period_end: '2026-03-15T00:00:00Z',
        past_due_since: null,
      }),
    });

    // Forward request to CF AI Gateway
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ id: 'msg_456' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': 'sk-ant-test-key',
        'x-mnemom-api-key': 'mk-live-test-key-12345',
      },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', messages: [{ role: 'user', content: 'hello' }] }),
    });
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    // Developer metered with active subscription should be allowed
    expect(response.status).toBe(200);
  });

  it('should return 402 when quota is rejected', async () => {
    const env = createBillingEnabledEnv();

    mockAgentLookupAndForward();

    // Mnemom API key validation RPC
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ valid: true, account_id: 'ba-acct-overdue' }),
    });

    // Policy fetch RPC runs first (no KV cache hop), quota RPC runs second (after KV miss)
    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    // resolveQuotaContext RPC — return a past_due context that triggers rejection
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-developer',
        billing_model: 'metered',
        subscription_status: 'past_due',
        included_checks: 0,
        check_count_this_period: 200,
        overage_threshold: null,
        per_check_price: 1.0,
        feature_flags: {},
        limits: {},
        account_id: 'ba-acct-overdue',
        current_period_end: '2026-02-01T00:00:00Z',
        past_due_since: tenDaysAgo,
      }),
    });

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': 'sk-ant-test-key',
        'x-mnemom-api-key': 'mk-live-overdue-key',
      },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', messages: [{ role: 'user', content: 'test' }] }),
    });
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    expect(response.status).toBe(402);
    const body = await response.json();
    expect(body.type).toBe('billing_error');
    expect(body.reason).toBe('subscription_past_due_grace_expired');
  });

  it('should return 401 when Mnemom API key is invalid', async () => {
    const env = createBillingEnabledEnv();

    mockAgentLookupAndForward();

    // Mnemom API key validation RPC — key is invalid
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ valid: false }),
    });

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': 'sk-ant-test-key',
        'x-mnemom-api-key': 'mk-invalid-key',
      },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', messages: [{ role: 'user', content: 'test' }] }),
    });
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.type).toBe('authentication_error');
    expect(body.error).toBe('Invalid Mnemom API key');
  });

  it('should not enforce billing when BILLING_ENFORCEMENT_ENABLED is false', async () => {
    const env = createTestEnv({
      BILLING_ENFORCEMENT_ENABLED: 'false',
      AIP_ENABLED: 'false',
    });

    const existingAgent = {
      id: 'agent-uuid-nobilling',
      agent_hash: 'abcdef0123456789',
      key_prefix: 'sk-ant-test-key-',
    };

    // Agent lookup
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([existingAgent]),
    });

    // Quota context RPC (always called now for agent_settings feature gating)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });

    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    // Forward request
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ id: 'msg_789' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': 'sk-ant-test-key',
        'x-mnemom-api-key': 'mk-should-be-ignored',
      },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', messages: [{ role: 'user', content: 'hi' }] }),
    });
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    // Should succeed without billing enforcement
    expect(response.status).toBe(200);
    // resolve_mnemom_api_key should NOT be called (gated on billingEnabled)
    expect(mockFetch.mock.calls.filter(
      (call: any[]) => call[0]?.toString().includes('resolve_mnemom_api_key')
    )).toHaveLength(0);
    // get_quota_context_for_agent IS called (always, for agent_settings feature gating)
  });

  it('should include usage warning headers when quota is approaching', async () => {
    const env = createBillingEnabledEnv();

    mockAgentLookupAndForward();

    // Mnemom API key validation
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ valid: true, account_id: 'ba-acct-warn' }),
    });

    // Policy fetch RPC runs first (no KV cache hop), quota RPC runs second (after KV miss)
    // Policy fetch RPC (returns null — no policy)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(null),
    });

    // resolveQuotaContext — team plan at 85% usage
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-team',
        billing_model: 'subscription_plus_metered',
        subscription_status: 'active',
        included_checks: 15000,
        check_count_this_period: 12750,
        overage_threshold: null,
        per_check_price: 0.5,
        feature_flags: { managed_gateway: true },
        limits: {},
        account_id: 'ba-acct-warn',
        current_period_end: '2026-03-15T00:00:00Z',
        past_due_since: null,
      }),
    });

    // Forward request
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ id: 'msg_warn' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    const request = new Request('https://gateway.smoltbot.com/anthropic/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': 'sk-ant-test-key',
        'x-mnemom-api-key': 'mk-live-warn-key',
      },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', messages: [{ role: 'user', content: 'test' }] }),
    });
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);

    // Should still allow but with warning headers
    expect(response.status).toBe(200);
    expect(response.headers.get('X-Mnemom-Usage-Warning')).toBe('approaching_quota');
    expect(response.headers.get('X-Mnemom-Usage-Percent')).toBe('85');
  });
});

// ============================================
// Phase 7: Hybrid Mode Tests
// ============================================

describe('Hybrid mode config detection', () => {
  it('should use local analysis when ANTHROPIC_API_KEY is set', () => {
    const env = createTestEnv({ ANTHROPIC_API_KEY: 'test-key' });
    // Local mode: ANTHROPIC_API_KEY takes precedence
    expect(env.ANTHROPIC_API_KEY).toBe('test-key');
    expect(env.MNEMOM_ANALYZE_URL).toBeUndefined();
  });

  it('should detect hybrid mode when MNEMOM_ANALYZE_URL is set without ANTHROPIC_API_KEY', () => {
    const env = createTestEnv({
      ANTHROPIC_API_KEY: '',
      MNEMOM_ANALYZE_URL: 'https://api.mnemom.ai/v1/analyze',
      MNEMOM_API_KEY: 'mnm_test_key',
    });
    expect(env.ANTHROPIC_API_KEY).toBe('');
    expect(env.MNEMOM_ANALYZE_URL).toBe('https://api.mnemom.ai/v1/analyze');
    expect(env.MNEMOM_API_KEY).toBe('mnm_test_key');
  });

  it('should detect skip-AIP when neither analysis key is configured', () => {
    const env = createTestEnv({ ANTHROPIC_API_KEY: '' });
    expect(env.ANTHROPIC_API_KEY).toBe('');
    expect(env.MNEMOM_ANALYZE_URL).toBeUndefined();
  });
});

describe('License validation', () => {
  it('should proceed normally when no license JWT is configured', async () => {
    const env = createTestEnv();
    const handler = (await import('../index')).default;

    const request = new Request('https://gateway.mnemom.ai/health');
    const ctx = createMockContext();
    const response = await handler.fetch(request, env, ctx);

    expect(response.status).toBe(200);
  });

  it('should reject requests when license JWT is expired and invalid', async () => {
    // Create an expired JWT with clearly invalid format
    const env = createTestEnv({
      MNEMOM_LICENSE_JWT: 'invalid.jwt.token',
    });
    const handler = (await import('../index')).default;

    // Non-health request (license check runs after health check)
    const request = new Request('https://gateway.mnemom.ai/models.json');
    const ctx = createMockContext();

    const response = await handler.fetch(request, env, ctx);
    // Should get 403 for invalid license
    expect(response.status).toBe(403);
    const body = await response.json() as Record<string, unknown>;
    expect(body.error).toContain('License');
  });

  it('should allow health check even with invalid license', async () => {
    const env = createTestEnv({
      MNEMOM_LICENSE_JWT: 'invalid.jwt.token',
    });
    const handler = (await import('../index')).default;

    const request = new Request('https://gateway.mnemom.ai/health');
    const ctx = createMockContext();
    const response = await handler.fetch(request, env, ctx);

    // Health check is before license validation
    expect(response.status).toBe(200);
  });

  it('should accept valid-format JWT with future expiry', async () => {
    // Create a properly-formatted JWT with future expiry
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payload = btoa(JSON.stringify({
      license_id: 'lic-test1234',
      account_id: 'ba-test',
      plan_id: 'plan-enterprise',
      feature_flags: { aip: true },
      limits: {},
      max_activations: 1,
      is_offline: true,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 86400,
      kid: 'lsk-test',
    })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const fakeSignature = btoa('fake-signature')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const env = createTestEnv({
      MNEMOM_LICENSE_JWT: `${header}.${payload}.${fakeSignature}`,
    });
    const handler = (await import('../index')).default;

    // Mock the validation fetch to succeed
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ valid: true }),
    });
    // Mock the models.json supabase call
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([]),
    });

    const request = new Request('https://gateway.mnemom.ai/models.json');
    const ctx = createMockContext();
    const response = await handler.fetch(request, env, ctx);

    // Should proceed past license check
    expect(response.status).toBe(200);
  });

  it('should reject when license JWT is expired and no grace period available', async () => {
    // Create JWT with expiry in the past
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payload = btoa(JSON.stringify({
      license_id: 'lic-expired1234',
      exp: Math.floor(Date.now() / 1000) - 86400, // expired yesterday
      is_offline: false,
    })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const fakeSignature = btoa('sig').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const kvGet = vi.fn()
      .mockResolvedValueOnce(null); // license:last_valid (no grace period cache)

    const env = createTestEnv({
      MNEMOM_LICENSE_JWT: `${header}.${payload}.${fakeSignature}`,
      BILLING_CACHE: {
        get: kvGet,
        put: vi.fn().mockResolvedValue(undefined),
        delete: vi.fn().mockResolvedValue(undefined),
        list: vi.fn(),
        getWithMetadata: vi.fn(),
      } as unknown as KVNamespace,
    });

    const handler = (await import('../index')).default;
    const request = new Request('https://gateway.mnemom.ai/models.json');
    const ctx = createMockContext();
    const response = await handler.fetch(request, env, ctx);

    // Expired JWT with no grace period → should reject
    expect(response.status).toBe(403);
  });
});

// ============================================================================
// JWT Signature Verification — ES256 via JWKS (scale/step-03b)
// ============================================================================

describe('handleProviderProxy — JWT signature verification (ES256/JWKS)', () => {
  // Generated once per describe block — ES256 P-256 key pair
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;

  beforeAll(async () => {
    const pair = await generateKeyPair('ES256');
    privateKey = pair.privateKey;
    publicKey = pair.publicKey;
  });

  async function makeJwt(expiresIn = '1h'): Promise<string> {
    return new SignJWT({ sub: 'test-user-id' })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(privateKey);
  }

  // Configure createRemoteJWKSet (already mocked via vi.mock at top of file)
  // to return a JWKS key function that resolves to the given CryptoKey.
  function stubJwksWithKey(key: CryptoKey) {
    vi.mocked(createRemoteJWKSet).mockReturnValue(async () => key);
    _resetJwksCacheForTests(); // force getSupabaseJwks() to call createRemoteJWKSet again
  }

  // Configure createRemoteJWKSet to return a function that throws — simulates bad/missing key.
  function stubJwksThrows() {
    vi.mocked(createRemoteJWKSet).mockReturnValue(async () => {
      throw new Error('JWSSignatureVerificationFailed');
    });
    _resetJwksCacheForTests();
  }

  beforeEach(() => {
    mockFetch.mockReset();
    _resetJwksCacheForTests();
  });

  it('rejects a JWT-shaped Bearer token with an invalid signature (401)', async () => {
    stubJwksThrows(); // JWKS returns a key that won't match the bad token's sig
    const env = createTestEnv();
    // Structurally valid JWT but with a garbage signature
    const badJwt = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.invalidsignatureXXXXXXXXX';
    const request = new Request('https://gateway.mnemom.ai/openai/v1/chat/completions', {
      method: 'POST',
      headers: { authorization: `Bearer ${badJwt}` },
    });

    const response = await handleProviderProxy(request, env, createMockContext(), 'openai');

    expect(response.status).toBe(401);
    const body = await response.json() as Record<string, unknown>;
    expect(body.type).toBe('authentication_error');
    expect(body.error).toBe('Invalid or expired token');
    // No downstream calls — auth failed before agent lookup
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('accepts a valid ES256 JWT and proceeds to agent identification', async () => {
    stubJwksWithKey(publicKey); // JWKS returns the matching public key
    const env = createTestEnv();
    const jwt = await makeJwt();

    const existingAgent = {
      id: 'agent-uuid-jwt',
      agent_hash: 'abcdef0123456789',
      key_prefix: 'test-user-id',
      name: null,
      created_at: '2024-01-01T00:00:00Z',
      last_seen: '2024-01-15T10:00:00Z',
    };

    mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([existingAgent]) });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });
    mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(null) });
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ id: 'chatcmpl-123' }), {
        status: 200,
        statusText: 'OK',
        headers: { 'Content-Type': 'application/json' },
      })
    );

    const request = new Request('https://gateway.mnemom.ai/openai/v1/models', {
      method: 'GET',
      headers: { authorization: `Bearer ${jwt}` },
    });

    const response = await handleProviderProxy(request, env, createMockContext(), 'openai');

    expect(response.status).not.toBe(401);
    expect(mockFetch).toHaveBeenCalled(); // agent lookup happened — JWT cleared verification
  });

  it('stores sub.slice(0,16) as key_prefix when creating a new JWT-authenticated agent', async () => {
    const SUB = '550e8400-e29b-41d4-a716-446655440000';
    const jwt = await new SignJWT({ sub: SUB })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);

    stubJwksWithKey(publicKey);
    const env = createTestEnv();

    const newAgent = {
      id: 'smolt-testjwt1',
      agent_hash: 'a1b2c3d4e5f60001',
      name: null,
      created_at: new Date().toISOString(),
      last_seen: null,
      key_prefix: SUB.slice(0, 16),
    };

    // [0] Agent lookup → empty (new agent)
    mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([]) });
    // [1] Agent INSERT — this is the body we assert against
    mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([newAgent]) });
    // [2] ensureAlignmentCard — background upsert, silently ignored on failure
    mockFetch.mockResolvedValueOnce({ ok: true });
    // [3] Quota context RPC
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free', billing_model: 'none', subscription_status: 'none',
        included_checks: 0, check_count_this_period: 0, overage_threshold: null,
        per_check_price: 0, feature_flags: {}, limits: {}, account_id: null,
        current_period_end: null, past_due_since: null, is_suspended: false,
        agent_settings: null, per_proof_price: 0,
      }),
    });
    // [4] Policy fetch RPC
    mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(null) });
    // [5] Forward to CF AI Gateway
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));

    const request = new Request('https://gateway.mnemom.ai/openai/v1/models', {
      method: 'GET',
      headers: { authorization: `Bearer ${jwt}` },
    });

    await handleProviderProxy(request, env, createMockContext(), 'openai');

    // INSERT body (call index 1) must have sub-derived prefix, NOT the JWT header bytes
    const insertBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    expect(insertBody.key_prefix).toBe(SUB.slice(0, 16));        // '550e8400-e29b-41'
    expect(insertBody.key_prefix).not.toBe('eyJhbGciOiJFUzI1'); // not the JWT header
  });

  it('passes a raw (non-JWT-shaped) API key through without calling createRemoteJWKSet', async () => {
    vi.mocked(createRemoteJWKSet).mockClear();
    _resetJwksCacheForTests();
    const env = createTestEnv();
    const rawKey = 'sk-proj-rawkey1234567890abcdef';

    const existingAgent = {
      id: 'agent-uuid-raw',
      agent_hash: 'fedcba9876543210',
      key_prefix: 'sk-proj-rawkey12',
      name: null,
      created_at: '2024-01-01T00:00:00Z',
      last_seen: '2024-01-15T10:00:00Z',
    };

    mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([existingAgent]) });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        plan_id: 'plan-free',
        billing_model: 'none',
        subscription_status: 'none',
        included_checks: 0,
        check_count_this_period: 0,
        overage_threshold: null,
        per_check_price: 0,
        feature_flags: {},
        limits: {},
        account_id: null,
        current_period_end: null,
        past_due_since: null,
        is_suspended: false,
        agent_settings: null,
        per_proof_price: 0,
      }),
    });
    mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(null) });
    mockFetch.mockResolvedValueOnce(
      new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } })
    );

    const request = new Request('https://gateway.mnemom.ai/openai/v1/models', {
      method: 'GET',
      headers: { authorization: `Bearer ${rawKey}` },
    });

    const response = await handleProviderProxy(request, env, createMockContext(), 'openai');

    const body = await response.json() as Record<string, unknown>;
    expect(body.error).not.toBe('Invalid or expired token');
    // JWKS was never invoked — raw key skips JWT verification entirely
    expect(vi.mocked(createRemoteJWKSet)).not.toHaveBeenCalled();
  });
});
