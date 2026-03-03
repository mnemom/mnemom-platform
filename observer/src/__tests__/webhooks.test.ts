/**
 * Tests for AAP Webhook Delivery
 *
 * Tests the webhook delivery pipeline:
 * - determineAAPEventTypes: Event type classification
 * - deliverAAPWebhooks: Delivery, retry, recording, failure handling
 *
 * Functions are re-implemented here since they are not exported from index.ts
 * (following the same pattern as index.test.ts).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type {
  APTrace,
  VerificationResult,
} from '@mnemom/agent-alignment-protocol';

// ============================================================================
// Re-implemented types from index.ts
// ============================================================================

interface Env {
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
  GATEWAY_ID: string;
  SUPABASE_URL: string;
  SUPABASE_KEY: string;
  ANTHROPIC_API_KEY: string;
  TRIGGER_SECRET: string;
}

interface EvaluationResult {
  verdict: 'allow' | 'deny' | 'warn';
  violations: Array<{ rule: string; message: string }>;
  warnings: Array<{ rule: string; message: string }>;
}

// ============================================================================
// Re-implemented functions from index.ts (not exported)
// ============================================================================

const AAP_VERSION = '1.0';
// Use zero delays in tests to avoid timeouts (real values are [1000, 5000, 15000])
const AAP_WEBHOOK_RETRY_DELAYS_MS = [0, 0, 0];

async function hmacSign(secret: string, payload: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function determineAAPEventTypes(
  trace: APTrace,
  verification: VerificationResult | null,
  policyResult: EvaluationResult | null
): string[] {
  const events: string[] = ['trace.created'];

  if (verification) {
    if (verification.passed) {
      events.push('trace.verified');
    } else {
      events.push('trace.failed');
    }
  }

  if (trace.escalation?.required) {
    events.push('trace.escalation_required');
  }

  if (policyResult?.verdict === 'deny') {
    events.push('policy.violation');
  }

  return events;
}

function randomHex(length: number): string {
  const chars = '0123456789abcdef';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

async function deliverAAPWebhooks(
  trace: APTrace,
  verification: VerificationResult | null,
  policyResult: EvaluationResult | null,
  env: Env
): Promise<void> {
  const timeoutMs = 25000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const eventTypes = determineAAPEventTypes(trace, verification, policyResult);

    const regResponse = await fetch(
      `${env.SUPABASE_URL}/rest/v1/aip_webhook_registrations?agent_id=eq.${trace.agent_id}&select=*`,
      {
        headers: {
          apikey: env.SUPABASE_KEY,
          Authorization: `Bearer ${env.SUPABASE_KEY}`,
        },
        signal: controller.signal,
      }
    );

    if (!regResponse.ok) {
      console.warn(`[observer/webhook] Failed to fetch registrations: ${regResponse.status}`);
      return;
    }

    const registrations = (await regResponse.json()) as Array<{
      registration_id: string;
      agent_id: string;
      callback_url: string;
      secret: string;
      events: string[];
      failure_count: number;
    }>;

    if (registrations.length === 0) return;

    const matchingRegistrations = registrations.filter(reg => {
      return reg.events.some(regEvent =>
        regEvent === '*' ||
        regEvent === 'trace.*' ||
        eventTypes.includes(regEvent)
      );
    });

    if (matchingRegistrations.length === 0) return;

    const webhookPayload = {
      event: eventTypes[eventTypes.length - 1],
      all_events: eventTypes,
      timestamp: new Date().toISOString(),
      trace: {
        trace_id: trace.trace_id,
        agent_id: trace.agent_id,
        session_id: trace.context?.session_id ?? null,
        decision: trace.decision ? {
          reasoning: trace.decision.reasoning_summary,
          alternatives_count: trace.decision.alternatives?.length ?? 0,
        } : null,
        verification: verification ? {
          passed: verification.passed,
          concerns: verification.concerns ?? [],
        } : null,
        escalation: trace.escalation ?? null,
        policy: policyResult ? {
          verdict: policyResult.verdict,
          violations: policyResult.violations?.length ?? 0,
          warnings: policyResult.warnings?.length ?? 0,
        } : null,
      },
    };

    const payloadString = JSON.stringify(webhookPayload);

    for (const reg of matchingRegistrations) {
      if (controller.signal.aborted) break;

      let delivered = false;
      let lastError: string | null = null;
      const retryDelays = [...AAP_WEBHOOK_RETRY_DELAYS_MS];

      const signature = await hmacSign(reg.secret, payloadString);

      for (let attempt = 0; attempt <= retryDelays.length; attempt++) {
        if (controller.signal.aborted) break;

        try {
          const webhookResponse = await fetch(reg.callback_url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-AAP-Signature': `sha256=${signature}`,
              'X-AAP-Version': AAP_VERSION,
            },
            body: payloadString,
            signal: controller.signal,
          });

          if (webhookResponse.ok) {
            delivered = true;
            break;
          }

          lastError = `HTTP ${webhookResponse.status}`;
        } catch (error) {
          if (controller.signal.aborted) break;
          lastError = error instanceof Error ? error.message : String(error);
        }

        if (attempt < retryDelays.length) {
          await new Promise(resolve => setTimeout(resolve, retryDelays[attempt]));
        }
      }

      try {
        await fetch(`${env.SUPABASE_URL}/rest/v1/aip_webhook_deliveries`, {
          method: 'POST',
          headers: {
            apikey: env.SUPABASE_KEY,
            Authorization: `Bearer ${env.SUPABASE_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=minimal',
          },
          body: JSON.stringify({
            id: `del-${randomHex(12)}`,
            registration_id: reg.registration_id,
            checkpoint_id: null,
            trace_id: trace.trace_id,
            event_type: eventTypes[eventTypes.length - 1],
            status: delivered ? 'success' : 'failed',
            attempts: delivered ? 1 : retryDelays.length + 1,
            last_attempt_at: new Date().toISOString(),
            error_message: lastError,
          }),
          signal: controller.signal,
        });
      } catch (error) {
        console.warn(`[observer/webhook] Failed to record delivery:`, error);
      }

      if (!delivered) {
        console.warn(`[observer/webhook] All retries exhausted for ${reg.registration_id} -> ${reg.callback_url}`);
        try {
          await fetch(
            `${env.SUPABASE_URL}/rest/v1/aip_webhook_registrations?registration_id=eq.${reg.registration_id}`,
            {
              method: 'PATCH',
              headers: {
                apikey: env.SUPABASE_KEY,
                Authorization: `Bearer ${env.SUPABASE_KEY}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                failure_count: reg.failure_count + 1,
              }),
              signal: controller.signal,
            }
          );
        } catch (error) {
          console.warn(`[observer/webhook] Failed to increment failure_count:`, error);
        }
      }
    }
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      console.warn('[observer/webhook] AAP webhook delivery timed out (25s limit)');
    } else {
      console.error('[observer/webhook] AAP webhook delivery failed:', error);
    }
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// Test Helpers
// ============================================================================

function createMockTrace(overrides: Partial<APTrace> = {}): APTrace {
  return {
    trace_id: `tr-${randomHex(8)}`,
    agent_id: 'agent-test-123',
    card_id: 'ac-test',
    timestamp: new Date().toISOString(),
    action: {
      type: 'execute',
      name: 'claude-3-sonnet',
      category: 'bounded',
      target: { type: 'api', identifier: 'anthropic' },
      parameters: {},
    },
    decision: {
      alternatives_considered: [],
      selected: 'respond',
      selection_reasoning: 'Test reasoning',
      values_applied: ['helpfulness'],
      confidence: 0.9,
      reasoning_summary: 'Test summary',
    },
    escalation: {
      evaluated: true,
      required: false,
      reason: 'No escalation triggers matched',
    },
    context: {
      session_id: 'sess-abc',
      conversation_turn: 1,
      environment: {},
    },
    ...overrides,
  } as APTrace;
}

function createMockVerification(overrides: Partial<VerificationResult> = {}): VerificationResult {
  return {
    passed: true,
    concerns: [],
    ...overrides,
  } as VerificationResult;
}

function createMockEnv(): Env {
  return {
    CF_ACCOUNT_ID: 'test-account',
    CF_API_TOKEN: 'test-token',
    GATEWAY_ID: 'test-gateway',
    SUPABASE_URL: 'https://test.supabase.co',
    SUPABASE_KEY: 'test-key',
    ANTHROPIC_API_KEY: 'test-anthropic',
    TRIGGER_SECRET: 'test-secret',
  };
}

function createMockRegistration(overrides: Record<string, unknown> = {}) {
  return {
    registration_id: 'reg-001',
    agent_id: 'agent-test-123',
    callback_url: 'https://example.com/webhook',
    secret: 'whsec_test123',
    events: ['trace.created'],
    failure_count: 0,
    ...overrides,
  };
}

// ============================================================================
// Tests: determineAAPEventTypes
// ============================================================================

describe('determineAAPEventTypes', () => {
  it('returns trace.created for a basic trace', () => {
    const trace = createMockTrace();
    const events = determineAAPEventTypes(trace, null, null);
    expect(events).toEqual(['trace.created']);
  });

  it('includes trace.verified when verification passed', () => {
    const trace = createMockTrace();
    const verification = createMockVerification({ passed: true });
    const events = determineAAPEventTypes(trace, verification, null);
    expect(events).toContain('trace.created');
    expect(events).toContain('trace.verified');
    expect(events).not.toContain('trace.failed');
  });

  it('includes trace.failed when verification failed', () => {
    const trace = createMockTrace();
    const verification = createMockVerification({ passed: false });
    const events = determineAAPEventTypes(trace, verification, null);
    expect(events).toContain('trace.created');
    expect(events).toContain('trace.failed');
    expect(events).not.toContain('trace.verified');
  });

  it('includes trace.escalation_required when escalation is required', () => {
    const trace = createMockTrace({
      escalation: {
        evaluated: true,
        required: true,
        reason: 'Sensitive content detected',
      },
    });
    const events = determineAAPEventTypes(trace, null, null);
    expect(events).toContain('trace.escalation_required');
  });

  it('includes policy.violation when policy verdict is deny', () => {
    const trace = createMockTrace();
    const policyResult: EvaluationResult = {
      verdict: 'deny',
      violations: [{ rule: 'no-pii', message: 'PII detected' }],
      warnings: [],
    };
    const events = determineAAPEventTypes(trace, null, policyResult);
    expect(events).toContain('policy.violation');
  });

  it('includes all events when all conditions are met', () => {
    const trace = createMockTrace({
      escalation: {
        evaluated: true,
        required: true,
        reason: 'Sensitive content',
      },
    });
    const verification = createMockVerification({ passed: false });
    const policyResult: EvaluationResult = {
      verdict: 'deny',
      violations: [{ rule: 'test', message: 'test' }],
      warnings: [],
    };
    const events = determineAAPEventTypes(trace, verification, policyResult);
    expect(events).toContain('trace.created');
    expect(events).toContain('trace.failed');
    expect(events).toContain('trace.escalation_required');
    expect(events).toContain('policy.violation');
    expect(events).toHaveLength(4);
  });
});

// ============================================================================
// Tests: deliverAAPWebhooks
// ============================================================================

describe('deliverAAPWebhooks', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does nothing when no registrations exist', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [],
    });

    const trace = createMockTrace();
    const env = createMockEnv();

    await deliverAAPWebhooks(trace, null, null, env);

    // Only the registration fetch should have been called
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockFetch.mock.calls[0][0]).toContain('aip_webhook_registrations');
  });

  it('delivers webhook with correct payload to matching registration', async () => {
    const reg = createMockRegistration({ events: ['trace.created'] });

    // Mock: fetch registrations
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [reg],
    });
    // Mock: webhook delivery (success)
    mockFetch.mockResolvedValueOnce({ ok: true });
    // Mock: delivery record
    mockFetch.mockResolvedValueOnce({ ok: true });

    const trace = createMockTrace();
    const env = createMockEnv();

    await deliverAAPWebhooks(trace, null, null, env);

    // Registration fetch + webhook delivery + delivery record = 3
    expect(mockFetch).toHaveBeenCalledTimes(3);

    // Check webhook delivery call
    const webhookCall = mockFetch.mock.calls[1];
    expect(webhookCall[0]).toBe('https://example.com/webhook');
    expect(webhookCall[1].method).toBe('POST');

    const body = JSON.parse(webhookCall[1].body);
    expect(body.event).toBe('trace.created');
    expect(body.trace.trace_id).toBe(trace.trace_id);
    expect(body.trace.agent_id).toBe(trace.agent_id);
  });

  it('sends correct X-AAP-Signature header', async () => {
    const secret = 'whsec_test_hmac';
    const reg = createMockRegistration({ secret, events: ['trace.created'] });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [reg],
    });
    mockFetch.mockResolvedValueOnce({ ok: true });
    mockFetch.mockResolvedValueOnce({ ok: true });

    const trace = createMockTrace();
    const env = createMockEnv();

    await deliverAAPWebhooks(trace, null, null, env);

    const webhookCall = mockFetch.mock.calls[1];
    const headers = webhookCall[1].headers;

    // Verify signature format
    expect(headers['X-AAP-Signature']).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(headers['X-AAP-Version']).toBe('1.0');

    // Verify HMAC is computed correctly
    const payloadString = webhookCall[1].body;
    const expectedSig = await hmacSign(secret, payloadString);
    expect(headers['X-AAP-Signature']).toBe(`sha256=${expectedSig}`);
  });

  it('retries on failure then records failed delivery', async () => {
    const reg = createMockRegistration({ events: ['trace.created'], failure_count: 2 });

    // Mock: fetch registrations
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [reg],
    });
    // Mock: 4 webhook delivery attempts (1 initial + 3 retries), all fail
    mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });
    mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });
    mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });
    mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });
    // Mock: delivery record
    mockFetch.mockResolvedValueOnce({ ok: true });
    // Mock: failure_count increment
    mockFetch.mockResolvedValueOnce({ ok: true });

    const trace = createMockTrace();
    const env = createMockEnv();

    await deliverAAPWebhooks(trace, null, null, env);

    // 1 reg fetch + 4 delivery attempts + 1 delivery record + 1 failure PATCH = 7
    expect(mockFetch).toHaveBeenCalledTimes(7);

    // Verify delivery record shows failed with 4 attempts
    const deliveryRecordCall = mockFetch.mock.calls[5];
    expect(deliveryRecordCall[0]).toContain('aip_webhook_deliveries');
    const deliveryBody = JSON.parse(deliveryRecordCall[1].body);
    expect(deliveryBody.status).toBe('failed');
    expect(deliveryBody.attempts).toBe(4);
    expect(deliveryBody.trace_id).toBe(trace.trace_id);
    expect(deliveryBody.checkpoint_id).toBeNull();
  });

  it('records delivery with trace_id and null checkpoint_id', async () => {
    const reg = createMockRegistration({ events: ['trace.created'] });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [reg],
    });
    mockFetch.mockResolvedValueOnce({ ok: true });
    mockFetch.mockResolvedValueOnce({ ok: true });

    const trace = createMockTrace();
    const env = createMockEnv();

    await deliverAAPWebhooks(trace, null, null, env);

    const deliveryCall = mockFetch.mock.calls[2];
    expect(deliveryCall[0]).toContain('aip_webhook_deliveries');
    expect(deliveryCall[1].method).toBe('POST');

    const body = JSON.parse(deliveryCall[1].body);
    expect(body.trace_id).toBe(trace.trace_id);
    expect(body.checkpoint_id).toBeNull();
    expect(body.status).toBe('success');
    expect(body.event_type).toBe('trace.created');
    expect(body.registration_id).toBe('reg-001');
    expect(body.id).toMatch(/^del-[0-9a-f]+$/);
  });

  it('increments failure_count when all retries exhausted', async () => {
    const reg = createMockRegistration({ events: ['trace.created'], failure_count: 3 });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [reg],
    });
    // 4 failed delivery attempts
    for (let i = 0; i < 4; i++) {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 502 });
    }
    // Delivery record
    mockFetch.mockResolvedValueOnce({ ok: true });
    // Failure count PATCH
    mockFetch.mockResolvedValueOnce({ ok: true });

    const trace = createMockTrace();
    const env = createMockEnv();

    await deliverAAPWebhooks(trace, null, null, env);

    // Check the PATCH call to increment failure_count
    const patchCall = mockFetch.mock.calls[6];
    expect(patchCall[0]).toContain('aip_webhook_registrations');
    expect(patchCall[0]).toContain('registration_id=eq.reg-001');
    expect(patchCall[1].method).toBe('PATCH');

    const patchBody = JSON.parse(patchCall[1].body);
    expect(patchBody.failure_count).toBe(4); // 3 + 1
  });

  it('matches wildcard events (* and trace.*)', async () => {
    const wildcardReg = createMockRegistration({
      registration_id: 'reg-wildcard',
      events: ['*'],
    });
    const traceWildcardReg = createMockRegistration({
      registration_id: 'reg-trace-wildcard',
      events: ['trace.*'],
    });
    const noMatchReg = createMockRegistration({
      registration_id: 'reg-nomatch',
      events: ['policy.violation'],
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [wildcardReg, traceWildcardReg, noMatchReg],
    });
    // Webhook deliveries for 2 matching registrations
    mockFetch.mockResolvedValueOnce({ ok: true }); // wildcard delivery
    mockFetch.mockResolvedValueOnce({ ok: true }); // wildcard record
    mockFetch.mockResolvedValueOnce({ ok: true }); // trace.* delivery
    mockFetch.mockResolvedValueOnce({ ok: true }); // trace.* record

    const trace = createMockTrace();
    const env = createMockEnv();

    await deliverAAPWebhooks(trace, null, null, env);

    // 1 reg fetch + 2 deliveries + 2 records = 5
    expect(mockFetch).toHaveBeenCalledTimes(5);

    // First webhook delivery goes to wildcard
    expect(mockFetch.mock.calls[1][0]).toBe('https://example.com/webhook');
    // Third call is trace.* delivery
    expect(mockFetch.mock.calls[3][0]).toBe('https://example.com/webhook');
  });
});
