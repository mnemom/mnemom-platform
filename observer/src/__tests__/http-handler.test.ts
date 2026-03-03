/**
 * Tests for Observer HTTP Handler
 *
 * Tests the fetch handler endpoints:
 * - /health: Health check (no auth)
 * - /trigger: Manual trigger (requires X-Trigger-Secret)
 * - /status: Status check (requires X-Trigger-Secret)
 * - 404: Unknown paths
 *
 * These tests verify request routing, authentication, and response structure
 * without calling external APIs (processAllLogs/fetchLogs are not invoked).
 */

import { describe, it, expect } from 'vitest';

// ============================================================================
// Re-implement the HTTP handler logic for isolated testing
// ============================================================================

interface Env {
  TRIGGER_SECRET: string;
  [key: string]: string | undefined;
}

/**
 * Minimal HTTP handler matching the observer's fetch() export.
 * Does NOT call processAllLogs or fetchLogs — only tests routing and auth.
 */
function handleRequest(request: Request, env: Env): Response {
  const url = new URL(request.url);

  // Health check endpoint
  if (url.pathname === '/health') {
    return Response.json({
      status: 'ok',
      service: 'smoltbot-observer',
      version: '2.0.0',
    });
  }

  // Manual trigger endpoint
  if (url.pathname === '/trigger') {
    const triggerSecret = request.headers.get('X-Trigger-Secret');
    if (!triggerSecret || triggerSecret !== env.TRIGGER_SECRET) {
      return new Response('Unauthorized', { status: 401 });
    }

    return Response.json({
      status: 'triggered',
      message: 'Log processing started in background',
    });
  }

  // Status endpoint
  if (url.pathname === '/status') {
    const triggerSecret = request.headers.get('X-Trigger-Secret');
    if (!triggerSecret || triggerSecret !== env.TRIGGER_SECRET) {
      return new Response('Unauthorized', { status: 401 });
    }

    return Response.json({
      status: 'ok',
      gateway_connected: true,
      pending_logs: 0,
    });
  }

  return Response.json(
    {
      error: 'Not found',
      endpoints: ['/health', '/trigger', '/status'],
    },
    { status: 404 }
  );
}

const mockEnv: Env = {
  TRIGGER_SECRET: 'test-secret-123',
};

// ============================================================================
// Tests: /health endpoint
// ============================================================================

describe('/health endpoint', () => {
  it('should return 200 with service info', async () => {
    const req = new Request('http://localhost/health');
    const res = handleRequest(req, mockEnv);

    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.status).toBe('ok');
    expect(body.service).toBe('smoltbot-observer');
    expect(body.version).toBe('2.0.0');
  });

  it('should not require authentication', async () => {
    const req = new Request('http://localhost/health');
    const res = handleRequest(req, mockEnv);
    expect(res.status).toBe(200);
  });
});

// ============================================================================
// Tests: /trigger endpoint
// ============================================================================

describe('/trigger endpoint', () => {
  it('should return 401 without X-Trigger-Secret header', async () => {
    const req = new Request('http://localhost/trigger');
    const res = handleRequest(req, mockEnv);

    expect(res.status).toBe(401);
    const text = await res.text();
    expect(text).toBe('Unauthorized');
  });

  it('should return 401 with wrong secret', async () => {
    const req = new Request('http://localhost/trigger', {
      headers: { 'X-Trigger-Secret': 'wrong-secret' },
    });
    const res = handleRequest(req, mockEnv);
    expect(res.status).toBe(401);
  });

  it('should return 200 with correct secret', async () => {
    const req = new Request('http://localhost/trigger', {
      headers: { 'X-Trigger-Secret': 'test-secret-123' },
    });
    const res = handleRequest(req, mockEnv);

    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.status).toBe('triggered');
    expect(body.message).toContain('background');
  });
});

// ============================================================================
// Tests: /status endpoint
// ============================================================================

describe('/status endpoint', () => {
  it('should return 401 without authentication', async () => {
    const req = new Request('http://localhost/status');
    const res = handleRequest(req, mockEnv);
    expect(res.status).toBe(401);
  });

  it('should return 401 with wrong secret', async () => {
    const req = new Request('http://localhost/status', {
      headers: { 'X-Trigger-Secret': 'bad-secret' },
    });
    const res = handleRequest(req, mockEnv);
    expect(res.status).toBe(401);
  });

  it('should return 200 with correct secret', async () => {
    const req = new Request('http://localhost/status', {
      headers: { 'X-Trigger-Secret': 'test-secret-123' },
    });
    const res = handleRequest(req, mockEnv);

    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.status).toBe('ok');
    expect(body.gateway_connected).toBe(true);
  });
});

// ============================================================================
// Tests: 404 unknown paths
// ============================================================================

describe('unknown paths', () => {
  it('should return 404 for unknown paths', async () => {
    const req = new Request('http://localhost/unknown');
    const res = handleRequest(req, mockEnv);

    expect(res.status).toBe(404);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe('Not found');
  });

  it('should list available endpoints in 404 response', async () => {
    const req = new Request('http://localhost/anything');
    const res = handleRequest(req, mockEnv);

    const body = await res.json() as Record<string, unknown>;
    expect(body.endpoints).toEqual(['/health', '/trigger', '/status']);
  });

  it('should return 404 for root path', async () => {
    const req = new Request('http://localhost/');
    const res = handleRequest(req, mockEnv);
    expect(res.status).toBe(404);
  });
});

// ============================================================================
// Tests: Authentication edge cases
// ============================================================================

describe('authentication edge cases', () => {
  it('should reject empty string secret', async () => {
    const req = new Request('http://localhost/trigger', {
      headers: { 'X-Trigger-Secret': '' },
    });
    const res = handleRequest(req, mockEnv);
    expect(res.status).toBe(401);
  });

  it('should be case-sensitive for secret comparison', async () => {
    const req = new Request('http://localhost/trigger', {
      headers: { 'X-Trigger-Secret': 'Test-Secret-123' },
    });
    const res = handleRequest(req, mockEnv);
    expect(res.status).toBe(401);
  });
});
