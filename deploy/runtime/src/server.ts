/**
 * HTTP Server — Hono-based request handling for self-hosted deployment
 *
 * Responsibilities:
 *   1. Creates the Hono app with health, metrics, and CORS middleware
 *   2. Routes HTTP requests to the gateway worker's fetch() handler
 *   3. Creates a NodeExecutionContext per request and drains it after response
 *   4. Instruments requests with Prometheus metrics
 *   5. Exports createApp() for use by the entrypoint
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

import type { KVNamespace } from './kv-adapter.js';
import { NodeExecutionContext } from './execution-context.js';
import { healthApp, configureHealth, markReady } from './health.js';
import { metricsApp, incRequests, startRequestTimer, incAipCheck } from './metrics.js';
import { buildGatewayEnv, type GatewayEnv } from './env-builder.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ServerConfig {
  kv: KVNamespace;
  gatewayWorker: {
    fetch(request: Request, env: GatewayEnv, ctx: NodeExecutionContext): Promise<Response>;
  };
}

// ---------------------------------------------------------------------------
// App factory
// ---------------------------------------------------------------------------

export function createApp(config: ServerConfig): Hono {
  const app = new Hono();

  // Build the gateway environment once (env vars do not change at runtime)
  const gatewayEnv = buildGatewayEnv(config.kv);

  // Configure health probes with dependencies
  configureHealth({
    supabaseUrl: gatewayEnv.SUPABASE_URL,
    kv: config.kv,
    licenseJwt: gatewayEnv.MNEMOM_LICENSE_JWT,
  });

  // -------------------------------------------------------------------------
  // Middleware
  // -------------------------------------------------------------------------

  // CORS — match the headers the CF worker exposes
  app.use(
    '*',
    cors({
      origin: '*',
      allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowHeaders: [
        'Content-Type',
        'x-api-key',
        'anthropic-version',
        'anthropic-beta',
        'authorization',
        'x-goog-api-key',
        'x-mnemom-api-key',
      ],
      exposeHeaders: [
        'x-mnemom-agent',
        'x-mnemom-session',
        'X-AIP-Verdict',
        'X-AIP-Checkpoint-Id',
        'X-AIP-Action',
        'X-AIP-Proceed',
        'X-AIP-Synthetic',
        'X-Mnemom-Usage-Warning',
        'X-Mnemom-Usage-Percent',
      ],
      maxAge: 86400,
    }),
  );

  // -------------------------------------------------------------------------
  // Health + Metrics sub-apps
  // -------------------------------------------------------------------------

  app.route('/', healthApp);
  app.route('/', metricsApp);

  // -------------------------------------------------------------------------
  // Gateway proxy — all other routes
  // -------------------------------------------------------------------------

  app.all('*', async (c) => {
    // Determine provider from path for metrics labeling
    const path = new URL(c.req.url).pathname;
    const providerMatch = path.match(/^\/(anthropic|openai|gemini)/);
    const provider = providerMatch?.[1] ?? 'unknown';

    // Start request timer for Prometheus histogram
    const endTimer = startRequestTimer(provider);

    // Create a per-request execution context
    const ctx = new NodeExecutionContext();

    try {
      // Delegate to the gateway worker's fetch handler.
      // The gateway expects a standard Request object.
      const request = new Request(c.req.url, {
        method: c.req.method,
        headers: c.req.raw.headers,
        body: c.req.raw.body,
        // Required for streaming request bodies on Node.js 22+
        ...(c.req.method !== 'GET' && c.req.method !== 'HEAD'
          ? { duplex: 'half' as const }
          : {}),
      });

      const response = await config.gatewayWorker.fetch(
        request,
        gatewayEnv,
        ctx,
      );

      // Record metrics
      const status = response.status;
      incRequests(provider, status);
      endTimer();

      // Extract AIP verdict for metrics if present
      const verdict = response.headers.get('X-AIP-Verdict');
      if (verdict) {
        incAipCheck(verdict);
      }

      // Drain background promises after sending the response.
      // We do not await this in the hot path — schedule it as a microtask.
      ctx.drain().catch((err) => {
        console.error('[server] Error draining execution context:', err);
      });

      // Return the response by copying status, headers, and body
      const body = response.body;
      return new Response(body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    } catch (err) {
      endTimer();
      incRequests(provider, 500);

      console.error('[server] Unhandled error in gateway handler:', err);

      // Drain any background work even on error
      ctx.drain().catch(() => {});

      return c.json(
        {
          error: 'Internal server error',
          type: 'gateway_error',
          message: err instanceof Error ? err.message : 'Unknown error',
        },
        500,
      );
    }
  });

  return app;
}

export { markReady };
