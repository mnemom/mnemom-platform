/**
 * Entrypoint — main entry point for the self-hosted mnemom runtime
 *
 * Orchestrates:
 *   1. Structured logger initialization
 *   2. Environment validation and KV adapter creation
 *   3. Fetch interceptor installation (AI Gateway URL rewriting)
 *   4. HTTP server creation and startup
 *   5. Cron scheduler for observer and API scheduled handlers
 *   6. Heartbeat client for license compliance
 *   7. Graceful shutdown on SIGTERM/SIGINT
 *
 * Supports MNEMOM_ROLE env var:
 *   - "gateway"   — HTTP server only (no cron jobs)
 *   - "scheduler" — Cron jobs only (no HTTP server)
 *   - "all"       — Both HTTP server and cron jobs (default)
 */

import { serve } from '@hono/node-server';
import cron from 'node-cron';

import { initLogger, logger } from './logger.js';
import { createKVAdapter } from './kv-adapter.js';
import { installFetchInterceptor } from './fetch-interceptor.js';
import { createApp, markReady } from './server.js';
import { buildObserverEnv, buildApiEnv } from './env-builder.js';
import { NodeExecutionContext } from './execution-context.js';
import { startHeartbeat, stopHeartbeat } from './heartbeat.js';
import { incCronRun } from './metrics.js';

// ---------------------------------------------------------------------------
// Role configuration
// ---------------------------------------------------------------------------

type Role = 'gateway' | 'scheduler' | 'all';

function getRole(): Role {
  const role = process.env.MNEMOM_ROLE?.toLowerCase();
  if (role === 'gateway' || role === 'scheduler' || role === 'all') {
    return role;
  }
  return 'all';
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // 1. Initialize structured logger
  const role = getRole();
  initLogger({
    level: process.env.LOG_LEVEL,
    service: `mnemom-${role}`,
  });

  logger.info(`Starting mnemom self-hosted runtime (role=${role})`);
  logger.info(`Node.js ${process.version}, platform=${process.platform}`);

  // 2. Install fetch interceptor for AI Gateway URL rewriting
  installFetchInterceptor();
  logger.info('Fetch interceptor installed');

  // 3. Create KV adapter (Redis or in-memory)
  const kv = createKVAdapter(process.env.REDIS_URL);
  logger.info(
    process.env.REDIS_URL
      ? 'KV adapter: Redis'
      : 'KV adapter: in-memory (set REDIS_URL for Redis)',
  );

  // Track active cron tasks and server for cleanup
  const cronTasks: cron.ScheduledTask[] = [];
  let httpServer: ReturnType<typeof serve> | null = null;
  let stopHeartbeatFn: (() => void) | null = null;

  // 4. Start HTTP server (gateway + scheduler roles)
  if (role === 'gateway' || role === 'all') {
    // Dynamically import the gateway worker module.
    // In production, the gateway worker is bundled alongside this runtime.
    // The path is configurable via GATEWAY_WORKER_PATH for flexibility.
    const gatewayPath =
      process.env.GATEWAY_WORKER_PATH ?? '../../../gateway/src/index.js';

    let gatewayWorker: any;
    try {
      gatewayWorker = await import(gatewayPath);
      // Handle both default export and named export patterns
      gatewayWorker = gatewayWorker.default ?? gatewayWorker;
    } catch (err) {
      logger.error('Failed to import gateway worker module:', err);
      logger.info(
        'Set GATEWAY_WORKER_PATH to the correct path for your deployment.',
      );
      process.exit(1);
    }

    const app = createApp({ kv, gatewayWorker });

    const port = parseInt(process.env.PORT ?? '8787', 10);
    const host = process.env.HOST ?? '0.0.0.0';

    httpServer = serve({
      fetch: app.fetch,
      port,
      hostname: host,
    });

    logger.info(`HTTP server listening on ${host}:${port}`);
  }

  // 5. Start cron scheduler (scheduler + all roles)
  if (role === 'scheduler' || role === 'all') {
    // Observer cron: every minute
    const observerEnv = buildObserverEnv();

    const observerPath =
      process.env.OBSERVER_WORKER_PATH ?? '../../../observer/src/index.js';

    let observerWorker: any;
    try {
      observerWorker = await import(observerPath);
      observerWorker = observerWorker.default ?? observerWorker;
    } catch (err) {
      logger.warn('Failed to import observer worker module:', err);
      logger.info(
        'Observer cron will be disabled. Set OBSERVER_WORKER_PATH if needed.',
      );
    }

    if (observerWorker?.scheduled) {
      const observerTask = cron.schedule('* * * * *', async () => {
        logger.info('[cron] Running observer scheduled handler');
        const ctx = new NodeExecutionContext();
        try {
          const event = { scheduledTime: Date.now(), cron: '* * * * *' };
          await observerWorker.scheduled(event, observerEnv, ctx);
          await ctx.drain();
          incCronRun('observer', 'success');
          logger.info('[cron] Observer scheduled handler complete');
        } catch (err) {
          incCronRun('observer', 'error');
          logger.error('[cron] Observer scheduled handler failed:', err);
          await ctx.drain().catch(() => {});
        }
      });
      cronTasks.push(observerTask);
      logger.info('Cron scheduled: observer (every minute)');
    }

    // API cron: every 6 hours
    const apiEnv = buildApiEnv(kv);

    const apiPath =
      process.env.API_WORKER_PATH ?? '../../../api/src/index.js';

    let apiWorker: any;
    try {
      apiWorker = await import(apiPath);
      apiWorker = apiWorker.default ?? apiWorker;
    } catch (err) {
      logger.warn('Failed to import API worker module:', err);
      logger.info(
        'API cron will be disabled. Set API_WORKER_PATH if needed.',
      );
    }

    if (apiWorker?.scheduled) {
      const apiTask = cron.schedule('0 */6 * * *', async () => {
        logger.info('[cron] Running API scheduled handler');
        const ctx = new NodeExecutionContext();
        try {
          const event = { scheduledTime: Date.now(), cron: '0 */6 * * *' };
          await apiWorker.scheduled(event, apiEnv, ctx);
          await ctx.drain();
          incCronRun('api', 'success');
          logger.info('[cron] API scheduled handler complete');
        } catch (err) {
          incCronRun('api', 'error');
          logger.error('[cron] API scheduled handler failed:', err);
          await ctx.drain().catch(() => {});
        }
      });
      cronTasks.push(apiTask);
      logger.info('Cron scheduled: api (every 6 hours)');
    }
  }

  // 6. Start heartbeat client
  const deploymentId =
    process.env.DEPLOYMENT_ID ?? `selfhosted-${process.env.HOSTNAME ?? 'local'}`;
  const version = process.env.GATEWAY_VERSION ?? '1.0.0-selfhosted';

  if (process.env.MNEMOM_LICENSE_JWT) {
    stopHeartbeatFn = startHeartbeat({
      deploymentId,
      licenseJwt: process.env.MNEMOM_LICENSE_JWT,
      version,
      heartbeatUrl: process.env.HEARTBEAT_URL,
      intervalMs: 60_000,
    });
    logger.info('Heartbeat client started (60s interval)');
  } else {
    logger.info('Heartbeat client skipped (no MNEMOM_LICENSE_JWT)');
  }

  // 7. Mark as ready
  markReady();
  logger.info('Startup complete — ready to serve requests');

  // 8. Graceful shutdown
  let isShuttingDown = false;

  async function shutdown(signal: string): Promise<void> {
    if (isShuttingDown) return;
    isShuttingDown = true;

    logger.info(`Received ${signal} — starting graceful shutdown`);

    // Stop accepting new cron jobs
    for (const task of cronTasks) {
      task.stop();
    }

    // Stop heartbeat
    if (stopHeartbeatFn) {
      stopHeartbeatFn();
    }
    stopHeartbeat();

    // Close HTTP server
    if (httpServer) {
      await new Promise<void>((resolve) => {
        httpServer!.close(() => resolve());
        // Force close after 15s
        setTimeout(() => {
          logger.warn('HTTP server close timed out, forcing shutdown');
          resolve();
        }, 15_000).unref();
      });
    }

    logger.info('Graceful shutdown complete');
    process.exit(0);
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
