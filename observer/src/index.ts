/**
 * Mnemom Observer Worker (mnemom-platform)
 *
 * Processes logs from Cloudflare AI Gateway, extracts thinking blocks,
 * analyzes decisions with Claude Haiku, builds AP-Traces, verifies against
 * alignment cards, and stores traces for transparency.
 *
 * AAP SDK Integration:
 * - Uses verifyTrace() to validate traces against alignment cards
 * - Uses detectDrift() to identify behavioral drift patterns
 * - All trace structures conform to APTrace interface
 *
 * AIP is handled by the gateway via real-time stream interception.
 * The observer links its traces to gateway-created checkpoints.
 */

import {
  verifyTrace,
  detectDrift,
  type APTrace,
  type AlignmentCard,
  type Action,
  type Decision,
  type Escalation,
  type VerificationResult,
  type DriftAlert,
  type TraceContext,
} from '@mnemom/agent-alignment-protocol';

import { createWorkersExporter, type WorkersOTelExporter } from '@mnemom/aip-otel-exporter/workers';
import { mapUnifiedCardToAAP, fetchCanonicalAlignmentCard } from './card-mappers';
// Note: fetchCanonicalAlignmentCardRaw returns the unified-shape card without
// mapping — used by the policy-eval block, which needs the unified capabilities
// + enforcement sections. Defined inline at the call site for clarity.
import {
  evaluatePolicy,
  // UC-8: mergePolicies removed from the public API; policy is derived from
  // the canonical card inside evaluatePolicy.
  type Policy,
  type EvaluationResult,
  type ToolReference,
} from '@mnemom/policy-engine';
import { createCircuitBreaker, checkAndReset, recordSuccess, recordFailure } from './circuit-breaker';
import { computeBandHashes, deserializeMinHash } from '@mnemom/safe-house';
import { fetchR2Batch } from './r2-ingest';
import type { ObserverQueueMessage } from './queue-types';
import { enqueueR2Records, enqueuePollingLogs } from './queue-producer';
import { handleQueueBatch } from './queue-consumer';
import {
  emitQueueBatchSpan,
  emitQueueBacklogSpans,
  fetchQueueDepths,
} from './metrics';

const AAP_VERSION = '1.0';
const AAP_WEBHOOK_RETRY_DELAYS_MS = [1000, 5000, 15000];

// DLQ retry backoff schedule (indexed by attempts - 4, since inline delivery uses 4 attempts)
// 1min, 5min, 30min, 2hr, 6hr, 24hr
const DLQ_BACKOFF_MS = [60_000, 300_000, 1_800_000, 7_200_000, 21_600_000, 86_400_000];
const DLQ_MAX_ATTEMPTS = 10;

// ============================================================================
// Supabase Fetch — 5s Timeout + Circuit Breaker
// ============================================================================

const observerSupabaseCircuitBreaker = createCircuitBreaker(3, 30000);

/** Reset observer circuit breaker state — for use in tests only. */
export function _resetObserverCircuitBreakerForTests(): void {
  observerSupabaseCircuitBreaker.failures = 0;
  observerSupabaseCircuitBreaker.lastFailure = 0;
  observerSupabaseCircuitBreaker.isOpen = false;
}

/**
 * Drop-in replacement for fetch() on all observer Supabase REST/RPC calls.
 * Adds 5s AbortController timeout and circuit breaker protection.
 * Callers retain their existing error handling and safe defaults.
 */
async function observerSupabaseFetch(url: string, options: RequestInit): Promise<Response> {
  checkAndReset(observerSupabaseCircuitBreaker, 'observer-supabase');
  if (observerSupabaseCircuitBreaker.isOpen) {
    throw new Error('[observer-supabase] Circuit open — DB temporarily unavailable');
  }
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    recordSuccess(observerSupabaseCircuitBreaker, 'observer-supabase');
    return response;
  } catch (err) {
    recordFailure(observerSupabaseCircuitBreaker, 'observer-supabase');
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

/** Exported for integration testing only. */
export { observerSupabaseFetch as _observerSupabaseFetchForTests };

// ============================================================================
// Types
// ============================================================================

interface Env {
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
  CF_AI_GATEWAY_URL?: string;
  GATEWAY_ID: string;
  SUPABASE_URL: string;
  SUPABASE_SECRET_KEY: string;
  ANTHROPIC_API_KEY: string;
  ANALYSIS_API_KEY?: string;
  OTLP_ENDPOINT?: string;
  OTLP_AUTH?: string;
  STRIPE_SECRET_KEY?: string;
  TRIGGER_SECRET: string;
  PROVER_URL?: string;
  PROVER_API_KEY?: string;
  OBSERVER_MAX_LOGS?: string; // Max logs per cron tick; default "5000"; parsed as int
  BILLING_CACHE?: KVNamespace; // Shared KV namespace with gateway — used for LSH index
  SLACK_WEBHOOK_URL?: string; // Slack incoming webhook for DLQ dead-letter alerts
  // R2-based log ingestion (ADR-009, ADR-026, scale/step-49).
  // LOGPUSH_SOURCE="r2" reads from GATEWAY_LOGS_BUCKET first; any failure or empty
  // list falls through to the CF AI Gateway REST polling path on the same tick.
  // Default "polling" preserves pre-step-49 behavior.
  LOGPUSH_SOURCE?: string;
  GATEWAY_LOGS_BUCKET?: R2Bucket;
  LOGPUSH_DECRYPT_PRIVATE_KEY?: string;
  // Cap on R2 objects fetched per tick. Each object holds one record in practice;
  // OBSERVER_MAX_LOGS still bounds total records processed across both sources.
  OBSERVER_MAX_R2_OBJECTS?: string;
  // BetterStack heartbeat URL. Observer POSTs here after every successful cron
  // tick; missing posts within the BS grace window trigger a paging incident.
  // Set per-env (prod period=60s, staging period=300s). Absence = no-op.
  BETTERSTACK_HEARTBEAT_URL?: string;
  // Queue fan-out (Step 50, ADR-010). OBSERVER_PROCESSING_MODE selects the
  // scheduled()-tick pipeline:
  //   "direct" (default) — cron ingests and processes records in-invocation
  //   "queue"             — cron only enqueues; consumer runs elsewhere
  // OBSERVER_QUEUE is the producer binding (declared in wrangler.toml
  // [[queues.producers]]). The consumer binding is declared separately via
  // [[queues.consumers]] and routes into the queue() handler on this Worker.
  OBSERVER_PROCESSING_MODE?: string;
  OBSERVER_QUEUE?: Queue<ObserverQueueMessage>;
}

interface GatewayLog {
  id: string;
  created_at: string;
  provider: string;
  model: string;
  success: boolean;
  tokens_in: number;
  tokens_out: number;
  duration: number;
  // CF AI Gateway returns metadata as a JSON string, not a parsed object.
  // Must be parsed before accessing fields like agent_id.
  metadata?: string | Record<string, string>;
}

interface GatewayMetadata {
  agent_id: string;
  agent_hash: string;
  session_id: string;
  timestamp?: string; // No longer sent — CF log created_at is used instead
  gateway_version: string;
  agent_name?: string;
}

interface HaikuAnalysis {
  alternatives: Array<{ id: string; description: string }>;
  selected: string;
  reasoning: string;
  values_applied: string[];
  content_flags?: Record<string, boolean>;
}

interface ExtractedContext {
  thinking: string | null;
  toolCalls: Array<{ name: string; input: Record<string, unknown> }>;
  userQuery: string | null;
  responseText: string | null;
}

interface ProcessingStats {
  processed: number;
  skipped: number;
  logs_fetched: number;
  errors: number;
}

// ============================================================================
// Worker Export
// ============================================================================

export default {
  /**
   * Queue consumer — ADR-010. Receives a batch of ObserverQueueMessage
   * items and drives each through processLog with the appropriate prefetched
   * body payload (re-fetched/decrypted from R2 or re-fetched from CF polling).
   *
   * Active only when [[queues.consumers]] routes this Worker to the observer
   * queue. The direct-mode path (OBSERVER_PROCESSING_MODE="direct") does not
   * enqueue, so the consumer sees empty traffic in that mode.
   */
  async queue(
    batch: MessageBatch<ObserverQueueMessage>,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    const otelExporter = createOTelExporter(env);
    const stats = await handleQueueBatch(
      batch,
      env as unknown as Parameters<typeof handleQueueBatch>[1],
      ctx,
      (log, innerEnv, innerCtx, options) =>
        processLog(log as unknown as GatewayLog, innerEnv as unknown as Env, innerCtx, otelExporter, options),
    );
    // Step 52 — emit per-batch span (+ one poison span per poison ack) alongside
    // the existing Tier 3 stats log. Fire-and-forget via waitUntil: the batch has
    // already been acked by now, so span emission failures don't risk replay.
    // Spans flow through the supported /v1/traces path per ADR-032.
    ctx.waitUntil(emitQueueBatchSpan(env, stats));
    if (otelExporter) {
      ctx.waitUntil(otelExporter.flush());
    }
  },

  /**
   * Cron trigger - runs every minute to process new logs
   */
  async scheduled(
    event: ScheduledEvent,
    env: Env,
    ctx: ExecutionContext
  ): Promise<void> {
    console.log('[observer] Scheduled trigger started');

    // BetterStack heartbeat — emitted immediately on cron entry, BEFORE the
    // main processing block. Intent: prove the cron scheduler fired AND the
    // Worker reached the handler. If processAllLogs later exhausts CPU budget
    // or throws, the heartbeat has already been queued via waitUntil.
    // Positioned here (not at the end of the try block) because prod ticks
    // routinely process thousands of logs per invocation and occasionally
    // exceed CF's per-invocation time budget (Outcome: unknown), which would
    // silently skip a trailing heartbeat. Fire-and-forget; a failed POST logs
    // a warning but never affects cron operation.
    if (env.BETTERSTACK_HEARTBEAT_URL) {
      ctx.waitUntil(
        fetch(env.BETTERSTACK_HEARTBEAT_URL, { method: 'POST' }).catch((err) => {
          console.warn(
            `[observer] heartbeat post failed: ${err instanceof Error ? err.message : String(err)}`
          );
        })
      );
    }

    const otelExporter = createOTelExporter(env);

    try {
      const stats = await processAllLogs(env, ctx, otelExporter);
      console.log(
        `[observer] Completed - fetched: ${stats.logs_fetched}, processed: ${stats.processed}, skipped: ${stats.skipped}, errors: ${stats.errors}`
      );

      // Expire stale nudges (>4h old pending nudges)
      ctx.waitUntil(expireStaleNudges(env));

      // Roll up metering events for billing (idempotent, safe every tick)
      ctx.waitUntil(triggerMeteringRollup(env));

      // Safe House pattern auto-promotion (every 5 minutes when enabled)
      const now = new Date();
      const now5 = now;
      if (now5.getUTCMinutes() % 5 === 0) {
        ctx.waitUntil(runSHAutoPromotion(env));
      }

      // Webhook DLQ retry scheduler (every 5 minutes, offset from auto-promotion)
      if (now.getUTCMinutes() % 5 === 2) {
        ctx.waitUntil(retryDLQWebhooks(env));
      }

      // Safe House adaptive threshold analysis (hourly, at :30)
      if (now.getUTCMinutes() === 30) {
        ctx.waitUntil(runSHAdaptiveThresholds(env));
      }

      // Arena V2: process pending bypass events into recipes (hourly, at :45)
      if (now.getUTCMinutes() === 45) {
        ctx.waitUntil(runArenaSidebandAnalysis(env));
      }

      // Report daily usage to Stripe (midnight UTC only)
      if (now.getUTCHours() === 0 && now.getUTCMinutes() === 0) {
        ctx.waitUntil(reportDailyUsageToStripe(env));
      }

      // Run retention cleanup weekly (Sundays at midnight UTC)
      const now2 = new Date();
      // Pattern TTL expiry — stale patterns deactivated weekly
      if (now2.getUTCDay() === 0 && now2.getUTCHours() === 0 && now2.getUTCMinutes() === 0) {
        ctx.waitUntil(runSHRetentionCleanup(env));
        ctx.waitUntil(runSHPatternExpiry(env)); // NEW
      }

      // Nightly LSH index rebuild + family consolidation + orphan expiry (2:00 AM UTC)
      if (now.getUTCHours() === 2 && now.getUTCMinutes() === 0) {
        ctx.waitUntil(runSHLSHIndexRebuild(env));
        ctx.waitUntil(runSHConsolidation(env));
        ctx.waitUntil(runSHExpireOrphans(env));
      }

      // Flush OTel spans for all processed logs in one batch
      if (otelExporter) {
        ctx.waitUntil(otelExporter.flush());
      }

      // Step 52 — per-queue backlog spans (carry depth + age_seconds attrs)
      // for main + DLQ. Only relevant when the observer is running in queue
      // mode; direct mode has no backlog to measure. The fetch chain is
      // defensive: a null return from fetchQueueDepths emits nothing that
      // tick. Depth/lag alerts evaluate via TraceQL metrics (ADR-032).
      if (env.OBSERVER_PROCESSING_MODE === 'queue') {
        ctx.waitUntil(
          fetchQueueDepths(env).then((depths) => {
            if (depths) return emitQueueBacklogSpans(env, depths);
          }),
        );
      }
    } catch (error) {
      console.error('[observer] Fatal error in scheduled handler:', error);
    }
  },

  /**
   * HTTP handler - manual trigger for testing
   */
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === '/health') {
      return Response.json({
        status: 'ok',
        service: 'mnemom-observer',
        version: '2.1.0',
        build: '2026-03-03-trace-fix',
      });
    }

    // Manual trigger endpoint
    if (url.pathname === '/trigger') {
      // Authenticate: require X-Trigger-Secret header
      const triggerSecret = request.headers.get('X-Trigger-Secret');
      if (!triggerSecret || triggerSecret !== env.TRIGGER_SECRET) {
        return new Response('Unauthorized', { status: 401 });
      }

      // LSH index rebuild job (for testing without waiting for nightly cron)
      if (url.searchParams.get('job') === 'lsh_rebuild') {
        ctx.waitUntil(runSHLSHIndexRebuild(env));
        return Response.json({ status: 'triggered', job: 'lsh_rebuild' });
      }

      console.log('[observer] Manual trigger initiated');

      const otelExporter = createOTelExporter(env);

      // Run processing in background
      ctx.waitUntil(
        processAllLogs(env, ctx, otelExporter).then(async (stats) => {
          console.log(
            `[observer] Manual trigger completed - processed: ${stats.processed}`
          );
          if (otelExporter) await otelExporter.flush();
        })
      );

      return Response.json({
        status: 'triggered',
        message: 'Log processing started in background',
      });
    }

    // Status endpoint - check gateway connectivity
    if (url.pathname === '/status') {
      // Authenticate: require X-Trigger-Secret header
      const triggerSecret = request.headers.get('X-Trigger-Secret');
      if (!triggerSecret || triggerSecret !== env.TRIGGER_SECRET) {
        return new Response('Unauthorized', { status: 401 });
      }

      try {
        const logs = await fetchLogs(env, 1);
        return Response.json({
          status: 'ok',
          gateway_connected: true,
          pending_logs: logs.length,
        });
      } catch (error) {
        return Response.json(
          {
            status: 'error',
            gateway_connected: false,
            error: String(error),
          },
          { status: 503 }
        );
      }
    }

    return Response.json(
      {
        error: 'Not found',
        endpoints: ['/health', '/trigger', '/status'],
      },
      { status: 404 }
    );
  },
};

// ============================================================================
// OTel Exporter
// ============================================================================

function createOTelExporter(env: Env) {
  if (!env.OTLP_ENDPOINT) return null;
  return createWorkersExporter({
    endpoint: env.OTLP_ENDPOINT,
    authorization: env.OTLP_AUTH,
    serviceName: 'mnemom-observer',
  });
}

// ============================================================================
// Main Processing Logic
// ============================================================================

/**
 * Process all pending logs per cron tick.
 *
 * Sources (ADR-009, ADR-026):
 *   - "r2"      — read from R2 bucket `mnemom-gateway-logs` (dataset `ai_gateway_events`,
 *                 per-field encrypted). Primary source once Logpush is flipped on.
 *   - "polling" — read from CF AI Gateway REST API (existing path). Default and fallback.
 *
 * Selection is via env.LOGPUSH_SOURCE. On any failure in the R2 path (list/read/decrypt
 * throws, or zero usable records after a successful list), falls through to the polling
 * path on the same tick so no cron tick is silently empty.
 */
async function processAllLogs(
  env: Env,
  ctx: ExecutionContext,
  otelExporter?: WorkersOTelExporter | null
): Promise<ProcessingStats> {
  // Step 50 / ADR-010 — OBSERVER_PROCESSING_MODE="queue" flips the scheduled
  // tick into a producer: it only enqueues reference messages and returns
  // fast. The queue() handler on this same Worker consumes the messages in
  // parallel invocations. Default ("direct") preserves the pre-step-50
  // behavior where the cron invocation also runs the per-record pipeline.
  if (env.OBSERVER_PROCESSING_MODE === 'queue') {
    const stats = await runAsProducer(env);
    emitTickSummary(env, stats, `queue-producer (${env.LOGPUSH_SOURCE === 'r2' ? 'r2' : 'polling'})`);
    return stats;
  }
  const source = env.LOGPUSH_SOURCE === 'r2' ? 'r2' : 'polling';
  if (source === 'r2') {
    try {
      const r2Stats = await processR2Batch(env, ctx, otelExporter);
      if (r2Stats.logs_fetched > 0) {
        emitTickSummary(env, r2Stats, 'r2');
        return r2Stats;
      }
      console.log('[observer] R2 source empty this tick — falling through to polling');
    } catch (error) {
      console.warn(`[observer] R2 source failed — falling through to polling: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const stats = await processPollingBatch(env, ctx, otelExporter);
  emitTickSummary(env, stats, source === 'r2' ? 'polling (fallback)' : 'polling');
  return stats;
}

/**
 * Step 50 / ADR-010 producer path — enqueues reference messages for the
 * queue consumer to process. No decrypt, no Anthropic call, no Supabase
 * write happens here. Bounded by OBSERVER_MAX_R2_OBJECTS (R2 path) or the
 * standard per_page cap (polling path).
 *
 * Returns ProcessingStats shaped to match the direct-mode output so the
 * shared tick-summary + OTel span stays uniform across modes.
 */
async function runAsProducer(env: Env): Promise<ProcessingStats> {
  const stats: ProcessingStats = { processed: 0, skipped: 0, errors: 0, logs_fetched: 0 };
  const source = env.LOGPUSH_SOURCE === 'r2' ? 'r2' : 'polling';
  try {
    if (source === 'r2') {
      const objectLimit = parseInt(env.OBSERVER_MAX_R2_OBJECTS ?? '200', 10);
      const r2Stats = await enqueueR2Records(env, { maxObjects: objectLimit });
      stats.logs_fetched = r2Stats.enqueued + r2Stats.skipped_foreign_gateway;
      stats.processed = r2Stats.enqueued;
      stats.errors = r2Stats.read_errors;
      console.log(
        `[observer/producer] r2: listed=${r2Stats.listed} enqueued=${r2Stats.enqueued} ` +
        `skipped_foreign_gateway=${r2Stats.skipped_foreign_gateway} read_errors=${r2Stats.read_errors}`
      );
    } else {
      const logs = await fetchLogs(env, 50);
      const pStats = await enqueuePollingLogs(env, logs.map((l) => ({
        id: l.id,
        provider: l.provider,
        model: l.model,
        success: l.success,
      })));
      stats.logs_fetched = pStats.enqueued;
      stats.processed = pStats.enqueued;
      console.log(`[observer/producer] polling: enqueued=${pStats.enqueued}`);
    }
  } catch (error) {
    console.error('[observer/producer] Fatal error while enqueueing:', error);
    stats.errors++;
  }
  return stats;
}

/**
 * Poll CF AI Gateway REST API for pending logs.
 *
 * Fetches logs in batches until the queue is exhausted or the per-tick safety
 * limit (OBSERVER_MAX_LOGS, default 5000) is hit. Each processed/skipped log
 * is deleted from CF AI Gateway by processLog(), which advances the queue.
 * Because deletions advance the queue, we always fetch page 1 — incrementing
 * the page number would skip logs that shifted into lower positions after deletion.
 */
async function processPollingBatch(
  env: Env,
  ctx: ExecutionContext,
  otelExporter?: WorkersOTelExporter | null
): Promise<ProcessingStats> {
  const stats: ProcessingStats = { processed: 0, skipped: 0, errors: 0, logs_fetched: 0 };
  const safetyLimit = parseInt(env.OBSERVER_MAX_LOGS ?? '5000', 10);
  // CF AI Gateway `/logs` endpoint enforces per_page ≤ 50 (tightened some time after
  // Step 2 shipped; before this change, cron ticks returned HTTP 400 from CF and never
  // fetched any logs). Keep at 50 — the pagination loop below already handles multiple
  // batches per tick, bounded by OBSERVER_MAX_LOGS.
  const batchSize = 50;
  let lastBatchSize = batchSize; // initialize to batchSize to enter the loop

  try {
    do {
      const batch = await fetchLogs(env, batchSize);
      lastBatchSize = batch.length;
      stats.logs_fetched += batch.length;

      const withMeta = batch.filter((l) => l.metadata != null).length;
      console.log(
        `[observer] Batch: ${batch.length} logs (${withMeta} with metadata), total_fetched=${stats.logs_fetched}`
      );

      for (const log of batch) {
        try {
          const wasProcessed = await processLog(log, env, ctx, otelExporter);
          if (wasProcessed) {
            stats.processed++;
          } else {
            stats.skipped++;
          }
        } catch (error) {
          console.error(`[observer] Failed to process log ${log.id}:`, error);
          stats.errors++;
          // Continue processing remaining logs even if one fails
        }
      }
    } while (lastBatchSize === batchSize && stats.logs_fetched < safetyLimit);
  } catch (error) {
    console.error('[observer] Failed to fetch logs:', error);
    throw error;
  }

  return stats;
}

/**
 * Emit the structured per-tick summary (console + OTel). Shared between the
 * polling and R2 paths so dashboards see a consistent shape regardless of source.
 */
function emitTickSummary(env: Env, stats: ProcessingStats, source: string): void {
  const safetyLimit = parseInt(env.OBSERVER_MAX_LOGS ?? '5000', 10);
  const backlog_estimate = stats.logs_fetched >= safetyLimit ? `>=${safetyLimit}` : 0;
  console.log(
    JSON.stringify({
      source,
      logs_fetched: stats.logs_fetched,
      logs_processed: stats.processed,
      logs_errored: stats.errors,
      logs_skipped: stats.skipped,
      backlog_estimate,
    })
  );

  if (stats.logs_fetched >= safetyLimit) {
    console.warn(`[observer] Hit safety limit (${safetyLimit} logs) — observer may be behind`);
  }

  if (env.OTLP_ENDPOINT) {
    const traceId = crypto.randomUUID().replace(/-/g, '');
    const spanId = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
    const nowNs = String(Date.now() * 1_000_000);
    const endNs = String(Date.now() * 1_000_000 + 1_000_000);
    fetch(`${env.OTLP_ENDPOINT}/v1/traces`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(env.OTLP_AUTH ? { Authorization: env.OTLP_AUTH } : {}),
      },
      body: JSON.stringify({
        resourceSpans: [{
          resource: { attributes: [{ key: 'service.name', value: { stringValue: 'mnemom-observer' } }] },
          scopeSpans: [{
            scope: { name: 'observer.health' },
            spans: [{
              traceId, spanId, name: 'observer.cron_tick', kind: 1,
              startTimeUnixNano: nowNs, endTimeUnixNano: endNs,
              attributes: [
                { key: 'observer.source', value: { stringValue: source } },
                { key: 'observer.logs_fetched', value: { intValue: String(stats.logs_fetched) } },
                { key: 'observer.logs_processed', value: { intValue: String(stats.processed) } },
                { key: 'observer.logs_errored', value: { intValue: String(stats.errors) } },
                { key: 'observer.backlog_estimate', value: { stringValue: String(backlog_estimate) } },
              ],
            }],
          }],
        }],
      }),
    }).catch(() => {}); // fire-and-forget
  }
}

/**
 * Drive the observer pipeline from R2 (primary source under ADR-009 / ADR-026).
 *
 * For each R2 object in the batch we run each decoded record through processLog
 * with `prefetched` set, accumulating a per-object success tally. An object is
 * deleted only if every record in it is fully processed (created a trace or
 * was explicitly skipped). On any thrown error mid-object we leave the object
 * in R2 for the next tick. Until Step 51 adds trace-level idempotency this
 * retry can produce duplicate traces for the already-succeeded records in the
 * object — documented in the PR description as the tradeoff.
 *
 * Safety limit (OBSERVER_MAX_R2_OBJECTS, default 200) caps listed objects per
 * tick. OBSERVER_MAX_LOGS still bounds total records to match polling behavior.
 */
async function processR2Batch(
  env: Env,
  ctx: ExecutionContext,
  otelExporter?: WorkersOTelExporter | null
): Promise<ProcessingStats> {
  const stats: ProcessingStats = { processed: 0, skipped: 0, errors: 0, logs_fetched: 0 };
  const recordLimit = parseInt(env.OBSERVER_MAX_LOGS ?? '5000', 10);
  const objectLimit = parseInt(env.OBSERVER_MAX_R2_OBJECTS ?? '200', 10);

  const batch = await fetchR2Batch(env, { maxObjects: objectLimit });
  stats.logs_fetched = batch.totalRecords;

  console.log(
    `[observer/r2] Listed ${batch.listedKeys} objects, ${batch.totalRecords} usable records (gateway=${env.GATEWAY_ID})`
  );

  if (batch.totalRecords === 0) {
    return stats;
  }

  let recordsProcessedThisTick = 0;
  for (const obj of batch.objects) {
    if (recordsProcessedThisTick >= recordLimit) {
      console.warn(`[observer/r2] Record safety limit reached (${recordLimit}); ${batch.objects.length - batch.objects.indexOf(obj)} objects deferred to next tick`);
      break;
    }
    let allRecordsOK = true;
    for (const rec of obj.records) {
      if (recordsProcessedThisTick >= recordLimit) {
        allRecordsOK = false; // leave the object for next tick
        break;
      }
      try {
        const wasProcessed = await processLog(
          rec.log as unknown as GatewayLog,
          env,
          ctx,
          otelExporter,
          { prefetched: { bodies: rec.bodies } },
        );
        if (wasProcessed) stats.processed++;
        else stats.skipped++;
      } catch (error) {
        console.error(`[observer/r2] Failed to process record ${rec.log.id} from ${obj.key}:`, error);
        stats.errors++;
        allRecordsOK = false;
      } finally {
        recordsProcessedThisTick++;
      }
    }
    if (allRecordsOK && env.GATEWAY_LOGS_BUCKET) {
      try {
        await env.GATEWAY_LOGS_BUCKET.delete(obj.key);
      } catch (err) {
        console.warn(`[observer/r2] Failed to delete R2 object ${obj.key} (will be reaped by 7d lifecycle): ${err instanceof Error ? err.message : String(err)}`);
      }
    } else if (!allRecordsOK) {
      console.warn(`[observer/r2] Leaving ${obj.key} in R2 after partial failure; will retry next tick`);
    }
  }

  return stats;
}

/**
 * Options controlling `processLog` behavior when the log came from R2 rather
 * than a CF AI Gateway REST poll. When `prefetched` is set:
 *   - fetchLogBodies() is skipped (bodies already decrypted by r2-ingest).
 *   - deleteLog() (CF REST delete) is skipped — the R2 caller handles the
 *     per-R2-object delete after all records in that object are processed.
 */
interface ProcessLogOptions {
  prefetched?: {
    bodies: { request: string; response: string };
  };
}

/**
 * Process a single log entry
 * @returns true if trace was created, false if log was skipped
 */
async function processLog(
  log: GatewayLog,
  env: Env,
  ctx: ExecutionContext,
  otelExporter?: WorkersOTelExporter | null,
  options: ProcessLogOptions = {}
): Promise<boolean> {
  const isR2Sourced = options.prefetched != null;
  // Extract metadata from log. CF AI Gateway returns the cf-aig-metadata
  // header value as a JSON string in the metadata field.
  let metadata: GatewayMetadata | undefined;
  if (typeof log.metadata === 'string') {
    try {
      let parsed = JSON.parse(log.metadata);
      // Handle double-encoded strings (CF may stringify twice)
      if (typeof parsed === 'string') {
        parsed = JSON.parse(parsed);
      }
      metadata = parsed as GatewayMetadata;
    } catch {
      console.warn(`[observer] Failed to parse metadata for ${log.id}: ${String(log.metadata).substring(0, 200)}`);
      metadata = undefined;
    }
  } else if (log.metadata && typeof log.metadata === 'object') {
    metadata = log.metadata as unknown as GatewayMetadata;
  }

  console.log(`[observer] Log ${log.id}: metadata_type=${typeof log.metadata}, has_agent_id=${!!metadata?.agent_id}, provider=${log.provider}, success=${log.success}`);

  // Fallback: if CF AI Gateway didn't preserve metadata (e.g. unknown headers
  // in the forwarded request cause it to drop cf-aig-metadata), recover
  // agent_id and session_id from the AIP checkpoint the gateway already stored.
  if (!metadata?.agent_id && log.success) {
    console.log(`[observer] No metadata for ${log.id}, attempting checkpoint fallback`);
    metadata = await recoverMetadataFromCheckpoint(log, env) ?? undefined;
  }

  // Validate this is a mnemom request by checking for agent_id
  if (!metadata?.agent_id) {
    console.log(`[observer] Skipping ${log.id}: no mnemom metadata and no checkpoint fallback`);
    if (!isR2Sourced) await deleteLog(log.id, env);
    return false;
  }

  // Skip failed API calls (e.g. 401 from invalid keys) — not behavioral events
  if (!log.success) {
    console.log(`[observer] Skipping ${log.id}: upstream API error (success=false)`);
    if (!isR2Sourced) await deleteLog(log.id, env);
    return false;
  }

  const { agent_id, session_id } = metadata;

  console.log(`[observer] Processing log ${log.id} for agent ${agent_id}`);

  // Step 51 / ADR-010 — idempotency pre-check. CF Queue is at-least-once;
  // producer may re-enqueue the same R2 record before lifecycle reap, and
  // consumer retries can duplicate. Short-circuit if we've already processed
  // this log id — saves the Anthropic call + verify + submit. The DB UNIQUE
  // index in migration 132 is the correctness guard; this is the cost-saving
  // optimization. Skip is not "processed": returns false so stats.skipped
  // increments and the caller acks (queue) or deletes (polling) without retry.
  if (await traceExistsForLogId(log.id, env)) {
    console.log(`[observer] Skipping ${log.id}: trace already exists (idempotency hit)`);
    if (!isR2Sourced) await deleteLog(log.id, env);
    return false;
  }

  // Fetch full request + response bodies (skipped when sourced from R2 — the
  // encrypted fields were already decrypted by r2-ingest into options.prefetched).
  const bodies = options.prefetched
    ? { ...options.prefetched.bodies }
    : await fetchLogBodies(log.id, env);

  // CF AI Gateway stores streamed responses with content flattened to a string
  // and raw SSE events in streamed_data[]. Reconstruct SSE format so the AIP
  // SDK's extractThinkingFromStream() can find thinking blocks.
  bodies.response = reconstructResponseForAIP(bodies.response, log.provider);

  // Extract thinking, tool calls, user query, response text
  const context = extractContext(bodies.request, bodies.response, log.provider);

  console.log(
    `[observer] Extracted: thinking=${!!context.thinking}, tools=${context.toolCalls.length}, query=${!!context.userQuery}`
  );

  // UC-8: fetch the AAP-shaped card for verifyTrace + the unified-shape
  // canonical card for policy evaluation. Both are KV-backed, so the two
  // calls collapse to a single network hit after the first.
  const [card, unifiedCard] = await Promise.all([
    fetchCard(agent_id, env),
    fetchCanonicalAlignmentCard(agent_id, env),
  ]);

  // Analyze reasoning with Claude Haiku (card-aware)
  const analysis = await analyzeWithHaiku(context, env, card);

  // Build APTrace conformant trace object
  const trace = buildTrace(log, metadata, context, analysis, card);

  // Verify trace against alignment card using AAP SDK
  const verification = card ? verifyTrace(trace, card) : null;

  if (verification && otelExporter) {
    otelExporter.recordVerification(verification);
  }

  // UC-8: policy evaluation runs against the canonical unified card. The
  // evaluator derives a Policy from card.capabilities + card.enforcement +
  // card.autonomy.escalation_triggers internally via extractPolicyFromCard.
  let policyResult: EvaluationResult | null = null;
  if (unifiedCard) {
    const tools = extractToolsFromTrace(trace);
    if (tools.length > 0) {
      policyResult = evaluatePolicy({
        context: 'observer',
        card: unifiedCard as Parameters<typeof evaluatePolicy>[0]['card'],
        tools,
      });
      console.log(`[observer/policy] Agent ${agent_id}: verdict=${policyResult.verdict}, violations=${policyResult.violations.length}, warnings=${policyResult.warnings.length}`);

      // Record policy evaluation OTel span
      if (otelExporter && 'recordPolicyEvaluation' in otelExporter) {
        (otelExporter as any).recordPolicyEvaluation({
          agent_id,
          policy_id: policyResult.policy_id,
          policy_version: String(policyResult.policy_version),
          verdict: policyResult.verdict,
          violations_count: policyResult.violations.length,
          warnings_count: policyResult.warnings.length,
          coverage_pct: policyResult.coverage.coverage_pct,
          context: policyResult.context,
          duration_ms: policyResult.duration_ms,
          enforcement_mode: 'observe',
          violations: policyResult.violations.map(v => ({
            type: v.type,
            tool: v.tool,
            severity: v.severity,
            reason: v.reason,
          })),
        });
      }
    }
  }

  // Submit trace to Supabase (trace + verification stored separately)
  try {
    await submitTrace(trace, verification, log, env);
  } catch (error) {
    console.error(`[observer] submitTrace FAILED for ${log.id} agent=${metadata.agent_id} trace=${trace.trace_id}:`, error);
    // Re-throw so the log is NOT deleted and will be retried next cron tick
    throw error;
  }

  // UC-8: Store policy evaluation result. The policy identifier is now the
  // canonical card's composition id (or card_id), since there's no separate
  // policy entity to reference.
  if (policyResult && unifiedCard) {
    const comp = ((unifiedCard as Record<string, any>)._composition ?? {}) as Record<string, any>;
    const canonicalId = typeof comp.canonical_id === 'string'
      ? comp.canonical_id
      : (typeof (unifiedCard as Record<string, any>).card_id === 'string'
          ? (unifiedCard as Record<string, any>).card_id
          : 'unknown');
    ctx.waitUntil(
      submitPolicyEvaluation(policyResult, agent_id, trace.trace_id, canonicalId, 1, env),
    );
  }

  // Submit usage event for admin tracking (non-blocking)
  ctx.waitUntil(submitUsageEvent(trace, log, env));

  // Link gateway-created checkpoint to this trace, then detect AIP/observer disagreements
  ctx.waitUntil(
    linkCheckpointToTrace(agent_id, session_id, trace.trace_id, env)
      .then(() => detectDisagreement(agent_id, session_id, trace.trace_id, verification, env, otelExporter))
  );

  // Emit Safe House calibration signal for false negative detection (fire-and-forget)
  ctx.waitUntil(emitSHCalibrationSignal(agent_id, session_id, verification?.verified === false ? 'boundary_violation' : '', null, env));

  // Check for behavioral drift (runs in background)
  ctx.waitUntil(checkForDrift(agent_id, card, env, otelExporter));

  // Deliver AAP webhooks (runs in background)
  ctx.waitUntil(deliverAAPWebhooks(trace, verification, policyResult, env));

  // Delete processed log for privacy. For R2-sourced logs, the caller deletes
  // the whole R2 object after every record in it has been processed — we
  // cannot delete a single record from an NDJSON file.
  if (!isR2Sourced) {
    await deleteLog(log.id, env);
  }

  console.log(`[observer] Created trace ${trace.trace_id} for agent ${agent_id}`);

  return true;
}

// ============================================================================
// Cloudflare AI Gateway API Functions
// ============================================================================

/**
 * Fetch logs from Cloudflare AI Gateway
 */
async function fetchLogs(env: Env, limit: number = 50): Promise<GatewayLog[]> {
  // CF caps per_page at 50 on the /logs endpoint. Requesting more returns 400
  // and observer cron ticks fail. Callers pass batchSize (50) from the
  // pagination loop; this default matches so ad-hoc callers don't regress.
  const url = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/ai-gateway/gateways/${env.GATEWAY_ID}/logs?per_page=${limit}&order_by=created_at&order_by_direction=asc&meta_info=true`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${env.CF_API_TOKEN}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `AI Gateway API error: ${response.status} - ${errorText}`
    );
  }

  const data = (await response.json()) as {
    success: boolean;
    result: GatewayLog[];
    errors?: Array<{ message: string }>;
  };

  if (!data.success) {
    throw new Error(
      `AI Gateway API failed: ${data.errors?.map((e) => e.message).join(', ')}`
    );
  }

  return data.result || [];
}

/**
 * Fetch full request and response bodies for a specific log entry.
 * CF AI Gateway stores bodies at separate endpoints:
 *   GET /logs/{id}/request  → request body
 *   GET /logs/{id}/response → response body
 */
async function fetchLogBodies(
  logId: string,
  env: Env
): Promise<{ request: string; response: string }> {
  const baseUrl = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/ai-gateway/gateways/${env.GATEWAY_ID}/logs/${logId}`;
  const headers = {
    Authorization: `Bearer ${env.CF_API_TOKEN}`,
  };

  const [reqRes, resRes] = await Promise.all([
    fetch(`${baseUrl}/request`, { headers }).catch((e) => { console.warn(`[observer] fetch /request threw for ${logId}: ${e}`); return null; }),
    fetch(`${baseUrl}/response`, { headers }).catch((e) => { console.warn(`[observer] fetch /response threw for ${logId}: ${e}`); return null; }),
  ]);

  let requestBody = '';
  let responseBody = '';

  if (reqRes && reqRes.ok) {
    const raw = await reqRes.text();
    // CF API may return raw body or wrap in {success, result} envelope
    try {
      const parsed = JSON.parse(raw);
      if (parsed.result !== undefined) {
        requestBody = typeof parsed.result === 'string' ? parsed.result : JSON.stringify(parsed.result);
      } else {
        requestBody = raw;
      }
    } catch {
      requestBody = raw;
    }
  } else {
    const statusText = reqRes ? `${reqRes.status} ${reqRes.statusText}` : 'null (fetch failed)';
    let errorBody = '';
    if (reqRes) { try { errorBody = await reqRes.text(); } catch {} }
    console.warn(`[observer] Failed to fetch request body for ${logId}: ${statusText} body=${errorBody.substring(0, 300)}`);
  }

  if (resRes && resRes.ok) {
    const raw = await resRes.text();
    try {
      const parsed = JSON.parse(raw);
      if (parsed.result !== undefined) {
        responseBody = typeof parsed.result === 'string' ? parsed.result : JSON.stringify(parsed.result);
      } else {
        responseBody = raw;
      }
    } catch {
      responseBody = raw;
    }
  } else {
    const statusText = resRes ? `${resRes.status} ${resRes.statusText}` : 'null (fetch failed)';
    let errorBody = '';
    if (resRes) { try { errorBody = await resRes.text(); } catch {} }
    console.warn(`[observer] Failed to fetch response body for ${logId}: ${statusText} body=${errorBody.substring(0, 300)}`);
  }

  return { request: requestBody, response: responseBody };
}

/**
 * Delete a processed log from the AI Gateway
 * Uses filter-based deletion per CF API spec
 */
async function deleteLog(logId: string, env: Env): Promise<void> {
  // CF AI Gateway API requires filter-based deletion with eq operator and array value
  const filters = JSON.stringify([{ key: 'id', operator: 'eq', value: [logId] }]);
  const url = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/ai-gateway/gateways/${env.GATEWAY_ID}/logs?filters=${encodeURIComponent(filters)}`;

  try {
    const response = await fetch(url, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${env.CF_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.warn(`[observer] Failed to delete log ${logId}: ${response.status} - ${errorText}`);
    }
  } catch (error) {
    console.warn(`[observer] Error deleting log ${logId}:`, error);
  }
}

// ============================================================================
// CF AI Gateway Response Reconstruction
// ============================================================================

/**
 * CF AI Gateway stores streamed responses with:
 *   - content: flattened text string (thinking blocks stripped)
 *   - streamed_data: array of raw SSE event objects (thinking preserved)
 *
 * The AIP SDK needs either:
 *   - Non-streaming JSON with content as array of blocks, OR
 *   - SSE text with "data: " prefixed lines
 *
 * This function detects the CF gateway format and reconstructs SSE text
 * from streamed_data so extractThinkingFromStream() can parse it.
 */
function reconstructResponseForAIP(responseBody: string, provider?: string): string {
  // Only reconstruct for Anthropic responses — other providers are handled
  // natively by the AIP SDK adapters, so return their responses as-is.
  if (provider === 'openai' || provider === 'gemini') {
    return responseBody;
  }

  if (!responseBody) return responseBody;

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(responseBody);
  } catch {
    return responseBody; // Not JSON, return as-is (might be raw SSE)
  }

  // If content is already an array, the SDK can handle it directly
  if (Array.isArray(parsed.content)) {
    return responseBody;
  }

  // If streamed_data exists, reconstruct SSE format
  const streamedData = parsed.streamed_data;
  if (!Array.isArray(streamedData) || streamedData.length === 0) {
    return responseBody;
  }

  // Convert each streamed_data object to an SSE "data: " line
  const sseLines = streamedData.map(
    (chunk: unknown) => `data: ${JSON.stringify(chunk)}`
  );

  return sseLines.join('\n');
}

// ============================================================================
// Context Extraction
// ============================================================================

/**
 * Extract thinking, tool calls, user query, and response text from
 * raw request/response bodies. Handles both JSON and SSE streaming formats.
 * Routes to provider-specific parsers based on the provider field from CF AI Gateway.
 */
function extractContext(requestBody: string, responseBody: string, provider?: string): ExtractedContext {
  const result: ExtractedContext = {
    thinking: null,
    toolCalls: [],
    userQuery: null,
    responseText: null,
  };

  // --- Parse response (route to provider-specific parser) ---
  if (responseBody) {
    let parsed = null;
    if (provider === 'openai') {
      parsed = tryParseOpenAIJSON(responseBody) || tryParseOpenAISSE(responseBody);
    } else if (provider === 'gemini') {
      parsed = tryParseGeminiJSON(responseBody);
    } else {
      // Anthropic (default)
      parsed = tryParseResponseJSON(responseBody) || tryParseSSE(responseBody);
    }
    if (parsed) {
      result.thinking = parsed.thinking;
      result.toolCalls = parsed.toolCalls;
      result.responseText = parsed.responseText;
    }
  }

  // --- Parse request for user query ---
  if (requestBody) {
    result.userQuery = extractUserQuery(requestBody, provider);
  }

  return result;
}

/**
 * Try to parse response as a complete JSON message (non-streaming)
 */
function tryParseResponseJSON(
  body: string
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } | null {
  try {
    const response = JSON.parse(body);
    const content = response.content;

    // Standard Anthropic format: content is an array of content blocks
    if (Array.isArray(content)) {
      return extractFromContentBlocks(content);
    }

    // CF AI Gateway format: content is a flattened string
    if (typeof content === 'string' && content.length > 0) {
      return {
        thinking: null,
        toolCalls: [],
        responseText: content.substring(0, 3000),
      };
    }

    // Error responses have error.message instead of content
    if (response.type === 'error' && response.error?.message) {
      return {
        thinking: null,
        toolCalls: [],
        responseText: `Error: ${response.error.message}`,
      };
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Try to parse response as OpenAI JSON format (non-streaming).
 * OpenAI responses have choices[].message with content, reasoning_content, and tool_calls.
 */
function tryParseOpenAIJSON(
  body: string
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } | null {
  try {
    const response = JSON.parse(body);
    const choices = response.choices;
    if (!Array.isArray(choices) || choices.length === 0) return null;

    const message = choices[0].message;
    if (!message) return null;

    const responseText = typeof message.content === 'string' && message.content.length > 0
      ? message.content.substring(0, 3000)
      : null;

    const thinking = typeof message.reasoning_content === 'string' && message.reasoning_content.length > 0
      ? message.reasoning_content
      : null;

    // Extract tool calls: tool_calls[] with {function: {name, arguments}}
    const toolCalls: ExtractedContext['toolCalls'] = [];
    if (Array.isArray(message.tool_calls)) {
      for (const tc of message.tool_calls) {
        if (tc.function?.name) {
          let input: Record<string, unknown> = {};
          try {
            input = JSON.parse(tc.function.arguments || '{}');
          } catch { /* */ }
          toolCalls.push({ name: tc.function.name, input });
        }
      }
    }

    return { thinking, toolCalls, responseText };
  } catch {
    return null;
  }
}

/**
 * Try to parse response as Gemini JSON format (non-streaming).
 * Gemini responses have candidates[].content.parts[] with text and optional thought flag.
 */
function tryParseGeminiJSON(
  body: string
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } | null {
  try {
    const response = JSON.parse(body);
    const candidates = response.candidates;
    if (!Array.isArray(candidates) || candidates.length === 0) return null;

    const content = candidates[0].content;
    if (!content || !Array.isArray(content.parts)) return null;

    const thinkingParts: string[] = [];
    const textParts: string[] = [];
    const toolCalls: ExtractedContext['toolCalls'] = [];

    for (const part of content.parts) {
      if (part.thought === true && typeof part.text === 'string') {
        // Thinking part (Gemini marks thinking with thought: true)
        thinkingParts.push(part.text);
      } else if (typeof part.text === 'string') {
        // Regular text part
        textParts.push(part.text);
      } else if (part.functionCall) {
        // Tool call: {functionCall: {name, args}}
        toolCalls.push({
          name: part.functionCall.name,
          input: (part.functionCall.args as Record<string, unknown>) || {},
        });
      }
    }

    return {
      thinking: thinkingParts.length > 0 ? thinkingParts.join('\n\n---\n\n') : null,
      toolCalls,
      responseText: textParts.length > 0 ? textParts.join('\n\n').substring(0, 3000) : null,
    };
  } catch {
    return null;
  }
}

/**
 * Try to parse response as SSE streaming events.
 * Reconstructs content blocks from content_block_start + content_block_delta events.
 */
function tryParseSSE(
  body: string
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } | null {
  if (!body.includes('data: ')) return null;

  try {
    // Track content blocks by index
    const blocks: Map<number, { type: string; content: string; name?: string; input?: string }> = new Map();

    const lines = body.split('\n');
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const jsonStr = line.slice(6).trim();
      if (!jsonStr || jsonStr === '[DONE]') continue;

      let event: Record<string, unknown>;
      try {
        event = JSON.parse(jsonStr);
      } catch {
        continue;
      }

      const eventType = event.type as string;

      if (eventType === 'content_block_start') {
        const index = event.index as number;
        const block = event.content_block as Record<string, unknown>;
        blocks.set(index, {
          type: block.type as string,
          content: '',
          name: block.name as string | undefined,
          input: '',
        });
      } else if (eventType === 'content_block_delta') {
        const index = event.index as number;
        const delta = event.delta as Record<string, unknown>;
        const existing = blocks.get(index);
        if (!existing) continue;

        if (delta.type === 'thinking_delta') {
          existing.content += (delta.thinking as string) || '';
        } else if (delta.type === 'text_delta') {
          existing.content += (delta.text as string) || '';
        } else if (delta.type === 'input_json_delta') {
          existing.input = (existing.input || '') + ((delta.partial_json as string) || '');
        }
      }
    }

    if (blocks.size === 0) return null;

    // Convert accumulated blocks to content block format
    const contentBlocks = Array.from(blocks.values()).map((b) => {
      if (b.type === 'thinking') {
        return { type: 'thinking', thinking: b.content };
      } else if (b.type === 'tool_use') {
        let input = {};
        try { input = JSON.parse(b.input || '{}'); } catch { /* */ }
        return { type: 'tool_use', name: b.name, input };
      } else {
        return { type: 'text', text: b.content };
      }
    });

    return extractFromContentBlocks(contentBlocks);
  } catch {
    return null;
  }
}

/**
 * Try to parse response as OpenAI SSE streaming events.
 * OpenAI streaming format: data: {"choices":[{"delta":{"content":"...","reasoning_content":"..."}}]}
 * Accumulates content and reasoning_content separately across chunks.
 */
function tryParseOpenAISSE(
  body: string
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } | null {
  if (!body.includes('data: ')) return null;

  try {
    let contentAccum = '';
    let reasoningAccum = '';
    // Track tool calls being streamed (by index)
    const toolCallsMap: Map<number, { name: string; arguments: string }> = new Map();

    const lines = body.split('\n');
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const jsonStr = line.slice(6).trim();
      if (!jsonStr || jsonStr === '[DONE]') continue;

      let event: Record<string, unknown>;
      try {
        event = JSON.parse(jsonStr);
      } catch {
        continue;
      }

      const choices = event.choices as Array<Record<string, unknown>> | undefined;
      if (!Array.isArray(choices) || choices.length === 0) continue;

      const delta = choices[0].delta as Record<string, unknown> | undefined;
      if (!delta) continue;

      if (typeof delta.content === 'string') {
        contentAccum += delta.content;
      }
      if (typeof delta.reasoning_content === 'string') {
        reasoningAccum += delta.reasoning_content;
      }

      // Stream tool calls: delta.tool_calls[]{index, function: {name?, arguments?}}
      const deltaToolCalls = delta.tool_calls as Array<Record<string, unknown>> | undefined;
      if (Array.isArray(deltaToolCalls)) {
        for (const dtc of deltaToolCalls) {
          const idx = (dtc.index as number) ?? 0;
          const fn = dtc.function as Record<string, unknown> | undefined;
          if (!fn) continue;
          const existing = toolCallsMap.get(idx);
          if (!existing) {
            toolCallsMap.set(idx, {
              name: (fn.name as string) || '',
              arguments: (fn.arguments as string) || '',
            });
          } else {
            if (fn.name) existing.name += fn.name as string;
            if (fn.arguments) existing.arguments += fn.arguments as string;
          }
        }
      }
    }

    if (contentAccum.length === 0 && reasoningAccum.length === 0 && toolCallsMap.size === 0) {
      return null;
    }

    const toolCalls: ExtractedContext['toolCalls'] = [];
    for (const tc of toolCallsMap.values()) {
      if (tc.name) {
        let input: Record<string, unknown> = {};
        try { input = JSON.parse(tc.arguments || '{}'); } catch { /* */ }
        toolCalls.push({ name: tc.name, input });
      }
    }

    return {
      thinking: reasoningAccum.length > 0 ? reasoningAccum : null,
      toolCalls,
      responseText: contentAccum.length > 0 ? contentAccum.substring(0, 3000) : null,
    };
  } catch {
    return null;
  }
}

/**
 * Extract thinking, tool calls, and text from parsed content blocks
 */
function extractFromContentBlocks(
  content: Array<Record<string, unknown>>
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } {
  const thinkingBlocks: string[] = [];
  const toolCalls: ExtractedContext['toolCalls'] = [];
  const textBlocks: string[] = [];

  for (const block of content) {
    if (block.type === 'thinking' && block.thinking) {
      thinkingBlocks.push(block.thinking as string);
    } else if (block.type === 'tool_use' && block.name) {
      toolCalls.push({
        name: block.name as string,
        input: (block.input as Record<string, unknown>) || {},
      });
    } else if (block.type === 'text' && block.text) {
      textBlocks.push(block.text as string);
    }
  }

  return {
    thinking: thinkingBlocks.length > 0 ? thinkingBlocks.join('\n\n---\n\n') : null,
    toolCalls,
    responseText: textBlocks.length > 0 ? textBlocks.join('\n\n') : null,
  };
}

/**
 * Extract the user's query from the request body.
 * Handles Anthropic/OpenAI format (messages array) and Gemini format (contents array).
 */
function extractUserQuery(requestBody: string, provider?: string): string | null {
  try {
    const request = JSON.parse(requestBody);

    // Gemini uses "contents" array with parts[].text
    if (provider === 'gemini') {
      const contents = request.contents;
      if (!Array.isArray(contents)) return null;

      // Walk backwards to find the last user message
      for (let i = contents.length - 1; i >= 0; i--) {
        const msg = contents[i] as Record<string, unknown>;
        if (msg.role !== 'user') continue;

        const parts = msg.parts as Array<Record<string, unknown>> | undefined;
        if (!Array.isArray(parts)) continue;

        const text = parts
          .filter((p) => typeof p.text === 'string')
          .map((p) => p.text as string)
          .join('\n');
        if (text.length > 0) {
          return text.substring(0, 500);
        }
      }
      return null;
    }

    // Anthropic and OpenAI both use "messages" array with role: 'user'
    const messages = request.messages;
    if (!Array.isArray(messages)) return null;

    // Walk backwards to find the last user message with actual text content
    // (skip tool_result-only messages common in multi-turn tool use)
    for (let i = messages.length - 1; i >= 0; i--) {
      const msg = messages[i] as Record<string, unknown>;
      if (msg.role !== 'user') continue;

      const content = msg.content;
      if (typeof content === 'string' && content.length > 0) {
        return content.substring(0, 500);
      }
      if (Array.isArray(content)) {
        const text = content
          .filter((c: Record<string, unknown>) => c.type === 'text')
          .map((c: Record<string, unknown>) => c.text as string)
          .join('\n');
        if (text.length > 0) {
          return text.substring(0, 500);
        }
        // This user message had no text (e.g., tool_result only) — keep looking
      }
    }
    return null;
  } catch {
    return null;
  }
}

// ============================================================================
// Haiku Analysis
// ============================================================================

/**
 * Build the observer system prompt dynamically from the agent's alignment card.
 * Values are derived entirely from the card — no hardcoded defaults.
 * Escalation trigger conditions are included as content classification flags.
 */
function buildObserverSystemPrompt(card: AlignmentCard | null): string {
  // Build values instruction ENTIRELY from the card — no hardcoded defaults
  let valuesInstruction: string;

  if (card?.values?.declared && card.values.declared.length > 0) {
    const valueNames = card.values.declared;
    const defs = card.values.definitions;
    const definitions = defs
      ? Object.entries(defs).map(([name, def]) => `  ${name}: ${def.description}`).join('\n')
      : null;
    valuesInstruction = `Pick ONLY from ${JSON.stringify(valueNames)}.`;
    if (definitions) {
      valuesInstruction += `\nValue definitions:\n${definitions}`;
    }
  } else {
    valuesInstruction = `Infer the most relevant values from the interaction. Use concise single-word or snake_case names.`;
  }

  // If card has escalation triggers with boolean conditions, add content classification
  const booleanConditions = card?.autonomy_envelope?.escalation_triggers
    ?.map(t => t.condition)
    .filter(c => /^\w+$/.test(c));

  let contentFlagsSchema = '';
  let contentFlagsRule = '';
  if (booleanConditions && booleanConditions.length > 0) {
    contentFlagsSchema = `\n  "content_flags": {}`;
    contentFlagsRule = `\n- content_flags: For each of ${JSON.stringify(booleanConditions)}, set true if the interaction content matches that condition, false otherwise.`;
  }

  return `Extract the decision structure from this AI agent interaction. Think step-by-step, then return ONLY valid JSON.

Schema:
{
  "alternatives": [{"id": "short_id", "description": "what this option does"}],
  "selected": "id of chosen option",
  "reasoning": "1-2 sentence plain-English summary of what the agent did and why",
  "values_applied": []${contentFlagsSchema ? ',' + contentFlagsSchema : ''}
}

Rules:
- alternatives: Extract from reasoning, or infer 2-3 likely options from the query.
- reasoning: Describe the action concretely (e.g. "Edited config file to fix auth bug"), not abstractly.
- values_applied: ${valuesInstruction}${contentFlagsRule}

Example input:
<user_query>Fix the login timeout bug</user_query>
<reasoning>I need to increase the session timeout. I could edit the config file directly or use the CLI tool. The config file is more reliable since CLI might not persist changes. I'll edit /etc/app/config.yaml.</reasoning>
<tools_used>- edit_file(path, content)</tools_used>

Example output:
{"alternatives":[{"id":"edit_config","description":"Edit config file directly"},{"id":"use_cli","description":"Use CLI tool to update timeout"}],"selected":"edit_config","reasoning":"Edited config file to increase session timeout, choosing direct file edit over CLI for persistence reliability.","values_applied":[${
    card?.values?.declared?.length
      ? card.values.declared.slice(0, 2).map(v => `"${v}"`).join(',')
      : ''
  }]}`;
}

/**
 * Sanitize JSON text by removing trailing commas before } or ].
 * Haiku 4.5 occasionally produces trailing commas in JSON arrays/objects.
 */
function sanitizeJson(text: string): string {
  return text.replace(/,\s*([}\]])/g, '$1');
}

/**
 * Analyze reasoning with Claude Haiku to extract decision structure.
 * Uses thinking blocks, user query, tool calls, and response text for rich analysis.
 * Card-aware: uses agent's declared values and escalation trigger conditions.
 */
async function analyzeWithHaiku(
  context: ExtractedContext,
  env: Env,
  card: AlignmentCard | null
): Promise<HaikuAnalysis> {
  // Skip analysis for contextless interactions — produces only noise traces
  if (!context.thinking && context.toolCalls.length === 0 && !context.userQuery) {
    return {
      alternatives: [{ id: 'passthrough', description: 'Direct response without tool use or reasoning' }],
      selected: 'passthrough',
      reasoning: 'Plain inference response with no captured decision context',
      values_applied: card?.values?.declared?.length ? [card.values.declared[0]] : [],
    };
  }

  // Build context sections for analysis
  const sections: string[] = [];

  if (context.userQuery) {
    sections.push(`<user_query>\n${context.userQuery}\n</user_query>`);
  }

  if (context.thinking) {
    sections.push(`<reasoning>\n${context.thinking.substring(0, 3000)}\n</reasoning>`);
  }

  if (context.toolCalls.length > 0) {
    const toolSummary = context.toolCalls
      .map((t) => `- ${t.name}(${Object.keys(t.input).join(', ')})`)
      .join('\n');
    sections.push(`<tools_used>\n${toolSummary}\n</tools_used>`);
  }

  if (context.responseText) {
    sections.push(`<response_excerpt>\n${context.responseText.substring(0, 1000)}\n</response_excerpt>`);
  }

  // If we have no context at all, return minimal fallback
  if (sections.length === 0) {
    return {
      alternatives: [{ id: 'direct', description: 'Direct response — no request/response data available' }],
      selected: 'direct',
      reasoning: 'No request or response data captured',
      values_applied: card?.values?.declared?.length ? [card.values.declared[0]] : [],
    };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    const systemPrompt = buildObserverSystemPrompt(card);

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 512,
        system: [{ type: 'text', text: systemPrompt, cache_control: { type: 'ephemeral' } }],
        messages: [
          {
            role: 'user',
            content: sections.join('\n\n'),
          },
        ],
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Haiku API error: ${response.status} - ${errorText}`);
    }

    const data = (await response.json()) as {
      content: Array<{ type: string; text: string }>;
    };

    const text = data.content[0]?.text || '';

    // Try to extract JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error('No JSON found in Haiku response');
    }

    const analysis = JSON.parse(sanitizeJson(jsonMatch[0])) as HaikuAnalysis;

    // Validate required fields
    if (!analysis.alternatives || !analysis.selected || !analysis.reasoning) {
      throw new Error('Invalid analysis structure');
    }

    // Post-parse validation: card-aware values_applied filtering
    if (card?.values?.declared && card.values.declared.length > 0) {
      const validValues = new Set(card.values.declared);
      analysis.values_applied = analysis.values_applied.filter((v: string) => validValues.has(v));
    }
    // If no card or all filtered out, keep Haiku's inferred values as-is

    return analysis;
  } catch (error) {
    console.error('[observer] Haiku analysis failed:', error);

    // Return fallback with whatever context we have
    // IMPORTANT: Never use responseText in fallback — that's the agent's actual output (PII)
    const fallbackReasoning = context.toolCalls.length > 0
      ? `Used tools: ${context.toolCalls.map((t) => t.name).join(', ')}`
      : 'Analysis unavailable — reasoning could not be extracted';

    return {
      alternatives: [{ id: 'analyzed', description: 'Analysis attempted but extraction failed' }],
      selected: 'analyzed',
      reasoning: fallbackReasoning,
      values_applied: card?.values?.declared?.length ? [card.values.declared[0]] : [],
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// Supabase Functions
// ============================================================================

/**
 * Fetch the active alignment card for an agent.
 *
 * Reads the canonical pre-composed card from `canonical_agent_cards`. The
 * UC-7 transitional fallback to legacy `alignment_cards` + `agents` dormant
 * columns + per-request org-template merge was removed in the 2026-04-17+
 * hardening pass after the 7-day zero-fallback observation window closed.
 * Missing canonical rows are now a hard error — the composition pipeline
 * (handleComposeAgent / recompose_pending) keeps every active agent's
 * canonical row current.
 */
async function fetchCard(
  agentId: string,
  env: Env
): Promise<AlignmentCard | null> {
  try {
    const canonical = await fetchCanonicalAlignmentCard(agentId, env);
    if (canonical) {
      console.log(JSON.stringify({
        event: 'card_read', card_source: 'canonical_hit', agent_id: agentId,
      }));
      return mapUnifiedCardToAAP(canonical) as unknown as AlignmentCard;
    }
    // Canonical row missing — log loudly so the composition pipeline gets
    // a nudge, but don't fall back to the pre-UC columns (which no longer
    // exist post-migration-129).
    console.error(JSON.stringify({
      event: 'card_read', card_source: 'canonical_missing', agent_id: agentId,
    }));
    return null;
  } catch (err) {
    console.error(JSON.stringify({
      event: 'card_read', card_source: 'canonical_error', agent_id: agentId,
      error: err instanceof Error ? err.message : String(err),
    }));
    return null;
  }
}

/**
 * Submit a trace to Supabase
 */
async function submitTrace(
  trace: APTrace,
  verification: VerificationResult | null,
  log: GatewayLog,
  env: Env
): Promise<void> {
  // Map APTrace to database schema.
  // Step 51 / ADR-010: gateway_log_id is the dedicated idempotency key (full
  // log.id, not the 8-char trace_id suffix). Column + partial UNIQUE index
  // landed in mnemom-api migration 132.
  const dbTrace = {
    trace_id: trace.trace_id,
    agent_id: trace.agent_id,
    card_id: trace.card_id,
    timestamp: trace.timestamp,

    // Action (stored as JSONB per schema)
    action: trace.action,

    // Decision (stored as JSONB per schema)
    decision: trace.decision,

    // Escalation (stored as JSONB per schema)
    escalation: trace.escalation,

    // Context (stored as JSONB per schema)
    context: trace.context,

    // Verification result from verifyTrace() - separate from APTrace
    verification: verification,

    // Full trace for extensibility
    trace_json: trace,

    // Idempotency key (Step 51). Redundant with trace_id at small scale but
    // structurally better: full entropy, queryable, independent of any
    // derivation change to trace_id.
    gateway_log_id: log.id,
  };

  // Conflict target is the UNIQUE partial index on gateway_log_id (migration
  // 132). On conflict, merge-duplicates treats the second insert as a
  // successful no-op; a genuine write race between two consumer invocations
  // therefore returns 201 with an empty body rather than 409 — processLog
  // completes normally. trace_id's own PK constraint is the secondary guard
  // (same log.id → same trace_id via the tr-{suffix} derivation).
  const response = await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/traces?on_conflict=gateway_log_id`, {
    method: 'POST',
    headers: {
      apikey: env.SUPABASE_SECRET_KEY,
      Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
      'Content-Type': 'application/json',
      Prefer: 'resolution=merge-duplicates,return=minimal',
    },
    body: JSON.stringify(dbTrace),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to submit trace: ${response.status} - ${errorText}`);
  }
}

/**
 * Step 51 / ADR-010 — idempotency pre-check.
 *
 * Before the expensive downstream pipeline (Anthropic analyzeWithHaiku +
 * verifyTrace + submitTrace), check whether a trace has already been written
 * for this source log id. Short-circuits on duplicate and saves both the
 * Anthropic API cost and the observer's CPU budget.
 *
 * The DB UNIQUE index (migration 132) is the correctness guarantee; this
 * pre-check is the cost-savings optimization. Fail-open: on any query error,
 * proceed with the pipeline (the index still catches a true duplicate at
 * submitTrace time via merge-duplicates).
 */
async function traceExistsForLogId(
  logId: string,
  env: Env,
): Promise<boolean> {
  try {
    const url = `${env.SUPABASE_URL}/rest/v1/traces?select=trace_id&gateway_log_id=eq.${encodeURIComponent(logId)}&limit=1`;
    const response = await observerSupabaseFetch(url, {
      method: 'GET',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
      },
    });
    if (!response.ok) return false; // fail-open
    const rows = (await response.json()) as Array<{ trace_id: string }>;
    return rows.length > 0;
  } catch (err) {
    console.warn(
      `[observer] traceExistsForLogId failed (fail-open): ${err instanceof Error ? err.message : String(err)}`
    );
    return false;
  }
}

// ============================================================================
// Policy Engine Functions (CLPI Phase 1)
// ============================================================================

/**
 * Fetch policy data for an agent from Supabase RPC.
 * Fail-open: returns null on error so agents without policies continue normally.
 */
async function fetchPolicyForAgent(
  agentId: string,
  env: Env,
  agentName?: string
): Promise<{ orgPolicy: Policy | null; agentPolicy: Policy | null; exempt: boolean; dbPolicyId: string | null; dbPolicyVersion: number | null } | null> {
  try {
    const response = await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/get_policy_for_agent`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ p_agent_id: agentId }),
    });

    if (!response.ok) {
      console.warn(`[observer/policy] RPC failed for ${agentId}: ${response.status}`);
      return null;
    }

    const data = await response.json() as Record<string, unknown> | null;

    // If RPC returned a policy, use it
    if (data?.agent_policy || data?.org_policy) {
      return {
        orgPolicy: (data.org_policy as Policy) ?? null,
        agentPolicy: (data.agent_policy as Policy) ?? null,
        exempt: (data.exempt as boolean) ?? false,
        dbPolicyId: ((data.agent_policy_id ?? data.org_policy_id) as string) ?? null,
        dbPolicyVersion: ((data.agent_policy_version ?? data.org_policy_version) as number) ?? null,
      };
    }

    // Name-based fallback: resolve linked_agent_id or same-name agent with policy
    if (agentName) {
      const linkedId = await resolveLinkedAgentId(agentId, agentName, env);
      if (linkedId) {
        console.log(`[observer/policy] Name fallback: ${agentName} → ${linkedId}`);
        const fallbackResponse = await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/get_policy_for_agent`, {
          method: 'POST',
          headers: {
            apikey: env.SUPABASE_SECRET_KEY,
            Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ p_agent_id: linkedId }),
        });
        if (fallbackResponse.ok) {
          const fallbackData = await fallbackResponse.json() as Record<string, unknown> | null;
          if (fallbackData?.agent_policy || fallbackData?.org_policy) {
            return {
              orgPolicy: (fallbackData.org_policy as Policy) ?? null,
              agentPolicy: (fallbackData.agent_policy as Policy) ?? null,
              exempt: (fallbackData.exempt as boolean) ?? false,
              dbPolicyId: ((fallbackData.agent_policy_id ?? fallbackData.org_policy_id) as string) ?? null,
              dbPolicyVersion: ((fallbackData.agent_policy_version ?? fallbackData.org_policy_version) as number) ?? null,
            };
          }
        }
      }
    }

    return data ? {
      orgPolicy: null,
      agentPolicy: null,
      exempt: (data.exempt as boolean) ?? false,
      dbPolicyId: null,
      dbPolicyVersion: null,
    } : null;
  } catch (error) {
    console.warn('[observer/policy] fetchPolicyForAgent failed (fail-open):', error);
    return null;
  }
}

/**
 * Resolve a linked agent ID for policy lookup via linked_agent_id column
 * or same-name agent match.
 */
async function resolveLinkedAgentId(
  agentId: string,
  agentName: string,
  env: Env
): Promise<string | null> {
  try {
    // First check if this agent has a linked_agent_id
    const linkedResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/agents?id=eq.${agentId}&select=linked_agent_id&limit=1`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );
    if (linkedResponse.ok) {
      const rows = await linkedResponse.json() as Array<{ linked_agent_id: string | null }>;
      if (rows[0]?.linked_agent_id) return rows[0].linked_agent_id;
    }

    // Fallback: find same-name agent with an active policy
    const nameResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/agents?name=eq.${encodeURIComponent(agentName)}&id=neq.${agentId}&select=id&limit=1`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );
    if (nameResponse.ok) {
      const nameRows = await nameResponse.json() as Array<{ id: string }>;
      if (nameRows[0]?.id) return nameRows[0].id;
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Extract tool references from a trace for policy evaluation.
 */
function extractToolsFromTrace(trace: APTrace): ToolReference[] {
  const action = trace.action as Record<string, any> | undefined;
  const toolCalls: any[] = action?.tool_calls ?? [];
  return toolCalls
    .map((tc: any) => ({ name: (tc.tool_name || tc.name) as string }))
    .filter((t: ToolReference) => t.name);
}

/**
 * Submit a policy evaluation result to Supabase.
 * Non-blocking, fail-open.
 */
async function submitPolicyEvaluation(
  result: EvaluationResult,
  agentId: string,
  traceId: string,
  dbPolicyId: string,
  dbPolicyVersion: number,
  env: Env
): Promise<void> {
  try {
    const evalId = `pe-${crypto.randomUUID().slice(0, 8)}`;
    const response = await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/policy_evaluations`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        id: evalId,
        policy_id: dbPolicyId,
        policy_version: dbPolicyVersion,
        agent_id: agentId,
        trace_id: traceId,
        context: result.context,
        verdict: result.verdict,
        violations: result.violations,
        warnings: result.warnings,
        card_gaps: result.card_gaps,
        coverage: result.coverage,
        duration_ms: result.duration_ms,
        dry_run: false,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.warn(`[observer/policy] Failed to store evaluation: ${response.status} - ${errorText}`);
    }
  } catch (error) {
    console.warn('[observer/policy] submitPolicyEvaluation failed (fail-open):', error);
  }
}

/**
 * Submit a usage event for admin tracking.
 * Non-blocking, fail-open: errors are logged but never propagate.
 */
async function submitUsageEvent(
  trace: APTrace,
  log: GatewayLog,
  env: Env
): Promise<void> {
  const eventId = `ue-${crypto.randomUUID().slice(0, 8)}`;
  const usageEvent = {
    id: eventId,
    agent_id: trace.agent_id,
    session_id: trace.context?.session_id || 'unknown',
    trace_id: trace.trace_id,
    timestamp: log.created_at,
    model: log.model || 'unknown',
    provider: log.provider || 'anthropic',
    tokens_in: log.tokens_in || 0,
    tokens_out: log.tokens_out || 0,
    duration_ms: log.duration || 0,
    gateway_log_id: log.id,
  };

  try {
    const response = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/usage_events`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify(usageEvent),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.warn(`[observer] Failed to submit usage event: ${response.status} - ${errorText}`);
    }
  } catch (error) {
    console.warn('[observer] Error submitting usage event:', error);
  }
}

// ============================================================================
// Metadata Recovery (Checkpoint Fallback)
// ============================================================================

/**
 * Recover agent_id and session_id from an AIP checkpoint when CF AI Gateway
 * metadata is missing. The gateway writes checkpoints to Supabase before the
 * observer processes logs, so a matching checkpoint should exist.
 *
 * Matches by timestamp proximity: finds the most recent unlinked checkpoint
 * created within 60 seconds of the CF AI Gateway log entry.
 */
async function recoverMetadataFromCheckpoint(
  log: GatewayLog,
  env: Env
): Promise<GatewayMetadata | null> {
  // Try up to 2 times — checkpoint may not be written yet (ctx.waitUntil race)
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, 2000)); // Wait 2s before retry
      }

      const logTime = new Date(log.created_at);
      const windowStart = new Date(logTime.getTime() - 60_000).toISOString();
      const windowEnd = new Date(logTime.getTime() + 60_000).toISOString();

      // Query by time window only — don't filter on linked_trace_id because
      // another log in the same batch may have already linked the checkpoint
      // via ctx.waitUntil(linkCheckpointToTrace(...)).
      const url = `${env.SUPABASE_URL}/rest/v1/integrity_checkpoints` +
        `?created_at=gte.${windowStart}` +
        `&created_at=lte.${windowEnd}` +
        `&select=agent_id,session_id` +
        `&order=created_at.desc&limit=1`;

      const response = await observerSupabaseFetch(url, {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      });

      if (!response.ok) {
        console.warn(`[observer] Checkpoint fallback query failed for ${log.id}: ${response.status}`);
        continue;
      }

      const rows = (await response.json()) as Array<{ agent_id: string; session_id: string }>;
      if (rows.length === 0) {
        console.log(`[observer] No checkpoint found for ${log.id} (attempt ${attempt + 1})`);
        continue;
      }

      const { agent_id, session_id } = rows[0];
      console.log(`[observer] Recovered metadata from checkpoint: agent=${agent_id} session=${session_id}`);

      return {
        agent_id,
        agent_hash: 'recovered',
        session_id,
        gateway_version: 'unknown',
      };
    } catch (error) {
      console.warn(`[observer] Checkpoint fallback error for ${log.id} (attempt ${attempt + 1}):`, error);
    }
  }

  return null;
}

// ============================================================================
// AIP Integrity Check Functions
// ============================================================================

/**
 * Link a gateway-created checkpoint to an observer trace.
 * The gateway creates AIP checkpoints in real-time; the observer links
 * its AAP traces to those checkpoints after processing the log.
 */
async function linkCheckpointToTrace(
  agentId: string,
  sessionId: string,
  traceId: string,
  env: Env
): Promise<void> {
  try {
    // Two-step GET-then-PATCH: PostgREST ignores `limit` on PATCH, so a single
    // PATCH with limit=1 would link ALL unlinked checkpoints for this agent+session.
    // Step 1: GET the most recent unlinked checkpoint (include output analysis fields)
    const getResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/integrity_checkpoints?agent_id=eq.${agentId}&session_id=eq.${sessionId}&linked_trace_id=is.null&order=timestamp.desc&limit=1&select=checkpoint_id,output_block_hash,analysis_scope`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );
    if (!getResponse.ok) return;
    const rows = await getResponse.json() as Array<{ checkpoint_id: string; output_block_hash?: string; analysis_scope?: string }>;
    if (!rows.length) return;

    // Log output analysis metadata if present
    const cp = rows[0];
    if (cp.output_block_hash || cp.analysis_scope) {
      console.log(`[observer] Checkpoint ${cp.checkpoint_id}: analysis_scope=${cp.analysis_scope}, output_hash=${cp.output_block_hash?.substring(0, 12)}...`);
    }

    // Step 2: PATCH that specific checkpoint by ID
    const cpId = cp.checkpoint_id;
    const patchResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/integrity_checkpoints?checkpoint_id=eq.${cpId}`,
      {
        method: 'PATCH',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({ linked_trace_id: traceId }),
      }
    );

    if (patchResponse.ok) {
      console.log(`[observer] Linked checkpoint ${cpId} to trace ${traceId}`);
    }
  } catch (error) {
    // Fail-open: linking is best-effort
    console.warn('[observer] Failed to link checkpoint to trace:', error);
  }
}


// ============================================================================
// Disagreement-Driven Review (DDR)
// ============================================================================

const RECONCILIATION_SYSTEM_PROMPT = `You are a reconciliation analyst for an AI agent integrity system.

Two independent systems assessed the same agent interaction:
- **AIP** (Agent Integrity Protocol): Real-time analysis of the agent's thinking/reasoning
- **AAP Observer**: Post-hoc verification of the agent's actions against its alignment card

They disagree. Your job is to determine which system is correct and why.

Analyze the evidence and return ONLY valid JSON:

{
  "outcome": "card_gap" | "aip_miss" | "observer_noise",
  "reasoning": "2-3 sentence explanation",
  "proposed_amendment": { "type": "bounded_action", "action": "semantic_capability_name", "description": "What this capability covers" }
}

Outcomes:
- **card_gap**: The agent acted appropriately but its alignment card doesn't list this capability. The card needs updating. Propose a meaningful semantic capability name (NOT the raw tool name). Example: Instead of "process" → "analyze_content" with description "Text processing, cross-referencing, and fact-checking operations".
- **aip_miss**: AIP incorrectly cleared the interaction. The observer caught a genuine concern that AIP's real-time analysis missed.
- **observer_noise**: The observer flagged a false positive. AIP was correct that the interaction was fine. The action maps to an existing bounded capability or is clearly within the agent's mandate.

Rules:
- proposed_amendment is ONLY included for card_gap outcomes
- Action names should be semantic capabilities, not raw tool/function names
- Description should explain what class of operations this capability covers
- Be precise in your reasoning — cite specific evidence from both assessments`;

/**
 * Emit a Safe House calibration signal when AIP detects a boundary violation.
 * This enables the Safe House closed feedback loop:
 * - If AIP verdict = boundary_violation and a recent Safe House evaluation exists for this session,
 *   we emit a 'false_negative' signal so Safe House can improve its detection thresholds.
 * - If the agent's thinking block shows it noticed the threat but proceeded,
 *   we emit a 'thinking_integrity' signal for retroactive scoring.
 * Always fire-and-forget — never throws.
 */
async function emitSHCalibrationSignal(
  agentId: string,
  sessionId: string,
  checkpointVerdict: string,
  concerns: Record<string, unknown> | null,
  env: Env
): Promise<void> {
  try {
    if (checkpointVerdict !== 'boundary_violation') return;

    // Look up the most recent Safe House evaluation for this agent+session
    const cfdResp = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/sh_evaluations?agent_id=eq.${agentId}&session_id=eq.${sessionId}&order=created_at.desc&limit=1`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!cfdResp.ok) return;

    const cfdEvals = await cfdResp.json() as Array<{
      id: string;
      overall_risk: number;
      verdict: string;
    }>;

    if (!cfdEvals || cfdEvals.length === 0) return;

    const cfdEval = cfdEvals[0];

    // Only emit if Safe House scored this session LOW (i.e., a false negative)
    if (cfdEval.overall_risk >= 0.6) return; // Safe House already flagged it — not a false negative

    // Compute retroactive score: bump it up since AIP found a real violation
    const retroactiveScore = Math.min(cfdEval.overall_risk + 0.35, 0.95);

    await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/sh_calibration_signals`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        signal_type: 'false_negative',
        sh_evaluation_id: cfdEval.id,
        sh_original_score: cfdEval.overall_risk,
        aip_verdict: checkpointVerdict,
        aip_concerns: concerns,
        retroactive_score: retroactiveScore,
      }),
    });

    console.log(`[observer/safe-house] Calibration signal emitted: false_negative for agent ${agentId} session ${sessionId} (original Safe House score: ${cfdEval.overall_risk.toFixed(2)} → retroactive: ${retroactiveScore.toFixed(2)})`);
  } catch {
    // Fire-and-forget: never throws
  }
}

/**
 * Detect disagreements between AIP checkpoint verdicts and AAP observer verification.
 * When they disagree, creates a disagreement_review record and optionally runs reconciliation.
 */
async function detectDisagreement(
  agentId: string,
  sessionId: string,
  traceId: string,
  verification: VerificationResult | null,
  env: Env,
  otelExporter?: WorkersOTelExporter | null
): Promise<void> {
  try {
    // Skip if no verification result (no card = nothing to compare)
    if (!verification) return;

    // Query the most recent checkpoint for this agent+session (now linked to this trace)
    const cpResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/integrity_checkpoints?agent_id=eq.${agentId}&session_id=eq.${sessionId}&linked_trace_id=eq.${traceId}&order=timestamp.desc&limit=1`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!cpResponse.ok) return;

    const checkpoints = await cpResponse.json() as Array<{
      checkpoint_id: string;
      verdict: string;
      reasoning_summary: string;
      concerns: Record<string, unknown> | null;
    }>;

    if (!checkpoints || checkpoints.length === 0) return;

    const checkpoint = checkpoints[0];

    // Compare: AIP verdict vs observer verification
    const aipClear = checkpoint.verdict === 'clear';
    const observerClear = verification.verified;

    // If they agree, no disagreement to detect
    if (aipClear === observerClear) return;

    console.log(`[observer/ddr] Disagreement detected: AIP=${checkpoint.verdict}, observer verified=${verification.verified} for agent ${agentId}`);

    // Fetch quota context to check feature flags and DDR mode
    const quotaResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/rpc/get_quota_context_for_agent`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ p_agent_id: agentId }),
      }
    );

    if (!quotaResponse.ok) return;

    const quota = await quotaResponse.json() as {
      feature_flags: Record<string, boolean>;
      agent_settings: { ddr_mode: string } | null;
    };

    const reconciliationEnabled = quota.feature_flags?.reconciliation === true;
    const ddrMode = quota.agent_settings?.ddr_mode || 'flag';

    if (!reconciliationEnabled || ddrMode === 'off') return;

    // INSERT disagreement review (idempotent via unique constraint)
    const reviewId = `ddr-${Date.now().toString(36)}-${randomHex(6)}`;
    const insertResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/disagreement_reviews`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({
          id: reviewId,
          agent_id: agentId,
          checkpoint_id: checkpoint.checkpoint_id,
          trace_id: traceId,
          aip_verdict: checkpoint.verdict,
          observer_outcome: verification.verified ? 'clear' : 'violation',
          status: 'pending',
        }),
      }
    );

    if (!insertResponse.ok) {
      const errorText = await insertResponse.text();
      // Unique constraint violation = already exists, idempotent
      if (errorText.includes('duplicate') || errorText.includes('unique') || errorText.includes('23505')) {
        console.log('[observer/ddr] Disagreement review already exists, skipping');
        return;
      }
      console.warn(`[observer/ddr] Failed to insert review: ${insertResponse.status} - ${errorText}`);
      return;
    }

    console.log(`[observer/ddr] Created disagreement review ${reviewId}`);

    // If mode supports reconciliation, run it
    if (ddrMode === 'auto-suggest' || ddrMode === 'auto-apply') {
      await runReconciliation(reviewId, agentId, checkpoint, traceId, verification, ddrMode, env, otelExporter);
    }
  } catch (error) {
    // Fail-open: DDR is best-effort
    console.warn('[observer/ddr] Disagreement detection failed:', error);
  }
}

/**
 * Run Sonnet-powered reconciliation analysis on a disagreement.
 * Determines whether the disagreement is a card gap, AIP miss, or observer noise.
 */
async function runReconciliation(
  reviewId: string,
  agentId: string,
  checkpoint: { checkpoint_id: string; verdict: string; reasoning_summary: string; concerns: Record<string, unknown> | null },
  traceId: string,
  verification: VerificationResult,
  ddrMode: string,
  env: Env,
  otelExporter?: WorkersOTelExporter | null
): Promise<void> {
  const startTime = Date.now();

  try {
    // Mark as analyzing
    await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/disagreement_reviews?id=eq.${reviewId}`,
      {
        method: 'PATCH',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({ status: 'analyzing' }),
      }
    );

    // Fetch the trace for action/decision details
    const traceResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/traces?trace_id=eq.${traceId}&limit=1`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    type TraceRecord = { action?: Record<string, unknown>; decision?: Record<string, unknown>; verification?: Record<string, unknown> };
    let traceData: TraceRecord | null = null;
    if (traceResponse.ok) {
      const traces = await traceResponse.json() as Array<Record<string, unknown>>;
      if (traces.length > 0) {
        traceData = traces[0] as TraceRecord;
      }
    }

    // Fetch the alignment card
    const cardResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/alignment_cards?agent_id=eq.${agentId}&is_active=eq.true&limit=1`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    let cardJson: Record<string, unknown> | null = null;
    if (cardResponse.ok) {
      const cards = await cardResponse.json() as Array<{ card_json: Record<string, unknown> }>;
      if (cards.length > 0) {
        cardJson = cards[0].card_json;
      }
    }

    // Build sections for Sonnet analysis
    const sections: string[] = [];

    sections.push(`<aip_assessment>
Verdict: ${checkpoint.verdict}
Reasoning: ${checkpoint.reasoning_summary || 'N/A'}
Concerns: ${checkpoint.concerns ? JSON.stringify(checkpoint.concerns) : 'None'}
</aip_assessment>`);

    if (traceData) {
      sections.push(`<observer_assessment>
Action: ${JSON.stringify(traceData.action || {})}
Decision Reasoning: ${(traceData.decision as Record<string, unknown>)?.selection_reasoning || 'N/A'}
Violations: ${JSON.stringify((traceData.verification as Record<string, unknown>)?.violations || verification.violations || [])}
</observer_assessment>`);
    }

    if (cardJson) {
      sections.push(`<alignment_card>
${JSON.stringify(cardJson, null, 2)}
</alignment_card>`);
    }

    // Call Sonnet for reconciliation
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 1024,
          system: [{ type: 'text', text: RECONCILIATION_SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
          messages: [
            {
              role: 'user',
              content: sections.join('\n\n'),
            },
          ],
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Sonnet API error: ${response.status}`);
      }

      const data = await response.json() as {
        content: Array<{ type: string; text: string }>;
      };

      const text = data.content[0]?.text || '';
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('No JSON found in Sonnet response');
      }

      const result = JSON.parse(jsonMatch[0]) as {
        outcome: 'card_gap' | 'aip_miss' | 'observer_noise';
        reasoning: string;
        proposed_amendment?: { type: string; action: string; description: string };
      };

      const durationMs = Date.now() - startTime;

      // Determine final status based on outcome and mode
      let finalStatus: string;
      if (result.outcome === 'observer_noise') {
        finalStatus = 'dismissed';
      } else if (result.outcome === 'card_gap' && ddrMode === 'auto-apply') {
        finalStatus = 'applied';
      } else {
        finalStatus = 'review';
      }

      // Update the review with reconciliation results
      await observerSupabaseFetch(
        `${env.SUPABASE_URL}/rest/v1/disagreement_reviews?id=eq.${reviewId}`,
        {
          method: 'PATCH',
          headers: {
            apikey: env.SUPABASE_SECRET_KEY,
            Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=minimal',
          },
          body: JSON.stringify({
            reconciliation_outcome: result.outcome,
            reconciliation_reasoning: result.reasoning,
            reconciliation_model: 'claude-sonnet-4-20250514',
            reconciliation_duration_ms: durationMs,
            proposed_amendment: result.proposed_amendment || null,
            status: finalStatus,
            ...(finalStatus === 'dismissed' || finalStatus === 'applied' ? {
              resolved_by: 'system/ddr',
              resolved_at: new Date().toISOString(),
            } : {}),
          }),
        }
      );

      console.log(`[observer/ddr] Reconciliation complete: ${result.outcome} (${durationMs}ms)`);

      // Resolve deferred proofs based on DDR outcome
      await resolveDeferredProof(checkpoint.checkpoint_id, result.outcome, env);

      // Auto-apply card amendment if mode is auto-apply and outcome is card_gap
      if (result.outcome === 'card_gap' && ddrMode === 'auto-apply' && result.proposed_amendment) {
        await applyCardAmendment(
          agentId,
          { tool_name: result.proposed_amendment.action, description: result.proposed_amendment.description },
          env,
          checkpoint.checkpoint_id,
          traceId,
          reviewId,
          otelExporter
        );
      }
    } finally {
      clearTimeout(timeoutId);
    }
  } catch (error) {
    // Fail-open: update review back to pending on failure
    console.warn('[observer/ddr] Reconciliation failed:', error);
    await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/disagreement_reviews?id=eq.${reviewId}`,
      {
        method: 'PATCH',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({ status: 'review' }),
      }
    );
  }
}

/**
 * Resolve a deferred proof based on DDR reconciliation outcome.
 * - card_gap / observer_noise → mark as skipped (no GPU cost)
 * - aip_miss → upgrade to pending and fire proof request to the prover
 */
async function resolveDeferredProof(
  checkpointId: string,
  outcome: 'card_gap' | 'aip_miss' | 'observer_noise',
  env: Env,
): Promise<void> {
  try {
    // Find deferred proof for this checkpoint
    const lookupUrl = new URL(`${env.SUPABASE_URL}/rest/v1/verdict_proofs`);
    lookupUrl.searchParams.set('checkpoint_id', `eq.${checkpointId}`);
    lookupUrl.searchParams.set('status', 'eq.deferred');
    lookupUrl.searchParams.set('select', 'proof_id,analysis_json,thinking_hash,card_hash,values_hash,model');
    lookupUrl.searchParams.set('limit', '1');

    const lookupRes = await observerSupabaseFetch(lookupUrl.toString(), {
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
      },
    });

    if (!lookupRes.ok) return;
    const proofs = (await lookupRes.json()) as Array<{
      proof_id: string;
      analysis_json: string;
      thinking_hash: string;
      card_hash: string;
      values_hash: string;
      model: string;
    }>;
    if (proofs.length === 0) return; // No deferred proof for this checkpoint

    const proof = proofs[0];

    if (outcome === 'aip_miss') {
      // Real violation confirmed — upgrade to pending and fire proof
      console.log(`[observer/proof] Upgrading deferred proof ${proof.proof_id} to pending (aip_miss confirmed)`);

      const patchUrl = new URL(`${env.SUPABASE_URL}/rest/v1/verdict_proofs`);
      patchUrl.searchParams.set('proof_id', `eq.${proof.proof_id}`);
      await observerSupabaseFetch(patchUrl.toString(), {
        method: 'PATCH',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({ status: 'pending' }),
      });

      // Fire proof request to prover
      if (env.PROVER_URL) {
        fetch(`${env.PROVER_URL}/prove`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(env.PROVER_API_KEY ? { 'X-Prover-Key': env.PROVER_API_KEY } : {}),
          },
          body: JSON.stringify({
            proof_id: proof.proof_id,
            checkpoint_id: checkpointId,
            analysis_json: proof.analysis_json,
            thinking_hash: proof.thinking_hash,
            card_hash: proof.card_hash,
            values_hash: proof.values_hash,
            model: proof.model,
          }),
        }).then(r => console.log(`[observer/proof] Prover POST for upgraded proof: ${r.status}`))
          .catch(err => console.warn(`[observer/proof] Prover POST failed:`, err));
      }
    } else {
      // card_gap or observer_noise — skip proving entirely
      const skipStatus = outcome === 'card_gap' ? 'skipped_card_gap' : 'skipped_noise';
      console.log(`[observer/proof] Resolving deferred proof ${proof.proof_id} as ${skipStatus}`);

      const patchUrl = new URL(`${env.SUPABASE_URL}/rest/v1/verdict_proofs`);
      patchUrl.searchParams.set('proof_id', `eq.${proof.proof_id}`);
      await observerSupabaseFetch(patchUrl.toString(), {
        method: 'PATCH',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({ status: skipStatus }),
      });
    }
  } catch (err) {
    // Fail-open: deferred proof resolution errors never block DDR
    console.warn('[observer/proof] resolveDeferredProof failed (fail-open):', err);
  }
}

/**
 * Apply a proposed card amendment from DDR reconciliation.
 * Adds the proposed action to the alignment card's bounded_actions,
 * then runs the Phase 3 trust recovery chain: audit trail, reclassify,
 * recompute score, OTel span, and re-proofing.
 */
async function applyCardAmendment(
  agentId: string,
  amendment: { tool_name: string; description: string },
  env: Env,
  checkpointId: string,
  traceId: string,
  reviewId: string,
  otelExporter?: WorkersOTelExporter | null
): Promise<void> {
  try {
    const supabaseUrl = env.SUPABASE_URL;
    const supabaseKey = env.SUPABASE_SECRET_KEY;

    const cardResponse = await observerSupabaseFetch(
      `${supabaseUrl}/rest/v1/alignment_cards?agent_id=eq.${agentId}&is_active=eq.true&limit=1`,
      {
        headers: {
          apikey: supabaseKey,
          Authorization: `Bearer ${supabaseKey}`,
        },
      }
    );

    if (!cardResponse.ok) return;

    const cards = await cardResponse.json() as Array<{ id: string; card_json: Record<string, any> }>;
    if (!cards || cards.length === 0) return;

    const card = cards[0];
    const cardJson = card.card_json;
    const cardId = card.id;

    const currentBounded: string[] = cardJson.autonomy_envelope?.bounded_actions || [];

    if (!currentBounded.includes(amendment.tool_name)) {
      // Capture before snapshot BEFORE mutating
      const beforeSnapshot = JSON.parse(JSON.stringify(cardJson));

      currentBounded.push(amendment.tool_name);
      if (!cardJson.autonomy_envelope) {
        cardJson.autonomy_envelope = {};
      }
      cardJson.autonomy_envelope.bounded_actions = currentBounded;

      await observerSupabaseFetch(
        `${supabaseUrl}/rest/v1/alignment_cards?id=eq.${cardId}`,
        {
          method: 'PATCH',
          headers: {
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ card_json: cardJson, issued_at: new Date().toISOString() }),
        }
      );

      console.log(`[observer/ddr] Auto-applied card amendment: ${amendment.tool_name} for agent ${agentId}`);

      // --- Trust Recovery Chain (Phase 3) ---
      try {
        // 1. Insert card_amendments row
        const amendmentId = 'ca-' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
        const amendRes = await observerSupabaseFetch(`${supabaseUrl}/rest/v1/card_amendments`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
            Prefer: 'return=minimal',
          },
          body: JSON.stringify({
            id: amendmentId,
            agent_id: agentId,
            amendment_type: 'bounded_action_added',
            before_snapshot: beforeSnapshot,
            after_snapshot: JSON.parse(JSON.stringify(cardJson)),
            diff_summary: `Added bounded action for tool: ${amendment.tool_name}`,
            reason: amendment.description,
            source: 'ddr_auto',
            ddr_review_id: reviewId,
          }),
        });
        if (!amendRes.ok) {
          console.error('[applyCardAmendment] card_amendments insert failed:', await amendRes.text());
        }

        // 2. Call reclassify_checkpoint RPC
        const reclRes = await observerSupabaseFetch(`${supabaseUrl}/rest/v1/rpc/reclassify_checkpoint`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
          },
          body: JSON.stringify({
            p_checkpoint_id: checkpointId,
            p_agent_id: agentId,
            p_reason: `Card gap resolved: added bounded action for ${amendment.tool_name}`,
            p_card_amendment_id: amendmentId,
            p_ddr_review_id: reviewId,
          }),
        });
        let reclData: any = null;
        if (reclRes.ok) {
          reclData = await reclRes.json();
        } else {
          console.error('[applyCardAmendment] reclassify_checkpoint failed:', await reclRes.text());
        }

        // 3. PATCH policy_evaluations: set re_evaluated_at for same agent+trace with card_gaps
        if (traceId) {
          const peUrl = new URL(`${supabaseUrl}/rest/v1/policy_evaluations`);
          peUrl.searchParams.set('agent_id', `eq.${agentId}`);
          peUrl.searchParams.set('trace_id', `eq.${traceId}`);
          peUrl.searchParams.set('card_gaps', 'neq.[]');
          await observerSupabaseFetch(peUrl.toString(), {
            method: 'PATCH',
            headers: {
              'Content-Type': 'application/json',
              apikey: supabaseKey,
              Authorization: `Bearer ${supabaseKey}`,
              Prefer: 'return=minimal',
            },
            body: JSON.stringify({ re_evaluated_at: new Date().toISOString() }),
          });
        }

        // 4. Trigger compute_reputation_score RPC for immediate recompute
        const scoreRes = await observerSupabaseFetch(`${supabaseUrl}/rest/v1/rpc/compute_reputation_score`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            apikey: supabaseKey,
            Authorization: `Bearer ${supabaseKey}`,
          },
          body: JSON.stringify({ p_agent_id: agentId }),
        });
        let scoreAfter: number | null = null;
        if (scoreRes.ok) {
          const scoreData = await scoreRes.json() as any;
          scoreAfter = scoreData?.score ?? null;

          // 5. Update reclassification score_after
          if (reclData?.reclassification_id && scoreAfter !== null) {
            const reclUrl = new URL(`${supabaseUrl}/rest/v1/reclassifications`);
            reclUrl.searchParams.set('id', `eq.${reclData.reclassification_id}`);
            await observerSupabaseFetch(reclUrl.toString(), {
              method: 'PATCH',
              headers: {
                'Content-Type': 'application/json',
                apikey: supabaseKey,
                Authorization: `Bearer ${supabaseKey}`,
                Prefer: 'return=minimal',
              },
              body: JSON.stringify({ score_after: scoreAfter }),
            });

            // Also update the reputation_event score_after
            if (reclData.event_id) {
              const evUrl = new URL(`${supabaseUrl}/rest/v1/reputation_events`);
              evUrl.searchParams.set('id', `eq.${reclData.event_id}`);
              await observerSupabaseFetch(evUrl.toString(), {
                method: 'PATCH',
                headers: {
                  'Content-Type': 'application/json',
                  apikey: supabaseKey,
                  Authorization: `Bearer ${supabaseKey}`,
                  Prefer: 'return=minimal',
                },
                body: JSON.stringify({ score_after: scoreAfter }),
              });
            }
          }
        }

        // 6. Emit OTel reclassification span
        if ((otelExporter as any)?.recordReclassification) {
          (otelExporter as any).recordReclassification({
            agent_id: agentId,
            checkpoint_id: checkpointId,
            trace_id: traceId,
            before_verdict: reclData?.before_verdict ?? 'unknown',
            after_classification: 'clear',
            reason: `Card gap resolved: ${amendment.tool_name}`,
            score_before: reclData?.score_before ?? undefined,
            score_after: scoreAfter ?? undefined,
          });
        }

        // 7. Request re-proofing (fire-and-forget)
        if (env.PROVER_URL && env.PROVER_API_KEY) {
          try {
            // Check for existing completed verdict_proof for this checkpoint
            const proofUrl = new URL(`${supabaseUrl}/rest/v1/verdict_proofs`);
            proofUrl.searchParams.set('checkpoint_id', `eq.${checkpointId}`);
            proofUrl.searchParams.set('status', 'eq.completed');
            proofUrl.searchParams.set('select', 'id,analysis_json,thinking_hash,card_hash,values_hash,model');
            proofUrl.searchParams.set('limit', '1');
            proofUrl.searchParams.set('order', 'created_at.desc');
            const proofRes = await observerSupabaseFetch(proofUrl.toString(), {
              headers: {
                apikey: supabaseKey,
                Authorization: `Bearer ${supabaseKey}`,
              },
            });
            if (proofRes.ok) {
              const proofs = await proofRes.json() as any[];
              if (proofs.length > 0) {
                const proof = proofs[0];
                // Compute new card hash from amended card
                const cardBytes = new TextEncoder().encode(JSON.stringify(cardJson));
                const cardHashBuf = await crypto.subtle.digest('SHA-256', cardBytes);
                const newCardHash = Array.from(new Uint8Array(cardHashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

                fetch(`${env.PROVER_URL}/prove/reproof`, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': env.PROVER_API_KEY,
                  },
                  body: JSON.stringify({
                    proof_id: 'vp-' + crypto.randomUUID().replace(/-/g, '').slice(0, 16),
                    original_proof_id: proof.id,
                    checkpoint_id: checkpointId,
                    reclassification_id: reclData?.reclassification_id,
                    analysis_json: proof.analysis_json,
                    thinking_hash: proof.thinking_hash,
                    card_hash: newCardHash,
                    values_hash: proof.values_hash,
                    model: proof.model,
                  }),
                }).catch(err => console.error('[applyCardAmendment] reproof request failed:', err));
              }
            }
          } catch (reproofErr) {
            console.error('[applyCardAmendment] reproof check failed:', reproofErr);
          }
        }

        console.log(`[applyCardAmendment] Trust recovery chain completed for checkpoint ${checkpointId}`);
      } catch (recoveryErr) {
        console.error('[applyCardAmendment] Trust recovery chain failed (non-blocking):', recoveryErr);
      }
    }
  } catch (error) {
    console.warn('[observer/ddr] Failed to apply card amendment:', error);
  }
}


/**
 * Call cleanup_expired_sh_data() RPC to enforce retention policies.
 * Runs weekly (Sundays at midnight UTC).
 */
async function runSHRetentionCleanup(env: Env): Promise<void> {
  try {
    const resp = await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/cleanup_expired_sh_data`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    if (resp.ok) {
      const result = await resp.json() as { quarantine_deleted: number; evaluations_deleted: number };
      console.log(`[observer/retention] Safe House cleanup: ${result.quarantine_deleted} quarantine, ${result.evaluations_deleted} evaluations deleted`);
    } else {
      console.warn(`[observer/retention] Safe House cleanup RPC failed: ${resp.status}`);
    }
  } catch (err) {
    console.warn('[observer/retention] Safe House cleanup failed:', err);
  }
}

/**
 * Auto-promote high-confidence Safe House patterns to active status.
 * Called every 5 minutes by the observer cron.
 * Only runs when sh_auto_promote_enabled = true in security_settings.
 */
async function runSHAutoPromotion(env: Env): Promise<void> {
  try {
    const resp = await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/auto_promote_sh_patterns`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    if (resp.ok) {
      const result = await resp.json() as { promoted: number; reason?: string };
      if (result.promoted > 0) {
        console.log(`[observer/safe-house-evolution] Auto-promoted ${result.promoted} Safe House patterns`);
      }
    }
  } catch (err) {
    console.warn('[observer/safe-house-evolution] Auto-promotion failed:', err);
  }
}

/**
 * Check false positive rates and emit threshold suggestions when FP rate exceeds threshold.
 * Called hourly by the observer cron.
 * Suggestions are stored in sh_configs.suggested_warn_threshold (if the column exists)
 * or logged for admin review.
 */
async function runSHAdaptiveThresholds(env: Env): Promise<void> {
  try {
    const resp = await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/get_sh_threshold_suggestions`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    if (!resp.ok) return;

    const suggestions = await resp.json() as Array<{
      confidence_band: number;
      fp_rate: number;
      suggested_threshold: number;
      estimated_fp_reduction: number;
    }>;

    if (suggestions.length > 0) {
      console.log(`[observer/safe-house-evolution] Threshold suggestions: ${suggestions.length} bands with high FP rate`);
      for (const s of suggestions) {
        console.log(`[observer/safe-house-evolution] Band ${s.confidence_band}-${(s.confidence_band + 0.1).toFixed(1)}: FP rate ${s.fp_rate}% → suggest warn threshold ${s.suggested_threshold}`);
      }
    }
  } catch (err) {
    console.warn('[observer/safe-house-evolution] Adaptive threshold check failed:', err);
  }
}

/**
 * Deactivate Safe House threat patterns that haven't been matched recently (TTL expired).
 * Prevents the pattern library from accumulating stale entries that slow down L1 matching.
 * Called weekly (Sunday midnight UTC).
 */
async function runSHPatternExpiry(env: Env): Promise<void> {
  try {
    const resp = await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/expire_stale_sh_patterns`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    if (resp.ok) {
      const result = await resp.json() as { expired: number; ttl_days: number };
      console.log(`[observer/safe-house-evolution] Pattern TTL: ${result.expired} patterns expired (TTL: ${result.ttl_days}d)`);
    }
  } catch (err) {
    console.warn('[observer/safe-house-evolution] Pattern expiry failed:', err);
  }
}

/**
 * Rebuild the MinHash LSH inverted index in KV for fast gateway-side candidate lookup.
 * Called nightly at 2:00 AM UTC. Fetches all active malicious patterns with minhash from
 * Supabase, computes 16 band hashes per pattern, and writes the inverted index to KV.
 *
 * KV key format: `sh_lsh:band:{bandIndex}:{bandHash}` → JSON array of pattern IDs
 * KV TTL: 16 hours (57600s) — rebuilt before expiry each night
 */
async function runSHLSHIndexRebuild(env: Env): Promise<void> {
  if (!env.BILLING_CACHE) return;
  try {
    // Paginate: fetch all active malicious patterns that have a minhash
    const allPatterns: Array<{ id: string; minhash: string }> = [];
    let lastId = '';
    for (;;) {
      const url = `${env.SUPABASE_URL}/rest/v1/sh_threat_patterns`
        + `?label=eq.malicious&is_active=eq.true&minhash=not.is.null`
        + `&select=id,minhash&order=id&limit=2000`
        + (lastId ? `&id=gt.${lastId}` : '');
      const resp = await observerSupabaseFetch(url, {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      });
      if (!resp.ok) break;
      const page = await resp.json() as Array<{ id: string; minhash: string }>;
      if (page.length === 0) break;
      allPatterns.push(...page);
      lastId = page[page.length - 1].id;
      if (page.length < 2000) break;
    }

    if (allPatterns.length === 0) {
      console.log('[observer/sh-lsh] No patterns with minhash — skipping LSH rebuild');
      return;
    }

    // Build inverted index: bandKey → pattern ID[]
    const bandMap = new Map<string, string[]>();
    for (const { id, minhash } of allPatterns) {
      const sig = deserializeMinHash(minhash);
      if (!sig) continue;
      const bands = computeBandHashes(sig);
      for (let b = 0; b < bands.length; b++) {
        const key = `sh_lsh:band:${b}:${bands[b]}`;
        const existing = bandMap.get(key);
        if (existing) existing.push(id);
        else bandMap.set(key, [id]);
      }
    }

    // Batch-write to KV in chunks of 100 (respects ~1000 writes/s rate limit)
    const TTL = 57600; // 16 hours
    const entries = [...bandMap.entries()];
    for (let i = 0; i < entries.length; i += 100) {
      await Promise.all(
        entries.slice(i, i + 100).map(([key, ids]) =>
          env.BILLING_CACHE!.put(key, JSON.stringify(ids), { expirationTtl: TTL }).catch(() => {})
        )
      );
    }

    // Metadata key for health checks / verification
    await env.BILLING_CACHE.put(
      'sh_lsh:meta',
      JSON.stringify({ count: allPatterns.length, band_keys: bandMap.size, rebuilt_at: new Date().toISOString() }),
      { expirationTtl: TTL }
    ).catch(() => {});

    console.log(`[observer/sh-lsh] Rebuilt: ${allPatterns.length} patterns, ${bandMap.size} band keys`);
  } catch (err) {
    console.warn('[observer/sh-lsh] LSH index rebuild failed:', err);
  }
}

/**
 * Refresh representative_minhash and card_count for families with ≥5 active patterns.
 * Called nightly at 2:00 AM UTC alongside the LSH rebuild.
 */
async function runSHConsolidation(env: Env): Promise<void> {
  try {
    const resp = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/rpc/consolidate_pattern_families`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: '{}',
      }
    );
    if (resp.ok) {
      const result = await resp.json() as { consolidated: number; families_updated: string[] };
      if (result.consolidated > 0) {
        console.log(`[observer/sh-families] Consolidated ${result.consolidated} families: ${result.families_updated.join(', ')}`);
      }
    }
  } catch (err) {
    console.warn('[observer/sh-families] Consolidation failed:', err);
  }
}

/**
 * Expire auto-created candidate patterns older than 14 days that are still pending review.
 * Called nightly at 2:00 AM UTC.
 */
async function runSHExpireOrphans(env: Env): Promise<void> {
  try {
    const resp = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/rpc/expire_orphaned_candidates`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: '{}',
      }
    );
    if (resp.ok) {
      const result = await resp.json() as { expired: number };
      if (result.expired > 0) {
        console.log(`[observer/sh-orphans] Expired ${result.expired} orphaned candidate patterns`);
      }
    }
  } catch (err) {
    console.warn('[observer/sh-orphans] Orphan expiry failed:', err);
  }
}

/**
 * Arena V2 sideband analyzer.
 *
 * Runs hourly (at :45). Polls arena_bypass_events WHERE recipe_status='pending'.
 * For each:
 *  1. Calls generate_arena_recipe() RPC to create a sh_recipes row
 *  2. Checks minhash similarity to existing active patterns
 *  3. If similarity < 0.65 (genuinely novel): auto-promotes via promote_arena_recipe()
 *  4. Otherwise: leaves in review queue for human action
 *
 * The auto-promotion threshold (0.65) is deliberately conservative.
 * The Safe House auto_promote_sh_patterns() cron still handles the final activation.
 */
async function runArenaSidebandAnalysis(env: Env): Promise<void> {
  try {
    // Fetch up to 20 pending bypass events from the last 24 hours
    const url = `${env.SUPABASE_URL}/rest/v1/arena_bypass_events`
      + `?recipe_status=eq.pending`
      + `&created_at=gte.${new Date(Date.now() - 86_400_000).toISOString()}`
      + `&select=id,payload,minhash,door,mutation_type,detector_scores`
      + `&order=created_at.desc&limit=20`;

    const resp = await observerSupabaseFetch(url, {
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
      },
    });
    if (!resp.ok) {
      console.warn('[observer/arena-sideband] Failed to fetch bypass events:', resp.status);
      return;
    }

    const events = await resp.json() as Array<{
      id: string;
      payload: string;
      minhash?: string;
      door: string;
      mutation_type?: string;
      detector_scores?: Record<string, unknown>;
    }>;

    if (events.length === 0) return;

    let generated = 0;
    let promoted = 0;

    for (const event of events) {
      // Step 1: generate the recipe
      const genResp = await observerSupabaseFetch(
        `${env.SUPABASE_URL}/rest/v1/rpc/generate_arena_recipe`,
        {
          method: 'POST',
          headers: {
            apikey: env.SUPABASE_SECRET_KEY,
            Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ p_bypass_id: event.id }),
        }
      );
      if (!genResp.ok) continue;
      const genResult = await genResp.json() as { recipe_id?: string; error?: string };
      if (!genResult.recipe_id) continue;
      generated++;

      // Step 2: check if this is a genuinely novel bypass (no similar active pattern)
      // If the bypass event has a precomputed minhash, use it.
      // If not, skip auto-promotion and leave for human review.
      if (!event.minhash) continue;

      // Step 3: check similarity against active patterns
      // Use the minhash_similarity RPC on the top existing pattern
      const simResp = await observerSupabaseFetch(
        `${env.SUPABASE_URL}/rest/v1/rpc/check_bypass_novelty`,
        {
          method: 'POST',
          headers: {
            apikey: env.SUPABASE_SECRET_KEY,
            Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ p_minhash: event.minhash }),
        }
      );

      let isNovel = true;
      if (simResp.ok) {
        const simResult = await simResp.json() as { max_similarity: number };
        // If max similarity to ANY existing active pattern is >= 0.65, not novel
        if (simResult.max_similarity >= 0.65) {
          isNovel = false;
        }
      }

      // Step 4: auto-promote novel bypasses
      if (isNovel) {
        const promoteResp = await observerSupabaseFetch(
          `${env.SUPABASE_URL}/rest/v1/rpc/promote_arena_recipe`,
          {
            method: 'POST',
            headers: {
              apikey: env.SUPABASE_SECRET_KEY,
              Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ p_recipe_id: genResult.recipe_id }),
          }
        );
        if (promoteResp.ok) promoted++;
      }
    }

    if (generated > 0) {
      console.log(`[observer/arena-sideband] Processed ${events.length} bypass events: ${generated} recipes generated, ${promoted} auto-promoted`);
    }
  } catch (err) {
    console.warn('[observer/arena-sideband] Sideband analysis failed:', err);
  }
}

/**
 * Trigger metering rollup for all active billing accounts.
 * Idempotent — upsert-based, safe to run on every cron tick.
 */
async function triggerMeteringRollup(env: Env): Promise<void> {
  try {
    const today = new Date().toISOString().split('T')[0];

    // Get all billing accounts that have metering events today
    const response = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/metering_events?select=account_id&timestamp=gte.${today}T00:00:00Z&order=account_id`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!response.ok) {
      console.warn(`[observer/metering] Failed to fetch accounts for rollup: ${response.status}`);
      return;
    }

    const events = (await response.json()) as Array<{ account_id: string }>;
    const accountIds = [...new Set(events.map(e => e.account_id))];

    for (const accountId of accountIds) {
      const rollupResponse = await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/rollup_metering`, {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ p_account_id: accountId, p_date: today }),
      });

      if (!rollupResponse.ok) {
        console.warn(`[observer/metering] Rollup failed for account ${accountId}: ${rollupResponse.status}`);
      }
    }

    if (accountIds.length > 0) {
      console.log(`[observer/metering] Rolled up ${accountIds.length} accounts for ${today}`);
    }
  } catch (error) {
    console.warn('[observer/metering] Error in metering rollup:', error);
  }
}

/**
 * Report daily usage to Stripe for metered billing.
 * Runs once per day at midnight UTC.
 * Queries all billing accounts with active metered subscriptions,
 * reports cumulative check_count_this_period via createUsageRecord(action:'set').
 */
async function reportDailyUsageToStripe(env: Env): Promise<void> {
  if (!env.STRIPE_SECRET_KEY) {
    console.log('[observer/stripe] No STRIPE_SECRET_KEY, skipping usage reporting');
    return;
  }

  try {
    // Import Stripe dynamically to avoid import errors when key is not set
    const { default: Stripe } = await import('stripe');
    const stripe = new Stripe(env.STRIPE_SECRET_KEY, {
      apiVersion: '2026-02-25.clover',
      httpClient: Stripe.createFetchHttpClient(),
    });

    // Fetch accounts with active metered subscriptions (checks and/or proofs)
    // Include stripe_customer_id for meter events API (proofs)
    const accountsResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/billing_accounts?subscription_status=in.(active,trialing)&stripe_subscription_item_id=not.is.null&select=account_id,stripe_customer_id,stripe_subscription_item_id,check_count_this_period,stripe_proof_subscription_item_id,proof_count_this_period,stripe_sh_subscription_item_id,sh_check_count_this_period`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!accountsResponse.ok) {
      console.warn(`[observer/stripe] Failed to fetch accounts: ${accountsResponse.status}`);
      return;
    }

    const accounts = (await accountsResponse.json()) as Array<{
      account_id: string;
      stripe_customer_id: string;
      stripe_subscription_item_id: string;
      check_count_this_period: number;
      stripe_proof_subscription_item_id: string | null;
      proof_count_this_period: number;
      stripe_sh_subscription_item_id: string | null;        // NEW
      sh_check_count_this_period: number;                   // NEW
    }>;

    const today = new Date().toISOString().split('T')[0];
    let reported = 0;

    // Fetch today's proof counts from usage_daily_rollup for meter event reporting.
    // Meter events are incremental (each event adds to total), so we send daily counts
    // rather than cumulative period totals.
    const proofRollupResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/usage_daily_rollup?date=eq.${today}&proof_count=gt.0&select=account_id,proof_count`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );
    const dailyProofCounts = new Map<string, number>();
    if (proofRollupResponse.ok) {
      const rows = (await proofRollupResponse.json()) as Array<{ account_id: string; proof_count: number }>;
      for (const row of rows) {
        dailyProofCounts.set(row.account_id, row.proof_count);
      }
    }

    for (const account of accounts) {
      try {
        const checkQuantity = account.check_count_this_period || 0;
        const checkIdempotencyKey = `${account.account_id}-checks-${today}`;

        // Report check usage via legacy createUsageRecord (cumulative, action:'set')
        await (stripe as any).subscriptionItems.createUsageRecord(
          account.stripe_subscription_item_id,
          {
            quantity: checkQuantity,
            timestamp: Math.floor(Date.now() / 1000),
            action: 'set',
          },
          { idempotencyKey: checkIdempotencyKey }
        );

        // Record check usage in stripe_usage_reports
        const checkReportId = `sur-${crypto.randomUUID().slice(0, 8)}`;
        await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/stripe_usage_reports`, {
          method: 'POST',
          headers: {
            apikey: env.SUPABASE_SECRET_KEY,
            Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=minimal',
          },
          body: JSON.stringify({
            id: checkReportId,
            account_id: account.account_id,
            stripe_subscription_item_id: account.stripe_subscription_item_id,
            reported_quantity: checkQuantity,
            idempotency_key: checkIdempotencyKey,
          }),
        });

        // Report proof usage via Stripe Meter Events API (incremental, daily count).
        // The proof price is linked to a Stripe Meter (event_name: 'zk_proof'),
        // which requires meter events instead of createUsageRecord.
        let proofQuantity = 0;
        const dailyProofCount = dailyProofCounts.get(account.account_id) || 0;
        if (dailyProofCount > 0 && account.stripe_customer_id) {
          proofQuantity = dailyProofCount;
          const proofIdentifier = `${account.account_id}-proofs-${today}`;

          await (stripe as any).billing.meterEvents.create({
            event_name: 'zk_proof',
            payload: {
              stripe_customer_id: account.stripe_customer_id,
              value: String(proofQuantity),
            },
            identifier: proofIdentifier,
            timestamp: Math.floor(Date.now() / 1000),
          });

          // Record proof usage in stripe_usage_reports
          const proofReportId = `sur-${crypto.randomUUID().slice(0, 8)}`;
          await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/stripe_usage_reports`, {
            method: 'POST',
            headers: {
              apikey: env.SUPABASE_SECRET_KEY,
              Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
              'Content-Type': 'application/json',
              Prefer: 'return=minimal',
            },
            body: JSON.stringify({
              id: proofReportId,
              account_id: account.account_id,
              stripe_subscription_item_id: account.stripe_proof_subscription_item_id || 'meter_event',
              reported_quantity: proofQuantity,
              idempotency_key: proofIdentifier,
            }),
          });
        }

        // Report Safe House check usage (follows same pattern as integrity checks)
        let shQuantity = 0;
        if (account.stripe_sh_subscription_item_id && (account.sh_check_count_this_period || 0) > 0) {
          shQuantity = account.sh_check_count_this_period || 0;
          const shIdempotencyKey = `${account.account_id}-sh-${today}`;

          await (stripe as any).subscriptionItems.createUsageRecord(
            account.stripe_sh_subscription_item_id,
            {
              quantity: shQuantity,
              timestamp: Math.floor(Date.now() / 1000),
              action: 'set',
            },
            { idempotencyKey: shIdempotencyKey }
          );

          // Record Safe House usage in stripe_usage_reports
          const shReportId = `sur-${crypto.randomUUID().slice(0, 8)}`;
          await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/stripe_usage_reports`, {
            method: 'POST',
            headers: {
              apikey: env.SUPABASE_SECRET_KEY,
              Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
              'Content-Type': 'application/json',
              Prefer: 'return=minimal',
            },
            body: JSON.stringify({
              id: shReportId,
              account_id: account.account_id,
              stripe_subscription_item_id: account.stripe_sh_subscription_item_id,
              reported_quantity: shQuantity,
              idempotency_key: shIdempotencyKey,
            }),
          });
        }

        // Log billing event (combined check + proof report)
        const eventId = `be-${crypto.randomUUID().slice(0, 8)}`;
        await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/billing_events`, {
          method: 'POST',
          headers: {
            apikey: env.SUPABASE_SECRET_KEY,
            Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=minimal',
          },
          body: JSON.stringify({
            event_id: eventId,
            account_id: account.account_id,
            event_type: 'usage_reported',
            details: {
              check_quantity: checkQuantity,
              proof_quantity: proofQuantity,
              sh_quantity: shQuantity,
              date: today,
              check_idempotency_key: checkIdempotencyKey,
              proof_identifier: proofQuantity > 0
                ? `${account.account_id}-proofs-${today}`
                : null,
            },
            performed_by: 'observer_cron',
            timestamp: new Date().toISOString(),
          }),
        });

        reported++;
      } catch (error) {
        console.warn(`[observer/stripe] Failed to report usage for ${account.account_id}:`, error);
      }
    }

    if (reported > 0) {
      console.log(`[observer/stripe] Reported usage for ${reported}/${accounts.length} accounts`);
    }
  } catch (error) {
    console.warn('[observer/stripe] Error in daily usage reporting:', error);
  }
}

/**
 * Check for behavioral drift across recent traces
 */
async function checkForDrift(
  agentId: string,
  card: AlignmentCard | null,
  env: Env,
  otelExporter?: WorkersOTelExporter | null
): Promise<void> {
  if (!card) {
    return;
  }

  try {
    // Fetch recent traces for drift analysis
    const response = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/traces?agent_id=eq.${agentId}&order=timestamp.desc&limit=50`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!response.ok) {
      console.warn(`[observer] Failed to fetch traces for drift check: ${response.status}`);
      return;
    }

    const traces = (await response.json()) as Array<{ trace_json: APTrace }>;

    if (traces.length < 10) {
      // Not enough traces for meaningful drift detection
      return;
    }

    // Extract APTrace objects from database records
    const apTraces = traces.map((t) => t.trace_json);

    // Use AAP SDK drift detection - returns DriftAlert[]
    const driftAlerts: DriftAlert[] = detectDrift(card, apTraces);

    if (driftAlerts.length > 0 && otelExporter) {
      otelExporter.recordDrift(driftAlerts, apTraces.length);
    }

    // Limit to first alert to prevent subrequest overflow
    // TODO: Add proper deduplication - check if similar alert exists before storing
    if (driftAlerts.length > 0) {
      const alert = driftAlerts[0];
      await storeDriftAlert(agentId, alert, env);
      console.log(
        `[observer] Drift detected for ${agentId}: ${alert.analysis.drift_direction} (${driftAlerts.length} total alerts)`
      );
    }
  } catch (error) {
    console.error(`[observer] Drift detection failed for ${agentId}:`, error);
  }
}

/**
 * Write Safe House training traces for messages that preceded detected behavioral drift.
 * These become labeled "high_risk" examples: the message the agent received
 * before drifting toward unsafe behavior is likely adversarial.
 * Always fire-and-forget — never throws.
 */
async function writeSHDriftTrainingTraces(
  agentId: string,
  driftAlertId: string,
  traceIds: string[],
  env: Env
): Promise<void> {
  try {
    if (traceIds.length === 0) return;

    // Take up to 5 trace IDs that preceded the drift — these are our training examples
    const precedingIds = traceIds.slice(0, 5);

    const inserts = precedingIds.map(traceId => ({
      source_signal: 'observer_drift',
      drift_alert_id: driftAlertId,
      trace_id: traceId,
      label: 'high_risk',
    }));

    await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/sh_training_traces`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify(inserts),
    });

    console.log(`[observer/safe-house] Wrote ${inserts.length} drift training traces for alert ${driftAlertId}`);
  } catch {
    // Fire-and-forget: never throws
  }
}

/**
 * Store a drift alert in Supabase
 */
async function storeDriftAlert(
  agentId: string,
  driftAlert: DriftAlert,
  env: Env
): Promise<void> {
  // Map DriftAlert analysis to severity based on similarity score
  const severity = driftAlert.analysis.similarity_score < 0.3 ? 'high'
    : driftAlert.analysis.similarity_score < 0.5 ? 'medium' : 'low';

  const alert = {
    id: `drift-${randomHex(8)}`,
    agent_id: agentId,
    card_id: driftAlert.card_id,
    alert_type: driftAlert.analysis.drift_direction,
    severity,
    description: driftAlert.recommendation,
    drift_data: driftAlert.analysis,
    trace_ids: driftAlert.trace_ids,
  };

  try {
    const response = await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/drift_alerts`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify(alert),
    });

    if (!response.ok) {
      console.warn(`[observer] Failed to store drift alert: ${response.status}`);
    } else {
      // Write Safe House training traces for preceding messages (fire-and-forget)
      writeSHDriftTrainingTraces(agentId, alert.id, driftAlert.trace_ids, env).catch(() => {});
    }
  } catch (error) {
    console.error('[observer] Error storing drift alert:', error);
  }
}

// ============================================================================
// Trace Building
// ============================================================================

/**
 * Build an APTrace conformant trace object
 */
function buildTrace(
  log: GatewayLog,
  metadata: GatewayMetadata,
  context: ExtractedContext,
  analysis: HaikuAnalysis,
  card: AlignmentCard | null
): APTrace {
  // Derive trace_id from log.id for idempotency - same log = same trace
  const traceId = `tr-${log.id.slice(-8)}`;

  // Build action name — prefer tool names, fall back to "inference"
  // Model identity is metadata (stored in parameters.model), not an action
  let actionName = 'inference';
  if (context.toolCalls.length > 0) {
    actionName = context.toolCalls.map((t) => t.name).join(', ');
  }

  // Build action object per AAP SDK Action interface
  const action: Action = {
    type: 'execute',
    name: actionName,
    category: 'bounded',
    target: {
      type: 'api',
      identifier: log.provider || 'anthropic',
    },
    parameters: {
      tokens_in: log.tokens_in,
      tokens_out: log.tokens_out,
      duration_ms: log.duration,
      model: log.model,
      ...(context.toolCalls.length > 0 && {
        tools: context.toolCalls.map((t) => t.name),
      }),
    },
  };

  // Compute confidence deterministically from context richness
  const confidence: number = context.thinking
    ? (context.thinking.length > 500 ? 0.9 : 0.6)
    : 0.3;

  // Build decision object per AAP SDK Decision interface
  const decision: Decision = {
    alternatives_considered: analysis.alternatives.map((a) => ({
      option_id: a.id,
      description: a.description,
    })),
    selected: analysis.selected,
    selection_reasoning: analysis.reasoning,
    values_applied: analysis.values_applied,
    confidence,
  };

  // Build escalation object per AAP SDK Escalation interface
  // Evaluate card's escalation triggers against content_flags to avoid false "missed_escalation" violations.
  // The AAP SDK's verifyTrace checks: if condition matches AND required=false → violation.
  // We must set required=true when the observer's own content flags would match.
  let escalationRequired = false;
  let escalationReason = 'No escalation triggers matched';
  if (card?.autonomy_envelope?.escalation_triggers && analysis.content_flags) {
    for (const trigger of card.autonomy_envelope.escalation_triggers) {
      const condition = trigger.condition;
      if (condition && /^\w+$/.test(condition) && analysis.content_flags[condition]) {
        escalationRequired = true;
        escalationReason = trigger.reason || `Trigger '${condition}' matched`;
        break;
      }
    }
  }

  const escalation: Escalation = {
    evaluated: true,
    required: escalationRequired,
    reason: escalationReason,
  };

  // Build the complete APTrace object (matches SDK exactly)
  const trace: APTrace = {
    trace_id: traceId,
    agent_id: metadata.agent_id,
    card_id: card?.card_id || 'ac-default',
    timestamp: log.created_at,

    action,
    decision,
    escalation,

    context: {
      session_id: metadata.session_id,
      conversation_turn: 1,
      environment: {
        gateway_version: metadata.gateway_version,
        provider: log.provider,
      },
      metadata: {
        has_thinking: !!context.thinking,
        gateway_log_id: log.id,
        success: log.success,
        tool_count: context.toolCalls.length,
        result_summary: `${log.tokens_out} tokens generated in ${log.duration}ms`,
        // Spread content classification flags for AAP SDK evaluateCondition()
        ...(analysis.content_flags || {}),
      },
    },
  };

  return trace;
}

// ============================================================================
// Enforcement Nudge Functions
// ============================================================================


/**
 * Expire stale pending nudges older than 4 hours.
 * Called during cron cycles.
 */
async function expireStaleNudges(env: Env): Promise<void> {
  try {
    const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString();
    const response = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/enforcement_nudges?status=eq.pending&created_at=lt.${fourHoursAgo}`,
      {
        method: 'PATCH',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=representation',
        },
        body: JSON.stringify({
          status: 'expired',
          expired_at: new Date().toISOString(),
        }),
      }
    );

    if (response.ok) {
      const expired = (await response.json()) as unknown[];
      if (expired.length > 0) {
        console.log(`[observer/nudge] Expired ${expired.length} stale nudge(s)`);
      }
    } else {
      console.warn(`[observer/nudge] Failed to expire stale nudges: ${response.status}`);
    }
  } catch (error) {
    console.error('[observer/nudge] Error expiring nudges:', error);
  }
}

// ============================================================================
// AAP Webhook Delivery
// ============================================================================

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
    if (verification.verified) {
      events.push('trace.verified');
    } else {
      events.push('trace.failed');
    }
  }

  if (trace.escalation?.required) {
    events.push('trace.escalation_required');
  }

  if (policyResult?.verdict === 'fail') {
    events.push('policy.violation');
  }

  return events;
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
    // 1. Determine event types for this trace
    const eventTypes = determineAAPEventTypes(trace, verification, policyResult);

    // 2. Fetch webhook registrations for this agent
    const regResponse = await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/aip_webhook_registrations?agent_id=eq.${trace.agent_id}&select=*`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
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

    // 3. Filter registrations by matching event types
    const matchingRegistrations = registrations.filter(reg => {
      return reg.events.some(regEvent =>
        regEvent === '*' ||
        regEvent === 'trace.*' ||
        eventTypes.includes(regEvent)
      );
    });

    if (matchingRegistrations.length === 0) return;

    // 4. Build webhook payload
    const webhookPayload = {
      event: eventTypes[eventTypes.length - 1], // most specific event
      all_events: eventTypes,
      timestamp: new Date().toISOString(),
      trace: {
        trace_id: trace.trace_id,
        agent_id: trace.agent_id,
        session_id: trace.context?.session_id ?? null,
        decision: trace.decision ? {
          reasoning: trace.decision.selection_reasoning,
          alternatives_count: trace.decision.alternatives_considered?.length ?? 0,
        } : null,
        verification: verification ? {
          verified: verification.verified,
          warnings: verification.warnings ?? [],
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

    // 5. Deliver to each matching registration
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

      // 6. Record delivery (include payload + next_retry_at for DLQ retry on failure)
      const totalAttempts = delivered ? 1 : retryDelays.length + 1;
      const deliveryRecord: Record<string, unknown> = {
        id: `del-${randomHex(12)}`,
        registration_id: reg.registration_id,
        checkpoint_id: null,
        trace_id: trace.trace_id,
        event_type: eventTypes[eventTypes.length - 1],
        status: delivered ? 'success' : 'failed',
        attempts: totalAttempts,
        last_attempt_at: new Date().toISOString(),
        error_message: lastError,
      };

      if (!delivered) {
        // Store payload for DLQ replay and schedule first retry
        deliveryRecord.payload = webhookPayload;
        deliveryRecord.next_retry_at = new Date(Date.now() + DLQ_BACKOFF_MS[0]).toISOString();
      }

      try {
        await observerSupabaseFetch(`${env.SUPABASE_URL}/rest/v1/aip_webhook_deliveries`, {
          method: 'POST',
          headers: {
            apikey: env.SUPABASE_SECRET_KEY,
            Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=minimal',
          },
          body: JSON.stringify(deliveryRecord),
          signal: controller.signal,
        });
      } catch (error) {
        console.warn(`[observer/webhook] Failed to record delivery:`, error);
      }

      // 7. Increment failure_count if all retries exhausted
      if (!delivered) {
        console.warn(`[observer/webhook] All retries exhausted for ${reg.registration_id} -> ${reg.callback_url}`);
        try {
          await observerSupabaseFetch(
            `${env.SUPABASE_URL}/rest/v1/aip_webhook_registrations?registration_id=eq.${reg.registration_id}`,
            {
              method: 'PATCH',
              headers: {
                apikey: env.SUPABASE_SECRET_KEY,
                Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
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
// Webhook DLQ Retry Scheduler
// ============================================================================

interface DLQDelivery {
  id: string;
  registration_id: string;
  event_type: string;
  status: string;
  attempts: number;
  payload: Record<string, unknown>;
  error_message: string | null;
  aip_webhook_registrations: {
    callback_url: string;
    secret: string;
  };
}

async function retryDLQWebhooks(env: Env): Promise<void> {
  try {
    // Fetch failed deliveries due for retry, joined with registration for callback_url + secret
    const nowISO = new Date().toISOString();
    const queryUrl = `${env.SUPABASE_URL}/rest/v1/aip_webhook_deliveries` +
      `?select=id,registration_id,event_type,status,attempts,payload,error_message,aip_webhook_registrations!inner(callback_url,secret)` +
      `&status=eq.failed&attempts=lt.${DLQ_MAX_ATTEMPTS}&next_retry_at=lte.${encodeURIComponent(nowISO)}` +
      `&order=next_retry_at.asc&limit=20`;

    const response = await observerSupabaseFetch(queryUrl, {
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
      },
    });

    if (!response.ok) {
      console.warn(`[observer/dlq] Failed to fetch DLQ deliveries: ${response.status}`);
      return;
    }

    const deliveries = (await response.json()) as DLQDelivery[];
    if (deliveries.length === 0) return;

    let succeeded = 0;
    let failed = 0;
    let deadLettered = 0;

    for (const delivery of deliveries) {
      if (!delivery.payload || !delivery.aip_webhook_registrations) {
        console.warn(`[observer/dlq] Skipping ${delivery.id}: missing payload or registration`);
        continue;
      }

      const reg = delivery.aip_webhook_registrations;
      const payloadString = JSON.stringify(delivery.payload);
      const signature = await hmacSign(reg.secret, payloadString);

      let retrySucceeded = false;
      let lastError: string | null = null;

      try {
        const webhookResponse = await fetch(reg.callback_url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-AAP-Signature': `sha256=${signature}`,
            'X-AAP-Version': AAP_VERSION,
          },
          body: payloadString,
        });

        if (webhookResponse.ok) {
          retrySucceeded = true;
        } else {
          lastError = `HTTP ${webhookResponse.status}`;
        }
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
      }

      const newAttempts = delivery.attempts + 1;

      if (retrySucceeded) {
        // Success — clear retry state
        await patchDelivery(env, delivery.id, {
          status: 'success',
          attempts: newAttempts,
          last_attempt_at: new Date().toISOString(),
          next_retry_at: null,
          error_message: null,
        });
        succeeded++;
      } else if (newAttempts >= DLQ_MAX_ATTEMPTS) {
        // Permanently failed — dead-letter
        await patchDelivery(env, delivery.id, {
          status: 'dead',
          attempts: newAttempts,
          last_attempt_at: new Date().toISOString(),
          next_retry_at: null,
          error_message: lastError,
        });
        await sendDLQSlackAlert(env, delivery, lastError);
        deadLettered++;
      } else {
        // Schedule next retry with backoff
        const backoffIndex = Math.min(newAttempts - 4, DLQ_BACKOFF_MS.length - 1);
        const backoffMs = DLQ_BACKOFF_MS[Math.max(0, backoffIndex)];
        await patchDelivery(env, delivery.id, {
          attempts: newAttempts,
          last_attempt_at: new Date().toISOString(),
          next_retry_at: new Date(Date.now() + backoffMs).toISOString(),
          error_message: lastError,
        });
        failed++;
      }
    }

    console.log(`[observer/dlq] Retried ${deliveries.length} deliveries: ${succeeded} succeeded, ${failed} failed, ${deadLettered} dead-lettered`);
  } catch (error) {
    console.error('[observer/dlq] DLQ retry scheduler failed:', error);
  }
}

async function patchDelivery(
  env: Env,
  deliveryId: string,
  fields: Record<string, unknown>
): Promise<void> {
  try {
    await observerSupabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/aip_webhook_deliveries?id=eq.${deliveryId}`,
      {
        method: 'PATCH',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify(fields),
      }
    );
  } catch (error) {
    console.warn(`[observer/dlq] Failed to patch delivery ${deliveryId}:`, error);
  }
}

async function sendDLQSlackAlert(
  env: Env,
  delivery: DLQDelivery,
  lastError: string | null
): Promise<void> {
  if (!env.SLACK_WEBHOOK_URL) {
    console.warn('[observer/dlq] SLACK_WEBHOOK_URL not configured, skipping dead-letter alert');
    return;
  }

  try {
    await fetch(env.SLACK_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: `[DLQ] Webhook delivery permanently failed: ${delivery.id}`,
        blocks: [
          {
            type: 'header',
            text: { type: 'plain_text', text: 'Webhook Dead Letter', emoji: true },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Delivery ID:*\n${delivery.id}` },
              { type: 'mrkdwn', text: `*Registration:*\n${delivery.registration_id}` },
              { type: 'mrkdwn', text: `*Event Type:*\n${delivery.event_type}` },
              { type: 'mrkdwn', text: `*Attempts:*\n${DLQ_MAX_ATTEMPTS}` },
              { type: 'mrkdwn', text: `*Last Error:*\n${lastError ?? 'Unknown'}` },
            ],
          },
        ],
      }),
    });
  } catch (error) {
    console.warn('[observer/dlq] Failed to send Slack alert:', error);
  }
}

// ============================================================================
// Utilities
// ============================================================================

/**
 * Generate a random hex string of specified length.
 * Uses crypto.getRandomValues for cryptographic safety.
 */
function randomHex(length: number): string {
  const bytes = new Uint8Array(Math.ceil(length / 2));
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, length);
}
