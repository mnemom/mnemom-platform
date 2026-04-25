/**
 * Queue consumer — processes ObserverQueueMessage batches from the main fan-
 * out queue. Step 50 / ADR-010.
 *
 * For each message:
 *   - R2 path: re-fetch the R2 object, gunzip if needed, parse NDJSON, skip
 *     to the record's index, adapt via r2-ingest.adaptRecord (decrypts the
 *     three encrypted fields), then hand off to processLog with
 *     prefetched: { bodies } so the core pipeline runs unchanged.
 *   - Polling path: call fetchLogBodies to pull request+response from CF AI
 *     Gateway, run processLog with prefetched bodies.
 *
 * Errors:
 *   - Transient (5xx, timeout): message.retry(). CF applies the queue's
 *     retry_delay + max_retries; exhausted messages land in the DLQ.
 *   - Poison (malformed, decrypt failure, schema error): message.ack() and
 *     log at error level. A poison message in an infinite retry loop is
 *     worse than lost telemetry; Tier 3 + Step 52 metrics catch the drops.
 *
 * R2 deletion: not done here (ADR-010). The lifecycle reaps objects at 7d.
 */

import {
  importDecryptPrivateKey,
  type EncryptedField,
} from './log-decrypt';
import {
  adaptRecord,
  parseNDJSON,
  type AIGatewayEventRecord,
  type AdaptedRecord,
  type R2Env,
} from './r2-ingest';
import type {
  ObserverQueueMessage,
  ObserverQueueMessageR2,
  ObserverQueueMessagePolling,
} from './queue-types';

export interface QueueConsumerEnv extends R2Env {
  LOGPUSH_DECRYPT_PRIVATE_KEY?: string;
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
}

/**
 * The downstream pipeline this consumer drives. `index.ts` wires its
 * existing `processLog` function in through this signature so we don't have
 * to hoist it here. Keeps this module decoupled from the big pipeline.
 */
export interface LogProcessor {
  (
    log: MinimalGatewayLog,
    env: QueueConsumerEnv & Record<string, unknown>,
    ctx: ExecutionContext,
    options: { prefetched: { bodies: { request: string; response: string } } },
  ): Promise<boolean>;
}

/**
 * Minimal shape of the `GatewayLog` the downstream processLog expects.
 * Deliberately loose typing (string | Record) on `metadata` matches index.ts.
 */
export interface MinimalGatewayLog {
  id: string;
  created_at: string;
  provider: string;
  model: string;
  success: boolean;
  tokens_in: number;
  tokens_out: number;
  duration: number;
  metadata?: string | Record<string, string>;
}

// ============================================================================
// Per-message handlers
// ============================================================================

/**
 * Marker thrown by loadR2Record when decrypt/adapt fails. Classified as
 * poison by the batch handler's catch — retrying a decrypt failure is
 * pointless; the ciphertext is either corrupt or signed under a key we
 * don't hold.
 */
class PoisonRecordError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'PoisonRecordError';
    if (cause !== undefined) (this as Error & { cause?: unknown }).cause = cause;
  }
}

/**
 * Load + decrypt a single record from R2 for queue consumption.
 * Returns null if the object is missing (lifecycle reaped it or was already
 * processed + deleted on a pre-ADR-010 branch) — the caller should ack
 * without retry, since retry won't help.
 *
 * Throws PoisonRecordError for any post-fetch failure that won't recover on
 * retry (malformed NDJSON, bad envelope shape, RSA/AES decrypt failure).
 * R2 GET failures themselves bubble up as-is so the caller's classifier can
 * treat them as transient.
 */
async function loadR2Record(
  msg: ObserverQueueMessageR2,
  env: QueueConsumerEnv,
): Promise<AdaptedRecord | null> {
  if (!env.GATEWAY_LOGS_BUCKET) {
    throw new Error('loadR2Record: GATEWAY_LOGS_BUCKET binding is not configured');
  }
  if (!env.LOGPUSH_DECRYPT_PRIVATE_KEY) {
    throw new Error('loadR2Record: LOGPUSH_DECRYPT_PRIVATE_KEY is not set');
  }

  // R2 GET — transient failures propagate up to the retry path.
  const obj = await env.GATEWAY_LOGS_BUCKET.get(msg.objectKey);
  if (!obj) return null;
  const buf = await obj.arrayBuffer();
  const bytes = new Uint8Array(buf);

  // Decode + parse + decrypt — any failure here is permanent.
  try {
    const isGzip = bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
    const text = isGzip
      ? await new Response(new Response(bytes).body!.pipeThrough(new DecompressionStream('gzip'))).text()
      : new TextDecoder().decode(bytes);
    const records = parseNDJSON(text);
    if (msg.recordIndex < 0 || msg.recordIndex >= records.length) return null;
    const raw: AIGatewayEventRecord = records[msg.recordIndex];
    if (raw.Gateway && raw.Gateway !== env.GATEWAY_ID) return null;

    const key = await importDecryptPrivateKey(env.LOGPUSH_DECRYPT_PRIVATE_KEY);
    return await adaptRecord(raw, msg.objectKey, msg.recordIndex, key);
  } catch (err) {
    const inner = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    throw new PoisonRecordError(`loadR2Record failed on ${msg.objectKey}#${msg.recordIndex}: ${inner}`, err);
  }
}

/**
 * Load a CF AI Gateway polling log for queue consumption. Re-fetches both
 * the log envelope + its request/response bodies. Returns null on 404
 * (log may have been deleted already by a prior tick or this consumer
 * pre-retry) so the caller can ack without further work.
 */
async function loadPollingLog(
  msg: ObserverQueueMessagePolling,
  env: QueueConsumerEnv,
): Promise<{ log: MinimalGatewayLog; bodies: { request: string; response: string } } | null> {
  const base = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/ai-gateway/gateways/${env.GATEWAY_ID}/logs/${msg.pollingLogId}`;
  const headers = { Authorization: `Bearer ${env.CF_API_TOKEN}` };

  const [envelopeRes, reqRes, respRes] = await Promise.all([
    fetch(base, { headers }),
    fetch(`${base}/request`, { headers }),
    fetch(`${base}/response`, { headers }),
  ]);

  if (envelopeRes.status === 404) return null;
  if (!envelopeRes.ok) {
    throw new Error(`CF AI Gateway API: ${envelopeRes.status} on log ${msg.pollingLogId}`);
  }

  const envelope = (await envelopeRes.json()) as {
    success?: boolean;
    result?: MinimalGatewayLog;
  };
  if (!envelope?.result) return null;

  const readBody = async (res: Response): Promise<string> => {
    if (!res.ok) return '';
    const raw = await res.text();
    try {
      const parsed = JSON.parse(raw);
      return parsed.result !== undefined
        ? typeof parsed.result === 'string'
          ? parsed.result
          : JSON.stringify(parsed.result)
        : raw;
    } catch {
      return raw;
    }
  };

  return {
    log: envelope.result,
    bodies: {
      request: await readBody(reqRes),
      response: await readBody(respRes),
    },
  };
}

// ============================================================================
// Batch handler
// ============================================================================

export interface BatchStats {
  total: number;
  processed: number;
  skipped: number;
  acks_on_missing: number;
  poison_acks: number;
  retries: number;
  /**
   * Age of the oldest message in this batch at the moment the consumer first
   * looked at it (ms). Captured before any processing so it reflects the lag
   * we want to alert on, not the lag plus our own batch-handling latency.
   * Zero when the batch is empty. See ADR-033.
   */
  oldest_message_lag_ms: number;
}

/**
 * Drive one MessageBatch through the consumer pipeline. Returns per-batch
 * stats for observability. Logs all per-message errors to Tier 3.
 */
export async function handleQueueBatch(
  batch: MessageBatch<ObserverQueueMessage>,
  env: QueueConsumerEnv & Record<string, unknown>,
  ctx: ExecutionContext,
  processLog: LogProcessor,
): Promise<BatchStats> {
  // Consumer-side lag (ADR-033): each CF Queue message carries its enqueue
  // timestamp. Computing lag here gives us a per-batch "oldest unacked
  // message age" signal that is more accurate, lower-latency, and free of
  // CF Analytics API dependency compared to inferring it externally.
  const batchStartMs = Date.now();
  const oldestMessageLagMs = batch.messages.length > 0
    ? batchStartMs - Math.min(
        ...batch.messages.map((m) => m.timestamp.getTime()),
      )
    : 0;

  const stats: BatchStats = {
    total: batch.messages.length,
    processed: 0,
    skipped: 0,
    acks_on_missing: 0,
    poison_acks: 0,
    retries: 0,
    oldest_message_lag_ms: oldestMessageLagMs,
  };

  for (const message of batch.messages) {
    const body = message.body;
    try {
      if (body.source === 'r2') {
        const rec = await loadR2Record(body, env);
        if (!rec) {
          message.ack();
          stats.acks_on_missing++;
          continue;
        }
        const processed = await processLog(rec.log as unknown as MinimalGatewayLog, env, ctx, {
          prefetched: { bodies: rec.bodies },
        });
        if (processed) stats.processed++;
        else stats.skipped++;
        message.ack();
      } else if (body.source === 'polling') {
        const loaded = await loadPollingLog(body, env);
        if (!loaded) {
          message.ack();
          stats.acks_on_missing++;
          continue;
        }
        const processed = await processLog(loaded.log, env, ctx, {
          prefetched: { bodies: loaded.bodies },
        });
        if (processed) stats.processed++;
        else stats.skipped++;
        message.ack();
      } else {
        // Unknown source — structural poison. Ack to drain.
        console.error(`[observer/consumer] Unknown message source: ${JSON.stringify(body).slice(0, 200)}`);
        message.ack();
        stats.poison_acks++;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const name = err instanceof Error ? err.name : '';
      // Decryption / parse failures are poison — retrying won't help, and
      // a poison-retry loop eats queue capacity. Ack the message and trust
      // Tier 3 + Step 52's "poison_acks" counter to surface the signal.
      if (isPoisonError(msg, name)) {
        console.error(`[observer/consumer] Poison message acked: ${name ? `${name}: ` : ''}${msg}`);
        message.ack();
        stats.poison_acks++;
      } else {
        console.warn(`[observer/consumer] Transient failure, retrying: ${name ? `${name}: ` : ''}${msg}`);
        message.retry();
        stats.retries++;
      }
    }
  }

  console.log(
    JSON.stringify({ observer_queue_batch: stats })
  );
  return stats;
}

/**
 * Heuristic classifier: which error messages warrant retry vs. ack-as-poison.
 * Errs on the side of retry (ambiguous → retry) because max_retries + DLQ
 * catches runaway retries and an incorrect retry just delays the DLQ entry,
 * whereas an incorrect ack permanently drops a potentially-good record.
 */
function isPoisonError(msg: string, name: string = ''): boolean {
  // Explicit poison marker from loadR2Record — covers every decrypt / parse /
  // adapter failure in one bucket. This is the primary signal.
  if (name === 'PoisonRecordError') return true;
  // WebCrypto / runtime-surfaced decrypt failures (for the polling path or
  // anywhere else that throws WebCrypto errors directly without being wrapped).
  if (name === 'OperationError' || name === 'DataError') return true;
  if (name === 'SyntaxError') return true;

  const s = msg.toLowerCase();
  // Specific binding/config errors are poison from the consumer's perspective —
  // an operator fix is needed; retrying immediately won't help.
  if (s.includes('binding is not configured')) return true;
  if (s.includes('private_key is not set')) return true;
  return false;
}
