/**
 * Queue producer — enqueues reference-shaped messages for the consumer to
 * process. Runs in the observer's `scheduled` handler when
 * `OBSERVER_PROCESSING_MODE === "queue"`. Step 50 / ADR-010.
 *
 * Producer responsibilities (kept minimal):
 *   - R2 path: list objects under {YYYYMMDD}/ prefixes, read + gunzip + parse
 *     NDJSON lines to harvest plaintext headers (Gateway/Provider/Model/Status),
 *     filter to this gateway, enqueue one message per record. **No decrypt**
 *     happens here — the consumer re-fetches + decrypts on demand. This saves
 *     CPU vs. the direct path for the producer's tick and sidesteps the CF
 *     Queue 128 KB message cap.
 *
 *   - Polling path: hit the CF AI Gateway REST /logs endpoint, enqueue one
 *     message per log id. No fetchLogBodies() here — consumer does it.
 *
 * Deletion is handled neither here nor by the consumer (see ADR-010 §R2
 * deletion contract): 7-day R2 lifecycle is the source of truth. Duplicate
 * enqueueing across ticks is absorbed by Step 51's submitTrace idempotency.
 */

import type { ObserverQueueMessage } from './queue-types';
import {
  listR2LogKeys,
  parseNDJSON,
  type AIGatewayEventRecord,
  type R2Env,
} from './r2-ingest';

export interface QueueProducerEnv extends R2Env {
  OBSERVER_QUEUE?: Queue<ObserverQueueMessage>;
}

export interface ProducerStats {
  listed: number;
  enqueued: number;
  skipped_foreign_gateway: number;
  read_errors: number;
}

/**
 * Read an R2 object body as text, transparently decompressing gzip-magic'd
 * bodies. Duplicated from r2-ingest.ts (not exported there) to keep that
 * module's surface minimal; both branches share the same byte-level logic.
 */
async function readObjectText(object: R2ObjectBody): Promise<string> {
  const buf = await object.arrayBuffer();
  const bytes = new Uint8Array(buf);
  const isGzip = bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
  if (!isGzip) return new TextDecoder().decode(bytes);
  const stream = new Response(bytes).body!.pipeThrough(new DecompressionStream('gzip'));
  return await new Response(stream).text();
}

/**
 * Enqueue reference messages for every ai_gateway_events record in the
 * R2 list. Filters by Gateway field to this Worker's GATEWAY_ID.
 *
 * Returns stats; does not throw on per-object failures — those are logged and
 * counted in `read_errors` so one corrupt object doesn't stall the tick.
 */
export async function enqueueR2Records(
  env: QueueProducerEnv,
  options: { maxObjects: number; now?: Date },
): Promise<ProducerStats> {
  if (!env.GATEWAY_LOGS_BUCKET) {
    throw new Error('enqueueR2Records: GATEWAY_LOGS_BUCKET binding is not configured');
  }
  if (!env.OBSERVER_QUEUE) {
    throw new Error('enqueueR2Records: OBSERVER_QUEUE binding is not configured');
  }

  const stats: ProducerStats = {
    listed: 0,
    enqueued: 0,
    skipped_foreign_gateway: 0,
    read_errors: 0,
  };

  const keys = await listR2LogKeys(env.GATEWAY_LOGS_BUCKET, options.maxObjects, options.now);
  stats.listed = keys.length;

  // Pending messages we'll flush to the queue in batches of up to 100 (CF limit).
  const pending: ObserverQueueMessage[] = [];

  const flush = async () => {
    while (pending.length > 0) {
      const chunk = pending.splice(0, 100);
      await env.OBSERVER_QUEUE!.sendBatch(chunk.map((body) => ({ body })));
    }
  };

  for (const key of keys) {
    try {
      const obj = await env.GATEWAY_LOGS_BUCKET.get(key);
      if (!obj) continue; // raced with lifecycle expiry
      const text = await readObjectText(obj);
      const records = parseNDJSON(text);

      for (let i = 0; i < records.length; i++) {
        const raw: AIGatewayEventRecord = records[i];
        if (raw.Gateway && raw.Gateway !== env.GATEWAY_ID) {
          stats.skipped_foreign_gateway++;
          continue;
        }
        pending.push({
          source: 'r2',
          objectKey: key,
          recordIndex: i,
          gateway: raw.Gateway ?? env.GATEWAY_ID,
          provider: raw.Provider ?? 'anthropic',
          model: raw.Model ?? 'unknown',
          statusCode: raw.StatusCode ?? 0,
        });
        stats.enqueued++;

        // Flush eagerly at the 100-message threshold to bound memory.
        if (pending.length >= 100) await flush();
      }
    } catch (err) {
      stats.read_errors++;
      console.warn(`[observer/producer] Failed to read ${key}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  await flush();
  return stats;
}

/**
 * Enqueue reference messages for every log returned by a CF polling pass.
 * Small wrapper — the caller passes in the already-fetched log list so this
 * module doesn't need to know about fetchLogs's paging loop.
 */
export interface PollingLogHeader {
  id: string;
  provider: string;
  model: string;
  success: boolean;
}

export async function enqueuePollingLogs(
  env: QueueProducerEnv,
  logs: PollingLogHeader[],
): Promise<ProducerStats> {
  if (!env.OBSERVER_QUEUE) {
    throw new Error('enqueuePollingLogs: OBSERVER_QUEUE binding is not configured');
  }
  const stats: ProducerStats = {
    listed: logs.length,
    enqueued: 0,
    skipped_foreign_gateway: 0,
    read_errors: 0,
  };
  const pending: ObserverQueueMessage[] = logs.map((log) => ({
    source: 'polling',
    pollingLogId: log.id,
    provider: log.provider,
    model: log.model,
    success: log.success,
  }));
  while (pending.length > 0) {
    const chunk = pending.splice(0, 100);
    await env.OBSERVER_QUEUE.sendBatch(chunk.map((body) => ({ body })));
    stats.enqueued += chunk.length;
  }
  return stats;
}
