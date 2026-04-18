/**
 * Tests for queue-producer.ts (Step 50 / ADR-010).
 *
 * Covers enqueueR2Records (lightweight header scan, no decrypt) and
 * enqueuePollingLogs (trivial shape conversion). Mocks R2Bucket + Queue
 * the same way r2-ingest.test.ts does, keeping the test surface
 * self-contained.
 */

import { describe, it, expect, vi } from 'vitest';
import { enqueueR2Records, enqueuePollingLogs } from '../queue-producer';
import type { ObserverQueueMessage } from '../queue-types';

// ============================================================================
// Fixtures / mocks
// ============================================================================

interface FakeR2Object {
  text: string;
}

function makeBucket(objects: Record<string, FakeR2Object>): R2Bucket {
  return {
    list: async ({ prefix, limit, cursor }: R2ListOptions = {}) => {
      const keys = Object.keys(objects).filter(k => !prefix || k.startsWith(prefix)).sort();
      const start = cursor ? parseInt(cursor, 10) : 0;
      const end = Math.min(keys.length, start + (limit ?? 1000));
      const page = keys.slice(start, end);
      return {
        objects: page.map(k => ({ key: k }) as R2Object),
        truncated: end < keys.length,
        cursor: end < keys.length ? String(end) : undefined,
      } as R2Objects;
    },
    get: async (key: string) => {
      const o = objects[key];
      if (!o) return null;
      const bytes = new TextEncoder().encode(o.text);
      return {
        key,
        arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
      } as unknown as R2ObjectBody;
    },
    delete: vi.fn(),
  } as unknown as R2Bucket;
}

function makeQueue() {
  const sent: ObserverQueueMessage[] = [];
  const q = {
    send: vi.fn(async (body: ObserverQueueMessage) => {
      sent.push(body);
    }),
    sendBatch: vi.fn(async (msgs: { body: ObserverQueueMessage }[]) => {
      for (const m of msgs) sent.push(m.body);
    }),
  };
  return { queue: q as unknown as Queue<ObserverQueueMessage>, sent };
}

// ============================================================================
// Fixture record (plaintext headers + encrypted-looking inner fields)
// ============================================================================

function ndjsonRecord(opts: { gateway: string; model?: string; provider?: string; status?: number }): string {
  return JSON.stringify({
    Gateway: opts.gateway,
    Model: opts.model ?? 'claude-haiku-4-5-20251001',
    Provider: opts.provider ?? 'anthropic',
    StatusCode: opts.status ?? 200,
    Cached: false,
    RateLimited: false,
    Endpoint: 'v1/messages',
    Metadata: { type: 'encrypted', key: 'k', iv: 'iv', data: 'd' },
    RequestBody: { type: 'encrypted', key: 'k', iv: 'iv', data: 'd' },
    ResponseBody: { type: 'encrypted', key: 'k', iv: 'iv', data: 'd' },
  });
}

// ============================================================================
// enqueueR2Records
// ============================================================================

describe('enqueueR2Records', () => {
  const now = new Date('2026-04-18T12:00:00Z');

  it('enqueues one message per this-gateway record, in the expected shape', async () => {
    const { queue, sent } = makeQueue();
    const bucket = makeBucket({
      '20260418/a_b_abc123.log.gz': {
        text:
          ndjsonRecord({ gateway: 'mnemom-staging', model: 'claude-haiku-4-5-20251001' }) + '\n' +
          ndjsonRecord({ gateway: 'mnemom-staging', model: 'claude-opus-4-7' }) + '\n',
      },
    });
    const stats = await enqueueR2Records(
      {
        GATEWAY_ID: 'mnemom-staging',
        GATEWAY_LOGS_BUCKET: bucket,
        OBSERVER_QUEUE: queue,
      },
      { maxObjects: 10, now },
    );
    expect(stats.enqueued).toBe(2);
    expect(stats.listed).toBe(1);
    expect(stats.skipped_foreign_gateway).toBe(0);
    expect(stats.read_errors).toBe(0);
    expect(sent).toHaveLength(2);
    expect(sent[0]).toEqual({
      source: 'r2',
      objectKey: '20260418/a_b_abc123.log.gz',
      recordIndex: 0,
      gateway: 'mnemom-staging',
      provider: 'anthropic',
      model: 'claude-haiku-4-5-20251001',
      statusCode: 200,
    });
    expect(sent[1].recordIndex).toBe(1);
    expect((sent[1] as { model?: string }).model).toBe('claude-opus-4-7');
  });

  it('filters foreign-gateway records and counts them', async () => {
    const { queue, sent } = makeQueue();
    const bucket = makeBucket({
      '20260418/shared.log.gz': {
        text:
          ndjsonRecord({ gateway: 'mnemom-staging' }) + '\n' +
          ndjsonRecord({ gateway: 'mnemom' }) + '\n' +
          ndjsonRecord({ gateway: 'mnemom-staging' }) + '\n',
      },
    });
    const stats = await enqueueR2Records(
      { GATEWAY_ID: 'mnemom-staging', GATEWAY_LOGS_BUCKET: bucket, OBSERVER_QUEUE: queue },
      { maxObjects: 10, now },
    );
    expect(stats.enqueued).toBe(2);
    expect(stats.skipped_foreign_gateway).toBe(1);
    expect(sent).toHaveLength(2);
  });

  it('does NOT decrypt records (no call to private-key import)', async () => {
    // If the producer were decrypting, it would need LOGPUSH_DECRYPT_PRIVATE_KEY.
    // Call without setting it — should succeed without throwing.
    const { queue } = makeQueue();
    const bucket = makeBucket({
      '20260418/x.log.gz': { text: ndjsonRecord({ gateway: 'mnemom-staging' }) + '\n' },
    });
    await expect(
      enqueueR2Records(
        { GATEWAY_ID: 'mnemom-staging', GATEWAY_LOGS_BUCKET: bucket, OBSERVER_QUEUE: queue },
        { maxObjects: 1, now },
      ),
    ).resolves.toBeDefined();
  });

  it('counts read errors but continues to the next object', async () => {
    const { queue, sent } = makeQueue();
    // Prefix-aware list: only today's prefix returns keys. Without this the
    // underlying listR2LogKeys helper would call list() for today AND
    // yesterday and the same keys would come back twice.
    const todayPrefix = '20260418/';
    const throwingBucket = {
      list: async ({ prefix }: R2ListOptions = {}) => ({
        objects: prefix === todayPrefix
          ? [
              { key: '20260418/bad.log.gz' } as R2Object,
              { key: '20260418/good.log.gz' } as R2Object,
            ]
          : [],
        truncated: false,
      } as R2Objects),
      get: async (key: string) => {
        if (key === '20260418/bad.log.gz') throw new Error('simulated read failure');
        const bytes = new TextEncoder().encode(ndjsonRecord({ gateway: 'mnemom-staging' }) + '\n');
        return {
          key,
          arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
        } as unknown as R2ObjectBody;
      },
      delete: vi.fn(),
    } as unknown as R2Bucket;
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const stats = await enqueueR2Records(
      { GATEWAY_ID: 'mnemom-staging', GATEWAY_LOGS_BUCKET: throwingBucket, OBSERVER_QUEUE: queue },
      { maxObjects: 10, now },
    );
    expect(stats.read_errors).toBe(1);
    expect(stats.enqueued).toBe(1);
    expect(sent).toHaveLength(1);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it('throws when bucket binding is missing (config error)', async () => {
    const { queue } = makeQueue();
    await expect(
      enqueueR2Records(
        { GATEWAY_ID: 'mnemom-staging', OBSERVER_QUEUE: queue },
        { maxObjects: 1, now },
      ),
    ).rejects.toThrow(/GATEWAY_LOGS_BUCKET/);
  });

  it('throws when queue binding is missing (config error)', async () => {
    const bucket = makeBucket({});
    await expect(
      enqueueR2Records(
        { GATEWAY_ID: 'mnemom-staging', GATEWAY_LOGS_BUCKET: bucket },
        { maxObjects: 1, now },
      ),
    ).rejects.toThrow(/OBSERVER_QUEUE/);
  });

  it('flushes in 100-message batches', async () => {
    const { queue, sent } = makeQueue();
    // Build a single R2 object with 250 records → expect 3 sendBatch calls
    // of 100, 100, 50 (or similar flush boundary).
    const lines = Array.from({ length: 250 }, () => ndjsonRecord({ gateway: 'mnemom-staging' }));
    const bucket = makeBucket({ '20260418/big.log.gz': { text: lines.join('\n') + '\n' } });
    await enqueueR2Records(
      { GATEWAY_ID: 'mnemom-staging', GATEWAY_LOGS_BUCKET: bucket, OBSERVER_QUEUE: queue },
      { maxObjects: 1, now },
    );
    expect(sent).toHaveLength(250);
    const sendBatchCalls = (queue as unknown as { sendBatch: { mock: { calls: unknown[][] } } }).sendBatch.mock.calls;
    const batchSizes = sendBatchCalls.map(c => (c[0] as unknown[]).length);
    // Batches should all be ≤ 100; and sum to 250.
    expect(Math.max(...batchSizes)).toBeLessThanOrEqual(100);
    expect(batchSizes.reduce((a, b) => a + b, 0)).toBe(250);
  });
});

// ============================================================================
// enqueuePollingLogs
// ============================================================================

describe('enqueuePollingLogs', () => {
  it('enqueues one message per log in polling shape', async () => {
    const { queue, sent } = makeQueue();
    const stats = await enqueuePollingLogs(
      { GATEWAY_ID: 'mnemom', OBSERVER_QUEUE: queue },
      [
        { id: 'log-1', provider: 'anthropic', model: 'claude-haiku-4-5-20251001', success: true },
        { id: 'log-2', provider: 'openai', model: 'gpt-4', success: false },
      ],
    );
    expect(stats.enqueued).toBe(2);
    expect(sent).toHaveLength(2);
    expect(sent[0]).toEqual({
      source: 'polling',
      pollingLogId: 'log-1',
      provider: 'anthropic',
      model: 'claude-haiku-4-5-20251001',
      success: true,
    });
    expect((sent[1] as { pollingLogId: string }).pollingLogId).toBe('log-2');
  });

  it('handles empty input as a no-op', async () => {
    const { queue, sent } = makeQueue();
    const stats = await enqueuePollingLogs(
      { GATEWAY_ID: 'mnemom', OBSERVER_QUEUE: queue },
      [],
    );
    expect(stats.enqueued).toBe(0);
    expect(sent).toHaveLength(0);
  });

  it('throws when queue binding is missing', async () => {
    await expect(
      enqueuePollingLogs({ GATEWAY_ID: 'mnemom' }, [{ id: 'x', provider: 'a', model: 'm', success: true }]),
    ).rejects.toThrow(/OBSERVER_QUEUE/);
  });
});
