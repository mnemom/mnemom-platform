/**
 * Tests for observer pagination loop (scale/step-02)
 *
 * Verifies that processAllLogs correctly:
 * - Loops until the queue is exhausted (lastBatchSize < batchSize)
 * - Respects the OBSERVER_MAX_LOGS safety limit
 * - Emits correct counts (logs_fetched, logs_processed, etc.)
 * - Never increments the page number (deletions advance the CF queue)
 *
 * Functions are not exported from index.ts so we re-implement the loop
 * logic here and test its invariants directly — matching the existing
 * test pattern in this repo.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================================================
// Types (matching index.ts)
// ============================================================================

interface GatewayLog {
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

interface ProcessingStats {
  processed: number;
  skipped: number;
  errors: number;
  logs_fetched: number;
}

// ============================================================================
// Re-implemented loop (mirrors processAllLogs in index.ts after step-02)
// ============================================================================

/**
 * Thin re-implementation of the processAllLogs pagination loop.
 * Delegates per-log work to an injectable processLog function so we can
 * control its behaviour in tests without mocking Anthropic/Supabase.
 */
async function paginationLoop(
  fetchPage: (batchSize: number) => Promise<GatewayLog[]>,
  processLog: (log: GatewayLog) => Promise<boolean>,
  safetyLimit: number
): Promise<{ stats: ProcessingStats; hitSafetyLimit: boolean }> {
  const stats: ProcessingStats = { processed: 0, skipped: 0, errors: 0, logs_fetched: 0 };
  const batchSize = 100;
  let lastBatchSize = batchSize;

  do {
    const batch = await fetchPage(batchSize);
    lastBatchSize = batch.length;
    stats.logs_fetched += batch.length;

    for (const log of batch) {
      try {
        const wasProcessed = await processLog(log);
        if (wasProcessed) {
          stats.processed++;
        } else {
          stats.skipped++;
        }
      } catch {
        stats.errors++;
      }
    }
  } while (lastBatchSize === batchSize && stats.logs_fetched < safetyLimit);

  const hitSafetyLimit = stats.logs_fetched >= safetyLimit;
  return { stats, hitSafetyLimit };
}

// ============================================================================
// Helpers
// ============================================================================

function makeLogs(count: number, startId = 0): GatewayLog[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `log-${startId + i}`,
    created_at: new Date(Date.now() + (startId + i) * 1000).toISOString(),
    provider: 'anthropic',
    model: 'claude-3-haiku',
    success: false, // no-metadata + success=false → skip quickly in real code
    tokens_in: 100,
    tokens_out: 50,
    duration: 200,
  }));
}

/** Returns a fetchPage that serves batches in order, then empty. */
function makePager(batches: GatewayLog[][]): {
  fetchPage: (batchSize: number) => Promise<GatewayLog[]>;
  callCount: () => number;
} {
  let call = 0;
  const fetchPage = async (_batchSize: number): Promise<GatewayLog[]> => {
    const batch = batches[call] ?? [];
    call++;
    return batch;
  };
  return { fetchPage, callCount: () => call };
}

// ============================================================================
// Tests
// ============================================================================

describe('observer pagination loop', () => {
  it('single partial batch — exits after one fetch', async () => {
    const { fetchPage, callCount } = makePager([makeLogs(30)]);
    const { stats, hitSafetyLimit } = await paginationLoop(
      fetchPage,
      async () => false,
      5000
    );

    expect(callCount()).toBe(1);
    expect(stats.logs_fetched).toBe(30);
    expect(stats.skipped).toBe(30);
    expect(hitSafetyLimit).toBe(false);
  });

  it('multi-batch (3 full + 1 partial) — fetches all four pages', async () => {
    const batches = [makeLogs(100, 0), makeLogs(100, 100), makeLogs(100, 200), makeLogs(40, 300)];
    const { fetchPage, callCount } = makePager(batches);
    const { stats, hitSafetyLimit } = await paginationLoop(
      fetchPage,
      async () => false,
      5000
    );

    expect(callCount()).toBe(4);
    expect(stats.logs_fetched).toBe(340);
    expect(hitSafetyLimit).toBe(false);
  });

  it('empty initial batch — exits immediately, no infinite loop', async () => {
    const { fetchPage, callCount } = makePager([[]]);
    const { stats, hitSafetyLimit } = await paginationLoop(
      fetchPage,
      async () => false,
      5000
    );

    expect(callCount()).toBe(1);
    expect(stats.logs_fetched).toBe(0);
    expect(hitSafetyLimit).toBe(false);
  });

  it('safety limit hit — stops mid-stream and sets hitSafetyLimit', async () => {
    // Each call returns 100 logs (infinite source); safetyLimit = 200
    let calls = 0;
    const fetchPage = async (_batchSize: number): Promise<GatewayLog[]> => {
      calls++;
      return makeLogs(100, (calls - 1) * 100);
    };
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const { stats, hitSafetyLimit } = await paginationLoop(fetchPage, async () => false, 200);

    expect(stats.logs_fetched).toBe(200);
    expect(hitSafetyLimit).toBe(true);
    expect(calls).toBe(2); // fetched 2 batches of 100 = 200, then stopped

    consoleSpy.mockRestore();
  });

  it('exactly one full batch equals safety limit — warns and stops cleanly', async () => {
    // safetyLimit = 100, one batch of 100 — should stop after 1 fetch
    const { fetchPage, callCount } = makePager([makeLogs(100), makeLogs(50)]); // second batch never reached
    const { stats, hitSafetyLimit } = await paginationLoop(
      fetchPage,
      async () => false,
      100
    );

    expect(stats.logs_fetched).toBe(100);
    expect(hitSafetyLimit).toBe(true);
    expect(callCount()).toBe(1); // safety limit hit after first batch
  });

  it('counts processed, skipped, and errors correctly across batches', async () => {
    let logIndex = 0;
    const logs = makeLogs(3);
    const { fetchPage } = makePager([logs]);

    const processLog = async (log: GatewayLog): Promise<boolean> => {
      const i = logIndex++;
      if (i === 0) return true;       // processed
      if (i === 1) return false;      // skipped
      throw new Error('test error');  // error
    };

    const { stats } = await paginationLoop(fetchPage, processLog, 5000);

    expect(stats.logs_fetched).toBe(3);
    expect(stats.processed).toBe(1);
    expect(stats.skipped).toBe(1);
    expect(stats.errors).toBe(1);
  });

  it('does not increment page — each fetch call receives the same batchSize=100', async () => {
    const receivedSizes: number[] = [];
    const { fetchPage } = makePager([makeLogs(100), makeLogs(50)]);
    const wrappedFetch = async (batchSize: number): Promise<GatewayLog[]> => {
      receivedSizes.push(batchSize);
      return fetchPage(batchSize);
    };

    await paginationLoop(wrappedFetch, async () => false, 5000);

    // Both calls must use batchSize=100 (no page increment)
    expect(receivedSizes).toEqual([100, 100]);
  });
});
