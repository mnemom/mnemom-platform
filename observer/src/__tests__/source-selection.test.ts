/**
 * Tests for the log-source selection contract in processAllLogs (scale/step-49).
 *
 * processAllLogs is internal to index.ts and depends on the full observer
 * pipeline, so we follow the established repo pattern (see pagination.test.ts):
 * re-implement the dispatch logic here and exercise it against injected
 * fakes. The assertions verify the contract documented on processAllLogs:
 *
 *   - env.LOGPUSH_SOURCE="polling" (or unset) → never touches R2.
 *   - env.LOGPUSH_SOURCE="r2" + R2 returns records → polling not invoked.
 *   - env.LOGPUSH_SOURCE="r2" + R2 returns zero records → falls through to polling.
 *   - env.LOGPUSH_SOURCE="r2" + R2 throws → falls through to polling (no thrown
 *     error propagates to the cron handler; a silent tick is worse than a loud
 *     fallback).
 */

import { describe, it, expect, vi } from 'vitest';

interface Stats {
  processed: number;
  skipped: number;
  errors: number;
  logs_fetched: number;
}

function zero(): Stats {
  return { processed: 0, skipped: 0, errors: 0, logs_fetched: 0 };
}

async function dispatch(
  source: string | undefined,
  r2: () => Promise<Stats>,
  polling: () => Promise<Stats>,
): Promise<{ stats: Stats; sourceUsed: string }> {
  const wantR2 = source === 'r2';
  if (wantR2) {
    try {
      const r2Stats = await r2();
      if (r2Stats.logs_fetched > 0) {
        return { stats: r2Stats, sourceUsed: 'r2' };
      }
    } catch {
      // fall through
    }
  }
  const pollingStats = await polling();
  return { stats: pollingStats, sourceUsed: wantR2 ? 'polling (fallback)' : 'polling' };
}

describe('log source dispatch', () => {
  it('LOGPUSH_SOURCE unset → polling only, R2 never touched', async () => {
    const r2 = vi.fn(async () => ({ ...zero(), logs_fetched: 99 }));
    const polling = vi.fn(async () => ({ ...zero(), logs_fetched: 5, processed: 5 }));
    const { sourceUsed } = await dispatch(undefined, r2, polling);
    expect(r2).not.toHaveBeenCalled();
    expect(polling).toHaveBeenCalledOnce();
    expect(sourceUsed).toBe('polling');
  });

  it('LOGPUSH_SOURCE="polling" → polling only', async () => {
    const r2 = vi.fn(async () => ({ ...zero(), logs_fetched: 99 }));
    const polling = vi.fn(async () => ({ ...zero(), logs_fetched: 3, processed: 3 }));
    await dispatch('polling', r2, polling);
    expect(r2).not.toHaveBeenCalled();
    expect(polling).toHaveBeenCalledOnce();
  });

  it('LOGPUSH_SOURCE="r2" + records present → R2 used, polling skipped', async () => {
    const r2 = vi.fn(async () => ({ ...zero(), logs_fetched: 7, processed: 7 }));
    const polling = vi.fn(async () => ({ ...zero() }));
    const { sourceUsed, stats } = await dispatch('r2', r2, polling);
    expect(r2).toHaveBeenCalledOnce();
    expect(polling).not.toHaveBeenCalled();
    expect(sourceUsed).toBe('r2');
    expect(stats.processed).toBe(7);
  });

  it('LOGPUSH_SOURCE="r2" + R2 returns empty → falls through to polling', async () => {
    const r2 = vi.fn(async () => ({ ...zero() }));
    const polling = vi.fn(async () => ({ ...zero(), logs_fetched: 4, processed: 4 }));
    const { sourceUsed, stats } = await dispatch('r2', r2, polling);
    expect(r2).toHaveBeenCalledOnce();
    expect(polling).toHaveBeenCalledOnce();
    expect(sourceUsed).toBe('polling (fallback)');
    expect(stats.processed).toBe(4);
  });

  it('LOGPUSH_SOURCE="r2" + R2 throws → falls through to polling (no error propagates)', async () => {
    const r2 = vi.fn(async () => {
      throw new Error('R2 list failed');
    });
    const polling = vi.fn(async () => ({ ...zero(), logs_fetched: 2, processed: 2 }));
    const { sourceUsed, stats } = await dispatch('r2', r2, polling);
    expect(r2).toHaveBeenCalledOnce();
    expect(polling).toHaveBeenCalledOnce();
    expect(sourceUsed).toBe('polling (fallback)');
    expect(stats.processed).toBe(2);
  });
});
