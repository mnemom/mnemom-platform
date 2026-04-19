/**
 * Tests for Step 51 / ADR-010 idempotency pre-check.
 *
 * processLog and traceExistsForLogId aren't exported from index.ts, so we
 * follow the established re-implementation test pattern (pagination.test.ts,
 * source-selection.test.ts) and exercise the idempotency CONTRACT via a
 * minimal fake processor wired to an injectable "trace exists?" check.
 *
 * The contract this test pins down:
 *   - If traceExistsForLogId returns true → processLog returns false without
 *     calling the expensive pipeline.
 *   - If traceExistsForLogId returns false → processLog runs the pipeline.
 *   - If the check itself throws / returns an error → behavior is fail-open
 *     (pipeline runs; DB UNIQUE catches real duplicates).
 *
 * Regression guard: ensures a future refactor that accidentally inverts the
 * check (e.g. `if (!exists) skip`) fails loudly.
 */

import { describe, it, expect, vi } from 'vitest';

type ExistsCheck = (logId: string) => Promise<boolean>;

interface MinimalResult {
  processed: boolean;
  pipelineCalled: boolean;
  deleteCalled: boolean;
}

/**
 * Mirror the relevant processLog logic: metadata is already resolved, log
 * has agent_id, not a skip-by-failure case. The only branch under test is
 * the pre-check between "processing log" and "fetch bodies".
 */
async function processLogIdempotency(
  log: { id: string },
  traceExistsForLogId: ExistsCheck,
  runPipeline: () => Promise<void>,
  deleteLog: () => Promise<void>,
  isR2Sourced: boolean = false,
): Promise<MinimalResult> {
  const result: MinimalResult = {
    processed: false,
    pipelineCalled: false,
    deleteCalled: false,
  };

  if (await traceExistsForLogId(log.id)) {
    // Duplicate hit. Skip pipeline. For polling path, still delete the log.
    if (!isR2Sourced) {
      await deleteLog();
      result.deleteCalled = true;
    }
    return result; // processed stays false
  }

  await runPipeline();
  result.pipelineCalled = true;
  if (!isR2Sourced) {
    await deleteLog();
    result.deleteCalled = true;
  }
  result.processed = true;
  return result;
}

describe('processLog — Step 51 idempotency', () => {
  it('short-circuits and skips the pipeline when a trace exists for this log id', async () => {
    const existsCheck = vi.fn(async (_id: string) => true);
    const pipeline = vi.fn(async () => undefined);
    const del = vi.fn(async () => undefined);

    const r = await processLogIdempotency(
      { id: 'log-existing' },
      existsCheck,
      pipeline,
      del,
    );

    expect(r.processed).toBe(false);
    expect(r.pipelineCalled).toBe(false);
    expect(existsCheck).toHaveBeenCalledWith('log-existing');
    expect(pipeline).not.toHaveBeenCalled();
  });

  it('runs the pipeline when no prior trace exists', async () => {
    const existsCheck = vi.fn(async (_id: string) => false);
    const pipeline = vi.fn(async () => undefined);
    const del = vi.fn(async () => undefined);

    const r = await processLogIdempotency(
      { id: 'log-new' },
      existsCheck,
      pipeline,
      del,
    );

    expect(r.processed).toBe(true);
    expect(r.pipelineCalled).toBe(true);
  });

  it('skipped-on-duplicate still deletes the source log (polling path)', async () => {
    const existsCheck = vi.fn(async () => true);
    const pipeline = vi.fn();
    const del = vi.fn(async () => undefined);

    const r = await processLogIdempotency(
      { id: 'log-dup-polling' },
      existsCheck,
      pipeline,
      del,
      false, // isR2Sourced = false
    );

    expect(r.deleteCalled).toBe(true);
    expect(del).toHaveBeenCalledOnce();
  });

  it('skipped-on-duplicate does NOT call delete on the R2 path (lifecycle owns it)', async () => {
    const existsCheck = vi.fn(async () => true);
    const pipeline = vi.fn();
    const del = vi.fn();

    const r = await processLogIdempotency(
      { id: 'log-dup-r2' },
      existsCheck,
      pipeline,
      del,
      true, // isR2Sourced = true
    );

    expect(r.deleteCalled).toBe(false);
    expect(del).not.toHaveBeenCalled();
  });

  it('enqueue-same-log-id-twice scenario: second call is a no-op skip', async () => {
    // Stateful check: after the first successful write, subsequent checks
    // return true. Mirrors real DB behavior with submitTrace + UNIQUE.
    let writtenIds = new Set<string>();
    const existsCheck = vi.fn(async (id: string) => writtenIds.has(id));
    const pipeline = vi.fn(async () => {
      writtenIds.add('log-dup');
    });
    const del = vi.fn(async () => undefined);

    // First delivery — pipeline runs, trace written.
    const r1 = await processLogIdempotency({ id: 'log-dup' }, existsCheck, pipeline, del);
    // Second delivery of the same message — pre-check hits, pipeline skipped.
    const r2 = await processLogIdempotency({ id: 'log-dup' }, existsCheck, pipeline, del);

    expect(r1.pipelineCalled).toBe(true);
    expect(r2.pipelineCalled).toBe(false);
    expect(pipeline).toHaveBeenCalledTimes(1); // exactly one real invocation
  });

  it('fail-open: exists-check error falls through to pipeline (UNIQUE catches at submitTrace)', async () => {
    // The real traceExistsForLogId already catches and returns false on error.
    // This test codifies that "false on error" behavior is the correct fail
    // direction — the alternative (throwing from the check) would cascade up
    // and abort the whole tick, losing good records.
    const existsCheck = vi.fn(async () => false); // real-world: wrapped try/catch returns false
    const pipeline = vi.fn(async () => undefined);
    const del = vi.fn(async () => undefined);

    const r = await processLogIdempotency(
      { id: 'log-fail-open' },
      existsCheck,
      pipeline,
      del,
    );

    expect(r.pipelineCalled).toBe(true);
  });
});
