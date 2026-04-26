/**
 * Tests for the trace_id PK-conflict detector used by submitTrace.
 *
 * Background — observed on prod 2026-04-26: every cron_tick reported
 * `Failed to submit trace: 409 - 23505 ... traces_pkey ...`, observer never
 * deleted the upstream CF AI Gateway log, so the same 21 logs cycled forever
 * (logs_fetched=21 / logs_errored=21 / logs_processed=0).
 *
 * Root cause: PostgREST `on_conflict=gateway_log_id` only merges on that one
 * target. A trace_id PK collision (legacy pre-Step-51 row with NULL
 * gateway_log_id, or 8-char suffix collision in CF log ids) raises a real
 * 23505. submitTrace now converts that specific shape into an idempotent
 * no-op so the polling loop drains.
 */
import { describe, it, expect } from 'vitest';
import { _isTracePkConflictForTests as isTracePkConflict } from '../index';

describe('isTracePkConflict', () => {
  it('returns true for the exact prod 23505 / traces_pkey shape', () => {
    const body = JSON.stringify({
      code: '23505',
      details: 'Key (trace_id)=(tr-9QWEZNKF) already exists.',
      hint: null,
      message: 'duplicate key value violates unique constraint "traces_pkey"',
    });
    expect(isTracePkConflict(409, body)).toBe(true);
  });

  it('returns false for a non-409 status even with matching body', () => {
    const body = JSON.stringify({
      code: '23505',
      message: 'duplicate key value violates unique constraint "traces_pkey"',
    });
    expect(isTracePkConflict(500, body)).toBe(false);
  });

  it('returns false for 409s on a different unique constraint', () => {
    // Hypothetical merge-duplicates miss on gateway_log_id — should NOT be
    // swallowed. submitTrace must keep throwing on those so we notice.
    const body = JSON.stringify({
      code: '23505',
      message: 'duplicate key value violates unique constraint "traces_gateway_log_id_key"',
    });
    expect(isTracePkConflict(409, body)).toBe(false);
  });

  it('returns false for a 409 with a non-23505 error code', () => {
    const body = JSON.stringify({
      code: '23503',
      message: 'foreign key violation',
    });
    expect(isTracePkConflict(409, body)).toBe(false);
  });

  it('returns false for an unparseable body', () => {
    expect(isTracePkConflict(409, '<html>oops</html>')).toBe(false);
    expect(isTracePkConflict(409, '')).toBe(false);
  });

  it('matches case-insensitively on the constraint name', () => {
    const body = JSON.stringify({
      code: '23505',
      message: 'duplicate key value violates unique constraint "TRACES_PKEY"',
    });
    expect(isTracePkConflict(409, body)).toBe(true);
  });
});
