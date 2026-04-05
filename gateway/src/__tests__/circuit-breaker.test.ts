import { describe, it, expect } from 'vitest';
import {
  createCircuitBreaker,
  checkAndReset,
  recordSuccess,
  recordFailure,
} from '../circuit-breaker';

describe('CircuitBreaker', () => {
  it('starts closed with zero failures', () => {
    const cb = createCircuitBreaker(3, 30000);
    expect(cb.isOpen).toBe(false);
    expect(cb.failures).toBe(0);
    expect(cb.lastFailure).toBe(0);
  });

  it('opens after exactly threshold failures (not before)', () => {
    const cb = createCircuitBreaker(3, 30000);
    recordFailure(cb, 'test');
    expect(cb.isOpen).toBe(false);
    recordFailure(cb, 'test');
    expect(cb.isOpen).toBe(false);
    recordFailure(cb, 'test'); // threshold reached
    expect(cb.isOpen).toBe(true);
    expect(cb.failures).toBe(3);
  });

  it('stays open before resetAfterMs elapses', () => {
    const cb = createCircuitBreaker(3, 30000);
    for (let i = 0; i < 3; i++) recordFailure(cb, 'test');
    cb.lastFailure = Date.now() - 29000; // 29s ago — not yet past reset window
    checkAndReset(cb, 'test');
    expect(cb.isOpen).toBe(true);
  });

  it('transitions to half-open after resetAfterMs — isOpen=false but failures stays at threshold', () => {
    const cb = createCircuitBreaker(3, 30000);
    for (let i = 0; i < 3; i++) recordFailure(cb, 'test');
    cb.lastFailure = Date.now() - 31000; // 31s ago — past reset window
    checkAndReset(cb, 'test');
    expect(cb.isOpen).toBe(false);   // half-open
    expect(cb.failures).toBe(3);     // failures NOT reset by checkAndReset
  });

  it('fully closes on success after half-open — failures reset to 0', () => {
    const cb = createCircuitBreaker(3, 30000);
    for (let i = 0; i < 3; i++) recordFailure(cb, 'test');
    cb.lastFailure = Date.now() - 31000;
    checkAndReset(cb, 'test');        // → half-open
    recordSuccess(cb, 'test');        // probe succeeded
    expect(cb.isOpen).toBe(false);
    expect(cb.failures).toBe(0);
  });

  it('re-opens if the half-open probe fails', () => {
    const cb = createCircuitBreaker(3, 30000);
    for (let i = 0; i < 3; i++) recordFailure(cb, 'test');
    cb.lastFailure = Date.now() - 31000;
    checkAndReset(cb, 'test');        // → half-open: isOpen=false, failures=3
    recordFailure(cb, 'test');        // probe failed: failures=4, re-opens
    expect(cb.isOpen).toBe(true);
    expect(cb.failures).toBe(4);
  });

  it('recordSuccess on a healthy circuit resets failures silently (no logged close)', () => {
    const cb = createCircuitBreaker(3, 30000);
    recordFailure(cb, 'test');        // 1 failure — below threshold, never opened
    recordFailure(cb, 'test');        // 2 failures
    recordSuccess(cb, 'test');        // recovers without ever opening
    expect(cb.isOpen).toBe(false);
    expect(cb.failures).toBe(0);
  });
});
