/**
 * Minimal circuit breaker for external service calls.
 *
 * State machine:
 *   CLOSED    — isOpen=false, failures < threshold  (normal operation)
 *   OPEN      — isOpen=true,  failures >= threshold (reject all calls)
 *   HALF-OPEN — isOpen=false, failures >= threshold (one probe allowed)
 *
 * Note: checkAndReset does NOT reset failures — only recordSuccess does.
 * This lets recordSuccess distinguish a healthy close from a half-open close.
 */

export interface CircuitBreaker {
  failures: number;
  lastFailure: number;
  isOpen: boolean;
  readonly threshold: number;
  readonly resetAfterMs: number;
}

export function createCircuitBreaker(threshold = 3, resetAfterMs = 30000): CircuitBreaker {
  return { failures: 0, lastFailure: 0, isOpen: false, threshold, resetAfterMs };
}

/**
 * If the circuit is open and resetAfterMs has elapsed since the last failure,
 * transition to half-open (isOpen=false). Does NOT reset failures — the
 * failures counter is used by recordSuccess to detect the close transition.
 */
export function checkAndReset(cb: CircuitBreaker, label: string): void {
  if (cb.isOpen && Date.now() - cb.lastFailure > cb.resetAfterMs) {
    cb.isOpen = false;
    console.log(`[circuit-breaker:${label}] Half-open — probing after ${cb.resetAfterMs}ms`);
  }
}

/**
 * Record a successful call. Resets failures and logs a close transition
 * if the circuit was previously at or above the threshold (half-open state).
 */
export function recordSuccess(cb: CircuitBreaker, label: string): void {
  const prevFailures = cb.failures;
  cb.failures = 0;
  if (prevFailures >= cb.threshold) {
    console.log(`[circuit-breaker:${label}] Circuit closed`);
  }
}

/**
 * Record a failed call. Opens the circuit once the threshold is reached.
 */
export function recordFailure(cb: CircuitBreaker, label: string): void {
  cb.failures++;
  cb.lastFailure = Date.now();
  if (!cb.isOpen && cb.failures >= cb.threshold) {
    cb.isOpen = true;
    console.warn(`[circuit-breaker:${label}] Circuit OPEN after ${cb.failures} consecutive failures`);
  }
}
