/**
 * Integration test for the observer's Supabase circuit breaker.
 *
 * Tests that observerSupabaseFetch correctly wires the circuit breaker:
 * - 3 consecutive failures → circuit opens
 * - 4th call → throws immediately without calling fetch
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  _observerSupabaseFetchForTests,
  _resetObserverCircuitBreakerForTests,
} from '../index';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

beforeEach(() => {
  mockFetch.mockReset();
  _resetObserverCircuitBreakerForTests();
});

describe('observerSupabaseFetch — circuit breaker integration', () => {
  it('opens circuit after 3 fetch failures and blocks the 4th call', async () => {
    mockFetch.mockRejectedValue(new Error('Network error'));

    const url = 'https://test.supabase.co/rest/v1/traces';
    const opts: RequestInit = { method: 'POST', headers: {}, body: '{}' };

    // Calls 1-3 reach fetch, fail, and increment the circuit breaker
    await expect(_observerSupabaseFetchForTests(url, opts)).rejects.toThrow('Network error');
    await expect(_observerSupabaseFetchForTests(url, opts)).rejects.toThrow('Network error');
    await expect(_observerSupabaseFetchForTests(url, opts)).rejects.toThrow('Network error');
    expect(mockFetch).toHaveBeenCalledTimes(3);

    // Call 4: circuit is now open — fetch must NOT be called
    mockFetch.mockClear();
    await expect(_observerSupabaseFetchForTests(url, opts)).rejects.toThrow('Circuit open');
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
