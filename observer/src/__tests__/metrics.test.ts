/**
 * Tests for metrics.ts (Step 52).
 *
 * Strategy: stub global fetch, drive the emitters through the happy path +
 * degraded paths, assert payload shape. Pure-function helpers (payload
 * builders, response parsers) are exercised directly so we don't need to
 * instantiate fetch at all.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  emitBatchMetrics,
  emitQueueDepthMetrics,
  fetchQueueDepths,
  buildOtlpMetricsBody,
  extractBacklogGroups,
  extractQueueIdMap,
  type MetricsEnv,
} from '../metrics';
import type { BatchStats } from '../queue-consumer';

function makeEnv(overrides: Partial<MetricsEnv> = {}): MetricsEnv {
  return {
    OTLP_ENDPOINT: 'https://otlp.example/otlp',
    OTLP_AUTH: 'Basic abc',
    GATEWAY_ID: 'mnemom-staging',
    OBSERVER_PROCESSING_MODE: 'queue',
    CF_ACCOUNT_ID: 'acct-1',
    CF_API_TOKEN: 'cf-token',
    ...overrides,
  };
}

function makeStats(overrides: Partial<BatchStats> = {}): BatchStats {
  return {
    total: 5,
    processed: 3,
    skipped: 1,
    acks_on_missing: 0,
    poison_acks: 1,
    retries: 0,
    ...overrides,
  };
}

const FETCH_OK = (body: unknown): Response =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

const FETCH_FAIL = (status: number): Response =>
  new Response('error', { status });

describe('buildOtlpMetricsBody', () => {
  it('wraps metrics in resourceMetrics with service.name attribute', () => {
    const json = buildOtlpMetricsBody([], 'scope.test');
    const parsed = JSON.parse(json);
    expect(parsed.resourceMetrics).toHaveLength(1);
    const resourceAttrs = parsed.resourceMetrics[0].resource.attributes;
    expect(resourceAttrs).toEqual([
      { key: 'service.name', value: { stringValue: 'mnemom-observer' } },
    ]);
    expect(parsed.resourceMetrics[0].scopeMetrics[0].scope.name).toBe('scope.test');
  });
});

describe('emitBatchMetrics', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn().mockResolvedValue(FETCH_OK({}));
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('no-ops when OTLP_ENDPOINT is unset', async () => {
    await emitBatchMetrics(makeEnv({ OTLP_ENDPOINT: undefined }), makeStats());
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('POSTs to /v1/metrics with DELTA monotonic counters per outcome', async () => {
    await emitBatchMetrics(makeEnv(), makeStats({
      processed: 4, skipped: 2, acks_on_missing: 1, poison_acks: 1, retries: 0,
    }));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://otlp.example/otlp/v1/metrics');
    expect((init as RequestInit).method).toBe('POST');
    expect((init as RequestInit).headers).toMatchObject({
      'Content-Type': 'application/json',
      Authorization: 'Basic abc',
    });

    const body = JSON.parse((init as RequestInit).body as string);
    const metrics = body.resourceMetrics[0].scopeMetrics[0].metrics;

    const processed = metrics.find((m: { name: string; sum?: { dataPoints: Array<{ attributes: Array<{ key: string; value: { stringValue?: string } }> }> } }) =>
      m.name === 'observer.messages_processed' &&
      m.sum?.dataPoints[0].attributes.find((a) => a.key === 'outcome')?.value.stringValue === 'processed',
    );
    expect(processed?.sum?.aggregationTemporality).toBe(1); // DELTA
    expect(processed?.sum?.isMonotonic).toBe(true);
    expect(processed?.sum?.dataPoints[0].asInt).toBe('4');

    const poison = metrics.find((m: { name: string; sum?: { dataPoints: Array<{ attributes: Array<{ key: string; value: { stringValue?: string } }> }> } }) =>
      m.name === 'observer.messages_failed' &&
      m.sum?.dataPoints[0].attributes.find((a) => a.key === 'reason')?.value.stringValue === 'poison',
    );
    expect(poison?.sum?.dataPoints[0].asInt).toBe('1');

    // Every data point should carry gateway_id + mode attributes.
    for (const m of metrics) {
      const attrs = m.sum.dataPoints[0].attributes as Array<{ key: string; value: { stringValue: string } }>;
      expect(attrs.find((a) => a.key === 'gateway_id')?.value.stringValue).toBe('mnemom-staging');
      expect(attrs.find((a) => a.key === 'mode')?.value.stringValue).toBe('queue');
    }
  });

  it('swallows fetch failures', async () => {
    fetchMock.mockRejectedValueOnce(new Error('network unreachable'));
    await expect(emitBatchMetrics(makeEnv(), makeStats())).resolves.toBeUndefined();
  });
});

describe('emitQueueDepthMetrics', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn().mockResolvedValue(FETCH_OK({}));
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('emits two gauges per queue (depth + consumer_lag)', async () => {
    await emitQueueDepthMetrics(makeEnv(), [
      { queue: 'main', backlogMessages: 1234, oldestMessageAgeSeconds: 12 },
      { queue: 'dlq', backlogMessages: 0, oldestMessageAgeSeconds: 0 },
    ]);

    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    const metrics = body.resourceMetrics[0].scopeMetrics[0].metrics;

    const depthMain = metrics.find((m: { name: string; gauge?: { dataPoints: Array<{ attributes: Array<{ key: string; value: { stringValue?: string } }>; asInt?: string }> } }) =>
      m.name === 'observer.queue_depth' &&
      m.gauge?.dataPoints[0].attributes.find((a) => a.key === 'queue')?.value.stringValue === 'main',
    );
    expect(depthMain?.gauge?.dataPoints[0].asInt).toBe('1234');

    const lagDlq = metrics.find((m: { name: string; gauge?: { dataPoints: Array<{ attributes: Array<{ key: string; value: { stringValue?: string } }>; asInt?: string }> } }) =>
      m.name === 'observer.consumer_lag_seconds' &&
      m.gauge?.dataPoints[0].attributes.find((a) => a.key === 'queue')?.value.stringValue === 'dlq',
    );
    expect(lagDlq?.gauge?.dataPoints[0].asInt).toBe('0');
  });

  it('no-ops on empty array', async () => {
    await emitQueueDepthMetrics(makeEnv(), []);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('extractBacklogGroups', () => {
  it('returns rows tolerating missing max fields', () => {
    const body = {
      data: {
        viewer: {
          accounts: [{
            queueBacklogAdaptiveGroups: [
              { dimensions: { queueId: 'q1' }, max: { backlogMessages: 99, oldestMessageAgeSeconds: 7 } },
              { dimensions: { queueId: 'q2' }, max: { backlogMessages: 0 } }, // missing oldestAge
              { dimensions: { queueId: 'q3' } }, // missing max entirely
            ],
          }],
        },
      },
    };
    const rows = extractBacklogGroups(body);
    expect(rows).toEqual([
      { queueId: 'q1', backlogMessages: 99, oldestMessageAgeSeconds: 7 },
      { queueId: 'q2', backlogMessages: 0, oldestMessageAgeSeconds: 0 },
      { queueId: 'q3', backlogMessages: 0, oldestMessageAgeSeconds: 0 },
    ]);
  });

  it('returns null on unrecognizable shape', () => {
    expect(extractBacklogGroups(null)).toBeNull();
    expect(extractBacklogGroups({ data: null })).toBeNull();
    expect(extractBacklogGroups({ data: { viewer: { accounts: 'nope' } } })).toBeNull();
  });

  it('returns empty list when no groups but shape is valid', () => {
    const body = { data: { viewer: { accounts: [{ queueBacklogAdaptiveGroups: [] }] } } };
    expect(extractBacklogGroups(body)).toEqual([]);
  });
});

describe('extractQueueIdMap', () => {
  it('returns only the requested names', () => {
    const body = {
      result: [
        { queue_id: 'id-a', queue_name: 'alpha' },
        { queue_id: 'id-b', queue_name: 'beta' },
        { queue_id: 'id-c', queue_name: 'gamma' },
      ],
    };
    const map = extractQueueIdMap(body, ['alpha', 'gamma', 'zeta']);
    expect(Array.from(map.entries())).toEqual([
      ['alpha', 'id-a'],
      ['gamma', 'id-c'],
    ]);
  });

  it('returns empty map on unrecognizable shape', () => {
    expect(extractQueueIdMap(null, ['alpha']).size).toBe(0);
    expect(extractQueueIdMap({ result: null }, ['alpha']).size).toBe(0);
  });
});

describe('fetchQueueDepths', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('returns null for unknown GATEWAY_ID', async () => {
    const r = await fetchQueueDepths(makeEnv({ GATEWAY_ID: 'something-else' }));
    expect(r).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('happy path: resolves names → ids → backlog', async () => {
    // (1) queue listing
    fetchMock.mockResolvedValueOnce(FETCH_OK({
      result: [
        { queue_id: 'QMAIN', queue_name: 'mnemom-observer-records-staging' },
        { queue_id: 'QDLQ', queue_name: 'mnemom-observer-records-staging-dlq' },
        { queue_id: 'QOTHER', queue_name: 'some-other-queue' },
      ],
    }));
    // (2) GraphQL backlog
    fetchMock.mockResolvedValueOnce(FETCH_OK({
      data: {
        viewer: {
          accounts: [{
            queueBacklogAdaptiveGroups: [
              { dimensions: { queueId: 'QMAIN' }, max: { backlogMessages: 42, oldestMessageAgeSeconds: 3 } },
              { dimensions: { queueId: 'QDLQ' }, max: { backlogMessages: 0, oldestMessageAgeSeconds: 0 } },
            ],
          }],
        },
      },
    }));

    const r = await fetchQueueDepths(makeEnv());
    expect(r).toEqual([
      { queue: 'main', backlogMessages: 42, oldestMessageAgeSeconds: 3 },
      { queue: 'dlq', backlogMessages: 0, oldestMessageAgeSeconds: 0 },
    ]);
    // Listing → graphql, two calls.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const firstUrl = fetchMock.mock.calls[0][0];
    expect(firstUrl).toContain('/accounts/acct-1/queues');
    const secondUrl = fetchMock.mock.calls[1][0];
    expect(secondUrl).toContain('/graphql');
  });

  it('returns zero-depth rows when queues are missing from listing', async () => {
    // Listing returns an unrelated queue only — the observer queues don't exist yet.
    fetchMock.mockResolvedValueOnce(FETCH_OK({
      result: [{ queue_id: 'QELSE', queue_name: 'different' }],
    }));
    // GraphQL still runs, returns empty groups (no queueIds to query).
    const r = await fetchQueueDepths(makeEnv());
    expect(r).toEqual([
      { queue: 'main', backlogMessages: 0, oldestMessageAgeSeconds: 0 },
      { queue: 'dlq', backlogMessages: 0, oldestMessageAgeSeconds: 0 },
    ]);
    // Only one fetch call — graphql is skipped because there are no IDs to query.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('returns null when queue listing fails', async () => {
    fetchMock.mockResolvedValueOnce(FETCH_FAIL(403));
    const r = await fetchQueueDepths(makeEnv());
    expect(r).toBeNull();
  });

  it('returns null when GraphQL fails (partial data dropped to avoid half-emission)', async () => {
    fetchMock.mockResolvedValueOnce(FETCH_OK({
      result: [{ queue_id: 'QMAIN', queue_name: 'mnemom-observer-records-staging' }],
    }));
    fetchMock.mockResolvedValueOnce(FETCH_FAIL(500));
    const r = await fetchQueueDepths(makeEnv());
    expect(r).toBeNull();
  });
});
