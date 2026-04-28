/**
 * Tests for metrics.ts (Step 52, span-derived per ADR-032).
 *
 * Strategy: stub global fetch, drive the emitters through the happy path +
 * degraded paths, assert OTLP span payload shape. Pure-function helpers
 * (payload builders, response parsers) are exercised directly so we don't
 * need to instantiate fetch at all.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  emitQueueBatchSpan,
  emitQueueBacklogSpans,
  fetchQueueDepths,
  buildOtlpSpansBody,
  extractBacklogGroups,
  extractQueueIdMap,
  type MetricsEnv,
  type QueueDepth,
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
    oldest_message_lag_ms: 0,
    ...overrides,
  };
}

const FETCH_OK = (body: unknown): Response =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

const FETCH_FAIL = (status: number): Response =>
  new Response('error', { status });

// ---------------------------------------------------------------------------
// Narrow payload-shape types used only inside assertions.
// ---------------------------------------------------------------------------

interface OtlpAttr { key: string; value: { stringValue?: string; intValue?: string } }
interface OtlpSpan {
  name: string;
  kind: number;
  attributes: OtlpAttr[];
  status: { code: number };
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  traceId: string;
  spanId: string;
}
interface OtlpBody {
  resourceSpans: Array<{
    resource: { attributes: OtlpAttr[] };
    scopeSpans: Array<{
      scope: { name: string };
      spans: OtlpSpan[];
    }>;
  }>;
}

function getSpans(init: RequestInit): OtlpSpan[] {
  const body = JSON.parse(init.body as string) as OtlpBody;
  return body.resourceSpans[0].scopeSpans[0].spans;
}

function attr(span: OtlpSpan, key: string): string | undefined {
  const a = span.attributes.find((a) => a.key === key);
  return a?.value.stringValue ?? a?.value.intValue;
}

// ===========================================================================

describe('buildOtlpSpansBody', () => {
  it('wraps spans in resourceSpans with service.name=mnemom-observer', () => {
    const json = buildOtlpSpansBody([], 'scope.test');
    const parsed = JSON.parse(json) as OtlpBody;
    expect(parsed.resourceSpans).toHaveLength(1);
    expect(parsed.resourceSpans[0].resource.attributes).toEqual([
      { key: 'service.name', value: { stringValue: 'mnemom-observer' } },
    ]);
    expect(parsed.resourceSpans[0].scopeSpans[0].scope.name).toBe('scope.test');
  });
});

describe('emitQueueBatchSpan', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn().mockResolvedValue(FETCH_OK({}));
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('no-ops when OTLP_ENDPOINT is unset', async () => {
    await emitQueueBatchSpan(makeEnv({ OTLP_ENDPOINT: undefined }), makeStats());
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('POSTs to /v1/traces with one batch span + one poison span per poison_ack', async () => {
    await emitQueueBatchSpan(
      makeEnv(),
      makeStats({ processed: 4, skipped: 2, acks_on_missing: 1, poison_acks: 2, retries: 0, total: 9 }),
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://otlp.example/otlp/v1/traces');
    expect((init as RequestInit).method).toBe('POST');
    expect((init as RequestInit).headers).toMatchObject({
      'Content-Type': 'application/json',
      Authorization: 'Basic abc',
    });

    const spans = getSpans(init as RequestInit);
    expect(spans.map((s) => s.name)).toEqual([
      'observer.queue_batch',
      'observer.queue_poison',
      'observer.queue_poison',
    ]);
  });

  it('batch span carries all integer counts + env/mode/gateway_id dimensions', async () => {
    await emitQueueBatchSpan(
      makeEnv(),
      makeStats({
        total: 10, processed: 7, skipped: 2, acks_on_missing: 1, poison_acks: 0, retries: 3,
        oldest_message_lag_ms: 12345,
      }),
    );

    const batch = getSpans(fetchMock.mock.calls[0][1] as RequestInit)[0];

    // Low-cardinality dimensions — these become spanmetrics labels.
    expect(attr(batch, 'env')).toBe('staging');
    expect(attr(batch, 'mode')).toBe('queue');
    expect(attr(batch, 'gateway_id')).toBe('mnemom-staging');

    // High-cardinality integer counts — stored as span attrs for TraceQL queries.
    expect(attr(batch, 'batch_size')).toBe('10');
    expect(attr(batch, 'processed')).toBe('7');
    expect(attr(batch, 'skipped')).toBe('2');
    expect(attr(batch, 'acks_on_missing')).toBe('1');
    expect(attr(batch, 'poison_acks')).toBe('0');
    expect(attr(batch, 'retries')).toBe('3');

    // Consumer-side lag (ADR-033) — used by ObserverConsumerLagHigh TraceQL alert.
    expect(attr(batch, 'oldest_message_lag_ms')).toBe('12345');

    // status=OK when no poison acks.
    expect(batch.status.code).toBe(1);
  });

  it('batch span status=ERROR when any poison ack', async () => {
    await emitQueueBatchSpan(makeEnv(), makeStats({ poison_acks: 1 }));
    const batch = getSpans(fetchMock.mock.calls[0][1] as RequestInit)[0];
    expect(batch.status.code).toBe(2);
  });

  it('poison span carries reason=poison + mode + gateway_id dimensions', async () => {
    await emitQueueBatchSpan(makeEnv(), makeStats({ poison_acks: 1 }));
    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    const poison = spans.find((s) => s.name === 'observer.queue_poison')!;

    expect(attr(poison, 'env')).toBe('staging');
    expect(attr(poison, 'mode')).toBe('queue');
    expect(attr(poison, 'gateway_id')).toBe('mnemom-staging');
    expect(attr(poison, 'reason')).toBe('poison');
    expect(poison.status.code).toBe(2);
  });

  it('env derived from GATEWAY_ID — production for "mnemom"', async () => {
    await emitQueueBatchSpan(makeEnv({ GATEWAY_ID: 'mnemom' }), makeStats({ poison_acks: 0 }));
    const batch = getSpans(fetchMock.mock.calls[0][1] as RequestInit)[0];
    expect(attr(batch, 'env')).toBe('production');
    expect(attr(batch, 'gateway_id')).toBe('mnemom');
  });

  it('env is "unknown" for unfamiliar GATEWAY_ID', async () => {
    await emitQueueBatchSpan(makeEnv({ GATEWAY_ID: 'mystery' }), makeStats({ poison_acks: 0 }));
    const batch = getSpans(fetchMock.mock.calls[0][1] as RequestInit)[0];
    expect(attr(batch, 'env')).toBe('unknown');
  });

  it('mode defaults to "direct" if OBSERVER_PROCESSING_MODE unset', async () => {
    await emitQueueBatchSpan(
      makeEnv({ OBSERVER_PROCESSING_MODE: undefined }),
      makeStats({ poison_acks: 0 }),
    );
    const batch = getSpans(fetchMock.mock.calls[0][1] as RequestInit)[0];
    expect(attr(batch, 'mode')).toBe('direct');
  });

  it('swallows fetch failures', async () => {
    fetchMock.mockRejectedValueOnce(new Error('network unreachable'));
    await expect(emitQueueBatchSpan(makeEnv(), makeStats())).resolves.toBeUndefined();
  });
});

describe('emitQueueBacklogSpans', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn().mockResolvedValue(FETCH_OK({}));
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('emits one observer.queue_backlog span per queue with depth attribute', async () => {
    const depths: QueueDepth[] = [
      { queue: 'main', messages: 1234 },
      { queue: 'dlq', messages: 0 },
    ];
    await emitQueueBacklogSpans(makeEnv(), depths);

    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    expect(spans).toHaveLength(2);
    expect(spans.every((s) => s.name === 'observer.queue_backlog')).toBe(true);

    const main = spans.find((s) => attr(s, 'queue') === 'main')!;
    expect(attr(main, 'depth')).toBe('1234');
    expect(attr(main, 'gateway_id')).toBe('mnemom-staging');
    expect(attr(main, 'env')).toBe('staging');
    // age_seconds intentionally absent — lag now lives on observer.queue_batch
    // per ADR-033, since CF Analytics doesn't expose oldest-message age.
    expect(attr(main, 'age_seconds')).toBeUndefined();

    const dlq = spans.find((s) => attr(s, 'queue') === 'dlq')!;
    expect(attr(dlq, 'depth')).toBe('0');
  });

  it('no-ops on empty array', async () => {
    await emitQueueBacklogSpans(makeEnv(), []);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('no-ops when OTLP_ENDPOINT unset', async () => {
    await emitQueueBacklogSpans(
      makeEnv({ OTLP_ENDPOINT: undefined }),
      [{ queue: 'main', messages: 1 }],
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

// ===========================================================================
// ADR-043 — threshold-breach spans turn the gauge signals into counter-style
// signals that ride spanmetrics → Prometheus, where the alert layer can
// actually evaluate them. The non-breach attribute spans (queue_backlog,
// queue_batch) keep emitting unchanged for Tempo triage.
// ===========================================================================

describe('emitQueueBacklogSpans — ADR-043 breach spans', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn().mockResolvedValue(FETCH_OK({}));
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('emits no breach spans when both queues are below thresholds', async () => {
    await emitQueueBacklogSpans(makeEnv(), [
      { queue: 'main', messages: 1234 },
      { queue: 'dlq', messages: 0 },
    ]);
    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    expect(spans.map((s) => s.name)).toEqual([
      'observer.queue_backlog',
      'observer.queue_backlog',
    ]);
  });

  it('emits observer.queue_backlog_breach when main queue depth crosses 50000', async () => {
    await emitQueueBacklogSpans(makeEnv(), [
      { queue: 'main', messages: 50_001 },
      { queue: 'dlq', messages: 0 },
    ]);
    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    const breach = spans.find((s) => s.name === 'observer.queue_backlog_breach');
    expect(breach).toBeDefined();
    expect(attr(breach!, 'queue')).toBe('main');
    expect(attr(breach!, 'depth')).toBe('50001');
    expect(attr(breach!, 'env')).toBe('staging');
    expect(attr(breach!, 'gateway_id')).toBe('mnemom-staging');
    expect(breach!.status.code).toBe(2);
  });

  it('does NOT emit backlog_breach exactly at threshold (strict >)', async () => {
    await emitQueueBacklogSpans(makeEnv(), [{ queue: 'main', messages: 50_000 }]);
    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    expect(spans.some((s) => s.name === 'observer.queue_backlog_breach')).toBe(false);
  });

  it('emits observer.queue_dlq_breach when DLQ has any message', async () => {
    await emitQueueBacklogSpans(makeEnv(), [
      { queue: 'main', messages: 0 },
      { queue: 'dlq', messages: 1 },
    ]);
    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    const breach = spans.find((s) => s.name === 'observer.queue_dlq_breach');
    expect(breach).toBeDefined();
    expect(attr(breach!, 'queue')).toBe('dlq');
    expect(attr(breach!, 'depth')).toBe('1');
    expect(breach!.status.code).toBe(2);
  });

  it('emits both breach spans when both queues breach simultaneously', async () => {
    await emitQueueBacklogSpans(makeEnv(), [
      { queue: 'main', messages: 60_000 },
      { queue: 'dlq', messages: 5 },
    ]);
    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    const names = spans.map((s) => s.name).sort();
    expect(names).toEqual([
      'observer.queue_backlog',
      'observer.queue_backlog',
      'observer.queue_backlog_breach',
      'observer.queue_dlq_breach',
    ]);
  });

  it('main-queue-with-zero-dlq does not accidentally fire dlq_breach', async () => {
    // Regression guard for the queue label discrimination: ensure the dlq
    // threshold is only checked against the dlq row.
    await emitQueueBacklogSpans(makeEnv(), [{ queue: 'main', messages: 99_999 }]);
    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    expect(spans.some((s) => s.name === 'observer.queue_dlq_breach')).toBe(false);
  });
});

describe('emitQueueBatchSpan — ADR-043 lag breach span', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn().mockResolvedValue(FETCH_OK({}));
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('does NOT emit lag breach when oldest_message_lag_ms is below 600000', async () => {
    await emitQueueBatchSpan(makeEnv(), makeStats({
      oldest_message_lag_ms: 599_999,
      poison_acks: 0,
    }));
    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    expect(spans.some((s) => s.name === 'observer.queue_consumer_lag_breach')).toBe(false);
  });

  it('emits observer.queue_consumer_lag_breach when lag crosses 600000ms', async () => {
    await emitQueueBatchSpan(makeEnv(), makeStats({
      oldest_message_lag_ms: 600_001,
      poison_acks: 0,
    }));
    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    const breach = spans.find((s) => s.name === 'observer.queue_consumer_lag_breach');
    expect(breach).toBeDefined();
    expect(attr(breach!, 'oldest_message_lag_ms')).toBe('600001');
    expect(attr(breach!, 'env')).toBe('staging');
    expect(attr(breach!, 'mode')).toBe('queue');
    expect(attr(breach!, 'gateway_id')).toBe('mnemom-staging');
    expect(breach!.status.code).toBe(2);
  });

  it('lag breach + poison breach can coexist on a single batch', async () => {
    await emitQueueBatchSpan(makeEnv(), makeStats({
      oldest_message_lag_ms: 700_000,
      poison_acks: 2,
    }));
    const spans = getSpans(fetchMock.mock.calls[0][1] as RequestInit);
    const names = spans.map((s) => s.name).sort();
    expect(names).toEqual([
      'observer.queue_batch',
      'observer.queue_consumer_lag_breach',
      'observer.queue_poison',
      'observer.queue_poison',
    ]);
  });
});

describe('extractBacklogGroups', () => {
  it('returns rows tolerating missing avg fields', () => {
    const body = {
      data: {
        viewer: {
          accounts: [{
            queueBacklogAdaptiveGroups: [
              { dimensions: { queueId: 'q1' }, avg: { messages: 99 } },
              { dimensions: { queueId: 'q2' }, avg: {} }, // missing messages
              { dimensions: { queueId: 'q3' } }, // missing avg entirely
            ],
          }],
        },
      },
    };
    const rows = extractBacklogGroups(body);
    expect(rows).toEqual([
      { queueId: 'q1', messages: 99 },
      { queueId: 'q2', messages: 0 },
      { queueId: 'q3', messages: 0 },
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
              { dimensions: { queueId: 'QMAIN' }, avg: { messages: 42 } },
              { dimensions: { queueId: 'QDLQ' }, avg: { messages: 0 } },
            ],
          }],
        },
      },
    }));

    const r = await fetchQueueDepths(makeEnv());
    expect(r).toEqual([
      { queue: 'main', messages: 42 },
      { queue: 'dlq', messages: 0 },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const firstUrl = fetchMock.mock.calls[0][0];
    expect(firstUrl).toContain('/accounts/acct-1/queues');
    const secondUrl = fetchMock.mock.calls[1][0];
    expect(secondUrl).toContain('/graphql');
  });

  it('returns zero-depth rows when queues are missing from listing', async () => {
    fetchMock.mockResolvedValueOnce(FETCH_OK({
      result: [{ queue_id: 'QELSE', queue_name: 'different' }],
    }));
    const r = await fetchQueueDepths(makeEnv());
    expect(r).toEqual([
      { queue: 'main', messages: 0 },
      { queue: 'dlq', messages: 0 },
    ]);
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
