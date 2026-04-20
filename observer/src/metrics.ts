/**
 * Observer queue metrics — Step 52.
 *
 * Emits OTLP/HTTP JSON metric payloads to $OTLP_ENDPOINT/v1/metrics, mirroring
 * the fire-and-forget trace emitter in index.ts's emitTickSummary. Same
 * endpoint, same auth, same failure posture: unreachable backend is swallowed.
 *
 * Three surfaces:
 *
 *   1. emitBatchMetrics(env, stats)
 *      Called from the queue() handler after each MessageBatch. Emits delta
 *      counters for messages_processed, messages_failed, poison_acks,
 *      acks_on_missing, retries. Low-cardinality attributes: outcome, mode,
 *      gateway_id.
 *
 *   2. emitQueueDepthMetrics(env, depths)
 *      Called from the scheduled() tick. Emits gauges for queue_depth and
 *      consumer_lag_seconds, tagged {queue="main"|"dlq"}. Feeds the P1 alert
 *      at queue_depth{queue="main"} > 50000.
 *
 *   3. fetchQueueDepths(env)
 *      Hits the Cloudflare GraphQL Analytics API for queueBacklogAdaptiveGroups.
 *      Requires CF_API_TOKEN with Analytics:Read scope. Returns null on any
 *      fetch error — gauges simply don't publish that tick.
 *
 * Grafana Cloud provisioning gap (2026-04-20): the OTLP metrics endpoint at
 * Grafana's otlp-gateway is not yet provisioned for our tenant. Emissions
 * silently 4xx until that lands; no user impact. Once provisioned, metrics
 * flow without a redeploy.
 */

import type { BatchStats } from './queue-consumer';

export interface MetricsEnv {
  OTLP_ENDPOINT?: string;
  OTLP_AUTH?: string;
  GATEWAY_ID: string;
  OBSERVER_PROCESSING_MODE?: string;
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
}

export interface QueueDepth {
  queue: 'main' | 'dlq';
  backlogMessages: number;
  oldestMessageAgeSeconds: number;
}

// ============================================================================
// Emitters
// ============================================================================

/**
 * Emit batch-level queue consumer counters. One emission per MessageBatch.
 * Safe to call with a zero-message batch — all counters end up at 0.
 */
export async function emitBatchMetrics(
  env: MetricsEnv,
  stats: BatchStats,
): Promise<void> {
  if (!env.OTLP_ENDPOINT) return;

  const mode = env.OBSERVER_PROCESSING_MODE ?? 'direct';
  const gw = env.GATEWAY_ID;
  const nowNs = timeUnixNano();
  // Each batch call represents ~max_batch_timeout (10s) of accumulated deltas.
  const startNs = startUnixNano(10_000);

  const metrics = [
    counter('observer.messages_processed', stats.processed, {
      outcome: 'processed', mode, gateway_id: gw,
    }, nowNs, startNs),
    counter('observer.messages_processed', stats.skipped, {
      outcome: 'skipped', mode, gateway_id: gw,
    }, nowNs, startNs),
    counter('observer.messages_processed', stats.acks_on_missing, {
      outcome: 'ack_on_missing', mode, gateway_id: gw,
    }, nowNs, startNs),
    counter('observer.messages_failed', stats.poison_acks, {
      reason: 'poison', mode, gateway_id: gw,
    }, nowNs, startNs),
    counter('observer.messages_failed', stats.retries, {
      reason: 'retry', mode, gateway_id: gw,
    }, nowNs, startNs),
  ];

  await postMetrics(env, metrics, 'observer.queue.consumer');
}

/**
 * Emit queue-state gauges (depth + consumer lag) for one tick. Call from
 * scheduled() after fetchQueueDepths resolves. A null depths arg is a no-op
 * so callers can chain `fetchQueueDepths(env).then(d => d && emit(...))`.
 */
export async function emitQueueDepthMetrics(
  env: MetricsEnv,
  depths: QueueDepth[],
): Promise<void> {
  if (!env.OTLP_ENDPOINT || depths.length === 0) return;

  const gw = env.GATEWAY_ID;
  const nowNs = timeUnixNano();

  const metrics: OtlpMetric[] = [];
  for (const d of depths) {
    metrics.push(
      gauge('observer.queue_depth', d.backlogMessages, {
        queue: d.queue, gateway_id: gw,
      }, nowNs),
      gauge('observer.consumer_lag_seconds', d.oldestMessageAgeSeconds, {
        queue: d.queue, gateway_id: gw,
      }, nowNs),
    );
  }

  await postMetrics(env, metrics, 'observer.queue.state');
}

// ============================================================================
// CF queue-state fetcher (REST listing → GraphQL backlog)
// ============================================================================

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';
const CF_GRAPHQL_ENDPOINT = `${CF_API_BASE}/graphql`;

/**
 * Fetch backlog + oldest-message-age for the main queue and its DLQ.
 *
 * Two-step resolution because the Analytics dataset keys queues by UUID, not
 * name:
 *   (1) GET /accounts/:id/queues → map queue-name → queue-id
 *   (2) POST /graphql queueBacklogAdaptiveGroups(queueId_in:[…]) → backlog
 *
 * Returns `null` on any failure at either step — fetch error, non-OK status,
 * GraphQL errors, or missing fields. The caller treats null as "no gauges this
 * tick". Requires CF_API_TOKEN with Queues:Read + Analytics:Read scopes.
 *
 * Queue-name convention matches mnemom-infra/queues.tf:
 *   prod:    mnemom-observer-records        + mnemom-observer-records-dlq
 *   staging: mnemom-observer-records-staging + mnemom-observer-records-staging-dlq
 *
 * Derived from GATEWAY_ID: "mnemom" → prod names, "mnemom-staging" → staging.
 */
export async function fetchQueueDepths(env: MetricsEnv): Promise<QueueDepth[] | null> {
  const names = queueNamesFor(env.GATEWAY_ID);
  if (!names) return null;

  const idMap = await resolveQueueIds(env, [names.main, names.dlq]);
  if (!idMap) return null;

  const mainId = idMap.get(names.main);
  const dlqId = idMap.get(names.dlq);
  // We still emit a row even if a queue wasn't found — a brand-new deploy
  // could race the listing. backlogMessages=0 is the right default.

  const ids = [mainId, dlqId].filter((x): x is string => typeof x === 'string');
  const groups = ids.length > 0 ? await fetchBacklogGroups(env, ids) : [];
  if (groups === null) return null;

  return [
    labeledDepth('main', mainId, groups),
    labeledDepth('dlq', dlqId, groups),
  ];
}

/**
 * List queues in the account and return a {name → id} map for the names we
 * care about. Returns null on fetch/parse failure. Not cached — one extra
 * HTTP round-trip per cron tick is trivial vs. the complexity of a TTLed
 * module-level cache.
 */
async function resolveQueueIds(
  env: MetricsEnv,
  wantedNames: string[],
): Promise<Map<string, string> | null> {
  let res: Response;
  try {
    res = await fetch(
      `${CF_API_BASE}/accounts/${env.CF_ACCOUNT_ID}/queues?per_page=100`,
      {
        headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` },
        signal: AbortSignal.timeout(5_000),
      },
    );
  } catch (err) {
    console.warn(`[observer/metrics] queue listing threw: ${describe(err)}`);
    return null;
  }
  if (!res.ok) {
    console.warn(`[observer/metrics] queue listing non-OK: ${res.status}`);
    return null;
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch (err) {
    console.warn(`[observer/metrics] queue listing parse threw: ${describe(err)}`);
    return null;
  }

  const idMap = extractQueueIdMap(body, wantedNames);
  return idMap;
}

async function fetchBacklogGroups(
  env: MetricsEnv,
  queueIds: string[],
): Promise<BacklogGroup[] | null> {
  const query = `
    query QueueBacklog($account: String!, $ids: [String!]!, $since: Time!) {
      viewer {
        accounts(filter: { accountTag: $account }) {
          queueBacklogAdaptiveGroups(
            filter: { queueId_in: $ids, datetime_geq: $since },
            limit: 100,
            orderBy: [datetime_DESC]
          ) {
            dimensions { queueId }
            max { backlogMessages oldestMessageAgeSeconds }
          }
        }
      }
    }
  `;
  const sinceIso = new Date(Date.now() - 5 * 60_000).toISOString();

  let res: Response;
  try {
    res = await fetch(CF_GRAPHQL_ENDPOINT, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.CF_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query,
        variables: { account: env.CF_ACCOUNT_ID, ids: queueIds, since: sinceIso },
      }),
      signal: AbortSignal.timeout(5_000),
    });
  } catch (err) {
    console.warn(`[observer/metrics] backlog fetch threw: ${describe(err)}`);
    return null;
  }
  if (!res.ok) {
    console.warn(`[observer/metrics] backlog fetch non-OK: ${res.status}`);
    return null;
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch (err) {
    console.warn(`[observer/metrics] backlog parse threw: ${describe(err)}`);
    return null;
  }
  return extractBacklogGroups(body);
}

function labeledDepth(
  label: 'main' | 'dlq',
  queueId: string | undefined,
  groups: BacklogGroup[],
): QueueDepth {
  const row = queueId ? groups.find((g) => g.queueId === queueId) : undefined;
  return {
    queue: label,
    backlogMessages: row?.backlogMessages ?? 0,
    oldestMessageAgeSeconds: row?.oldestMessageAgeSeconds ?? 0,
  };
}

// ============================================================================
// OTLP payload builders
// ============================================================================

interface OtlpAttributeValue {
  stringValue?: string;
  intValue?: string;
  doubleValue?: number;
}
interface OtlpAttribute {
  key: string;
  value: OtlpAttributeValue;
}
interface OtlpMetric {
  name: string;
  unit?: string;
  sum?: {
    dataPoints: OtlpNumberDataPoint[];
    aggregationTemporality: 1 | 2; // 1=DELTA, 2=CUMULATIVE
    isMonotonic: boolean;
  };
  gauge?: {
    dataPoints: OtlpNumberDataPoint[];
  };
}
interface OtlpNumberDataPoint {
  attributes: OtlpAttribute[];
  timeUnixNano: string;
  startTimeUnixNano?: string;
  asInt?: string;
  asDouble?: number;
}

function counter(
  name: string,
  value: number,
  attrs: Record<string, string>,
  timeNs: string,
  startNs: string,
): OtlpMetric {
  return {
    name,
    unit: '1',
    sum: {
      aggregationTemporality: 1, // DELTA — each emission is the per-batch delta
      isMonotonic: true,
      dataPoints: [{
        attributes: toAttrs(attrs),
        timeUnixNano: timeNs,
        startTimeUnixNano: startNs,
        asInt: String(Math.max(0, Math.floor(value))),
      }],
    },
  };
}

function gauge(
  name: string,
  value: number,
  attrs: Record<string, string>,
  timeNs: string,
): OtlpMetric {
  return {
    name,
    unit: '1',
    gauge: {
      dataPoints: [{
        attributes: toAttrs(attrs),
        timeUnixNano: timeNs,
        asInt: String(Math.max(0, Math.floor(value))),
      }],
    },
  };
}

function toAttrs(attrs: Record<string, string>): OtlpAttribute[] {
  return Object.entries(attrs).map(([key, value]) => ({
    key, value: { stringValue: value },
  }));
}

/**
 * Exported for tests. Builds the full OTLP/HTTP JSON body for a set of metrics
 * under a single scope name.
 */
export function buildOtlpMetricsBody(
  metrics: OtlpMetric[],
  scopeName: string,
): string {
  return JSON.stringify({
    resourceMetrics: [{
      resource: {
        attributes: [
          { key: 'service.name', value: { stringValue: 'mnemom-observer' } },
        ],
      },
      scopeMetrics: [{
        scope: { name: scopeName },
        metrics,
      }],
    }],
  });
}

async function postMetrics(
  env: MetricsEnv,
  metrics: OtlpMetric[],
  scopeName: string,
): Promise<void> {
  const body = buildOtlpMetricsBody(metrics, scopeName);
  try {
    await fetch(`${env.OTLP_ENDPOINT}/v1/metrics`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(env.OTLP_AUTH ? { Authorization: env.OTLP_AUTH } : {}),
      },
      body,
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    // Swallowed — matches the trace emitter's fire-and-forget posture.
    // Tier 3 Worker logs capture the fetch failure if needed.
  }
}

// ============================================================================
// Helpers
// ============================================================================

function timeUnixNano(): string {
  // Date.now() is ms — multiply by 1e6 for ns. Workers don't expose nanosecond
  // resolution; the lossy conversion is fine for metrics (sub-ms buckets are
  // never queried on these signals).
  return String(Date.now() * 1_000_000);
}

function startUnixNano(deltaWindowMs: number): string {
  return String((Date.now() - deltaWindowMs) * 1_000_000);
}

function describe(err: unknown): string {
  return err instanceof Error ? `${err.name}: ${err.message}` : String(err);
}

function queueNamesFor(gatewayId: string): { main: string; dlq: string } | null {
  if (gatewayId === 'mnemom') {
    return {
      main: 'mnemom-observer-records',
      dlq: 'mnemom-observer-records-dlq',
    };
  }
  if (gatewayId === 'mnemom-staging') {
    return {
      main: 'mnemom-observer-records-staging',
      dlq: 'mnemom-observer-records-staging-dlq',
    };
  }
  return null;
}

interface BacklogGroup {
  queueId: string;
  backlogMessages: number;
  oldestMessageAgeSeconds: number;
}

/**
 * Pull the flat list of {queueId, backlogMessages, oldestMessageAgeSeconds}
 * rows out of the CF GraphQL response, tolerating missing fields at every
 * layer. Returns null if the response shape is unrecognizable.
 *
 * Exported for tests.
 */
export function extractBacklogGroups(body: unknown): BacklogGroup[] | null {
  if (!isObject(body)) return null;
  const data = body.data;
  if (!isObject(data) || !isObject(data.viewer)) return null;
  const accounts = data.viewer.accounts;
  if (!Array.isArray(accounts) || accounts.length === 0) return null;

  const rows: BacklogGroup[] = [];
  for (const acct of accounts) {
    if (!isObject(acct)) continue;
    const groups = acct.queueBacklogAdaptiveGroups;
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      if (!isObject(g)) continue;
      const dims = isObject(g.dimensions) ? g.dimensions : undefined;
      const max = isObject(g.max) ? g.max : undefined;
      const queueId = typeof dims?.queueId === 'string' ? dims.queueId : null;
      if (!queueId) continue;
      rows.push({
        queueId,
        backlogMessages: typeof max?.backlogMessages === 'number' ? max.backlogMessages : 0,
        oldestMessageAgeSeconds:
          typeof max?.oldestMessageAgeSeconds === 'number' ? max.oldestMessageAgeSeconds : 0,
      });
    }
  }

  return rows;
}

/**
 * Pull {name → id} for the names we asked about out of the CF /queues REST
 * response. Tolerates every layer being missing.
 *
 * Exported for tests.
 */
export function extractQueueIdMap(body: unknown, wantedNames: string[]): Map<string, string> {
  const out = new Map<string, string>();
  if (!isObject(body)) return out;
  const result = body.result;
  if (!Array.isArray(result)) return out;
  for (const q of result) {
    if (!isObject(q)) continue;
    const name = typeof q.queue_name === 'string' ? q.queue_name : null;
    const id = typeof q.queue_id === 'string' ? q.queue_id : null;
    if (!name || !id) continue;
    if (wantedNames.includes(name)) out.set(name, id);
  }
  return out;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}
