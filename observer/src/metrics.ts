/**
 * Observer queue observability — Step 52, span-derived per ADR-032 + ADR-033.
 *
 * Emits OTLP spans to $OTLP_ENDPOINT/v1/traces (the supported CF Workers path
 * per Grafana Cloud support ticket #225229). Grafana's metrics-generator
 * aggregates the spans into `traces_spanmetrics_*` series for RED-style
 * alerting; gauge-style queries use Tempo TraceQL metrics at query time.
 *
 * Three span families:
 *
 *   observer.queue_batch     One span per MessageBatch. Integer counts are
 *                            span attributes; carries `oldest_message_lag_ms`
 *                            measured from CF Queue message.timestamp at the
 *                            moment the consumer received the batch (ADR-033
 *                            — consumer-side lag, not from CF Analytics).
 *                            Dimensions: env, mode, gateway_id. Status=error
 *                            when stats.poison_acks > 0.
 *
 *   observer.queue_poison    One span per poison-acked message (emitted
 *                            stats.poison_acks times per batch). Makes
 *                            ObserverPoisonAckRate a direct spanmetrics
 *                            call-rate alert. Dimensions: env, mode,
 *                            gateway_id, reason=poison.
 *
 *   observer.queue_backlog   One span per queue per scheduled() tick,
 *                            carrying `depth` (avg messages backlogged) as
 *                            a numeric attribute. Depth alerts evaluate via
 *                            TraceQL max_over_time(span.depth). Dimensions:
 *                            env, queue, gateway_id.
 *
 * Source for backlog depth: CF GraphQL Analytics
 * `queueBacklogAdaptiveGroups.avg.messages`. Source for consumer lag:
 * `Date.now() - message.timestamp.getTime()` inside handleQueueBatch.
 * The split is deliberate — CF is the only signal source for backlog (we
 * can't see un-consumed messages); we are the only correct source for lag
 * (we know exactly when our consumer first saw a given message).
 *
 * Fire-and-forget posture preserved: unreachable backend is swallowed, the
 * batch has already been acked before emission. See ADR-032 for the pattern
 * choice + migration triggers toward a collector tier (Option B). See
 * ADR-033 for the consumer-side lag rationale.
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
  /** Average backlog depth (messages) over the sample window. Source: CF
   *  GraphQL `queueBacklogAdaptiveGroups.avg.messages`. */
  messages: number;
}

// ============================================================================
// Span emitters
// ============================================================================

/**
 * Emit the per-batch `observer.queue_batch` span plus one `observer.queue_poison`
 * span for each poison-acked message in the batch. Safe to call with a
 * zero-message batch.
 */
export async function emitQueueBatchSpan(
  env: MetricsEnv,
  stats: BatchStats,
): Promise<void> {
  if (!env.OTLP_ENDPOINT) return;

  const mode = env.OBSERVER_PROCESSING_MODE ?? 'direct';
  const env_ = envLabel(env);
  const gw = env.GATEWAY_ID;

  const spans: OtlpSpan[] = [buildBatchSpan(env_, mode, gw, stats)];
  for (let i = 0; i < stats.poison_acks; i++) {
    spans.push(buildPoisonSpan(env_, mode, gw));
  }

  await postSpans(env, spans);
}

/**
 * Emit queue-state backlog spans (one per queue) for the current tick.
 * Called from scheduled() after fetchQueueDepths resolves. A null or empty
 * depths arg is a no-op so the caller can chain
 * `fetchQueueDepths(env).then(d => d && emit(...))` unchanged.
 */
export async function emitQueueBacklogSpans(
  env: MetricsEnv,
  depths: QueueDepth[],
): Promise<void> {
  if (!env.OTLP_ENDPOINT || depths.length === 0) return;

  const env_ = envLabel(env);
  const gw = env.GATEWAY_ID;

  const spans = depths.map((d) => buildBacklogSpan(env_, gw, d));
  await postSpans(env, spans);
}

// ============================================================================
// Span builders
// ============================================================================

interface OtlpAttributeValue {
  stringValue?: string;
  intValue?: string;
}
interface OtlpAttribute {
  key: string;
  value: OtlpAttributeValue;
}
interface OtlpSpanStatus {
  code: 0 | 1 | 2; // 0=UNSET, 1=OK, 2=ERROR
}
interface OtlpSpan {
  traceId: string;
  spanId: string;
  name: string;
  kind: 1; // INTERNAL
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: OtlpAttribute[];
  status: OtlpSpanStatus;
}

function buildBatchSpan(
  env_: string,
  mode: string,
  gatewayId: string,
  stats: BatchStats,
): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: 'observer.queue_batch',
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str('env', env_),
      str('mode', mode),
      str('gateway_id', gatewayId),
      int('batch_size', stats.total),
      int('processed', stats.processed),
      int('skipped', stats.skipped),
      int('acks_on_missing', stats.acks_on_missing),
      int('poison_acks', stats.poison_acks),
      int('retries', stats.retries),
      // Consumer-side lag (ADR-033) — TraceQL alerts on max_over_time(span.oldest_message_lag_ms).
      int('oldest_message_lag_ms', stats.oldest_message_lag_ms),
    ],
    status: { code: stats.poison_acks > 0 ? 2 : 1 },
  };
}

function buildPoisonSpan(env_: string, mode: string, gatewayId: string): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: 'observer.queue_poison',
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str('env', env_),
      str('mode', mode),
      str('gateway_id', gatewayId),
      str('reason', 'poison'),
    ],
    status: { code: 2 },
  };
}

function buildBacklogSpan(env_: string, gatewayId: string, d: QueueDepth): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: 'observer.queue_backlog',
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str('env', env_),
      str('queue', d.queue),
      str('gateway_id', gatewayId),
      int('depth', d.messages),
    ],
    status: { code: 1 },
  };
}

/**
 * Exported for tests. Wraps a list of spans in the OTLP ResourceSpans envelope.
 */
export function buildOtlpSpansBody(spans: OtlpSpan[], scopeName: string): string {
  return JSON.stringify({
    resourceSpans: [{
      resource: {
        attributes: [
          { key: 'service.name', value: { stringValue: 'mnemom-observer' } },
        ],
      },
      scopeSpans: [{
        scope: { name: scopeName },
        spans,
      }],
    }],
  });
}

async function postSpans(env: MetricsEnv, spans: OtlpSpan[]): Promise<void> {
  const body = buildOtlpSpansBody(spans, 'observer.queue');
  try {
    await fetch(`${env.OTLP_ENDPOINT}/v1/traces`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(env.OTLP_AUTH ? { Authorization: env.OTLP_AUTH } : {}),
      },
      body,
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    // Swallowed — fire-and-forget matches emitTickSummary's posture.
  }
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

  return extractQueueIdMap(body, wantedNames);
}

async function fetchBacklogGroups(
  env: MetricsEnv,
  queueIds: string[],
): Promise<BacklogGroup[] | null> {
  // CF Analytics schema (verified 2026-04-24):
  //   queueBacklogAdaptiveGroups exposes only avg { messages, bytes,
  //   sampleInterval } — there is no `max` aggregate, no
  //   oldestMessageAgeSeconds field, and datetime is not orderable. The
  //   original Step 52 query used a stale schema and silently returned
  //   null on every tick. See ADR-033 for the lag-tracking pivot.
  const query = `
    query QueueBacklog($account: String!, $ids: [String!]!, $since: Time!) {
      viewer {
        accounts(filter: { accountTag: $account }) {
          queueBacklogAdaptiveGroups(
            filter: { queueId_in: $ids, datetime_geq: $since },
            limit: 100
          ) {
            dimensions { queueId }
            avg { messages }
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
    messages: row?.messages ?? 0,
  };
}

// ============================================================================
// Helpers
// ============================================================================

function envLabel(env: MetricsEnv): 'production' | 'staging' | 'unknown' {
  if (env.GATEWAY_ID === 'mnemom') return 'production';
  if (env.GATEWAY_ID === 'mnemom-staging') return 'staging';
  return 'unknown';
}

function str(key: string, value: string): OtlpAttribute {
  return { key, value: { stringValue: value } };
}

function int(key: string, value: number): OtlpAttribute {
  return { key, value: { intValue: String(Math.max(0, Math.floor(value))) } };
}

function hex32(): string {
  return crypto.randomUUID().replace(/-/g, '');
}

function hex16(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 16);
}

function timeUnixNano(): string {
  return String(Date.now() * 1_000_000);
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
  messages: number;
}

/**
 * Pull the flat list of {queueId, messages} rows out of the CF GraphQL
 * response, tolerating missing fields at every layer. Returns null if the
 * response shape is unrecognizable.
 *
 * Schema reference (verified 2026-04-24):
 *   queueBacklogAdaptiveGroups[].avg.messages — uint64
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
      const avg = isObject(g.avg) ? g.avg : undefined;
      const queueId = typeof dims?.queueId === 'string' ? dims.queueId : null;
      if (!queueId) continue;
      rows.push({
        queueId,
        messages: typeof avg?.messages === 'number' ? avg.messages : 0,
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
