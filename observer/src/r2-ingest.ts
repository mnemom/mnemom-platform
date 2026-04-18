/**
 * R2-sourced log ingestion for the observer (scale/step-49, ADR-009, ADR-026).
 *
 * CF AI Gateway Logpush delivers encrypted `ai_gateway_events` records into the
 * shared R2 bucket `mnemom-gateway-logs` under a per-UTC-date prefix. This
 * module handles:
 *
 *   1. Listing objects under today + yesterday's UTC date prefixes (to cover
 *      the day-boundary window).
 *   2. Fetching + decoding each object. Files are NDJSON; CF's `.log.gz`
 *      filename is a naming convention — actual bytes may or may not be
 *      gzipped, so we detect via the 0x1f 0x8b magic and use
 *      `DecompressionStream("gzip")` when needed.
 *   3. Filtering records to this gateway (bucket is shared across
 *      `mnemom` + `mnemom-staging`; records carry a plaintext `Gateway`
 *      field that must match `env.GATEWAY_ID`).
 *   4. Decrypting the three encrypted fields via log-decrypt.
 *   5. Adapting `ai_gateway_events` record shape → the legacy `GatewayLog` +
 *      {request, response} bodies tuple that the rest of the pipeline expects.
 *
 * Deletion: returned batches carry the R2 object key; the caller deletes the
 * object only after every record in it has been fully processed. Until Step 51
 * (idempotency) lands, per-object atomicity is the dedup boundary — partial
 * failure leaves the object in R2 for retry and accepts at-least-once shape
 * for the already-succeeded records.
 */

import {
  importDecryptPrivateKey,
  isEncryptedField,
  decryptField,
  type EncryptedField,
} from './log-decrypt';

// ============================================================================
// Types — records as they live in R2, and the shape the observer pipeline wants
// ============================================================================

/** Shape of a single decoded record from an R2 `ai_gateway_events` NDJSON object. */
export interface AIGatewayEventRecord {
  Cached?: boolean;
  Endpoint?: string;
  Gateway?: string;
  Metadata?: EncryptedField | string | Record<string, unknown>;
  Model?: string;
  Provider?: string;
  RateLimited?: boolean;
  RequestBody?: EncryptedField | string;
  ResponseBody?: EncryptedField | string;
  StatusCode?: number;
}

/**
 * Subset of the legacy GatewayLog shape that r2-ingest produces. Kept local to
 * avoid a circular import with index.ts; the consumer casts to GatewayLog.
 */
export interface AdaptedGatewayLog {
  id: string;
  created_at: string;
  provider: string;
  model: string;
  success: boolean;
  tokens_in: number;
  tokens_out: number;
  duration: number;
  metadata?: string;
}

export interface AdaptedRecord {
  log: AdaptedGatewayLog;
  bodies: { request: string; response: string };
}

export interface R2ObjectBatch {
  key: string;
  records: AdaptedRecord[];
}

export interface R2Env {
  GATEWAY_ID: string;
  GATEWAY_LOGS_BUCKET?: R2Bucket;
  LOGPUSH_DECRYPT_PRIVATE_KEY?: string;
}

// ============================================================================
// Synthetic id (stable within an R2 object; unique across objects)
// ============================================================================

/**
 * `ai_gateway_events` records have no plaintext `id` field (per ADR-009 §Execution
 * notes and the session-start brief). We synthesize one whose last 8 characters
 * are stable + unique — because buildTrace() in index.ts uses `log.id.slice(-8)`
 * to derive trace_id. Step 51 formalizes the idempotency key.
 *
 * Format: `r2-{objectHashSuffix}-{recordIndexHex4}`
 * The R2 filename already embeds a CF-generated object hash (`_1787dcc9.log.gz`);
 * combining it with the record's in-file index yields per-tick uniqueness.
 */
export function synthesizeLogId(objectKey: string, recordIndex: number): string {
  const match = objectKey.match(/_([0-9a-f]+)\.log\.gz$/);
  const objHash = match?.[1] ?? objectKey.replace(/[^0-9a-z]/gi, '').slice(-8);
  const idx = recordIndex.toString(16).padStart(4, '0');
  return `r2-${objHash}-${idx}`;
}

/**
 * Extract an ISO-8601 timestamp from a CF Logpush R2 key.
 * Filename format: `{YYYYMMDD}/{YYYYMMDD}T{HHMMSS}Z_..._hash.log.gz`
 * Returns the start timestamp of the record window, or the current time if
 * the key doesn't match (defensive — lets downstream code still function).
 */
export function parseTimestampFromKey(objectKey: string): string {
  const m = objectKey.match(/(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z/);
  if (!m) return new Date().toISOString();
  const [, y, mo, d, h, mi, s] = m;
  return `${y}-${mo}-${d}T${h}:${mi}:${s}Z`;
}

// ============================================================================
// Object listing
// ============================================================================

function utcDatePrefix(date: Date): string {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  return `${y}${m}${d}/`;
}

/**
 * List up to `max` R2 objects for today + yesterday's UTC date prefixes.
 * Two-prefix coverage handles cron ticks that straddle the UTC day boundary.
 */
export async function listR2LogKeys(
  bucket: R2Bucket,
  max: number,
  now: Date = new Date(),
): Promise<string[]> {
  const prefixes = [
    utcDatePrefix(new Date(now.getTime() - 24 * 3600_000)),
    utcDatePrefix(now),
  ];
  const keys: string[] = [];
  for (const prefix of prefixes) {
    if (keys.length >= max) break;
    let cursor: string | undefined;
    do {
      const page = await bucket.list({
        prefix,
        limit: Math.min(1000, max - keys.length),
        cursor,
      });
      for (const obj of page.objects) {
        keys.push(obj.key);
        if (keys.length >= max) break;
      }
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor && keys.length < max);
  }
  return keys;
}

// ============================================================================
// Object body decoding
// ============================================================================

/** Detect gzip magic (1f 8b) and transparently decompress if present. */
async function readObjectText(object: R2ObjectBody): Promise<string> {
  const buf = await object.arrayBuffer();
  const bytes = new Uint8Array(buf);
  const isGzip = bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
  if (!isGzip) {
    return new TextDecoder().decode(bytes);
  }
  const stream = new Response(bytes).body!.pipeThrough(new DecompressionStream('gzip'));
  return await new Response(stream).text();
}

export function parseNDJSON(text: string): AIGatewayEventRecord[] {
  const out: AIGatewayEventRecord[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed));
    } catch (err) {
      console.warn(`[observer/r2] Skipping malformed NDJSON line: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return out;
}

// ============================================================================
// Record adaptation
// ============================================================================

/**
 * Decrypt one encrypted-or-plaintext field. If the field is already a plain
 * string or object (shouldn't happen on CF AI Gateway Logpush but guarded
 * defensively), return it as text. Throws on decrypt failure — caller drops
 * the record.
 */
async function readField(
  field: unknown,
  privateKey: CryptoKey,
): Promise<string> {
  if (field == null) return '';
  if (isEncryptedField(field)) {
    return await decryptField(field, privateKey);
  }
  if (typeof field === 'string') return field;
  return JSON.stringify(field);
}

export async function adaptRecord(
  raw: AIGatewayEventRecord,
  objectKey: string,
  recordIndex: number,
  privateKey: CryptoKey,
): Promise<AdaptedRecord> {
  const [metadata, request, response] = await Promise.all([
    readField(raw.Metadata, privateKey),
    readField(raw.RequestBody, privateKey),
    readField(raw.ResponseBody, privateKey),
  ]);

  const status = raw.StatusCode ?? 0;
  const log: AdaptedGatewayLog = {
    id: synthesizeLogId(objectKey, recordIndex),
    created_at: parseTimestampFromKey(objectKey),
    provider: raw.Provider ?? 'anthropic',
    model: raw.Model ?? 'unknown',
    success: status >= 200 && status < 300,
    // ai_gateway_events does not carry token counts or duration at the top level.
    // Downstream usage-event code already handles zeros via `|| 0`. Step 52 is
    // the natural place to surface this degradation as a metric if it matters.
    tokens_in: 0,
    tokens_out: 0,
    duration: 0,
    metadata,
  };
  return { log, bodies: { request, response } };
}

// ============================================================================
// Public entrypoint — list + fetch + decrypt + adapt a batch
// ============================================================================

export interface FetchR2BatchOptions {
  maxObjects: number;
  now?: Date;
}

/**
 * Produce a batch of R2-sourced records for this gateway.
 *
 * Fail shape: bubbles up the first unrecoverable error (missing bucket binding,
 * missing decrypt key, R2 list throws). Per-object and per-record errors are
 * caught + logged; the batch reports what it could produce. Empty batch is
 * valid — caller falls through to polling.
 */
export async function fetchR2Batch(
  env: R2Env,
  options: FetchR2BatchOptions,
): Promise<{ objects: R2ObjectBatch[]; totalRecords: number; listedKeys: number }> {
  if (!env.GATEWAY_LOGS_BUCKET) {
    throw new Error('fetchR2Batch: GATEWAY_LOGS_BUCKET binding is not configured');
  }
  if (!env.LOGPUSH_DECRYPT_PRIVATE_KEY) {
    throw new Error('fetchR2Batch: LOGPUSH_DECRYPT_PRIVATE_KEY is not set');
  }

  const privateKey = await importDecryptPrivateKey(env.LOGPUSH_DECRYPT_PRIVATE_KEY);
  const keys = await listR2LogKeys(env.GATEWAY_LOGS_BUCKET, options.maxObjects, options.now);
  const objects: R2ObjectBatch[] = [];
  let totalRecords = 0;

  for (const key of keys) {
    const records: AdaptedRecord[] = [];
    try {
      const obj = await env.GATEWAY_LOGS_BUCKET.get(key);
      if (!obj) {
        // Raced with lifecycle expiry or another consumer; skip.
        continue;
      }
      const text = await readObjectText(obj);
      const raws = parseNDJSON(text);
      for (let i = 0; i < raws.length; i++) {
        const raw = raws[i];
        if (raw.Gateway && raw.Gateway !== env.GATEWAY_ID) {
          // Bucket is shared across mnemom + mnemom-staging; drop foreign records.
          continue;
        }
        try {
          records.push(await adaptRecord(raw, key, i, privateKey));
        } catch (err) {
          console.warn(`[observer/r2] Drop record ${key}#${i}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    } catch (err) {
      console.warn(`[observer/r2] Failed to read ${key}: ${err instanceof Error ? err.message : String(err)}`);
      // Object stays in R2 — next tick retries. Do NOT push an empty batch entry;
      // we don't want to accidentally delete an object whose records we couldn't read.
      continue;
    }
    objects.push({ key, records });
    totalRecords += records.length;
  }

  return { objects, totalRecords, listedKeys: keys.length };
}
