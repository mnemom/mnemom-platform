/**
 * Tests for r2-ingest.ts — R2 object listing, decoding, decryption, adapting
 * (scale/step-49, ADR-009).
 *
 * Strategy: construct an in-memory R2Bucket stub that mirrors the two methods
 * we touch (list, get), plus a delete spy. Encrypt fixture records with a
 * fresh RSA keypair (same shape CF uses) and push them through fetchR2Batch
 * to verify the full pipeline end-to-end.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  listR2LogKeys,
  parseNDJSON,
  adaptRecord,
  fetchR2Batch,
  synthesizeLogId,
  parseTimestampFromKey,
  type AIGatewayEventRecord,
} from '../r2-ingest';
import {
  importDecryptPrivateKey,
  _resetDecryptCacheForTests,
  type EncryptedField,
} from '../log-decrypt';

// ============================================================================
// Fixture helpers
// ============================================================================

function bytesToB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function pkcs8DerToPem(der: ArrayBuffer): string {
  const b64 = bytesToB64(new Uint8Array(der));
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;
}

async function freshKeypair(): Promise<{ publicKey: CryptoKey; privateKeyPem: string }> {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  return { publicKey: pair.publicKey, privateKeyPem: pkcs8DerToPem(pkcs8) };
}

async function encryptField(plaintext: string, publicKey: CryptoKey): Promise<EncryptedField> {
  const aesKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey('raw', aesKeyRaw, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext));
  const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, aesKeyRaw);
  return {
    type: 'encrypted',
    key: bytesToB64(new Uint8Array(wrapped)),
    iv: bytesToB64(iv),
    data: bytesToB64(new Uint8Array(ciphertext)),
  };
}

async function buildEncryptedRecord(
  publicKey: CryptoKey,
  opts: {
    gateway?: string;
    status?: number;
    provider?: string;
    model?: string;
    metadata?: string;
    request?: string;
    response?: string;
  } = {},
): Promise<AIGatewayEventRecord> {
  return {
    Gateway: opts.gateway ?? 'mnemom-staging',
    StatusCode: opts.status ?? 200,
    Provider: opts.provider ?? 'anthropic',
    Model: opts.model ?? 'claude-haiku-4-5-20251001',
    Cached: false,
    RateLimited: false,
    Endpoint: 'v1/messages',
    Metadata: await encryptField(opts.metadata ?? '{"agent_id":"agent_r2_test","session_id":"s1"}', publicKey),
    RequestBody: await encryptField(opts.request ?? '{"messages":[{"role":"user","content":"hi"}]}', publicKey),
    ResponseBody: await encryptField(opts.response ?? '{"content":[{"type":"text","text":"hello"}]}', publicKey),
  };
}

// Minimal R2Bucket mock with just the methods we exercise.
interface FakeR2Object {
  text: string;
  gzipped?: boolean;
}
function makeBucket(objects: Record<string, FakeR2Object>): R2Bucket {
  const deleted = new Set<string>();
  return {
    list: async ({ prefix, limit, cursor }: R2ListOptions = {}) => {
      const keys = Object.keys(objects)
        .filter(k => !deleted.has(k))
        .filter(k => !prefix || k.startsWith(prefix))
        .sort();
      const start = cursor ? parseInt(cursor, 10) : 0;
      const end = Math.min(keys.length, start + (limit ?? 1000));
      const page = keys.slice(start, end);
      return {
        objects: page.map(k => ({ key: k }) as R2Object),
        truncated: end < keys.length,
        cursor: end < keys.length ? String(end) : undefined,
      } as R2Objects;
    },
    get: async (key: string) => {
      const o = objects[key];
      if (!o || deleted.has(key)) return null;
      let bytes: Uint8Array;
      if (o.gzipped) {
        // Build gzip-wrapped body using the same CompressionStream API
        const stream = new Response(new TextEncoder().encode(o.text)).body!.pipeThrough(
          new CompressionStream('gzip'),
        );
        const ab = await new Response(stream).arrayBuffer();
        bytes = new Uint8Array(ab);
      } else {
        bytes = new TextEncoder().encode(o.text);
      }
      return {
        key,
        arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
      } as unknown as R2ObjectBody;
    },
    delete: vi.fn(async (key: string) => {
      if (Array.isArray(key)) {
        for (const k of key) deleted.add(k);
      } else {
        deleted.add(key);
      }
    }),
  } as unknown as R2Bucket;
}

// ============================================================================
// Tests
// ============================================================================

beforeEach(() => {
  _resetDecryptCacheForTests();
});

describe('synthesizeLogId', () => {
  it('extracts the CF filename hash and appends record index', () => {
    const id = synthesizeLogId('20260418/20260418T000210Z_20260418T000210Z_a3cfe972.log.gz', 0);
    expect(id).toBe('r2-a3cfe972-0000');
    expect(id.slice(-8)).toBe('972-0000');
  });

  it('produces stable trace-id suffix across records in the same object', () => {
    const a = synthesizeLogId('path/20260418T000000Z_x_deadbeef.log.gz', 0).slice(-8);
    const b = synthesizeLogId('path/20260418T000000Z_x_deadbeef.log.gz', 1).slice(-8);
    expect(a).not.toBe(b);
  });

  it('falls back gracefully when the key does not match CF format', () => {
    const id = synthesizeLogId('weird-key-name.txt', 5);
    expect(id).toMatch(/^r2-[0-9a-z]+-0005$/);
  });
});

describe('parseTimestampFromKey', () => {
  it('extracts ISO-8601 from a CF Logpush key', () => {
    expect(parseTimestampFromKey('20260418/20260418T000210Z_20260418T000243Z_hash.log.gz'))
      .toBe('2026-04-18T00:02:10Z');
  });

  it('falls back to now on unmatched keys', () => {
    const ts = parseTimestampFromKey('garbage');
    // Must still parse as a valid date
    expect(Number.isNaN(Date.parse(ts))).toBe(false);
  });
});

describe('parseNDJSON', () => {
  it('parses multiple JSON lines', () => {
    const text = '{"a":1}\n{"b":2}\n';
    expect(parseNDJSON(text)).toEqual([{ a: 1 }, { b: 2 }]);
  });

  it('tolerates blank lines', () => {
    expect(parseNDJSON('{"a":1}\n\n{"b":2}')).toEqual([{ a: 1 }, { b: 2 }]);
  });

  it('drops malformed lines but keeps good ones', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(parseNDJSON('{"a":1}\n{not json\n{"b":2}')).toEqual([{ a: 1 }, { b: 2 }]);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });
});

describe('listR2LogKeys', () => {
  it('lists today + yesterday UTC date prefixes', async () => {
    const now = new Date('2026-04-18T00:30:00Z');
    const bucket = makeBucket({
      '20260417/a.log.gz': { text: '' },
      '20260417/b.log.gz': { text: '' },
      '20260418/c.log.gz': { text: '' },
      '20260416/old.log.gz': { text: '' }, // must NOT be listed
      'other/unrelated': { text: '' },
    });
    const keys = await listR2LogKeys(bucket, 100, now);
    expect(keys.sort()).toEqual([
      '20260417/a.log.gz',
      '20260417/b.log.gz',
      '20260418/c.log.gz',
    ]);
  });

  it('respects max cap', async () => {
    const bucket = makeBucket({
      '20260418/a': { text: '' },
      '20260418/b': { text: '' },
      '20260418/c': { text: '' },
    });
    const keys = await listR2LogKeys(bucket, 2, new Date('2026-04-18T00:00:00Z'));
    expect(keys.length).toBe(2);
  });
});

describe('adaptRecord', () => {
  it('decrypts all three encrypted fields and shapes the GatewayLog', async () => {
    const { publicKey, privateKeyPem } = await freshKeypair();
    const raw = await buildEncryptedRecord(publicKey, {
      metadata: '{"agent_id":"agent_abc","session_id":"sess1","agent_hash":"h","gateway_version":"1.0"}',
      request: '{"messages":[]}',
      response: '{"content":[{"type":"text","text":"ok"}]}',
      model: 'claude-haiku-4-5-20251001',
      status: 200,
    });
    const key = await importDecryptPrivateKey(privateKeyPem);
    const adapted = await adaptRecord(
      raw,
      '20260418/20260418T000210Z_20260418T000243Z_cafef00d.log.gz',
      0,
      key,
    );
    expect(adapted.log.id).toBe('r2-cafef00d-0000');
    expect(adapted.log.created_at).toBe('2026-04-18T00:02:10Z');
    expect(adapted.log.provider).toBe('anthropic');
    expect(adapted.log.model).toBe('claude-haiku-4-5-20251001');
    expect(adapted.log.success).toBe(true);
    expect(adapted.log.metadata).toBe('{"agent_id":"agent_abc","session_id":"sess1","agent_hash":"h","gateway_version":"1.0"}');
    expect(adapted.bodies.request).toBe('{"messages":[]}');
    expect(adapted.bodies.response).toBe('{"content":[{"type":"text","text":"ok"}]}');
  });

  it('marks success=false for non-2xx status', async () => {
    const { publicKey, privateKeyPem } = await freshKeypair();
    const raw = await buildEncryptedRecord(publicKey, { status: 500 });
    const key = await importDecryptPrivateKey(privateKeyPem);
    const adapted = await adaptRecord(raw, 'k_a1b2c3d4.log.gz', 0, key);
    expect(adapted.log.success).toBe(false);
  });

  it('zeros token + duration counters (not in ai_gateway_events)', async () => {
    const { publicKey, privateKeyPem } = await freshKeypair();
    const raw = await buildEncryptedRecord(publicKey);
    const key = await importDecryptPrivateKey(privateKeyPem);
    const adapted = await adaptRecord(raw, 'k_a1b2c3d4.log.gz', 0, key);
    expect(adapted.log.tokens_in).toBe(0);
    expect(adapted.log.tokens_out).toBe(0);
    expect(adapted.log.duration).toBe(0);
  });

  it('handles plaintext fields as well as encrypted envelopes (defensive)', async () => {
    const { privateKeyPem } = await freshKeypair();
    const raw: AIGatewayEventRecord = {
      Gateway: 'mnemom-staging',
      StatusCode: 200,
      Provider: 'anthropic',
      Model: 'claude-opus-4-7',
      Metadata: '{"agent_id":"plain"}',
      RequestBody: 'raw request body',
      ResponseBody: 'raw response body',
    };
    const key = await importDecryptPrivateKey(privateKeyPem);
    const adapted = await adaptRecord(raw, 'k_xx.log.gz', 0, key);
    expect(adapted.log.metadata).toBe('{"agent_id":"plain"}');
    expect(adapted.bodies.request).toBe('raw request body');
    expect(adapted.bodies.response).toBe('raw response body');
  });
});

describe('fetchR2Batch', () => {
  it('filters records by Gateway and returns only this-gateway records', async () => {
    const { publicKey, privateKeyPem } = await freshKeypair();
    const line1 = JSON.stringify(await buildEncryptedRecord(publicKey, { gateway: 'mnemom-staging' }));
    const line2 = JSON.stringify(await buildEncryptedRecord(publicKey, { gateway: 'mnemom' }));
    const bucket = makeBucket({
      '20260418/20260418T000000Z_20260418T000001Z_abc123.log.gz': { text: `${line1}\n${line2}\n` },
    });
    const batch = await fetchR2Batch(
      {
        GATEWAY_ID: 'mnemom-staging',
        GATEWAY_LOGS_BUCKET: bucket,
        LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem,
      },
      { maxObjects: 10, now: new Date('2026-04-18T00:30:00Z') },
    );
    expect(batch.objects.length).toBe(1);
    expect(batch.objects[0].records.length).toBe(1);
    expect(batch.totalRecords).toBe(1);
  });

  it('decodes gzipped objects transparently', async () => {
    const { publicKey, privateKeyPem } = await freshKeypair();
    const rec = JSON.stringify(await buildEncryptedRecord(publicKey));
    const bucket = makeBucket({
      '20260418/20260418T000000Z_20260418T000001Z_abc123.log.gz': { text: `${rec}\n`, gzipped: true },
    });
    const batch = await fetchR2Batch(
      {
        GATEWAY_ID: 'mnemom-staging',
        GATEWAY_LOGS_BUCKET: bucket,
        LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem,
      },
      { maxObjects: 10, now: new Date('2026-04-18T00:30:00Z') },
    );
    expect(batch.totalRecords).toBe(1);
  });

  it('throws when the bucket binding is missing', async () => {
    const { privateKeyPem } = await freshKeypair();
    await expect(
      fetchR2Batch(
        { GATEWAY_ID: 'mnemom-staging', LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem },
        { maxObjects: 10 },
      ),
    ).rejects.toThrow(/GATEWAY_LOGS_BUCKET/);
  });

  it('throws when the decrypt key is missing', async () => {
    const bucket = makeBucket({});
    await expect(
      fetchR2Batch(
        { GATEWAY_ID: 'mnemom-staging', GATEWAY_LOGS_BUCKET: bucket },
        { maxObjects: 10 },
      ),
    ).rejects.toThrow(/LOGPUSH_DECRYPT_PRIVATE_KEY/);
  });

  it('returns empty batch when no objects exist (caller falls through to polling)', async () => {
    const { privateKeyPem } = await freshKeypair();
    const bucket = makeBucket({});
    const batch = await fetchR2Batch(
      {
        GATEWAY_ID: 'mnemom-staging',
        GATEWAY_LOGS_BUCKET: bucket,
        LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem,
      },
      { maxObjects: 10, now: new Date('2026-04-18T00:30:00Z') },
    );
    expect(batch.objects.length).toBe(0);
    expect(batch.totalRecords).toBe(0);
  });

  it('skips individual malformed records but keeps good ones in the same object', async () => {
    const { publicKey, privateKeyPem } = await freshKeypair();
    const goodRec = JSON.stringify(await buildEncryptedRecord(publicKey));
    const bucket = makeBucket({
      '20260418/20260418T000000Z_20260418T000001Z_abc123.log.gz': {
        text: `${goodRec}\nnot-json\n${goodRec}\n`,
      },
    });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const batch = await fetchR2Batch(
      {
        GATEWAY_ID: 'mnemom-staging',
        GATEWAY_LOGS_BUCKET: bucket,
        LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem,
      },
      { maxObjects: 10, now: new Date('2026-04-18T00:30:00Z') },
    );
    expect(batch.totalRecords).toBe(2);
    warn.mockRestore();
  });

  it('skips entire objects whose read throws (leaves them for next tick)', async () => {
    const { privateKeyPem } = await freshKeypair();
    const throwingBucket = {
      list: async () => ({
        objects: [{ key: '20260418/bad.log.gz' } as R2Object],
        truncated: false,
      } as R2Objects),
      get: async () => {
        throw new Error('R2 transient failure');
      },
      delete: vi.fn(),
    } as unknown as R2Bucket;
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const batch = await fetchR2Batch(
      {
        GATEWAY_ID: 'mnemom-staging',
        GATEWAY_LOGS_BUCKET: throwingBucket,
        LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem,
      },
      { maxObjects: 10, now: new Date('2026-04-18T00:30:00Z') },
    );
    expect(batch.objects.length).toBe(0);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('Failed to read'));
    warn.mockRestore();
  });
});
