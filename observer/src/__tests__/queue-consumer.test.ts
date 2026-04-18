/**
 * Tests for queue-consumer.ts (Step 50 / ADR-010).
 *
 * Strategy: mock Message + MessageBatch + processLog + R2Bucket and drive
 * handleQueueBatch through its core branches. Uses a fresh RSA keypair to
 * build encrypted fixture records so the loadR2Record decrypt path exercises
 * the real code end-to-end.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleQueueBatch, type LogProcessor } from '../queue-consumer';
import {
  _resetDecryptCacheForTests,
  type EncryptedField,
} from '../log-decrypt';
import type { ObserverQueueMessage } from '../queue-types';

// ============================================================================
// Crypto fixture helpers (mirror r2-ingest.test.ts)
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

async function encryptedR2Object(publicKey: CryptoKey, numRecords: number, gateway: string): Promise<string> {
  const lines: string[] = [];
  for (let i = 0; i < numRecords; i++) {
    const rec = {
      Gateway: gateway,
      Provider: 'anthropic',
      Model: 'claude-haiku-4-5-20251001',
      StatusCode: 200,
      Cached: false,
      RateLimited: false,
      Endpoint: 'v1/messages',
      Metadata: await encryptField(JSON.stringify({ agent_id: `agent_${i}`, session_id: `s${i}` }), publicKey),
      RequestBody: await encryptField('{"messages":[]}', publicKey),
      ResponseBody: await encryptField('{"content":[{"type":"text","text":"ok"}]}', publicKey),
    };
    lines.push(JSON.stringify(rec));
  }
  return lines.join('\n') + '\n';
}

// ============================================================================
// Message + batch fakes
// ============================================================================

interface FakeMessage {
  body: ObserverQueueMessage;
  _ack: ReturnType<typeof vi.fn>;
  _retry: ReturnType<typeof vi.fn>;
  ack: () => void;
  retry: () => void;
}

function msg(body: ObserverQueueMessage): FakeMessage {
  const _ack = vi.fn();
  const _retry = vi.fn();
  return { body, _ack, _retry, ack: _ack, retry: _retry };
}

function batchOf(messages: FakeMessage[]): MessageBatch<ObserverQueueMessage> {
  return { messages, queue: 'test', ackAll: vi.fn(), retryAll: vi.fn() } as unknown as MessageBatch<ObserverQueueMessage>;
}

// ============================================================================
// Bucket fake
// ============================================================================

function makeBucket(objects: Record<string, string>): R2Bucket {
  return {
    list: vi.fn(),
    get: async (key: string) => {
      const text = objects[key];
      if (text === undefined) return null;
      const bytes = new TextEncoder().encode(text);
      return {
        key,
        arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
      } as unknown as R2ObjectBody;
    },
    delete: vi.fn(),
  } as unknown as R2Bucket;
}

const fakeCtx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;

// ============================================================================
// Tests
// ============================================================================

beforeEach(() => {
  _resetDecryptCacheForTests();
});

describe('handleQueueBatch — r2 source', () => {
  it('loads, decrypts, and delegates to processLog; acks the message on success', async () => {
    const { publicKey, privateKeyPem } = await freshKeypair();
    const bucket = makeBucket({
      '20260418/x_y_abc.log.gz': await encryptedR2Object(publicKey, 1, 'mnemom-staging'),
    });
    const m = msg({
      source: 'r2',
      objectKey: '20260418/x_y_abc.log.gz',
      recordIndex: 0,
      gateway: 'mnemom-staging',
      provider: 'anthropic',
      model: 'claude-haiku-4-5-20251001',
      statusCode: 200,
    });
    const processLog: LogProcessor = vi.fn(async () => true);
    const stats = await handleQueueBatch(batchOf([m]), {
      GATEWAY_ID: 'mnemom-staging',
      GATEWAY_LOGS_BUCKET: bucket,
      LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem,
      CF_ACCOUNT_ID: 'acct',
      CF_API_TOKEN: 'tok',
    } as unknown as Parameters<typeof handleQueueBatch>[1], fakeCtx, processLog);
    expect(m._ack).toHaveBeenCalledOnce();
    expect(m._retry).not.toHaveBeenCalled();
    expect(processLog).toHaveBeenCalledOnce();
    expect(stats.total).toBe(1);
    expect(stats.processed).toBe(1);
  });

  it('acks (does not retry) when the R2 object is missing (lifecycle reaped)', async () => {
    const { privateKeyPem } = await freshKeypair();
    const bucket = makeBucket({}); // empty — get() returns null
    const m = msg({
      source: 'r2',
      objectKey: '20260418/gone.log.gz',
      recordIndex: 0,
      gateway: 'mnemom-staging',
      provider: 'anthropic',
      model: 'claude-haiku-4-5-20251001',
      statusCode: 200,
    });
    const processLog: LogProcessor = vi.fn();
    const stats = await handleQueueBatch(batchOf([m]), {
      GATEWAY_ID: 'mnemom-staging',
      GATEWAY_LOGS_BUCKET: bucket,
      LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem,
      CF_ACCOUNT_ID: 'acct',
      CF_API_TOKEN: 'tok',
    } as unknown as Parameters<typeof handleQueueBatch>[1], fakeCtx, processLog);
    expect(m._ack).toHaveBeenCalledOnce();
    expect(m._retry).not.toHaveBeenCalled();
    expect(processLog).not.toHaveBeenCalled();
    expect(stats.acks_on_missing).toBe(1);
  });

  it('retries (not ack) on transient processor error', async () => {
    const { publicKey, privateKeyPem } = await freshKeypair();
    const bucket = makeBucket({
      '20260418/x.log.gz': await encryptedR2Object(publicKey, 1, 'mnemom-staging'),
    });
    const m = msg({
      source: 'r2',
      objectKey: '20260418/x.log.gz',
      recordIndex: 0,
      gateway: 'mnemom-staging',
      provider: 'anthropic',
      model: 'claude-haiku-4-5-20251001',
      statusCode: 200,
    });
    const processLog: LogProcessor = vi.fn(async () => {
      throw new Error('Supabase 502 Bad Gateway');
    });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const stats = await handleQueueBatch(batchOf([m]), {
      GATEWAY_ID: 'mnemom-staging',
      GATEWAY_LOGS_BUCKET: bucket,
      LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem,
      CF_ACCOUNT_ID: 'acct',
      CF_API_TOKEN: 'tok',
    } as unknown as Parameters<typeof handleQueueBatch>[1], fakeCtx, processLog);
    expect(m._retry).toHaveBeenCalledOnce();
    expect(m._ack).not.toHaveBeenCalled();
    expect(stats.retries).toBe(1);
    warn.mockRestore();
  });

  it('acks (not retries) on poison error (malformed / auth tag mismatch)', async () => {
    const { privateKeyPem } = await freshKeypair();
    // Build an object whose Metadata envelope will fail AES-GCM auth tag check
    const bad = {
      Gateway: 'mnemom-staging',
      Provider: 'anthropic',
      Model: 'claude-haiku-4-5-20251001',
      StatusCode: 200,
      Metadata: { type: 'encrypted', key: 'AAAA', iv: 'BBBB', data: 'CCCC' },
      RequestBody: { type: 'encrypted', key: 'AAAA', iv: 'BBBB', data: 'CCCC' },
      ResponseBody: { type: 'encrypted', key: 'AAAA', iv: 'BBBB', data: 'CCCC' },
    };
    const bucket = makeBucket({
      '20260418/bad.log.gz': JSON.stringify(bad) + '\n',
    });
    const m = msg({
      source: 'r2',
      objectKey: '20260418/bad.log.gz',
      recordIndex: 0,
      gateway: 'mnemom-staging',
      provider: 'anthropic',
      model: 'claude-haiku-4-5-20251001',
      statusCode: 200,
    });
    const processLog: LogProcessor = vi.fn();
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const stats = await handleQueueBatch(batchOf([m]), {
      GATEWAY_ID: 'mnemom-staging',
      GATEWAY_LOGS_BUCKET: bucket,
      LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem,
      CF_ACCOUNT_ID: 'acct',
      CF_API_TOKEN: 'tok',
    } as unknown as Parameters<typeof handleQueueBatch>[1], fakeCtx, processLog);
    // Either the RSA-OAEP unwrap or AES-GCM decrypt will throw — both classify as poison.
    expect(m._ack).toHaveBeenCalledOnce();
    expect(m._retry).not.toHaveBeenCalled();
    expect(stats.poison_acks).toBe(1);
    expect(processLog).not.toHaveBeenCalled();
    err.mockRestore();
  });

  it('handles a mixed batch: ok, missing, and poison in one pass', async () => {
    const { publicKey, privateKeyPem } = await freshKeypair();
    const bucket = makeBucket({
      '20260418/good.log.gz': await encryptedR2Object(publicKey, 1, 'mnemom-staging'),
      // gone.log.gz missing on purpose
      '20260418/bad.log.gz': JSON.stringify({ Gateway: 'mnemom-staging', Metadata: { type: 'encrypted', key: 'X', iv: 'Y', data: 'Z' }, RequestBody: { type: 'encrypted', key: 'X', iv: 'Y', data: 'Z' }, ResponseBody: { type: 'encrypted', key: 'X', iv: 'Y', data: 'Z' } }) + '\n',
    });
    const mGood = msg({ source: 'r2', objectKey: '20260418/good.log.gz', recordIndex: 0, gateway: 'mnemom-staging', provider: 'anthropic', model: 'x', statusCode: 200 });
    const mGone = msg({ source: 'r2', objectKey: '20260418/gone.log.gz', recordIndex: 0, gateway: 'mnemom-staging', provider: 'anthropic', model: 'x', statusCode: 200 });
    const mBad  = msg({ source: 'r2', objectKey: '20260418/bad.log.gz',  recordIndex: 0, gateway: 'mnemom-staging', provider: 'anthropic', model: 'x', statusCode: 200 });
    const processLog: LogProcessor = vi.fn(async () => true);
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const stats = await handleQueueBatch(batchOf([mGood, mGone, mBad]), {
      GATEWAY_ID: 'mnemom-staging',
      GATEWAY_LOGS_BUCKET: bucket,
      LOGPUSH_DECRYPT_PRIVATE_KEY: privateKeyPem,
      CF_ACCOUNT_ID: 'acct',
      CF_API_TOKEN: 'tok',
    } as unknown as Parameters<typeof handleQueueBatch>[1], fakeCtx, processLog);
    expect(stats.total).toBe(3);
    expect(stats.processed).toBe(1);
    expect(stats.acks_on_missing).toBe(1);
    expect(stats.poison_acks).toBe(1);
    expect(processLog).toHaveBeenCalledTimes(1);
  });
});

describe('handleQueueBatch — unknown source', () => {
  it('acks unknown-source messages as poison (forward-compat drain)', async () => {
    const processLog: LogProcessor = vi.fn();
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const m = { body: { source: 'wat' } as unknown as ObserverQueueMessage, _ack: vi.fn(), _retry: vi.fn() } as FakeMessage;
    m.ack = m._ack;
    m.retry = m._retry;
    const stats = await handleQueueBatch(batchOf([m]), {} as unknown as Parameters<typeof handleQueueBatch>[1], fakeCtx, processLog);
    expect(m._ack).toHaveBeenCalledOnce();
    expect(stats.poison_acks).toBe(1);
    err.mockRestore();
  });
});
