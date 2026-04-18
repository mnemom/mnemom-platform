/**
 * Tests for log-decrypt.ts — CF AI Gateway Logpush decryption (scale/step-49).
 *
 * Strategy: generate a fresh RSA-4096 keypair per test, encrypt a known
 * payload with the CF Logpush scheme, verify round-trip via decryptField.
 * Catches regressions in PEM parsing, key unwrap, and AES-GCM decrypt.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  decryptField,
  importDecryptPrivateKey,
  isEncryptedField,
  b64ToBytes,
  _resetDecryptCacheForTests,
  type EncryptedField,
} from '../log-decrypt';

// ============================================================================
// Helpers — mirror CF's encryption scheme to build fixtures
// ============================================================================

function bytesToB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function spkiDerToPem(der: ArrayBuffer): string {
  const b64 = bytesToB64(new Uint8Array(der));
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`;
}

function pkcs8DerToPem(der: ArrayBuffer): string {
  const b64 = bytesToB64(new Uint8Array(der));
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;
}

async function generateKeypair(): Promise<{
  publicKey: CryptoKey;
  privateKeyPem: string;
}> {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048, // faster than 4096 for test fixtures; same scheme
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  return {
    publicKey: pair.publicKey,
    privateKeyPem: pkcs8DerToPem(pkcs8),
  };
}

/**
 * Build an encrypted-field envelope matching CF AI Gateway Logpush's exact
 * shape: RSA-OAEP-SHA256 wraps a fresh 256-bit AES key; AES-GCM encrypts the
 * payload under that key with a 12-byte nonce. All fields base64.
 */
async function encryptFieldForTest(
  plaintext: string,
  publicKey: CryptoKey,
): Promise<EncryptedField> {
  const aesKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey(
    'raw',
    aesKeyRaw,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(plaintext),
  );
  const wrappedKey = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    aesKeyRaw,
  );
  return {
    type: 'encrypted',
    key: bytesToB64(new Uint8Array(wrappedKey)),
    iv: bytesToB64(iv),
    data: bytesToB64(new Uint8Array(ciphertext)),
  };
}

// ============================================================================
// Tests
// ============================================================================

beforeEach(() => {
  _resetDecryptCacheForTests();
});

describe('isEncryptedField', () => {
  it('accepts the canonical shape', () => {
    expect(
      isEncryptedField({ type: 'encrypted', key: 'a', iv: 'b', data: 'c' }),
    ).toBe(true);
  });

  it('rejects missing keys', () => {
    expect(isEncryptedField({ type: 'encrypted', key: 'a', iv: 'b' })).toBe(false);
  });

  it('rejects wrong type tag', () => {
    expect(
      isEncryptedField({ type: 'plaintext', key: 'a', iv: 'b', data: 'c' }),
    ).toBe(false);
  });

  it('rejects primitives and null', () => {
    expect(isEncryptedField(null)).toBe(false);
    expect(isEncryptedField('encrypted')).toBe(false);
    expect(isEncryptedField(undefined)).toBe(false);
  });
});

describe('b64ToBytes', () => {
  it('round-trips with bytesToB64', () => {
    const original = new Uint8Array([0, 1, 2, 3, 254, 255]);
    const b64 = bytesToB64(original);
    const decoded = b64ToBytes(b64);
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });
});

describe('importDecryptPrivateKey', () => {
  it('parses a valid PKCS#8 PEM', async () => {
    const { privateKeyPem } = await generateKeypair();
    const key = await importDecryptPrivateKey(privateKeyPem);
    expect(key.type).toBe('private');
    expect(key.algorithm.name).toBe('RSA-OAEP');
  });

  it('caches within an isolate — second call returns the same key', async () => {
    const { privateKeyPem } = await generateKeypair();
    const k1 = await importDecryptPrivateKey(privateKeyPem);
    const k2 = await importDecryptPrivateKey(privateKeyPem);
    expect(k2).toBe(k1);
  });

  it('rotates when a different PEM is passed', async () => {
    const a = await generateKeypair();
    const b = await generateKeypair();
    const k1 = await importDecryptPrivateKey(a.privateKeyPem);
    const k2 = await importDecryptPrivateKey(b.privateKeyPem);
    expect(k2).not.toBe(k1);
  });

  it('throws on empty PEM', async () => {
    await expect(importDecryptPrivateKey('')).rejects.toThrow();
  });
});

describe('decryptField — round-trip', () => {
  it('decrypts a small JSON payload', async () => {
    const { publicKey, privateKeyPem } = await generateKeypair();
    const payload = JSON.stringify({ agent_id: 'agent_test', session_id: 's1' });
    const envelope = await encryptFieldForTest(payload, publicKey);
    const key = await importDecryptPrivateKey(privateKeyPem);
    const plaintext = await decryptField(envelope, key);
    expect(plaintext).toBe(payload);
  });

  it('decrypts multi-KB payloads (request/response body shape)', async () => {
    const { publicKey, privateKeyPem } = await generateKeypair();
    const big = JSON.stringify({
      content: Array.from({ length: 500 }, (_, i) => `line ${i}`).join('\n'),
    });
    const envelope = await encryptFieldForTest(big, publicKey);
    const key = await importDecryptPrivateKey(privateKeyPem);
    const plaintext = await decryptField(envelope, key);
    expect(plaintext).toBe(big);
  });

  it('produces independent ciphertexts for identical plaintexts (fresh IV + key)', async () => {
    const { publicKey } = await generateKeypair();
    const payload = 'identical';
    const e1 = await encryptFieldForTest(payload, publicKey);
    const e2 = await encryptFieldForTest(payload, publicKey);
    expect(e1.data).not.toBe(e2.data);
    expect(e1.key).not.toBe(e2.key);
    expect(e1.iv).not.toBe(e2.iv);
  });

  it('throws on tampered ciphertext (AES-GCM auth tag catches it)', async () => {
    const { publicKey, privateKeyPem } = await generateKeypair();
    const envelope = await encryptFieldForTest('payload', publicKey);
    // Flip one byte in the ciphertext data
    const tampered = b64ToBytes(envelope.data);
    tampered[0] ^= 0x01;
    const mutated: EncryptedField = {
      ...envelope,
      data: bytesToB64(tampered),
    };
    const key = await importDecryptPrivateKey(privateKeyPem);
    await expect(decryptField(mutated, key)).rejects.toThrow();
  });

  it('throws when the wrong key is provided', async () => {
    const a = await generateKeypair();
    const b = await generateKeypair();
    const envelope = await encryptFieldForTest('payload', a.publicKey);
    const wrongKey = await importDecryptPrivateKey(b.privateKeyPem);
    await expect(decryptField(envelope, wrongKey)).rejects.toThrow();
  });
});
