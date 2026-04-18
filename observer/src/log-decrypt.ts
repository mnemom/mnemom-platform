/**
 * Log decryption for CF AI Gateway Logpush to R2 (ADR-009).
 *
 * Every record delivered to `mnemom-gateway-logs` has Metadata / RequestBody /
 * ResponseBody wrapped as {type:"encrypted", key, iv, data} (all base64). The
 * scheme is hybrid RSA-OAEP-SHA256 + AES-256-GCM, applied per field:
 *
 *   - `key` is a 512-byte RSA-OAEP-SHA256 ciphertext of the per-field AES-256
 *     content key, wrapped under the customer public key uploaded to CF.
 *   - `iv` is the 12-byte AES-GCM nonce.
 *   - `data` is AES-256-GCM(plaintext, key, iv) — includes the 16-byte auth
 *     tag appended by Web Crypto's AES-GCM implementation.
 *
 * This module is pure Web Crypto — no Node crypto, no WASM. Runs unchanged in
 * Workers and Vitest-on-Node (Node 20+ ships WebCrypto as `crypto.subtle`).
 */

export interface EncryptedField {
  type: 'encrypted';
  key: string;
  iv: string;
  data: string;
}

/**
 * Type guard for the encrypted-field envelope. Records where a field is the
 * plaintext object (e.g. during the rare case CF emits without encryption)
 * are returned as-is elsewhere — callers check `isEncryptedField` first.
 */
export function isEncryptedField(value: unknown): value is EncryptedField {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return (
    v.type === 'encrypted' &&
    typeof v.key === 'string' &&
    typeof v.iv === 'string' &&
    typeof v.data === 'string'
  );
}

/**
 * Parse a PKCS#8 PEM private key into raw DER bytes suitable for
 * `crypto.subtle.importKey("pkcs8", ...)`.
 */
function pkcs8PemToDer(pem: string): ArrayBuffer {
  const cleaned = pem
    .replace(/-----BEGIN (?:RSA )?PRIVATE KEY-----/g, '')
    .replace(/-----END (?:RSA )?PRIVATE KEY-----/g, '')
    .replace(/\s+/g, '');
  if (!cleaned) {
    throw new Error('pkcs8PemToDer: empty PEM body');
  }
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/** Decode standard base64 to a Uint8Array (no padding assumptions). */
export function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Import the RSA-OAEP-SHA256 private key once. Caches by PEM-body hash so
 * concurrent ticks in the same isolate don't re-import on every record.
 */
let cachedImport: { fingerprint: string; key: CryptoKey } | null = null;

export async function importDecryptPrivateKey(pem: string): Promise<CryptoKey> {
  if (!pem || typeof pem !== 'string') {
    throw new Error('importDecryptPrivateKey: missing PEM');
  }
  // Cheap fingerprint: first/last 32 chars of the stripped body. Full SHA256
  // would be better but this is a within-isolate cache key, not a security boundary.
  const body = pem.replace(/\s+/g, '');
  const fingerprint = body.slice(0, 32) + body.slice(-32);
  if (cachedImport && cachedImport.fingerprint === fingerprint) {
    return cachedImport.key;
  }
  const der = pkcs8PemToDer(pem);
  const key = await crypto.subtle.importKey(
    'pkcs8',
    der,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt'],
  );
  cachedImport = { fingerprint, key };
  return key;
}

/** Test hook — clears the module-level key cache between tests. */
export function _resetDecryptCacheForTests(): void {
  cachedImport = null;
}

/**
 * Decrypt a single encrypted-field envelope. Throws on malformed input, tag
 * mismatch, or key-unwrap failure — callers decide whether to drop the record
 * or surface the error.
 */
export async function decryptField(
  field: EncryptedField,
  privateKey: CryptoKey,
): Promise<string> {
  const wrappedKey = b64ToBytes(field.key);
  const iv = b64ToBytes(field.iv);
  const ciphertext = b64ToBytes(field.data);

  const aesKeyRaw = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    wrappedKey as BufferSource,
  );
  const aesKey = await crypto.subtle.importKey(
    'raw',
    aesKeyRaw,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );
  const plaintextBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    aesKey,
    ciphertext as BufferSource,
  );
  return new TextDecoder().decode(plaintextBuf);
}
