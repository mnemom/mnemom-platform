/**
 * Tests for deriveTraceId — ADR-036 widens the trace_id derivation from a
 * 36^8 base36 suffix (the 2026-04-26 prod failure surface) to a 16-char hex
 * digest of SHA-256(log.id), giving ~1.8e19 collision space and preserving
 * the "same log = same trace" idempotency contract Step 51 depends on.
 */
import { describe, it, expect } from 'vitest';
import { _deriveTraceIdForTests as deriveTraceId } from '../index';

describe('deriveTraceId (ADR-036)', () => {
  it('emits the documented format: tr-{16 hex chars}', async () => {
    const id = await deriveTraceId('9QWEZNKF');
    expect(id).toMatch(/^tr-[0-9a-f]{16}$/);
  });

  it('is deterministic — same input always produces the same id', async () => {
    const a = await deriveTraceId('9QWEZNKF');
    const b = await deriveTraceId('9QWEZNKF');
    expect(a).toBe(b);
  });

  it('produces distinct ids for inputs that share an 8-char suffix (the legacy collision shape)', async () => {
    // Both inputs end in "9QWEZNKF", which collided under the old slice(-8)
    // derivation. Under SHA-256-16 they must not collide.
    const a = await deriveTraceId('A1B2C39QWEZNKF');
    const b = await deriveTraceId('Z9Y8X79QWEZNKF');
    expect(a).not.toBe(b);
  });

  it('matches the SHA-256 prefix of the input bytes', async () => {
    // Pin the exact derivation so a future refactor that swaps algorithms
    // (e.g. accidentally to SHA-1, or different slice offset) fails loudly.
    // SHA-256("9QWEZNKF") → first 16 hex chars of the digest.
    const id = await deriveTraceId('9QWEZNKF');
    const expectedDigest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode('9QWEZNKF'),
    );
    const expectedHex = Array.from(new Uint8Array(expectedDigest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 16);
    expect(id).toBe(`tr-${expectedHex}`);
  });

  it('handles arbitrary-length inputs (no slice assumption on log.id)', async () => {
    const short = await deriveTraceId('a');
    const long = await deriveTraceId('a'.repeat(256));
    expect(short).toMatch(/^tr-[0-9a-f]{16}$/);
    expect(long).toMatch(/^tr-[0-9a-f]{16}$/);
    expect(short).not.toBe(long);
  });
});
