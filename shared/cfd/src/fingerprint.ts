/**
 * MinHash fingerprint library for near-duplicate attack detection.
 *
 * Uses 64 hash permutations over character 3-grams (trigrams).
 * Two texts with Jaccard similarity >= 0.5 will have matching MinHash
 * signatures ~87% of the time with this configuration.
 *
 * No external dependencies — FNV-1a hash, pure TypeScript.
 */

// Number of hash permutations (higher = more accurate, slower)
const NUM_HASHES = 64;

// Large prime for modular arithmetic
const MERSENNE_PRIME = 2147483647; // 2^31 - 1

// Pre-computed (a, b) pairs for each hash function: hash_i(x) = (a*x + b) mod p
// Generated deterministically so signatures are stable across restarts
const HASH_PARAMS: Array<[number, number]> = (() => {
  const params: Array<[number, number]> = [];
  // Use FNV-1a to generate deterministic seed values
  let seed = 2166136261;
  for (let i = 0; i < NUM_HASHES; i++) {
    seed = ((seed ^ (i + 1)) * 16777619) >>> 0;
    const a = (seed % (MERSENNE_PRIME - 1)) + 1;
    seed = ((seed ^ (i + 1000)) * 16777619) >>> 0;
    const b = seed % MERSENNE_PRIME;
    params.push([a, b]);
  }
  return params;
})();

/** FNV-1a 32-bit hash of a string */
function fnv1a(str: string): number {
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 16777619) >>> 0; // unsigned 32-bit
  }
  return hash;
}

/** Tokenize text into character trigrams (3-grams), lowercased */
function trigrams(text: string): Set<number> {
  const lower = text.toLowerCase().replace(/\s+/g, ' ').trim();
  const hashes = new Set<number>();
  for (let i = 0; i <= lower.length - 3; i++) {
    hashes.add(fnv1a(lower.slice(i, i + 3)));
  }
  return hashes;
}

/**
 * Compute a MinHash signature for the given text.
 * Returns an array of NUM_HASHES integers (the signature).
 */
export function computeMinHash(text: string): number[] {
  if (text.length < 3) return new Array(NUM_HASHES).fill(0);

  const shingles = trigrams(text);
  const signature = new Array<number>(NUM_HASHES).fill(Number.MAX_SAFE_INTEGER);

  for (const shingle of shingles) {
    for (let i = 0; i < NUM_HASHES; i++) {
      const [a, b] = HASH_PARAMS[i];
      const hashed = ((a * shingle + b) % MERSENNE_PRIME + MERSENNE_PRIME) % MERSENNE_PRIME;
      if (hashed < signature[i]) {
        signature[i] = hashed;
      }
    }
  }

  return signature;
}

/**
 * Estimate Jaccard similarity between two texts using their MinHash signatures.
 * Returns a value between 0.0 (completely different) and 1.0 (identical).
 *
 * A similarity of 0.8 means ~80% of 3-gram shingles are shared.
 */
export function estimateSimilarity(sigA: number[], sigB: number[]): number {
  if (sigA.length !== sigB.length || sigA.length === 0) return 0;
  let matches = 0;
  for (let i = 0; i < sigA.length; i++) {
    if (sigA[i] === sigB[i]) matches++;
  }
  return matches / sigA.length;
}

/** Current serialization format version. Increment if algorithm changes. */
const MINHASH_VERSION = 'v1';
/** Total serialized length: 3 (prefix "v1:") + NUM_HASHES * 8 hex chars */
const SERIALIZED_LENGTH = MINHASH_VERSION.length + 1 + NUM_HASHES * 8;

/**
 * Serialize a MinHash signature to a versioned hex string for storage.
 * Format: "v1:<64 × 8-char hex>" = 515 chars total.
 * Version prefix enables safe algorithm upgrades without silent corruption.
 */
export function serializeMinHash(sig: number[]): string {
  return MINHASH_VERSION + ':' + sig.map(n => (n >>> 0).toString(16).padStart(8, '0')).join('');
}

/**
 * Deserialize a versioned MinHash string back to a signature array.
 * Returns null if the string is malformed or has an unrecognised version.
 * Backward-compatible: unversioned 512-char strings (pre-v1) are treated as v1.
 */
export function deserializeMinHash(raw: string): number[] | null {
  // Strip version prefix if present; accept legacy unversioned format
  let hex: string;
  if (raw.startsWith(MINHASH_VERSION + ':')) {
    hex = raw.slice(MINHASH_VERSION.length + 1);
  } else if (raw.length === NUM_HASHES * 8) {
    // Legacy unversioned format — treat as v1 for backward compatibility
    hex = raw;
  } else {
    return null; // unrecognised format
  }
  if (hex.length !== NUM_HASHES * 8) return null;
  try {
    const sig: number[] = [];
    for (let i = 0; i < hex.length; i += 8) {
      const val = parseInt(hex.slice(i, i + 8), 16);
      if (isNaN(val)) return null;
      sig.push(val);
    }
    return sig;
  } catch {
    return null;
  }
}

void SERIALIZED_LENGTH; // suppress unused warning (used as documentation)

// ── LSH band hashing ──────────────────────────────────────────────────────────

const BAND_COUNT = 16;
const BAND_WIDTH = NUM_HASHES / BAND_COUNT; // 4 values per band

/**
 * Divide a 64-element MinHash signature into 16 bands of 4 values each,
 * hash each band using FNV-1a, and return 16 lowercase 8-char hex strings.
 *
 * Two texts with Jaccard similarity ≥ 0.65 share at least one band with
 * high probability, making this an efficient pre-filter before full similarity.
 *
 * KV key pattern: `cfd_lsh:band:{bandIndex}:{result[bandIndex]}`
 * Patterns sharing ≥1 band key with a query are near-duplicate candidates.
 */
export function computeBandHashes(sig: number[]): string[] {
  const bands: string[] = [];
  for (let b = 0; b < BAND_COUNT; b++) {
    let h = 2166136261; // FNV-1a 32-bit offset basis
    for (let i = 0; i < BAND_WIDTH; i++) {
      const val = sig[b * BAND_WIDTH + i] >>> 0;
      // Mix each byte of the 32-bit value into the running hash
      for (let byte = 0; byte < 4; byte++) {
        h ^= (val >>> (byte * 8)) & 0xff;
        h = (h * 16777619) >>> 0; // FNV prime, unsigned 32-bit
      }
    }
    bands.push(h.toString(16).padStart(8, '0'));
  }
  return bands;
}

/**
 * Check if a text is a near-duplicate of a known pattern.
 * Returns the similarity score (0-1) or 0 if the stored hash is invalid.
 */
export function isSimilarToPattern(
  textSig: number[],
  storedMinHash: string,
  threshold = 0.65,
): { similar: boolean; similarity: number } {
  const patternSig = deserializeMinHash(storedMinHash);
  if (!patternSig) return { similar: false, similarity: 0 };
  const similarity = estimateSimilarity(textSig, patternSig);
  return { similar: similarity >= threshold, similarity };
}
