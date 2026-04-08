/**
 * preprocessor.ts — Text normalization for L1 detection
 *
 * Runs BEFORE pattern matching to close unicode-obfuscation attack vectors:
 *   - Zero-width character injection (U+200B etc.)
 *   - Fullwidth Latin spoofing (Ａ instead of A)
 *   - Cyrillic/Greek homoglyph substitution (а looks like a)
 *   - Emoji injection between word characters
 *   - Base64/encoding-wrapper detection
 *
 * Important: normalization applies ONLY to Latin-script lookalike characters.
 * Arabic, Korean, Japanese, and Chinese characters are NOT modified — blanket
 * NFKD would decompose Korean Hangul into Jamo, breaking detection entirely.
 *
 * The original text is preserved for storage/decoration. The normalized text
 * is used exclusively for pattern matching and scoring.
 */

export interface PreprocessResult {
  /** Normalized text — use for ALL pattern matching, DLP, and scoring */
  normalized: string;
  /** Original unmodified text — use for quarantine storage and decoration */
  original: string;
  /** True when a decode instruction + base64-like string appear near each other.
   *  Advisory only — forces SemanticAnalyzer, never auto-blocks. */
  encoding_detected: boolean;
  zero_width_stripped: number;
  homoglyphs_mapped: number;
  emoji_stripped: number;
}

// ── Zero-width characters ──────────────────────────────────────────────────
const ZERO_WIDTH_RE =
  /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u2060\u2064\u2066\u2067\u2068\u2069]/g;

// Unicode Tag block (U+E0000–U+E007F) — invisible tag characters sometimes
// used to hide instructions from human readers while being visible to LLMs.
// MUST use the 'u' flag + \u{...} syntax for supplementary plane code points;
// \uE000 without 'u' flag is BMP U+E000, not U+E0000.
const TAG_CHARS_RE = /[\u{E0000}-\u{E007F}]/gu;

// ── Fullwidth Latin → ASCII ────────────────────────────────────────────────
// Fullwidth chars U+FF01–U+FF5E map to U+0021–U+007E (same code point offset)
const FULLWIDTH_RE = /[\uFF01-\uFF5E]/g;
function fullwidthToAscii(char: string): string {
  return String.fromCodePoint(char.codePointAt(0)! - 0xFF00 + 0x20);
}

// ── Cyrillic / Greek homoglyphs → Latin ASCII ──────────────────────────────
// Only maps visually identical lookalikes. Does not touch chars that are
// part of legitimate Cyrillic/Greek text (they won't match Latin patterns anyway,
// but mapping them makes mixed-script attacks detectable).
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic lowercase
  '\u0430': 'a', // а → a
  '\u0435': 'e', // е → e
  '\u043E': 'o', // о → o
  '\u0440': 'p', // р → p
  '\u0441': 'c', // с → c
  '\u0443': 'y', // у → y
  '\u0445': 'x', // х → x
  '\u0456': 'i', // і → i  (Ukrainian/Byelorussian І, very common i-homoglyph)
  '\u0454': 'e', // є → e  (Ukrainian є)
  '\u0455': 's', // ѕ → s
  '\u0457': 'i', // ї → i  (Ukrainian Ї)
  '\u0458': 'j', // ј → j
  // Cyrillic uppercase
  '\u0410': 'A', // А → A
  '\u0412': 'B', // В → B
  '\u0415': 'E', // Е → E
  '\u041A': 'K', // К → K
  '\u041C': 'M', // М → M
  '\u041D': 'H', // Н → H
  '\u041E': 'O', // О → O
  '\u0420': 'P', // Р → P
  '\u0421': 'C', // С → C
  '\u0422': 'T', // Т → T
  '\u0425': 'X', // Х → X
  '\u0423': 'Y', // У → Y
  '\u0406': 'I', // І → I  (Ukrainian uppercase І)
  // Greek lowercase
  '\u03B1': 'a', // α → a
  '\u03B2': 'b', // β → b
  '\u03B5': 'e', // ε → e
  '\u03B7': 'h', // η → h
  '\u03B9': 'i', // ι → i
  '\u03BA': 'k', // κ → k
  '\u03BD': 'v', // ν → v
  '\u03BF': 'o', // ο → o
  '\u03C1': 'r', // ρ → r
  '\u03C4': 't', // τ → t
  '\u03C5': 'y', // υ → y
  '\u03C7': 'x', // χ → x
  // Greek uppercase
  '\u0391': 'A', // Α → A
  '\u0392': 'B', // Β → B
  '\u0395': 'E', // Ε → E
  '\u0397': 'H', // Η → H
  '\u0399': 'I', // Ι → I
  '\u039A': 'K', // Κ → K
  '\u039C': 'M', // Μ → M
  '\u039D': 'N', // Ν → N
  '\u039F': 'O', // Ο → O
  '\u03A1': 'P', // Ρ → P
  '\u03A4': 'T', // Τ → T
  '\u03A7': 'X', // Χ → X
};

const HOMOGLYPH_RE = new RegExp(
  Object.keys(HOMOGLYPH_MAP).map(c => c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
  'g',
);

// ── Emoji between ASCII word characters ────────────────────────────────────
// Strips emoji injected between ASCII letters only (the actual attack vector).
// Restricted to ASCII context ([a-zA-Z]) to avoid any risk of stripping
// CJK, Arabic, Korean, or other non-Latin script characters.
//
// Emoji ranges covered (explicit, not \p{Extended_Pictographic} which is too
// broad in V8 and can match unexpected characters):
//   U+1F300-U+1F9FF — main emoji block (faces, objects, nature, travel…)
//   U+1FA00-U+1FAFF — symbols and pictographs extended-A
//   U+2600-U+26FF   — miscellaneous symbols (☺ ⚡ etc.)
//   U+2700-U+27BF   — dingbats (✈ ✉ etc.)
// Uses the 'u' flag for proper code point handling of supplementary chars.
const EMOJI_BETWEEN_LETTERS_RE = /([a-zA-Z])[\u{1F300}-\u{1F9FF}\u{1FA00}-\u{1FAFF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]+([a-zA-Z])/gu;

// ── Encoding detection ─────────────────────────────────────────────────────
const DECODE_INSTRUCTION_RE = /\b(?:decode|base64_decode|from_base64|rot13|decipher|decrypt)\b/i;
// Base64-like: ≥24 chars of base64 alphabet (avoid matching normal long words)
const BASE64_LIKE_RE = /[A-Za-z0-9+/]{24,}={0,2}/;

// ── Main function ──────────────────────────────────────────────────────────

export function preprocessForDetection(text: string): PreprocessResult {
  const original = text;
  let normalized = text;
  let zero_width_stripped = 0;
  let homoglyphs_mapped = 0;
  let emoji_stripped = 0;

  // 1. Strip zero-width characters (invisible — no legitimate use in AI messages)
  normalized = normalized.replace(ZERO_WIDTH_RE, (m) => {
    zero_width_stripped += m.length;
    return '';
  });
  normalized = normalized.replace(TAG_CHARS_RE, (m) => {
    zero_width_stripped += m.length;
    return '';
  });

  // 2. Fullwidth Latin → ASCII
  normalized = normalized.replace(FULLWIDTH_RE, fullwidthToAscii);

  // 3. Cyrillic / Greek homoglyphs → Latin
  normalized = normalized.replace(HOMOGLYPH_RE, (m) => {
    homoglyphs_mapped++;
    return HOMOGLYPH_MAP[m] ?? m;
  });

  // 4. Strip emoji injected between ASCII word characters
  // Multiple passes handle chained emoji: "a😊😂b" → "a😂b" → "ab"
  {
    let prev = '';
    while (prev !== normalized) {
      prev = normalized;
      normalized = normalized.replace(EMOJI_BETWEEN_LETTERS_RE, (_, a, b) => {
        emoji_stripped++;
        return a + b;
      });
    }
    // Reset lastIndex for the global regex after use
    EMOJI_BETWEEN_LETTERS_RE.lastIndex = 0;
  }

  // 5. Encoding detection (advisory flag — never changes text)
  const encoding_detected =
    DECODE_INSTRUCTION_RE.test(normalized) && BASE64_LIKE_RE.test(normalized);

  return {
    normalized,
    original,
    encoding_detected,
    zero_width_stripped,
    homoglyphs_mapped,
    emoji_stripped,
  };
}
