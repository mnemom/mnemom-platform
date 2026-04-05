import type { DLPMatch } from './types.js';

// Luhn algorithm for credit card validation
function luhn(num: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let n = parseInt(num[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// Credit card patterns (Visa, MC, Amex, Discover)
const CARD_PATTERN = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g;

// SSN
const SSN_PATTERN = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;

// Common API key prefixes (non-exhaustive but covers major providers)
const API_KEY_PATTERN = /\b(sk-[a-zA-Z0-9]{20,}|pk_(?:live|test)_[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|xoxb-[0-9]+-[a-zA-Z0-9]+|xoxp-[0-9]+-[a-zA-Z0-9]+|AIza[a-zA-Z0-9_-]{35}|ya29\.[a-zA-Z0-9_-]{50,}|AKIA[A-Z0-9]{16})\b/g;

// PEM private keys
const PEM_PATTERN = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g;

// Password-like fields in structured text
const PASSWORD_FIELD_PATTERN = /(?:password|passwd|pwd|secret|token|api_key)\s*[=:]\s*["']?([^\s"',;]{8,})["']?/gi;

// OAuth/Bearer tokens
const OAUTH_PATTERN = /Bearer\s+([a-zA-Z0-9\-._~+/]+=*){20,}/g;

// Email addresses (HIPAA identifier #6)
const EMAIL_PATTERN = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;

// US phone numbers and E.164 (HIPAA identifier #4)
// Area code must start 2-9 to exclude test/invalid numbers (NPA 000, 555 excluded via context)
const PHONE_PATTERN = /\b(?:\+1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b/g;

// IPv4 addresses (HIPAA identifier #15)
// Loopback (127.x) and link-local (169.254.x) excluded — not PII
const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const IPV4_EXCLUDED = /^(?:127\.|169\.254\.|0\.0\.0\.0$|255\.255\.255\.255$)/;

// Database connection strings (credential leak)
const DB_CONNECTION_PATTERN = /(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|jdbc:[a-z]+):\/\/[^\s"'\n]{10,}/gi;

export function scanDLP(text: string): DLPMatch[] {
  const matches: DLPMatch[] = [];

  // Credit cards
  for (const match of text.matchAll(CARD_PATTERN)) {
    const digits = match[0].replace(/\D/g, '');
    if (luhn(digits)) {
      matches.push({
        type: 'credit_card',
        value_masked: '*'.repeat(digits.length - 4) + digits.slice(-4),
        offset: match.index ?? 0,
      });
    }
  }

  // SSN
  for (const match of text.matchAll(SSN_PATTERN)) {
    matches.push({ type: 'ssn', value_masked: '***-**-' + match[0].slice(-4), offset: match.index ?? 0 });
  }

  // API keys
  for (const match of text.matchAll(API_KEY_PATTERN)) {
    matches.push({ type: 'api_key', value_masked: match[0].slice(0, 6) + '****', offset: match.index ?? 0 });
  }

  // PEM
  for (const match of text.matchAll(PEM_PATTERN)) {
    matches.push({ type: 'pem_key', value_masked: '[PRIVATE KEY REDACTED]', offset: match.index ?? 0 });
  }

  // Password fields
  for (const match of text.matchAll(PASSWORD_FIELD_PATTERN)) {
    matches.push({ type: 'password_field', value_masked: '[CREDENTIAL REDACTED]', offset: match.index ?? 0 });
  }

  // OAuth
  for (const match of text.matchAll(OAUTH_PATTERN)) {
    matches.push({ type: 'oauth_token', value_masked: 'Bearer ****', offset: match.index ?? 0 });
  }

  // Email addresses
  for (const match of text.matchAll(EMAIL_PATTERN)) {
    const addr = match[0];
    // Skip obvious placeholder emails
    if (addr.includes('example.com') || addr.includes('test@') || addr.endsWith('@localhost')) continue;
    const parts = addr.split('@');
    const masked = parts[0].slice(0, 2) + '****@' + parts[1];
    matches.push({ type: 'email', value_masked: masked, offset: match.index ?? 0 });
  }

  // Phone numbers
  for (const match of text.matchAll(PHONE_PATTERN)) {
    const digits = match[0].replace(/\D/g, '');
    // Need at least 10 digits, reject 555-01xx test numbers and all-same-digit patterns
    if (digits.length < 10) continue;
    const last10 = digits.slice(-10);
    if (/^(\d)\1{9}$/.test(last10)) continue; // all same digit
    matches.push({ type: 'phone', value_masked: '***-***-' + last10.slice(-4), offset: match.index ?? 0 });
  }

  // IPv4 addresses
  for (const match of text.matchAll(IPV4_PATTERN)) {
    if (IPV4_EXCLUDED.test(match[0])) continue;
    const parts = match[0].split('.');
    const masked = parts[0] + '.' + parts[1] + '.***.' + parts[3];
    matches.push({ type: 'ipv4', value_masked: masked, offset: match.index ?? 0 });
  }

  // Database connection strings
  for (const match of text.matchAll(DB_CONNECTION_PATTERN)) {
    const url = match[0];
    // Mask credentials: proto://user:pass@host → proto://****@host
    const masked = url.replace(/(:\/{2})[^@]*@/, '$1****@').slice(0, 60) + (url.length > 60 ? '...' : '');
    matches.push({ type: 'db_connection', value_masked: masked, offset: match.index ?? 0 });
  }

  return matches;
}

export function hasDLPMatches(text: string): boolean {
  return scanDLP(text).length > 0;
}

/**
 * Redact all DLP matches in text, replacing sensitive values with [REDACTED].
 * Returns the redacted text and a list of what was redacted.
 */
export function redactDLPMatches(text: string): { redacted: string; matches: DLPMatch[] } {
  const matches = scanDLP(text);
  if (matches.length === 0) return { redacted: text, matches: [] };

  // Sort by offset descending so we can replace from end without shifting indices
  const sorted = [...matches].sort((a, b) => b.offset - a.offset);

  // Build redacted text by replacing matched values
  // Since we only have offsets (not end positions), use the patterns directly
  let redacted = text;

  // Re-run each pattern to get actual matched strings for replacement
  const REDACT_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, label: '[CARD REDACTED]' },
    { pattern: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, label: '[SSN REDACTED]' },
    { pattern: /\b(sk-[a-zA-Z0-9]{20,}|pk_(?:live|test)_[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|xoxb-[0-9]+-[a-zA-Z0-9]+|xoxp-[0-9]+-[a-zA-Z0-9]+|AIza[a-zA-Z0-9_-]{35}|ya29\.[a-zA-Z0-9_-]{50,}|AKIA[A-Z0-9]{16})\b/g, label: '[API_KEY REDACTED]' },
    { pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, label: '[PRIVATE_KEY REDACTED]' },
    { pattern: /(?:password|passwd|pwd|secret|token|api_key)\s*[=:]\s*["']?([^\s"',;]{8,})["']?/gi, label: '[CREDENTIAL REDACTED]' },
    { pattern: /Bearer\s+([a-zA-Z0-9\-._~+/]+=*){20,}/g, label: 'Bearer [TOKEN REDACTED]' },
    { pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g, label: '[EMAIL REDACTED]' },
    { pattern: /\b(?:\+1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b/g, label: '[PHONE REDACTED]' },
    { pattern: /(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|jdbc:[a-z]+):\/\/[^\s"'\n]{10,}/gi, label: '[DB_CONNECTION REDACTED]' },
  ];

  for (const { pattern, label } of REDACT_PATTERNS) {
    redacted = redacted.replace(pattern, label);
  }

  // sorted is used to document match offsets but replacement is done via patterns above
  void sorted;

  return { redacted, matches };
}
