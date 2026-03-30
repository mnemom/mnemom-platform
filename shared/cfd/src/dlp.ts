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

  return matches;
}

export function hasDLPMatches(text: string): boolean {
  return scanDLP(text).length > 0;
}
