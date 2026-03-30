import { describe, it, expect } from 'vitest';
import { scanDLP, hasDLPMatches } from '../src/dlp.js';

describe('scanDLP', () => {
  it('detects valid Visa card number (Luhn valid)', () => {
    // 4532015112830366 passes Luhn check
    const matches = scanDLP('Please charge card 4532015112830366 for the order.');
    expect(matches.some(m => m.type === 'credit_card')).toBe(true);
    const cc = matches.find(m => m.type === 'credit_card')!;
    expect(cc.value_masked).toMatch(/0366$/);
  });

  it('does NOT detect a number that fails Luhn check', () => {
    // 4532015112830360 — last digit changed, fails Luhn
    const matches = scanDLP('Card number: 4532015112830360');
    expect(matches.some(m => m.type === 'credit_card')).toBe(false);
  });

  it('detects SSN pattern', () => {
    const matches = scanDLP('Social security: 123-45-6789');
    expect(matches.some(m => m.type === 'ssn')).toBe(true);
    const ssn = matches.find(m => m.type === 'ssn')!;
    expect(ssn.value_masked).toBe('***-**-6789');
  });

  it('does not detect invalid SSN with 000 prefix', () => {
    const matches = scanDLP('Not an SSN: 000-45-6789');
    expect(matches.some(m => m.type === 'ssn')).toBe(false);
  });

  it('detects sk- API key', () => {
    const matches = scanDLP('Use this key: sk-abcdefghijklmnopqrstuvwxyz123456789');
    expect(matches.some(m => m.type === 'api_key')).toBe(true);
    const key = matches.find(m => m.type === 'api_key')!;
    expect(key.value_masked).toMatch(/^sk-abc/);
    expect(key.value_masked).toContain('****');
  });

  it('detects GitHub personal access token (ghp_)', () => {
    const token = 'ghp_' + 'a'.repeat(36);
    const matches = scanDLP(`My token is ${token}`);
    expect(matches.some(m => m.type === 'api_key')).toBe(true);
  });

  it('detects PEM private key header', () => {
    const matches = scanDLP('Key content: -----BEGIN RSA PRIVATE KEY-----\nMIIE...');
    expect(matches.some(m => m.type === 'pem_key')).toBe(true);
    const pem = matches.find(m => m.type === 'pem_key')!;
    expect(pem.value_masked).toBe('[PRIVATE KEY REDACTED]');
  });

  it('detects EC private key header', () => {
    const matches = scanDLP('-----BEGIN EC PRIVATE KEY-----');
    expect(matches.some(m => m.type === 'pem_key')).toBe(true);
  });

  it('detects password field assignment', () => {
    const matches = scanDLP('Config: password=mysecretpassword123');
    expect(matches.some(m => m.type === 'password_field')).toBe(true);
    const pw = matches.find(m => m.type === 'password_field')!;
    expect(pw.value_masked).toBe('[CREDENTIAL REDACTED]');
  });

  it('detects password with colon separator', () => {
    const matches = scanDLP('Login: api_key: supersecretkey12345');
    expect(matches.some(m => m.type === 'password_field')).toBe(true);
  });

  it('returns empty array for clean text', () => {
    const matches = scanDLP('Hello, please summarize this article about climate change.');
    expect(matches).toHaveLength(0);
  });

  it('returns multiple matches when multiple patterns present', () => {
    const text = [
      'SSN: 123-45-6789',
      'Card: 4532015112830366',
      'Key: sk-abcdefghijklmnopqrstuvwxyz123456789',
    ].join(' ');
    const matches = scanDLP(text);
    expect(matches.length).toBeGreaterThanOrEqual(3);
    const types = matches.map(m => m.type);
    expect(types).toContain('ssn');
    expect(types).toContain('credit_card');
    expect(types).toContain('api_key');
  });

  it('hasDLPMatches returns true when matches exist', () => {
    expect(hasDLPMatches('SSN: 123-45-6789')).toBe(true);
  });

  it('hasDLPMatches returns false for clean text', () => {
    expect(hasDLPMatches('No sensitive data here.')).toBe(false);
  });
});
