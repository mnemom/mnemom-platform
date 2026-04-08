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

// Phase 2.5: HIPAA extended patterns
describe('scanDLP — email (HIPAA #6)', () => {
  it('detects a plain email address', () => {
    const matches = scanDLP('Contact us at patient@hospital.org for appointments.');
    expect(matches.some(m => m.type === 'email')).toBe(true);
    const m = matches.find(m => m.type === 'email')!;
    expect(m.value_masked).toContain('@hospital.org');
  });

  it('does NOT flag example.com emails', () => {
    const matches = scanDLP('See user@example.com for details.');
    expect(matches.some(m => m.type === 'email')).toBe(false);
  });

  it('detects multiple emails', () => {
    const matches = scanDLP('From: alice@acme.com To: bob@corp.io');
    expect(matches.filter(m => m.type === 'email').length).toBe(2);
  });

  it('does not flag text without @ symbol', () => {
    expect(hasDLPMatches('no email here, just text')).toBe(false);
  });
});

describe('scanDLP — phone (HIPAA #4)', () => {
  it('detects US phone in (NPA) NXX-XXXX format', () => {
    const matches = scanDLP('Call us at (617) 555-0100 for support.');
    expect(matches.some(m => m.type === 'phone')).toBe(true);
  });

  it('detects phone with dots', () => {
    const matches = scanDLP('Reach the doctor at 617.555.0199');
    expect(matches.some(m => m.type === 'phone')).toBe(true);
  });

  it('detects E.164 format', () => {
    const matches = scanDLP('International: +1-617-555-0143');
    expect(matches.some(m => m.type === 'phone')).toBe(true);
  });

  it('does NOT flag 10-digit numbers that are all the same digit', () => {
    const matches = scanDLP('Test: 555-555-5555');
    // All same digit — filtered out
    const phones = matches.filter(m => m.type === 'phone');
    expect(phones.length).toBe(0);
  });

  it('does NOT flag numbers starting with 0 or 1 in area code', () => {
    const matches = scanDLP('Invalid: 011-555-0100 or 100-555-0100');
    expect(matches.filter(m => m.type === 'phone').length).toBe(0);
  });
});

describe('scanDLP — IPv4 (HIPAA #15)', () => {
  it('detects a public IPv4 address', () => {
    const matches = scanDLP('Server IP: 203.0.113.42');
    expect(matches.some(m => m.type === 'ipv4')).toBe(true);
    expect(matches.find(m => m.type === 'ipv4')!.value_masked).toContain('203.0');
  });

  it('does NOT flag loopback 127.0.0.1', () => {
    const matches = scanDLP('localhost: 127.0.0.1');
    expect(matches.some(m => m.type === 'ipv4')).toBe(false);
  });

  it('does NOT flag link-local 169.254.x.x', () => {
    const matches = scanDLP('link-local: 169.254.0.1');
    expect(matches.some(m => m.type === 'ipv4')).toBe(false);
  });
});

describe('scanDLP — database connection strings', () => {
  it('detects PostgreSQL connection string', () => {
    const matches = scanDLP('DB: postgresql://admin:secret@db.prod.example.com/patients');
    expect(matches.some(m => m.type === 'db_connection')).toBe(true);
    const m = matches.find(m => m.type === 'db_connection')!;
    expect(m.value_masked).not.toContain('secret');
  });

  it('detects MongoDB connection string', () => {
    const matches = scanDLP('Connect with mongodb+srv://user:pass@cluster.mongodb.net/prod');
    expect(matches.some(m => m.type === 'db_connection')).toBe(true);
  });

  it('detects Redis URL', () => {
    const matches = scanDLP('Cache: redis://user:token@redis.example.com:6379/0');
    expect(matches.some(m => m.type === 'db_connection')).toBe(true);
  });

  it('does NOT flag short db-like strings', () => {
    const matches = scanDLP('Use redis://local');
    expect(matches.some(m => m.type === 'db_connection')).toBe(false);
  });
});
