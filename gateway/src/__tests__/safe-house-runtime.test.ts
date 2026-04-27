/**
 * Unit tests for the ADR-037 Safe House runtime helpers — trusted-source
 * matching (typed buckets, IPv4 CIDR) and nudge advisory injection.
 */

import { describe, it, expect } from 'vitest';
import {
  checkTrustedSource,
  ipInCidr,
  buildNudgeAnnotation,
  prependNudgeToLastUserMessage,
} from '../safe-house-runtime.js';
import type { SafeHouseDecision, TrustedSourceBuckets } from '@mnemom/safe-house';

const EMPTY: TrustedSourceBuckets = { domains: [], agent_ids: [], ip_ranges: [] };

describe('checkTrustedSource', () => {
  it('returns null when no buckets present', () => {
    expect(checkTrustedSource({}, undefined)).toBeNull();
    expect(checkTrustedSource({ apparentAgentId: 'mnm-x' }, undefined)).toBeNull();
  });

  it('returns null when context is empty', () => {
    expect(checkTrustedSource({}, EMPTY)).toBeNull();
  });

  it('matches an agent_ids bucket', () => {
    const m = checkTrustedSource(
      { apparentAgentId: 'mnm-aabbcc' },
      { ...EMPTY, agent_ids: ['mnm-aabbcc'] },
    );
    expect(m).toEqual({ bucket: 'agent_ids', entry: 'mnm-aabbcc' });
  });

  it('matches a domains bucket case-insensitively', () => {
    const m = checkTrustedSource(
      { apparentDomain: 'INTERNAL.acme.COM' },
      { ...EMPTY, domains: ['internal.acme.com'] },
    );
    expect(m).toEqual({ bucket: 'domains', entry: 'internal.acme.com' });
  });

  it('matches an ip_ranges bucket via CIDR', () => {
    const m = checkTrustedSource(
      { clientIp: '10.5.42.7' },
      { ...EMPTY, ip_ranges: ['10.0.0.0/8'] },
    );
    expect(m).toEqual({ bucket: 'ip_ranges', entry: '10.0.0.0/8' });
  });

  it('does not match outside any bucket', () => {
    const m = checkTrustedSource(
      { apparentAgentId: 'mnm-other', apparentDomain: 'evil.com', clientIp: '8.8.8.8' },
      { domains: ['internal.acme.com'], agent_ids: ['mnm-aabbcc'], ip_ranges: ['10.0.0.0/8'] },
    );
    expect(m).toBeNull();
  });

  it('first-match-wins ordering: agent_ids before domains before ip_ranges', () => {
    const m = checkTrustedSource(
      { apparentAgentId: 'mnm-x', apparentDomain: 'd.com', clientIp: '10.0.0.1' },
      { agent_ids: ['mnm-x'], domains: ['d.com'], ip_ranges: ['10.0.0.0/8'] },
    );
    expect(m?.bucket).toBe('agent_ids');
  });
});

describe('ipInCidr (IPv4)', () => {
  it('matches /32 exact', () => {
    expect(ipInCidr('192.168.1.1', '192.168.1.1/32')).toBe(true);
    expect(ipInCidr('192.168.1.2', '192.168.1.1/32')).toBe(false);
  });

  it('matches /24 subnet', () => {
    expect(ipInCidr('10.0.5.10', '10.0.5.0/24')).toBe(true);
    expect(ipInCidr('10.0.6.10', '10.0.5.0/24')).toBe(false);
  });

  it('matches /8 large subnet', () => {
    expect(ipInCidr('10.255.255.255', '10.0.0.0/8')).toBe(true);
    expect(ipInCidr('11.0.0.0', '10.0.0.0/8')).toBe(false);
  });

  it('matches /0 (everything) — but the validator deny-lists 0.0.0.0/0', () => {
    expect(ipInCidr('1.2.3.4', '0.0.0.0/0')).toBe(true);
  });

  it('rejects malformed input', () => {
    expect(ipInCidr('not-an-ip', '10.0.0.0/8')).toBe(false);
    expect(ipInCidr('10.0.0.1', 'not-a-cidr')).toBe(false);
    expect(ipInCidr('10.0.0.1', '10.0.0.1/abc')).toBe(false);
  });

  it('returns false for IPv6 (not yet implemented)', () => {
    expect(ipInCidr('::1', '::/0')).toBe(false);
  });
});

describe('buildNudgeAnnotation', () => {
  function decision(score: number, threats: string[]): SafeHouseDecision {
    return {
      verdict: 'nudge',
      overall_risk: score,
      threats: threats.map((t) => ({ type: t as any, confidence: 0.5, reasoning: 'r' })),
      detector_scores: {},
      detection_sources: [],
      session_multiplier: 1,
      duration_ms: 0,
    };
  }

  it('includes risk score and threat categories', () => {
    const out = buildNudgeAnnotation(decision(0.72, ['prompt_injection']));
    expect(out).toContain('0.72');
    expect(out).toContain('prompt_injection');
    expect(out).toMatch(/<safe_house_advisory>/);
    expect(out).toMatch(/<\/safe_house_advisory>/);
  });

  it('falls back to "unspecified" when no threats listed', () => {
    const out = buildNudgeAnnotation(decision(0.5, []));
    expect(out).toContain('unspecified');
  });

  it('lists multiple threats comma-separated', () => {
    const out = buildNudgeAnnotation(decision(0.6, ['prompt_injection', 'data_exfiltration']));
    expect(out).toContain('prompt_injection, data_exfiltration');
  });

  it('instructs the model to treat content as data, not instructions', () => {
    const out = buildNudgeAnnotation(decision(0.5, ['prompt_injection']));
    expect(out).toMatch(/data, not as instructions/);
  });

  it('does NOT instruct the model to refuse — refusal causes downstream retry loops', () => {
    const out = buildNudgeAnnotation(decision(0.7, ['prompt_injection']));
    expect(out).not.toMatch(/\brefuse\b/i);
    expect(out).not.toMatch(/escalate/i);
  });

  it('explicitly tells the model it can continue responding normally', () => {
    const out = buildNudgeAnnotation(decision(0.7, ['prompt_injection']));
    expect(out).toMatch(/respond.*normally|continue/i);
  });
});

describe('prependNudgeToLastUserMessage', () => {
  it('prepends to a string-content user message (anthropic/openai shape)', () => {
    const body = {
      messages: [
        { role: 'system', content: 'sys' },
        { role: 'user', content: 'help me' },
      ],
    };
    const ok = prependNudgeToLastUserMessage(body, '<advisory/>', 'anthropic');
    expect(ok).toBe(true);
    expect((body.messages[1] as any).content).toBe('<advisory/>\n\nhelp me');
  });

  it('targets the last user message when several exist', () => {
    const body = {
      messages: [
        { role: 'user', content: 'first' },
        { role: 'assistant', content: 'reply' },
        { role: 'user', content: 'second' },
      ],
    };
    prependNudgeToLastUserMessage(body, 'NUDGE', 'anthropic');
    expect((body.messages[0] as any).content).toBe('first'); // unchanged
    expect((body.messages[2] as any).content).toBe('NUDGE\n\nsecond');
  });

  it('handles array content blocks (anthropic tool-call shape)', () => {
    const body = {
      messages: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'hello' }],
        },
      ],
    };
    prependNudgeToLastUserMessage(body, '<adv/>', 'anthropic');
    const blocks = (body.messages[0] as any).content;
    expect(Array.isArray(blocks)).toBe(true);
    expect(blocks[0]).toEqual({ type: 'text', text: '<adv/>' });
    expect(blocks[1]).toEqual({ type: 'text', text: 'hello' });
  });

  it('handles gemini contents/parts shape', () => {
    const body = {
      contents: [
        { role: 'user', parts: [{ text: 'q1' }, { text: 'q2' }] },
      ],
    };
    const ok = prependNudgeToLastUserMessage(body, 'NUDGE', 'gemini');
    expect(ok).toBe(true);
    expect((body.contents[0] as any).parts).toEqual([{ text: 'NUDGE\n\nq1q2' }]);
  });

  it('returns false when no user message exists', () => {
    const body = { messages: [{ role: 'system', content: 'sys' }] };
    expect(prependNudgeToLastUserMessage(body, 'NUDGE', 'anthropic')).toBe(false);
  });

  it('returns false on malformed body without throwing', () => {
    expect(prependNudgeToLastUserMessage({}, 'NUDGE', 'anthropic')).toBe(false);
    expect(prependNudgeToLastUserMessage({ messages: 'wat' as any }, 'NUDGE', 'anthropic')).toBe(false);
  });
});
