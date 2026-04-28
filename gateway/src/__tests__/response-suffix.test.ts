/**
 * Unit tests for the T0-8 user-visible-explanation suffix (ADR-040 §I10).
 *
 * Three helpers under test:
 *   - appendSuffixToProviderResponse: per-provider text-slot append.
 *   - ensureInterventionReference: skips when the body already names a
 *     Mnemom intervention; otherwise builds + appends a structured
 *     suffix.
 *   - summarizeRequestInterventions: derives intervention summaries
 *     from front-door verdict + back-door modification state.
 */

import { describe, it, expect } from 'vitest';
import {
  appendSuffixToProviderResponse,
  ensureInterventionReference,
  summarizeRequestInterventions,
} from '../index';

// ─── appendSuffixToProviderResponse ─────────────────────────────────────────

describe('appendSuffixToProviderResponse', () => {
  it('appends a new text block to Anthropic content[]', () => {
    const original = JSON.stringify({
      type: 'message',
      role: 'assistant',
      content: [{ type: 'text', text: "Here's the answer." }],
      stop_reason: 'end_turn',
    });
    const result = appendSuffixToProviderResponse(original, '[Mnemom: x]');
    expect(result.applied).toBe(true);
    const parsed = JSON.parse(result.body);
    expect(parsed.content).toHaveLength(2);
    expect(parsed.content[0]).toEqual({ type: 'text', text: "Here's the answer." });
    expect(parsed.content[1]).toEqual({ type: 'text', text: '[Mnemom: x]' });
    expect(parsed.stop_reason).toBe('end_turn');
  });

  it('appends to the LAST OpenAI choice message.content', () => {
    const original = JSON.stringify({
      id: 'chatcmpl-1',
      object: 'chat.completion',
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: 'first' },
          finish_reason: 'stop',
        },
        {
          index: 1,
          message: { role: 'assistant', content: 'last' },
          finish_reason: 'stop',
        },
      ],
    });
    const result = appendSuffixToProviderResponse(original, '[Mnemom: y]');
    expect(result.applied).toBe(true);
    const parsed = JSON.parse(result.body);
    expect(parsed.choices[0].message.content).toBe('first');
    expect(parsed.choices[1].message.content).toBe('last\n\n[Mnemom: y]');
  });

  it('handles OpenAI choice with empty content', () => {
    const original = JSON.stringify({
      choices: [
        { message: { role: 'assistant', content: '' }, finish_reason: 'stop' },
      ],
    });
    const result = appendSuffixToProviderResponse(original, '[Mnemom: z]');
    expect(result.applied).toBe(true);
    const parsed = JSON.parse(result.body);
    expect(parsed.choices[0].message.content).toBe('[Mnemom: z]');
  });

  it('appends a new text part to the LAST Gemini candidate', () => {
    const original = JSON.stringify({
      candidates: [
        {
          content: { parts: [{ text: 'first' }], role: 'model' },
          finishReason: 'STOP',
        },
        {
          content: { parts: [{ text: 'last' }], role: 'model' },
          finishReason: 'STOP',
        },
      ],
    });
    const result = appendSuffixToProviderResponse(original, '[Mnemom: g]');
    expect(result.applied).toBe(true);
    const parsed = JSON.parse(result.body);
    expect(parsed.candidates[0].content.parts).toEqual([{ text: 'first' }]);
    expect(parsed.candidates[1].content.parts).toEqual([
      { text: 'last' },
      { text: '[Mnemom: g]' },
    ]);
  });

  it('returns body unchanged on non-JSON input (applied=false)', () => {
    const result = appendSuffixToProviderResponse('not json', '[Mnemom: x]');
    expect(result.applied).toBe(false);
    expect(result.body).toBe('not json');
  });

  it('returns body unchanged on unrecognized JSON shape', () => {
    const original = JSON.stringify({ unknown_envelope: { foo: 1 } });
    const result = appendSuffixToProviderResponse(original, '[Mnemom: x]');
    expect(result.applied).toBe(false);
    expect(result.body).toBe(original);
  });

  it('returns body unchanged on JSON null', () => {
    const result = appendSuffixToProviderResponse('null', '[Mnemom: x]');
    expect(result.applied).toBe(false);
    expect(result.body).toBe('null');
  });

  it('returns body unchanged when choices array is empty', () => {
    const original = JSON.stringify({ choices: [] });
    const result = appendSuffixToProviderResponse(original, '[Mnemom: x]');
    expect(result.applied).toBe(false);
  });
});

// ─── ensureInterventionReference ────────────────────────────────────────────

describe('ensureInterventionReference', () => {
  it('returns body unchanged when no interventions occurred', () => {
    const original = JSON.stringify({
      content: [{ type: 'text', text: 'plain answer' }],
    });
    const result = ensureInterventionReference(original, []);
    expect(result.suffixed).toBe(false);
    expect(result.body).toBe(original);
  });

  it('returns body unchanged when the response already names a Mnemom intervention', () => {
    const original = JSON.stringify({
      content: [
        { type: 'text', text: '[Mnemom Intervention: blocked the data leak]' },
      ],
    });
    const result = ensureInterventionReference(original, ['front-door block']);
    expect(result.suffixed).toBe(false);
    expect(result.body).toBe(original);
  });

  it('matches case-insensitively on the marker', () => {
    const original = JSON.stringify({
      content: [{ type: 'text', text: '[mnemom advisory: heads up]' }],
    });
    const result = ensureInterventionReference(original, ['back-door redacted 1 item']);
    expect(result.suffixed).toBe(false);
  });

  it('matches the legacy "[Mnemom advisor" prefix variant', () => {
    const original = JSON.stringify({
      content: [{ type: 'text', text: '[Mnemom advisor noted that...]' }],
    });
    const result = ensureInterventionReference(original, ['front-door warn']);
    expect(result.suffixed).toBe(false);
  });

  it('appends a structured suffix when interventions occurred and the body lacks the marker', () => {
    const original = JSON.stringify({
      content: [{ type: 'text', text: "I'll help with that." }],
    });
    const result = ensureInterventionReference(original, [
      'front-door quarantine',
      'back-door redacted 2 item(s) (email, phone)',
    ]);
    expect(result.suffixed).toBe(true);
    const parsed = JSON.parse(result.body);
    expect(parsed.content).toHaveLength(2);
    const suffix = parsed.content[1].text as string;
    expect(suffix).toMatch(/^\[Mnemom: /);
    expect(suffix).toContain('front-door quarantine');
    expect(suffix).toContain('back-door redacted 2 item');
  });

  it('joins multiple summaries with semicolons', () => {
    const original = JSON.stringify({
      content: [{ type: 'text', text: 'response' }],
    });
    const result = ensureInterventionReference(original, ['a', 'b', 'c']);
    const parsed = JSON.parse(result.body);
    expect(parsed.content[1].text).toBe('[Mnemom: a; b; c]');
  });

  it('reports suffixed=false when the response shape is unrecognized (graceful)', () => {
    // Even with interventions, if we can't append (unrecognized shape),
    // suffixed=false so the caller doesn't set X-Mnemom-Suffixed.
    const original = JSON.stringify({ unknown: true });
    const result = ensureInterventionReference(original, ['front-door block']);
    expect(result.suffixed).toBe(false);
    expect(result.body).toBe(original);
  });
});

// ─── summarizeRequestInterventions ──────────────────────────────────────────

describe('summarizeRequestInterventions', () => {
  it('returns [] when no intervention occurred', () => {
    expect(
      summarizeRequestInterventions({
        shVerdict: undefined,
        outboundDLPMatches: [],
        backDoorBodyReplaced: false,
      }),
    ).toEqual([]);
  });

  it('emits "front-door pass" copy not produced (only block/quarantine/warn)', () => {
    expect(
      summarizeRequestInterventions({
        shVerdict: 'pass',
        outboundDLPMatches: [],
        backDoorBodyReplaced: false,
      }),
    ).toEqual([]);
  });

  it('summarizes a front-door block', () => {
    const result = summarizeRequestInterventions({
      shVerdict: 'block',
      outboundDLPMatches: [],
      backDoorBodyReplaced: false,
    });
    expect(result).toEqual(['front-door block']);
  });

  it('summarizes a front-door quarantine', () => {
    const result = summarizeRequestInterventions({
      shVerdict: 'quarantine',
      outboundDLPMatches: [],
      backDoorBodyReplaced: false,
    });
    expect(result).toEqual(['front-door quarantine']);
  });

  it('summarizes a front-door warn', () => {
    const result = summarizeRequestInterventions({
      shVerdict: 'warn',
      outboundDLPMatches: [],
      backDoorBodyReplaced: false,
    });
    expect(result).toEqual(['front-door warn']);
  });

  it('summarizes a back-door redaction with type list', () => {
    const result = summarizeRequestInterventions({
      shVerdict: undefined,
      outboundDLPMatches: [
        { type: 'email' },
        { type: 'phone' },
        { type: 'email' },
      ],
      backDoorBodyReplaced: true,
    });
    expect(result).toHaveLength(1);
    expect(result[0]).toContain('back-door redacted 3 item');
    expect(result[0]).toContain('email');
    expect(result[0]).toContain('phone');
  });

  it('skips back-door summary when matches exist but body was not replaced (observe mode)', () => {
    const result = summarizeRequestInterventions({
      shVerdict: undefined,
      outboundDLPMatches: [{ type: 'email' }],
      backDoorBodyReplaced: false,
    });
    expect(result).toEqual([]);
  });

  it('combines front-door + back-door summaries in order', () => {
    const result = summarizeRequestInterventions({
      shVerdict: 'quarantine',
      outboundDLPMatches: [{ type: 'ssn' }],
      backDoorBodyReplaced: true,
    });
    expect(result).toHaveLength(2);
    expect(result[0]).toBe('front-door quarantine');
    expect(result[1]).toContain('back-door redacted 1 item');
  });
});
