/**
 * Tests for the SSE synthesizer (T0-4 + T0-5 streaming addenda).
 *
 * The strongest correctness check is round-trip: each synthesized stream
 * goes back through the existing `parseSSEEvents` parser (which is what
 * the gateway uses to read upstream streams) and the assembled text
 * matches the input. If a real provider's SDK can parse upstream output,
 * and our parser can parse upstream output, and our parser can parse our
 * synthesized output, then SDK clients can parse our synthesized output.
 *
 * Beyond round-trip we assert event sequence, sentinel presence/absence,
 * required field shapes — the exact fidelity points where SDK clients
 * have historically broken on non-conforming streams.
 */

import { describe, it, expect } from 'vitest';
import {
  buildAnthropicSSE,
  buildOpenAISSE,
  buildGeminiSSE,
  synthesizeProviderStream,
} from '../sse-synthesizer';
import { parseSSEEvents, readStreamToText } from '../sse-parser';

const INTERVENTION = '[Mnemom Intervention: I cannot proceed; this violates BOUNDARY value `no_harm`.]';
const SHORT = 'Hello.';

// ── Anthropic ─────────────────────────────────────────────────────────────

describe('buildAnthropicSSE', () => {
  it('round-trips through parseSSEEvents', () => {
    const sse = buildAnthropicSSE(INTERVENTION, 'claude-opus-4-7');
    const parsed = parseSSEEvents(sse, 'anthropic');
    expect(parsed.text).toBe(INTERVENTION);
    expect(parsed.thinking).toBe('');
    expect(parsed.toolCalls).toEqual([]);
  });

  it('emits the documented event sequence in order', () => {
    const sse = buildAnthropicSSE(SHORT, 'claude-opus-4-7');
    const eventNames = sse
      .split('\n')
      .filter(line => line.startsWith('event: '))
      .map(line => line.slice(7));
    expect(eventNames).toEqual([
      'message_start',
      'content_block_start',
      'content_block_delta',
      'content_block_stop',
      'message_delta',
      'message_stop',
    ]);
  });

  it('does NOT emit a [DONE] sentinel (Anthropic uses connection close)', () => {
    const sse = buildAnthropicSSE(SHORT, 'claude-opus-4-7');
    expect(sse).not.toContain('[DONE]');
    expect(sse).not.toMatch(/data:\s*\[DONE\]/);
  });

  it('starts message_start.usage.output_tokens at 1 (per docs)', () => {
    const sse = buildAnthropicSSE(SHORT, 'claude-opus-4-7');
    const messageStart = extractAnthropicEvent(sse, 'message_start');
    expect(messageStart.message.usage.output_tokens).toBe(1);
    expect(messageStart.message.usage.input_tokens).toBe(0);
  });

  it('reports cumulative output_tokens in message_delta.usage', () => {
    const sse = buildAnthropicSSE(INTERVENTION, 'claude-opus-4-7');
    const messageDelta = extractAnthropicEvent(sse, 'message_delta');
    // Cumulative count must be a positive integer (we approximate from word
    // count). What matters is: not zero, monotonic vs message_start (1).
    expect(messageDelta.usage.output_tokens).toBeGreaterThan(1);
    expect(messageDelta.delta.stop_reason).toBe('end_turn');
    expect(messageDelta.delta.stop_sequence).toBe(null);
  });

  it('includes required message_start.message fields', () => {
    const sse = buildAnthropicSSE(SHORT, 'claude-opus-4-7');
    const evt = extractAnthropicEvent(sse, 'message_start');
    const m = evt.message;
    expect(m.id).toMatch(/^msg_/);
    expect(m.type).toBe('message');
    expect(m.role).toBe('assistant');
    expect(m.model).toBe('claude-opus-4-7');
    expect(m.content).toEqual([]);
    expect(m.stop_reason).toBe(null);
    expect(m.stop_sequence).toBe(null);
  });

  it('content_block_start describes a text block at index 0', () => {
    const sse = buildAnthropicSSE(SHORT, 'claude-opus-4-7');
    const evt = extractAnthropicEvent(sse, 'content_block_start');
    expect(evt.index).toBe(0);
    expect(evt.content_block).toEqual({ type: 'text', text: '' });
  });

  it('content_block_delta carries text_delta with the intervention text', () => {
    const sse = buildAnthropicSSE(INTERVENTION, 'claude-opus-4-7');
    const evt = extractAnthropicEvent(sse, 'content_block_delta');
    expect(evt.delta.type).toBe('text_delta');
    expect(evt.delta.text).toBe(INTERVENTION);
    expect(evt.index).toBe(0);
  });

  it('message_stop has only the type field', () => {
    const sse = buildAnthropicSSE(SHORT, 'claude-opus-4-7');
    const evt = extractAnthropicEvent(sse, 'message_stop');
    expect(evt).toEqual({ type: 'message_stop' });
  });
});

// ── OpenAI ────────────────────────────────────────────────────────────────

describe('buildOpenAISSE', () => {
  it('round-trips through parseSSEEvents', () => {
    const sse = buildOpenAISSE(INTERVENTION, 'gpt-4o-mini');
    const parsed = parseSSEEvents(sse, 'openai');
    expect(parsed.text).toBe(INTERVENTION);
    expect(parsed.toolCalls).toEqual([]);
  });

  it('emits role-only first chunk, then content, then finish_reason, then [DONE]', () => {
    const sse = buildOpenAISSE(SHORT, 'gpt-4o-mini');
    const chunks = extractOpenAIDataLines(sse);
    expect(chunks).toHaveLength(4);
    expect(chunks[3]).toBe('[DONE]');

    const role = JSON.parse(chunks[0] as string);
    const content = JSON.parse(chunks[1] as string);
    const finish = JSON.parse(chunks[2] as string);

    expect(role.choices[0].delta).toEqual({ role: 'assistant', content: '' });
    expect(role.choices[0].finish_reason).toBe(null);

    expect(content.choices[0].delta).toEqual({ content: SHORT });
    // Critical: subsequent chunks OMIT role entirely (must not be null).
    expect('role' in content.choices[0].delta).toBe(false);
    expect(content.choices[0].finish_reason).toBe(null);

    expect(finish.choices[0].delta).toEqual({});
    expect(finish.choices[0].finish_reason).toBe('stop');
  });

  it('emits the literal [DONE] sentinel (not a JSON object)', () => {
    const sse = buildOpenAISSE(SHORT, 'gpt-4o-mini');
    expect(sse).toContain('data: [DONE]\n\n');
    // openai-python `_streaming.py` checks `sse.data.startswith("[DONE]")`
    // BEFORE attempting JSON parse. Anything that parses as JSON breaks it.
    expect(() => JSON.parse('[DONE]')).toThrow();
  });

  it('every chunk has object="chat.completion.chunk"', () => {
    const sse = buildOpenAISSE(SHORT, 'gpt-4o-mini');
    const chunks = extractOpenAIDataLines(sse).filter(c => c !== '[DONE]');
    for (const chunk of chunks) {
      const parsed = JSON.parse(chunk as string);
      expect(parsed.object).toBe('chat.completion.chunk');
    }
  });

  it('id and created are stable across all chunks', () => {
    const sse = buildOpenAISSE(SHORT, 'gpt-4o-mini');
    const chunks = extractOpenAIDataLines(sse)
      .filter(c => c !== '[DONE]')
      .map(c => JSON.parse(c as string));
    const ids = new Set(chunks.map(c => c.id));
    const createds = new Set(chunks.map(c => c.created));
    expect(ids.size).toBe(1);
    expect(createds.size).toBe(1);
    const [id] = ids;
    expect(id as string).toMatch(/^chatcmpl-/);
  });

  it('does not emit a usage chunk (no stream_options.include_usage)', () => {
    const sse = buildOpenAISSE(SHORT, 'gpt-4o-mini');
    const chunks = extractOpenAIDataLines(sse)
      .filter(c => c !== '[DONE]')
      .map(c => JSON.parse(c as string));
    for (const chunk of chunks) {
      expect(chunk.usage).toBeUndefined();
    }
  });

  it('uses the model from the request body', () => {
    const sse = buildOpenAISSE(SHORT, 'gpt-4o-2024-11-20');
    const first = JSON.parse(extractOpenAIDataLines(sse)[0] as string);
    expect(first.model).toBe('gpt-4o-2024-11-20');
  });
});

// ── Gemini ────────────────────────────────────────────────────────────────

describe('buildGeminiSSE', () => {
  it('round-trips through parseSSEEvents', () => {
    const sse = buildGeminiSSE(INTERVENTION, 'gemini-2.5-flash');
    const parsed = parseSSEEvents(sse, 'gemini');
    expect(parsed.text).toBe(INTERVENTION);
    expect(parsed.toolCalls).toEqual([]);
  });

  it('emits two chunks: text-bearing first, then finishReason-bearing', () => {
    const sse = buildGeminiSSE(SHORT, 'gemini-2.5-flash');
    const chunks = extractGeminiDataLines(sse).map(c => JSON.parse(c));
    expect(chunks).toHaveLength(2);

    const [textChunk, finishChunk] = chunks;
    expect(textChunk.candidates[0].content.parts[0].text).toBe(SHORT);
    expect(textChunk.candidates[0].finishReason).toBeUndefined();
    expect(finishChunk.candidates[0].finishReason).toBe('STOP');
  });

  it('does NOT emit a [DONE] sentinel (Gemini uses connection close)', () => {
    const sse = buildGeminiSSE(SHORT, 'gemini-2.5-flash');
    expect(sse).not.toContain('[DONE]');
  });

  it('every chunk has role:"model" in content', () => {
    const sse = buildGeminiSSE(SHORT, 'gemini-2.5-flash');
    const chunks = extractGeminiDataLines(sse).map(c => JSON.parse(c));
    for (const chunk of chunks) {
      expect(chunk.candidates[0].content.role).toBe('model');
    }
  });

  it('responseId and modelVersion are stable across chunks', () => {
    const sse = buildGeminiSSE(SHORT, 'gemini-2.5-flash');
    const chunks = extractGeminiDataLines(sse).map(c => JSON.parse(c));
    const ids = new Set(chunks.map(c => c.responseId));
    const versions = new Set(chunks.map(c => c.modelVersion));
    expect(ids.size).toBe(1);
    expect(versions.size).toBe(1);
    expect(versions.has('gemini-2.5-flash')).toBe(true);
  });

  it('usageMetadata is cumulative and present on every chunk', () => {
    const sse = buildGeminiSSE(INTERVENTION, 'gemini-2.5-flash');
    const chunks = extractGeminiDataLines(sse).map(c => JSON.parse(c));
    const counts = chunks.map(c => c.usageMetadata.candidatesTokenCount);
    expect(counts.every(c => typeof c === 'number' && c > 0)).toBe(true);
    // Monotonic non-decreasing
    for (let i = 1; i < counts.length; i++) {
      expect(counts[i]).toBeGreaterThanOrEqual(counts[i - 1] as number);
    }
  });
});

// ── Public synthesizeProviderStream ───────────────────────────────────────

describe('synthesizeProviderStream', () => {
  it('returns a ReadableStream that yields the same text as the per-provider builder for anthropic', async () => {
    const { body, headers } = synthesizeProviderStream('anthropic', INTERVENTION, { model: 'claude-opus-4-7' });
    const text = await readStreamToText(body);
    expect(text).toBe(buildAnthropicSSE(INTERVENTION, 'claude-opus-4-7').replace(
      /msg_[a-f0-9]+/, text.match(/msg_[a-f0-9]+/)?.[0] ?? '',
    ));
    expect(headers['Content-Type']).toBe('text/event-stream');
  });

  it('returns the right openai content-type with charset', async () => {
    const { headers } = synthesizeProviderStream('openai', INTERVENTION, null);
    expect(headers['Content-Type']).toBe('text/event-stream; charset=utf-8');
    expect(headers['Cache-Control']).toBe('no-cache, must-revalidate');
  });

  it('returns the right gemini headers including X-Accel-Buffering', async () => {
    const { headers } = synthesizeProviderStream('gemini', INTERVENTION, null);
    expect(headers['Content-Type']).toBe('text/event-stream');
    expect(headers['X-Accel-Buffering']).toBe('no');
  });

  it('falls back to a sane model name when requestBody is null', async () => {
    for (const provider of ['anthropic', 'openai', 'gemini'] as const) {
      const { body } = synthesizeProviderStream(provider, INTERVENTION, null);
      const text = await readStreamToText(body);
      expect(text.length).toBeGreaterThan(0);
      // No `null` or `undefined` leaking into the JSON
      expect(text).not.toMatch(/"model":\s*null/);
      expect(text).not.toMatch(/"model":\s*"undefined"/);
    }
  });

  it('preserves intervention text byte-for-byte through synthesis + parse', async () => {
    for (const provider of ['anthropic', 'openai', 'gemini'] as const) {
      const { body } = synthesizeProviderStream(provider, INTERVENTION, { model: 'm' });
      const text = await readStreamToText(body);
      const parsed = parseSSEEvents(text, provider);
      expect(parsed.text).toBe(INTERVENTION);
    }
  });

  it('handles intervention text with embedded special characters', async () => {
    const tricky = 'Quote: "no harm"\nNewline.\tTab.\\Backslash. {"json":"like"}';
    for (const provider of ['anthropic', 'openai', 'gemini'] as const) {
      const { body } = synthesizeProviderStream(provider, tricky, null);
      const text = await readStreamToText(body);
      const parsed = parseSSEEvents(text, provider);
      expect(parsed.text).toBe(tricky);
    }
  });
});

// ── Helpers ──────────────────────────────────────────────────────────────

function extractAnthropicEvent(sse: string, eventName: string): any {
  // Find `event: <name>\ndata: <json>` pairs.
  const lines = sse.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === `event: ${eventName}`) {
      const dataLine = lines[i + 1];
      if (dataLine?.startsWith('data: ')) {
        return JSON.parse(dataLine.slice(6));
      }
    }
  }
  throw new Error(`No event ${eventName} in stream`);
}

function extractOpenAIDataLines(sse: string): string[] {
  return sse
    .split('\n')
    .filter(line => line.startsWith('data: '))
    .map(line => line.slice(6));
}

function extractGeminiDataLines(sse: string): string[] {
  return sse
    .split('\n')
    .filter(line => line.startsWith('data: '))
    .map(line => line.slice(6));
}
