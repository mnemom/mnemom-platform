/**
 * Provider-shaped SSE stream synthesis (T0-4 + T0-5 streaming addenda, ADR-040).
 *
 * Produces a complete server-sent-event response carrying just the intervention
 * text as a single assistant turn. Byte-indistinguishable from a real upstream
 * stream so SDK clients (`@anthropic-ai/sdk`, `openai-node`, `@google/generative-ai`)
 * parse it without errors and surface the intervention as a normal assistant
 * turn.
 *
 * The buffered (non-stream) analogue lives in `buildAutonomyEnforceResponse`
 * (CLPI enforce) and `replaceIntegrityViolationContent` (AIP enforce); this
 * file covers the `stream: true` shape.
 *
 * Provider formats verified 2026-04-28 against:
 *   - Anthropic: https://platform.claude.com/docs/en/api/messages-streaming
 *     (event order: message_start → content_block_start → content_block_delta
 *     → content_block_stop → message_delta → message_stop; NO `[DONE]`
 *     sentinel; `message_start.usage.output_tokens` starts at 1; the docs
 *     mark `message_delta.usage` as *cumulative*).
 *   - OpenAI: https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events
 *     (chunks of `chat.completion.chunk`; role on first chunk only — OMITTED,
 *     not null, on subsequent chunks; finish_reason on its own chunk with
 *     empty `delta:{}`; literal `data: [DONE]\n\n` sentinel after the last
 *     chunk).
 *   - Gemini: https://ai.google.dev/api/generate-content with `?alt=sse`
 *     (each chunk `data: <GenerateContentResponse JSON>`; NO sentinel;
 *     `role:"model"` on every chunk; `finishReason:"STOP"` only on terminal
 *     chunk; `usageMetadata` cumulative).
 */

export type GatewayProviderName = 'anthropic' | 'openai' | 'gemini';

export interface SynthesizedStream {
  body: ReadableStream<Uint8Array>;
  headers: Record<string, string>;
}

const TEXT_ENCODER = new TextEncoder();

/**
 * Build a single-source ReadableStream that emits the provided bytes as one
 * chunk and closes. SSE framing (the `\n\n` event terminators) is independent
 * of TCP framing so SDK clients don't care that we send everything in one
 * frame; what matters is the byte-exact event sequence.
 */
function streamFromBytes(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

/**
 * Public helper: build a ReadableStream that emits the provided text as a
 * single UTF-8 chunk. Used by the streaming-enforce foreground path to
 * re-emit buffered upstream SSE bytes after AIP analysis.
 */
export function streamFromText(text: string): ReadableStream<Uint8Array> {
  return streamFromBytes(TEXT_ENCODER.encode(text));
}

/**
 * Approximate output_tokens from text length. The AAP / SDK clients don't
 * validate these against a true tokenizer; what matters is monotonicity
 * (start-of-stream <= end-of-stream) and shape correctness.
 */
function approxTokens(text: string): number {
  // Whitespace-split is a coarse but consistent approximation. Real per-
  // provider tokenizers diverge; the only constraint here is that the
  // value is a positive integer.
  const words = text.trim().split(/\s+/).filter(Boolean).length;
  return Math.max(1, words);
}

function shortId(): string {
  // 16 hex chars derived from crypto.randomUUID for stable per-stream id
  // (used by SDK clients to correlate chunks within one message).
  return crypto.randomUUID().replace(/-/g, '').slice(0, 16);
}

function modelFromRequest(requestBody: Record<string, unknown> | null, fallback: string): string {
  if (requestBody && typeof requestBody === 'object') {
    const m = (requestBody as { model?: unknown }).model;
    if (typeof m === 'string' && m.length > 0) return m;
  }
  return fallback;
}

// ── Anthropic ─────────────────────────────────────────────────────────────

/**
 * Anthropic Messages streaming format.
 *
 *   event: message_start
 *   data: {"type":"message_start","message":{...}}
 *
 *   event: content_block_start
 *   data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}
 *
 *   event: content_block_delta
 *   data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"..."}}
 *
 *   event: content_block_stop
 *   data: {"type":"content_block_stop","index":0}
 *
 *   event: message_delta
 *   data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":N}}
 *
 *   event: message_stop
 *   data: {"type":"message_stop"}
 *
 * No `[DONE]` sentinel; the connection closes after `message_stop`.
 */
export function buildAnthropicSSE(text: string, model: string): string {
  const id = `msg_${shortId()}`;
  const outputTokens = approxTokens(text);

  const messageStart = {
    type: 'message_start',
    message: {
      id,
      type: 'message',
      role: 'assistant',
      content: [],
      model,
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 0, output_tokens: 1 },
    },
  };

  const contentBlockStart = {
    type: 'content_block_start',
    index: 0,
    content_block: { type: 'text', text: '' },
  };

  const contentBlockDelta = {
    type: 'content_block_delta',
    index: 0,
    delta: { type: 'text_delta', text },
  };

  const contentBlockStop = { type: 'content_block_stop', index: 0 };

  const messageDelta = {
    type: 'message_delta',
    delta: { stop_reason: 'end_turn', stop_sequence: null },
    usage: { output_tokens: outputTokens },
  };

  const messageStop = { type: 'message_stop' };

  return [
    `event: message_start\ndata: ${JSON.stringify(messageStart)}\n\n`,
    `event: content_block_start\ndata: ${JSON.stringify(contentBlockStart)}\n\n`,
    `event: content_block_delta\ndata: ${JSON.stringify(contentBlockDelta)}\n\n`,
    `event: content_block_stop\ndata: ${JSON.stringify(contentBlockStop)}\n\n`,
    `event: message_delta\ndata: ${JSON.stringify(messageDelta)}\n\n`,
    `event: message_stop\ndata: ${JSON.stringify(messageStop)}\n\n`,
  ].join('');
}

// ── OpenAI ────────────────────────────────────────────────────────────────

/**
 * OpenAI Chat Completions streaming format.
 *
 *   data: {"id":"chatcmpl-X","object":"chat.completion.chunk","created":T,"model":"M","choices":[{"index":0,"delta":{"role":"assistant","content":""},"logprobs":null,"finish_reason":null}]}
 *
 *   data: {"id":"chatcmpl-X","object":"chat.completion.chunk","created":T,"model":"M","choices":[{"index":0,"delta":{"content":"..."},"logprobs":null,"finish_reason":null}]}
 *
 *   data: {"id":"chatcmpl-X","object":"chat.completion.chunk","created":T,"model":"M","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"stop"}]}
 *
 *   data: [DONE]
 *
 * `role` only on the first chunk (omitted on subsequent — not null). `[DONE]`
 * is a literal sentinel string, not JSON. Without `stream_options.include_usage`
 * no usage chunk is emitted; we don't synthesize one.
 */
export function buildOpenAISSE(text: string, model: string): string {
  const id = `chatcmpl-${shortId()}`;
  const created = Math.floor(Date.now() / 1000);

  const baseChunk = {
    id,
    object: 'chat.completion.chunk',
    created,
    model,
  };

  const roleChunk = {
    ...baseChunk,
    choices: [
      {
        index: 0,
        delta: { role: 'assistant', content: '' },
        logprobs: null,
        finish_reason: null,
      },
    ],
  };

  const contentChunk = {
    ...baseChunk,
    choices: [
      {
        index: 0,
        delta: { content: text },
        logprobs: null,
        finish_reason: null,
      },
    ],
  };

  const finishChunk = {
    ...baseChunk,
    choices: [
      {
        index: 0,
        delta: {},
        logprobs: null,
        finish_reason: 'stop',
      },
    ],
  };

  return [
    `data: ${JSON.stringify(roleChunk)}\n\n`,
    `data: ${JSON.stringify(contentChunk)}\n\n`,
    `data: ${JSON.stringify(finishChunk)}\n\n`,
    `data: [DONE]\n\n`,
  ].join('');
}

// ── Gemini ────────────────────────────────────────────────────────────────

/**
 * Gemini streamGenerateContent SSE format (`?alt=sse` query param required
 * in the upstream request — without it, Gemini returns a JSON array, not SSE).
 *
 *   data: {"candidates":[{"content":{"parts":[{"text":"..."}],"role":"model"},"index":0}],"usageMetadata":{...},"modelVersion":"M","responseId":"R"}
 *
 *   data: {"candidates":[{"content":{"parts":[{"text":""}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{...},"modelVersion":"M","responseId":"R"}
 *
 * No sentinel; the connection closes after the terminal chunk. Two chunks
 * (text-bearing then finishReason-bearing) for SDK robustness — concatenating
 * `parts[0].text` across chunks is the documented contract. `role:"model"`
 * on every chunk matches real-world behavior even though the docs hint it
 * appears once. `usageMetadata` is cumulative.
 */
export function buildGeminiSSE(text: string, model: string): string {
  const responseId = shortId();
  const candidatesTokens = approxTokens(text);

  const textChunk = {
    candidates: [
      {
        content: {
          parts: [{ text }],
          role: 'model',
        },
        index: 0,
      },
    ],
    usageMetadata: {
      promptTokenCount: 0,
      candidatesTokenCount: candidatesTokens,
      totalTokenCount: candidatesTokens,
    },
    modelVersion: model,
    responseId,
  };

  const finishChunk = {
    candidates: [
      {
        content: {
          parts: [{ text: '' }],
          role: 'model',
        },
        finishReason: 'STOP',
        index: 0,
      },
    ],
    usageMetadata: {
      promptTokenCount: 0,
      candidatesTokenCount: candidatesTokens,
      totalTokenCount: candidatesTokens,
    },
    modelVersion: model,
    responseId,
  };

  return [
    `data: ${JSON.stringify(textChunk)}\n\n`,
    `data: ${JSON.stringify(finishChunk)}\n\n`,
  ].join('');
}

// ── Public API ────────────────────────────────────────────────────────────

const PROVIDER_FALLBACK_MODEL: Record<GatewayProviderName, string> = {
  anthropic: 'claude-opus-4-7',
  openai: 'gpt-4o-mini',
  gemini: 'gemini-2.5-flash',
};

const PROVIDER_HEADERS: Record<GatewayProviderName, Record<string, string>> = {
  anthropic: {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  },
  openai: {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, must-revalidate',
    'Connection': 'keep-alive',
  },
  gemini: {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'X-Accel-Buffering': 'no',
  },
};

/**
 * Build a complete provider-shaped SSE stream carrying the intervention text
 * as a single assistant turn. Returns a ReadableStream and the provider's
 * canonical SSE headers.
 *
 * Always 200 — never 4xx/5xx; CAC requires the chat to complete on the
 * user-visible request path regardless of detection outcome.
 */
export function synthesizeProviderStream(
  provider: GatewayProviderName,
  interventionText: string,
  requestBody: Record<string, unknown> | null,
): SynthesizedStream {
  const model = modelFromRequest(requestBody, PROVIDER_FALLBACK_MODEL[provider]);
  let sseText: string;
  switch (provider) {
    case 'anthropic':
      sseText = buildAnthropicSSE(interventionText, model);
      break;
    case 'openai':
      sseText = buildOpenAISSE(interventionText, model);
      break;
    case 'gemini':
      sseText = buildGeminiSSE(interventionText, model);
      break;
  }
  return {
    body: streamFromBytes(TEXT_ENCODER.encode(sseText)),
    headers: { ...PROVIDER_HEADERS[provider] },
  };
}
