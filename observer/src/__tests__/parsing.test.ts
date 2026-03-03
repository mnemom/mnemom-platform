/**
 * Tests for Observer Parsing & Extraction Functions
 *
 * Covers the untested pure-logic functions:
 * - reconstructResponseForAIP: CF AI Gateway response reconstruction
 * - tryParseResponseJSON: Anthropic JSON response parsing
 * - tryParseOpenAIJSON: OpenAI JSON response parsing
 * - tryParseGeminiJSON: Gemini JSON response parsing
 * - tryParseSSE: Anthropic SSE streaming parsing
 * - tryParseOpenAISSE: OpenAI SSE streaming parsing
 * - extractFromContentBlocks: Content block extraction
 * - extractContext: Multi-provider routing
 * - extractUserQuery: User query extraction (all providers)
 * - buildObserverSystemPrompt: Card-aware system prompt generation
 * - sanitizeJson: Trailing comma cleanup
 * - extractToolsFromTrace: Tool extraction for policy evaluation
 */

import { describe, it, expect } from 'vitest';
import type { AlignmentCard, APTrace } from '@mnemom/agent-alignment-protocol';

// ============================================================================
// Re-implement functions from index.ts for isolated testing
// (Functions are not exported from the worker module)
// ============================================================================

function reconstructResponseForAIP(responseBody: string, provider?: string): string {
  if (provider === 'openai' || provider === 'gemini') {
    return responseBody;
  }

  if (!responseBody) return responseBody;

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(responseBody);
  } catch {
    return responseBody;
  }

  if (Array.isArray(parsed.content)) {
    return responseBody;
  }

  const streamedData = parsed.streamed_data;
  if (!Array.isArray(streamedData) || streamedData.length === 0) {
    return responseBody;
  }

  const sseLines = streamedData.map(
    (chunk: unknown) => `data: ${JSON.stringify(chunk)}`
  );

  return sseLines.join('\n');
}

interface ExtractedContext {
  thinking: string | null;
  toolCalls: Array<{ name: string; input: Record<string, unknown> }>;
  userQuery: string | null;
  responseText: string | null;
}

function extractFromContentBlocks(
  content: Array<Record<string, unknown>>
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } {
  const thinkingBlocks: string[] = [];
  const toolCalls: ExtractedContext['toolCalls'] = [];
  const textBlocks: string[] = [];

  for (const block of content) {
    if (block.type === 'thinking' && block.thinking) {
      thinkingBlocks.push(block.thinking as string);
    } else if (block.type === 'tool_use' && block.name) {
      toolCalls.push({
        name: block.name as string,
        input: (block.input as Record<string, unknown>) || {},
      });
    } else if (block.type === 'text' && block.text) {
      textBlocks.push(block.text as string);
    }
  }

  return {
    thinking: thinkingBlocks.length > 0 ? thinkingBlocks.join('\n\n---\n\n') : null,
    toolCalls,
    responseText: textBlocks.length > 0 ? textBlocks.join('\n\n') : null,
  };
}

function tryParseResponseJSON(
  body: string
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } | null {
  try {
    const response = JSON.parse(body);
    const content = response.content;

    if (Array.isArray(content)) {
      return extractFromContentBlocks(content);
    }

    if (typeof content === 'string' && content.length > 0) {
      return {
        thinking: null,
        toolCalls: [],
        responseText: content.substring(0, 3000),
      };
    }

    if (response.type === 'error' && response.error?.message) {
      return {
        thinking: null,
        toolCalls: [],
        responseText: `Error: ${response.error.message}`,
      };
    }

    return null;
  } catch {
    return null;
  }
}

function tryParseOpenAIJSON(
  body: string
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } | null {
  try {
    const response = JSON.parse(body);
    const choices = response.choices;
    if (!Array.isArray(choices) || choices.length === 0) return null;

    const message = choices[0].message;
    if (!message) return null;

    const responseText = typeof message.content === 'string' && message.content.length > 0
      ? message.content.substring(0, 3000)
      : null;

    const thinking = typeof message.reasoning_content === 'string' && message.reasoning_content.length > 0
      ? message.reasoning_content
      : null;

    const toolCalls: ExtractedContext['toolCalls'] = [];
    if (Array.isArray(message.tool_calls)) {
      for (const tc of message.tool_calls) {
        if (tc.function?.name) {
          let input: Record<string, unknown> = {};
          try {
            input = JSON.parse(tc.function.arguments || '{}');
          } catch { /* */ }
          toolCalls.push({ name: tc.function.name, input });
        }
      }
    }

    return { thinking, toolCalls, responseText };
  } catch {
    return null;
  }
}

function tryParseGeminiJSON(
  body: string
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } | null {
  try {
    const response = JSON.parse(body);
    const candidates = response.candidates;
    if (!Array.isArray(candidates) || candidates.length === 0) return null;

    const content = candidates[0].content;
    if (!content || !Array.isArray(content.parts)) return null;

    const thinkingParts: string[] = [];
    const textParts: string[] = [];
    const toolCalls: ExtractedContext['toolCalls'] = [];

    for (const part of content.parts) {
      if (part.thought === true && typeof part.text === 'string') {
        thinkingParts.push(part.text);
      } else if (typeof part.text === 'string') {
        textParts.push(part.text);
      } else if (part.functionCall) {
        toolCalls.push({
          name: part.functionCall.name,
          input: (part.functionCall.args as Record<string, unknown>) || {},
        });
      }
    }

    return {
      thinking: thinkingParts.length > 0 ? thinkingParts.join('\n\n---\n\n') : null,
      toolCalls,
      responseText: textParts.length > 0 ? textParts.join('\n\n').substring(0, 3000) : null,
    };
  } catch {
    return null;
  }
}

function tryParseSSE(
  body: string
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } | null {
  if (!body.includes('data: ')) return null;

  try {
    const blocks: Map<number, { type: string; content: string; name?: string; input?: string }> = new Map();

    const lines = body.split('\n');
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const jsonStr = line.slice(6).trim();
      if (!jsonStr || jsonStr === '[DONE]') continue;

      let event: Record<string, unknown>;
      try {
        event = JSON.parse(jsonStr);
      } catch {
        continue;
      }

      const eventType = event.type as string;

      if (eventType === 'content_block_start') {
        const index = event.index as number;
        const block = event.content_block as Record<string, unknown>;
        blocks.set(index, {
          type: block.type as string,
          content: '',
          name: block.name as string | undefined,
          input: '',
        });
      } else if (eventType === 'content_block_delta') {
        const index = event.index as number;
        const delta = event.delta as Record<string, unknown>;
        const existing = blocks.get(index);
        if (!existing) continue;

        if (delta.type === 'thinking_delta') {
          existing.content += (delta.thinking as string) || '';
        } else if (delta.type === 'text_delta') {
          existing.content += (delta.text as string) || '';
        } else if (delta.type === 'input_json_delta') {
          existing.input = (existing.input || '') + ((delta.partial_json as string) || '');
        }
      }
    }

    if (blocks.size === 0) return null;

    const contentBlocks = Array.from(blocks.values()).map((b) => {
      if (b.type === 'thinking') {
        return { type: 'thinking', thinking: b.content };
      } else if (b.type === 'tool_use') {
        let input = {};
        try { input = JSON.parse(b.input || '{}'); } catch { /* */ }
        return { type: 'tool_use', name: b.name, input };
      } else {
        return { type: 'text', text: b.content };
      }
    });

    return extractFromContentBlocks(contentBlocks);
  } catch {
    return null;
  }
}

function tryParseOpenAISSE(
  body: string
): { thinking: string | null; toolCalls: ExtractedContext['toolCalls']; responseText: string | null } | null {
  if (!body.includes('data: ')) return null;

  try {
    let contentAccum = '';
    let reasoningAccum = '';
    const toolCallsMap: Map<number, { name: string; arguments: string }> = new Map();

    const lines = body.split('\n');
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const jsonStr = line.slice(6).trim();
      if (!jsonStr || jsonStr === '[DONE]') continue;

      let event: Record<string, unknown>;
      try {
        event = JSON.parse(jsonStr);
      } catch {
        continue;
      }

      const choices = event.choices as Array<Record<string, unknown>> | undefined;
      if (!Array.isArray(choices) || choices.length === 0) continue;

      const delta = choices[0].delta as Record<string, unknown> | undefined;
      if (!delta) continue;

      if (typeof delta.content === 'string') {
        contentAccum += delta.content;
      }
      if (typeof delta.reasoning_content === 'string') {
        reasoningAccum += delta.reasoning_content;
      }

      const deltaToolCalls = delta.tool_calls as Array<Record<string, unknown>> | undefined;
      if (Array.isArray(deltaToolCalls)) {
        for (const dtc of deltaToolCalls) {
          const idx = (dtc.index as number) ?? 0;
          const fn = dtc.function as Record<string, unknown> | undefined;
          if (!fn) continue;
          const existing = toolCallsMap.get(idx);
          if (!existing) {
            toolCallsMap.set(idx, {
              name: (fn.name as string) || '',
              arguments: (fn.arguments as string) || '',
            });
          } else {
            if (fn.name) existing.name += fn.name as string;
            if (fn.arguments) existing.arguments += fn.arguments as string;
          }
        }
      }
    }

    if (contentAccum.length === 0 && reasoningAccum.length === 0 && toolCallsMap.size === 0) {
      return null;
    }

    const toolCalls: ExtractedContext['toolCalls'] = [];
    for (const tc of toolCallsMap.values()) {
      if (tc.name) {
        let input: Record<string, unknown> = {};
        try { input = JSON.parse(tc.arguments || '{}'); } catch { /* */ }
        toolCalls.push({ name: tc.name, input });
      }
    }

    return {
      thinking: reasoningAccum.length > 0 ? reasoningAccum : null,
      toolCalls,
      responseText: contentAccum.length > 0 ? contentAccum.substring(0, 3000) : null,
    };
  } catch {
    return null;
  }
}

function extractContext(requestBody: string, responseBody: string, provider?: string): ExtractedContext {
  const result: ExtractedContext = {
    thinking: null,
    toolCalls: [],
    userQuery: null,
    responseText: null,
  };

  if (responseBody) {
    let parsed = null;
    if (provider === 'openai') {
      parsed = tryParseOpenAIJSON(responseBody) || tryParseOpenAISSE(responseBody);
    } else if (provider === 'gemini') {
      parsed = tryParseGeminiJSON(responseBody);
    } else {
      parsed = tryParseResponseJSON(responseBody) || tryParseSSE(responseBody);
    }
    if (parsed) {
      result.thinking = parsed.thinking;
      result.toolCalls = parsed.toolCalls;
      result.responseText = parsed.responseText;
    }
  }

  if (requestBody) {
    result.userQuery = extractUserQuery(requestBody, provider);
  }

  return result;
}

function extractUserQuery(requestBody: string, provider?: string): string | null {
  try {
    const request = JSON.parse(requestBody);

    if (provider === 'gemini') {
      const contents = request.contents;
      if (!Array.isArray(contents)) return null;

      for (let i = contents.length - 1; i >= 0; i--) {
        const msg = contents[i] as Record<string, unknown>;
        if (msg.role !== 'user') continue;

        const parts = msg.parts as Array<Record<string, unknown>> | undefined;
        if (!Array.isArray(parts)) continue;

        const text = parts
          .filter((p) => typeof p.text === 'string')
          .map((p) => p.text as string)
          .join('\n');
        if (text.length > 0) {
          return text.substring(0, 500);
        }
      }
      return null;
    }

    const messages = request.messages;
    if (!Array.isArray(messages)) return null;

    for (let i = messages.length - 1; i >= 0; i--) {
      const msg = messages[i] as Record<string, unknown>;
      if (msg.role !== 'user') continue;

      const content = msg.content;
      if (typeof content === 'string' && content.length > 0) {
        return content.substring(0, 500);
      }
      if (Array.isArray(content)) {
        const text = content
          .filter((c: Record<string, unknown>) => c.type === 'text')
          .map((c: Record<string, unknown>) => c.text as string)
          .join('\n');
        if (text.length > 0) {
          return text.substring(0, 500);
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

function buildObserverSystemPrompt(card: AlignmentCard | null): string {
  let valuesInstruction: string;

  if (card?.values?.declared && card.values.declared.length > 0) {
    const valueNames = card.values.declared;
    const defs = card.values.definitions;
    const definitions = defs
      ? Object.entries(defs).map(([name, def]) => `  ${name}: ${def.description}`).join('\n')
      : null;
    valuesInstruction = `Pick ONLY from ${JSON.stringify(valueNames)}.`;
    if (definitions) {
      valuesInstruction += `\nValue definitions:\n${definitions}`;
    }
  } else {
    valuesInstruction = `Infer the most relevant values from the interaction. Use concise single-word or snake_case names.`;
  }

  const booleanConditions = card?.autonomy_envelope?.escalation_triggers
    ?.map(t => t.condition)
    .filter(c => /^\w+$/.test(c));

  let contentFlagsSchema = '';
  let contentFlagsRule = '';
  if (booleanConditions && booleanConditions.length > 0) {
    contentFlagsSchema = `\n  "content_flags": {}`;
    contentFlagsRule = `\n- content_flags: For each of ${JSON.stringify(booleanConditions)}, set true if the interaction content matches that condition, false otherwise.`;
  }

  return `Extract the decision structure from this AI agent interaction. Think step-by-step, then return ONLY valid JSON.

Schema:
{
  "alternatives": [{"id": "short_id", "description": "what this option does"}],
  "selected": "id of chosen option",
  "reasoning": "1-2 sentence plain-English summary of what the agent did and why",
  "values_applied": []${contentFlagsSchema ? ',' + contentFlagsSchema : ''}
}

Rules:
- alternatives: Extract from reasoning, or infer 2-3 likely options from the query.
- reasoning: Describe the action concretely (e.g. "Edited config file to fix auth bug"), not abstractly.
- values_applied: ${valuesInstruction}${contentFlagsRule}

Example input:
<user_query>Fix the login timeout bug</user_query>
<reasoning>I need to increase the session timeout. I could edit the config file directly or use the CLI tool. The config file is more reliable since CLI might not persist changes. I'll edit /etc/app/config.yaml.</reasoning>
<tools_used>- edit_file(path, content)</tools_used>

Example output:
{"alternatives":[{"id":"edit_config","description":"Edit config file directly"},{"id":"use_cli","description":"Use CLI tool to update timeout"}],"selected":"edit_config","reasoning":"Edited config file to increase session timeout, choosing direct file edit over CLI for persistence reliability.","values_applied":["accuracy","quality"]}`;
}

function sanitizeJson(text: string): string {
  return text.replace(/,\s*([}\]])/g, '$1');
}

interface ToolReference {
  name: string;
}

function extractToolsFromTrace(trace: APTrace): ToolReference[] {
  const action = trace.action as Record<string, any> | undefined;
  const toolCalls: any[] = action?.tool_calls ?? [];
  return toolCalls
    .map((tc: any) => ({ name: (tc.tool_name || tc.name) as string }))
    .filter((t: ToolReference) => t.name);
}

// ============================================================================
// Tests: reconstructResponseForAIP
// ============================================================================

describe('reconstructResponseForAIP', () => {
  it('should pass through OpenAI responses unchanged', () => {
    const body = '{"choices":[{"message":{"content":"hello"}}]}';
    expect(reconstructResponseForAIP(body, 'openai')).toBe(body);
  });

  it('should pass through Gemini responses unchanged', () => {
    const body = '{"candidates":[{"content":{"parts":[{"text":"hello"}]}}]}';
    expect(reconstructResponseForAIP(body, 'gemini')).toBe(body);
  });

  it('should return empty/falsy bodies as-is', () => {
    expect(reconstructResponseForAIP('')).toBe('');
  });

  it('should return non-JSON responses as-is', () => {
    const rawSSE = 'data: {"type":"message_start"}\ndata: [DONE]';
    expect(reconstructResponseForAIP(rawSSE)).toBe(rawSSE);
  });

  it('should return responses with content array as-is', () => {
    const body = JSON.stringify({
      content: [
        { type: 'thinking', thinking: 'reasoning here' },
        { type: 'text', text: 'response here' },
      ],
    });
    expect(reconstructResponseForAIP(body)).toBe(body);
  });

  it('should return responses without streamed_data as-is', () => {
    const body = JSON.stringify({ content: 'flattened string', model: 'test' });
    expect(reconstructResponseForAIP(body)).toBe(body);
  });

  it('should reconstruct SSE from streamed_data array', () => {
    const chunk1 = { type: 'content_block_start', index: 0, content_block: { type: 'thinking' } };
    const chunk2 = { type: 'content_block_delta', index: 0, delta: { type: 'thinking_delta', thinking: 'hello' } };
    const body = JSON.stringify({
      content: 'flattened text',
      streamed_data: [chunk1, chunk2],
    });

    const result = reconstructResponseForAIP(body);
    expect(result).toContain('data: ');
    expect(result).toContain('content_block_start');
    expect(result).toContain('thinking_delta');

    // Each chunk becomes a "data: " line
    const lines = result.split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatch(/^data: /);
    expect(lines[1]).toMatch(/^data: /);
  });

  it('should handle empty streamed_data array', () => {
    const body = JSON.stringify({ content: 'flat', streamed_data: [] });
    expect(reconstructResponseForAIP(body)).toBe(body);
  });

  it('should default to Anthropic behavior when provider is undefined', () => {
    const chunk = { type: 'content_block_start', index: 0, content_block: { type: 'text' } };
    const body = JSON.stringify({ content: 'flat', streamed_data: [chunk] });
    const result = reconstructResponseForAIP(body);
    expect(result).toContain('data: ');
  });
});

// ============================================================================
// Tests: tryParseResponseJSON (Anthropic)
// ============================================================================

describe('tryParseResponseJSON', () => {
  it('should parse standard Anthropic content block array', () => {
    const body = JSON.stringify({
      content: [
        { type: 'thinking', thinking: 'Let me consider...' },
        { type: 'text', text: 'Here is the answer.' },
      ],
    });
    const result = tryParseResponseJSON(body);
    expect(result).not.toBeNull();
    expect(result!.thinking).toBe('Let me consider...');
    expect(result!.responseText).toBe('Here is the answer.');
    expect(result!.toolCalls).toHaveLength(0);
  });

  it('should parse Anthropic response with tool_use blocks', () => {
    const body = JSON.stringify({
      content: [
        { type: 'thinking', thinking: 'I need to search' },
        { type: 'tool_use', name: 'search', input: { query: 'test' } },
        { type: 'text', text: 'Found results.' },
      ],
    });
    const result = tryParseResponseJSON(body);
    expect(result!.thinking).toBe('I need to search');
    expect(result!.toolCalls).toHaveLength(1);
    expect(result!.toolCalls[0].name).toBe('search');
    expect(result!.toolCalls[0].input).toEqual({ query: 'test' });
    expect(result!.responseText).toBe('Found results.');
  });

  it('should parse CF AI Gateway flattened string content', () => {
    const body = JSON.stringify({ content: 'The answer is 42.' });
    const result = tryParseResponseJSON(body);
    expect(result!.thinking).toBeNull();
    expect(result!.responseText).toBe('The answer is 42.');
  });

  it('should truncate long flattened content at 3000 chars', () => {
    const longContent = 'x'.repeat(5000);
    const body = JSON.stringify({ content: longContent });
    const result = tryParseResponseJSON(body);
    expect(result!.responseText!.length).toBe(3000);
  });

  it('should parse error responses', () => {
    const body = JSON.stringify({
      type: 'error',
      error: { type: 'invalid_request', message: 'Model not found' },
    });
    const result = tryParseResponseJSON(body);
    expect(result!.responseText).toBe('Error: Model not found');
  });

  it('should return null for invalid JSON', () => {
    expect(tryParseResponseJSON('not json')).toBeNull();
  });

  it('should return null for empty content', () => {
    expect(tryParseResponseJSON(JSON.stringify({ content: '' }))).toBeNull();
  });

  it('should return null for missing content', () => {
    expect(tryParseResponseJSON(JSON.stringify({ data: 'something' }))).toBeNull();
  });

  it('should handle multiple thinking blocks', () => {
    const body = JSON.stringify({
      content: [
        { type: 'thinking', thinking: 'First thought' },
        { type: 'thinking', thinking: 'Second thought' },
        { type: 'text', text: 'Answer' },
      ],
    });
    const result = tryParseResponseJSON(body);
    expect(result!.thinking).toBe('First thought\n\n---\n\nSecond thought');
  });
});

// ============================================================================
// Tests: tryParseOpenAIJSON
// ============================================================================

describe('tryParseOpenAIJSON', () => {
  it('should parse standard OpenAI response', () => {
    const body = JSON.stringify({
      choices: [{
        message: {
          content: 'Hello world',
          role: 'assistant',
        },
      }],
    });
    const result = tryParseOpenAIJSON(body);
    expect(result!.responseText).toBe('Hello world');
    expect(result!.thinking).toBeNull();
    expect(result!.toolCalls).toHaveLength(0);
  });

  it('should parse OpenAI response with reasoning_content', () => {
    const body = JSON.stringify({
      choices: [{
        message: {
          content: 'The answer is 42.',
          reasoning_content: 'Let me think step by step...',
        },
      }],
    });
    const result = tryParseOpenAIJSON(body);
    expect(result!.responseText).toBe('The answer is 42.');
    expect(result!.thinking).toBe('Let me think step by step...');
  });

  it('should parse OpenAI response with tool_calls', () => {
    const body = JSON.stringify({
      choices: [{
        message: {
          content: null,
          tool_calls: [
            {
              id: 'call_123',
              type: 'function',
              function: {
                name: 'get_weather',
                arguments: '{"location":"NYC"}',
              },
            },
          ],
        },
      }],
    });
    const result = tryParseOpenAIJSON(body);
    expect(result!.toolCalls).toHaveLength(1);
    expect(result!.toolCalls[0].name).toBe('get_weather');
    expect(result!.toolCalls[0].input).toEqual({ location: 'NYC' });
    expect(result!.responseText).toBeNull();
  });

  it('should handle malformed tool_call arguments gracefully', () => {
    const body = JSON.stringify({
      choices: [{
        message: {
          content: 'text',
          tool_calls: [
            {
              function: {
                name: 'bad_tool',
                arguments: 'not valid json',
              },
            },
          ],
        },
      }],
    });
    const result = tryParseOpenAIJSON(body);
    expect(result!.toolCalls).toHaveLength(1);
    expect(result!.toolCalls[0].name).toBe('bad_tool');
    expect(result!.toolCalls[0].input).toEqual({});
  });

  it('should return null for empty choices array', () => {
    expect(tryParseOpenAIJSON(JSON.stringify({ choices: [] }))).toBeNull();
  });

  it('should return null for missing choices', () => {
    expect(tryParseOpenAIJSON(JSON.stringify({ data: 'test' }))).toBeNull();
  });

  it('should return null for invalid JSON', () => {
    expect(tryParseOpenAIJSON('not json')).toBeNull();
  });

  it('should handle missing message in choice', () => {
    expect(tryParseOpenAIJSON(JSON.stringify({ choices: [{ finish_reason: 'stop' }] }))).toBeNull();
  });
});

// ============================================================================
// Tests: tryParseGeminiJSON
// ============================================================================

describe('tryParseGeminiJSON', () => {
  it('should parse standard Gemini response', () => {
    const body = JSON.stringify({
      candidates: [{
        content: {
          parts: [{ text: 'Hello from Gemini' }],
          role: 'model',
        },
      }],
    });
    const result = tryParseGeminiJSON(body);
    expect(result!.responseText).toBe('Hello from Gemini');
    expect(result!.thinking).toBeNull();
  });

  it('should parse Gemini response with thinking parts', () => {
    const body = JSON.stringify({
      candidates: [{
        content: {
          parts: [
            { text: 'Let me reason about this...', thought: true },
            { text: 'Here is the answer.' },
          ],
        },
      }],
    });
    const result = tryParseGeminiJSON(body);
    expect(result!.thinking).toBe('Let me reason about this...');
    expect(result!.responseText).toBe('Here is the answer.');
  });

  it('should parse Gemini function calls', () => {
    const body = JSON.stringify({
      candidates: [{
        content: {
          parts: [
            {
              functionCall: {
                name: 'search_web',
                args: { query: 'test query' },
              },
            },
          ],
        },
      }],
    });
    const result = tryParseGeminiJSON(body);
    expect(result!.toolCalls).toHaveLength(1);
    expect(result!.toolCalls[0].name).toBe('search_web');
    expect(result!.toolCalls[0].input).toEqual({ query: 'test query' });
    expect(result!.responseText).toBeNull();
  });

  it('should handle multiple thinking parts', () => {
    const body = JSON.stringify({
      candidates: [{
        content: {
          parts: [
            { text: 'Step 1', thought: true },
            { text: 'Step 2', thought: true },
            { text: 'Final answer.' },
          ],
        },
      }],
    });
    const result = tryParseGeminiJSON(body);
    expect(result!.thinking).toBe('Step 1\n\n---\n\nStep 2');
    expect(result!.responseText).toBe('Final answer.');
  });

  it('should return null for empty candidates', () => {
    expect(tryParseGeminiJSON(JSON.stringify({ candidates: [] }))).toBeNull();
  });

  it('should return null for missing parts', () => {
    const body = JSON.stringify({ candidates: [{ content: {} }] });
    expect(tryParseGeminiJSON(body)).toBeNull();
  });

  it('should return null for invalid JSON', () => {
    expect(tryParseGeminiJSON('not json')).toBeNull();
  });

  it('should handle mixed parts (thinking + text + function call)', () => {
    const body = JSON.stringify({
      candidates: [{
        content: {
          parts: [
            { text: 'Reasoning...', thought: true },
            { functionCall: { name: 'lookup', args: { id: 1 } } },
            { text: 'Based on the lookup...' },
          ],
        },
      }],
    });
    const result = tryParseGeminiJSON(body);
    expect(result!.thinking).toBe('Reasoning...');
    expect(result!.toolCalls).toHaveLength(1);
    expect(result!.responseText).toBe('Based on the lookup...');
  });
});

// ============================================================================
// Tests: tryParseSSE (Anthropic streaming)
// ============================================================================

describe('tryParseSSE', () => {
  it('should return null for non-SSE content', () => {
    expect(tryParseSSE('{"content": "not sse"}')).toBeNull();
  });

  it('should parse thinking + text blocks from SSE', () => {
    const sse = [
      `data: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'thinking' } })}`,
      `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'thinking_delta', thinking: 'Let me think...' } })}`,
      `data: ${JSON.stringify({ type: 'content_block_start', index: 1, content_block: { type: 'text' } })}`,
      `data: ${JSON.stringify({ type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: 'Here is my answer.' } })}`,
      'data: [DONE]',
    ].join('\n');

    const result = tryParseSSE(sse);
    expect(result!.thinking).toBe('Let me think...');
    expect(result!.responseText).toBe('Here is my answer.');
    expect(result!.toolCalls).toHaveLength(0);
  });

  it('should accumulate multiple deltas for the same block', () => {
    const sse = [
      `data: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'text' } })}`,
      `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'Hello ' } })}`,
      `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'world!' } })}`,
    ].join('\n');

    const result = tryParseSSE(sse);
    expect(result!.responseText).toBe('Hello world!');
  });

  it('should parse tool_use blocks with streamed JSON input', () => {
    const sse = [
      `data: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'tool_use', name: 'search' } })}`,
      `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"query":' } })}`,
      `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '"test"}' } })}`,
    ].join('\n');

    const result = tryParseSSE(sse);
    expect(result!.toolCalls).toHaveLength(1);
    expect(result!.toolCalls[0].name).toBe('search');
    expect(result!.toolCalls[0].input).toEqual({ query: 'test' });
  });

  it('should skip invalid JSON in SSE lines', () => {
    const sse = [
      `data: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'text' } })}`,
      'data: {invalid json here',
      `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'valid' } })}`,
    ].join('\n');

    const result = tryParseSSE(sse);
    expect(result!.responseText).toBe('valid');
  });

  it('should ignore non-data lines', () => {
    const sse = [
      'event: message_start',
      `data: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'text' } })}`,
      '',
      `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'hi' } })}`,
    ].join('\n');

    const result = tryParseSSE(sse);
    expect(result!.responseText).toBe('hi');
  });

  it('should return null when no blocks are found', () => {
    const sse = 'data: {"type":"message_start"}\ndata: [DONE]';
    expect(tryParseSSE(sse)).toBeNull();
  });

  it('should handle deltas for unknown block indices', () => {
    const sse = [
      `data: ${JSON.stringify({ type: 'content_block_delta', index: 99, delta: { type: 'text_delta', text: 'orphan' } })}`,
    ].join('\n');

    // No blocks created, so this should return null
    expect(tryParseSSE(sse)).toBeNull();
  });
});

// ============================================================================
// Tests: tryParseOpenAISSE
// ============================================================================

describe('tryParseOpenAISSE', () => {
  it('should return null for non-SSE content', () => {
    expect(tryParseOpenAISSE('{"choices":[{"message":{}}]}')).toBeNull();
  });

  it('should parse content from OpenAI SSE chunks', () => {
    const sse = [
      `data: ${JSON.stringify({ choices: [{ delta: { content: 'Hello ' } }] })}`,
      `data: ${JSON.stringify({ choices: [{ delta: { content: 'world!' } }] })}`,
      'data: [DONE]',
    ].join('\n');

    const result = tryParseOpenAISSE(sse);
    expect(result!.responseText).toBe('Hello world!');
    expect(result!.thinking).toBeNull();
  });

  it('should parse reasoning_content from OpenAI SSE', () => {
    const sse = [
      `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: 'Step 1. ' } }] })}`,
      `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: 'Step 2.' } }] })}`,
      `data: ${JSON.stringify({ choices: [{ delta: { content: 'Answer: 42' } }] })}`,
    ].join('\n');

    const result = tryParseOpenAISSE(sse);
    expect(result!.thinking).toBe('Step 1. Step 2.');
    expect(result!.responseText).toBe('Answer: 42');
  });

  it('should parse streamed tool calls', () => {
    const sse = [
      `data: ${JSON.stringify({ choices: [{ delta: { tool_calls: [{ index: 0, function: { name: 'get_weather', arguments: '' } }] } }] })}`,
      `data: ${JSON.stringify({ choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: '{"loc' } }] } }] })}`,
      `data: ${JSON.stringify({ choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: 'ation":"NYC"}' } }] } }] })}`,
    ].join('\n');

    const result = tryParseOpenAISSE(sse);
    expect(result!.toolCalls).toHaveLength(1);
    expect(result!.toolCalls[0].name).toBe('get_weather');
    expect(result!.toolCalls[0].input).toEqual({ location: 'NYC' });
  });

  it('should handle multiple concurrent tool calls', () => {
    const sse = [
      `data: ${JSON.stringify({ choices: [{ delta: { tool_calls: [{ index: 0, function: { name: 'tool_a', arguments: '{}' } }] } }] })}`,
      `data: ${JSON.stringify({ choices: [{ delta: { tool_calls: [{ index: 1, function: { name: 'tool_b', arguments: '{}' } }] } }] })}`,
    ].join('\n');

    const result = tryParseOpenAISSE(sse);
    expect(result!.toolCalls).toHaveLength(2);
    expect(result!.toolCalls[0].name).toBe('tool_a');
    expect(result!.toolCalls[1].name).toBe('tool_b');
  });

  it('should return null when no content is accumulated', () => {
    const sse = [
      `data: ${JSON.stringify({ choices: [{ delta: {} }] })}`,
      'data: [DONE]',
    ].join('\n');

    expect(tryParseOpenAISSE(sse)).toBeNull();
  });

  it('should truncate long content at 3000 chars', () => {
    const longContent = 'a'.repeat(4000);
    const sse = `data: ${JSON.stringify({ choices: [{ delta: { content: longContent } }] })}`;
    const result = tryParseOpenAISSE(sse);
    expect(result!.responseText!.length).toBe(3000);
  });
});

// ============================================================================
// Tests: extractFromContentBlocks
// ============================================================================

describe('extractFromContentBlocks', () => {
  it('should return null thinking/text when no matching blocks', () => {
    const result = extractFromContentBlocks([]);
    expect(result.thinking).toBeNull();
    expect(result.toolCalls).toHaveLength(0);
    expect(result.responseText).toBeNull();
  });

  it('should extract all block types', () => {
    const blocks = [
      { type: 'thinking', thinking: 'reasoning' },
      { type: 'tool_use', name: 'search', input: { q: 'test' } },
      { type: 'text', text: 'response' },
    ];
    const result = extractFromContentBlocks(blocks);
    expect(result.thinking).toBe('reasoning');
    expect(result.toolCalls).toEqual([{ name: 'search', input: { q: 'test' } }]);
    expect(result.responseText).toBe('response');
  });

  it('should skip blocks with missing content', () => {
    const blocks = [
      { type: 'thinking' }, // no thinking field
      { type: 'tool_use' }, // no name field
      { type: 'text' }, // no text field
    ];
    const result = extractFromContentBlocks(blocks);
    expect(result.thinking).toBeNull();
    expect(result.toolCalls).toHaveLength(0);
    expect(result.responseText).toBeNull();
  });

  it('should concatenate multiple text blocks with separator', () => {
    const blocks = [
      { type: 'text', text: 'Part 1' },
      { type: 'text', text: 'Part 2' },
    ];
    const result = extractFromContentBlocks(blocks);
    expect(result.responseText).toBe('Part 1\n\nPart 2');
  });

  it('should default to empty input for tool_use without input', () => {
    const blocks = [
      { type: 'tool_use', name: 'my_tool' },
    ];
    const result = extractFromContentBlocks(blocks);
    expect(result.toolCalls[0].input).toEqual({});
  });
});

// ============================================================================
// Tests: extractContext (multi-provider routing)
// ============================================================================

describe('extractContext', () => {
  it('should route Anthropic responses to tryParseResponseJSON', () => {
    const response = JSON.stringify({
      content: [
        { type: 'thinking', thinking: 'anthropic thinking' },
        { type: 'text', text: 'anthropic answer' },
      ],
    });
    const request = JSON.stringify({
      messages: [{ role: 'user', content: 'Hello Anthropic' }],
    });

    const result = extractContext(request, response);
    expect(result.thinking).toBe('anthropic thinking');
    expect(result.responseText).toBe('anthropic answer');
    expect(result.userQuery).toBe('Hello Anthropic');
  });

  it('should route OpenAI responses to tryParseOpenAIJSON', () => {
    const response = JSON.stringify({
      choices: [{
        message: {
          content: 'openai answer',
          reasoning_content: 'openai thinking',
        },
      }],
    });
    const request = JSON.stringify({
      messages: [{ role: 'user', content: 'Hello OpenAI' }],
    });

    const result = extractContext(request, response, 'openai');
    expect(result.thinking).toBe('openai thinking');
    expect(result.responseText).toBe('openai answer');
    expect(result.userQuery).toBe('Hello OpenAI');
  });

  it('should route Gemini responses to tryParseGeminiJSON', () => {
    const response = JSON.stringify({
      candidates: [{
        content: {
          parts: [
            { text: 'gemini thinking', thought: true },
            { text: 'gemini answer' },
          ],
        },
      }],
    });
    const request = JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: 'Hello Gemini' }] }],
    });

    const result = extractContext(request, response, 'gemini');
    expect(result.thinking).toBe('gemini thinking');
    expect(result.responseText).toBe('gemini answer');
    expect(result.userQuery).toBe('Hello Gemini');
  });

  it('should fall back to SSE parsing for Anthropic when JSON fails', () => {
    const sse = [
      `data: ${JSON.stringify({ type: 'content_block_start', index: 0, content_block: { type: 'text' } })}`,
      `data: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'SSE answer' } })}`,
    ].join('\n');

    const result = extractContext('', sse);
    expect(result.responseText).toBe('SSE answer');
  });

  it('should fall back to SSE parsing for OpenAI when JSON fails', () => {
    const sse = [
      `data: ${JSON.stringify({ choices: [{ delta: { content: 'SSE openai' } }] })}`,
    ].join('\n');

    const result = extractContext('', sse, 'openai');
    expect(result.responseText).toBe('SSE openai');
  });

  it('should handle empty response and request bodies', () => {
    const result = extractContext('', '');
    expect(result.thinking).toBeNull();
    expect(result.toolCalls).toHaveLength(0);
    expect(result.userQuery).toBeNull();
    expect(result.responseText).toBeNull();
  });
});

// ============================================================================
// Tests: extractUserQuery
// ============================================================================

describe('extractUserQuery', () => {
  it('should extract string content from Anthropic messages', () => {
    const request = JSON.stringify({
      messages: [
        { role: 'user', content: 'What is 2+2?' },
      ],
    });
    expect(extractUserQuery(request)).toBe('What is 2+2?');
  });

  it('should extract text from Anthropic array content', () => {
    const request = JSON.stringify({
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'First part' },
            { type: 'text', text: 'Second part' },
          ],
        },
      ],
    });
    expect(extractUserQuery(request)).toBe('First part\nSecond part');
  });

  it('should find the LAST user message', () => {
    const request = JSON.stringify({
      messages: [
        { role: 'user', content: 'First question' },
        { role: 'assistant', content: 'Response' },
        { role: 'user', content: 'Follow-up question' },
      ],
    });
    expect(extractUserQuery(request)).toBe('Follow-up question');
  });

  it('should skip tool_result-only user messages', () => {
    const request = JSON.stringify({
      messages: [
        { role: 'user', content: 'Original question' },
        { role: 'assistant', content: 'Let me search...' },
        {
          role: 'user',
          content: [
            { type: 'tool_result', tool_use_id: '123', content: 'result data' },
          ],
        },
      ],
    });
    expect(extractUserQuery(request)).toBe('Original question');
  });

  it('should extract from Gemini contents format', () => {
    const request = JSON.stringify({
      contents: [
        { role: 'user', parts: [{ text: 'Gemini question' }] },
      ],
    });
    expect(extractUserQuery(request, 'gemini')).toBe('Gemini question');
  });

  it('should find last user in Gemini multi-turn', () => {
    const request = JSON.stringify({
      contents: [
        { role: 'user', parts: [{ text: 'First' }] },
        { role: 'model', parts: [{ text: 'Response' }] },
        { role: 'user', parts: [{ text: 'Second' }] },
      ],
    });
    expect(extractUserQuery(request, 'gemini')).toBe('Second');
  });

  it('should join multiple Gemini text parts', () => {
    const request = JSON.stringify({
      contents: [
        { role: 'user', parts: [{ text: 'Part A' }, { text: 'Part B' }] },
      ],
    });
    expect(extractUserQuery(request, 'gemini')).toBe('Part A\nPart B');
  });

  it('should truncate at 500 characters', () => {
    const longQuery = 'q'.repeat(600);
    const request = JSON.stringify({
      messages: [{ role: 'user', content: longQuery }],
    });
    expect(extractUserQuery(request)!.length).toBe(500);
  });

  it('should return null for invalid JSON', () => {
    expect(extractUserQuery('not json')).toBeNull();
  });

  it('should return null for missing messages array', () => {
    expect(extractUserQuery(JSON.stringify({ model: 'test' }))).toBeNull();
  });

  it('should return null when no user messages exist', () => {
    const request = JSON.stringify({
      messages: [{ role: 'assistant', content: 'I am an AI' }],
    });
    expect(extractUserQuery(request)).toBeNull();
  });

  it('should handle OpenAI format (same as Anthropic messages)', () => {
    const request = JSON.stringify({
      messages: [{ role: 'user', content: 'OpenAI question' }],
    });
    expect(extractUserQuery(request, 'openai')).toBe('OpenAI question');
  });
});

// ============================================================================
// Tests: buildObserverSystemPrompt
// ============================================================================

describe('buildObserverSystemPrompt', () => {
  it('should generate prompt with inferred values when no card', () => {
    const prompt = buildObserverSystemPrompt(null);
    expect(prompt).toContain('Infer the most relevant values');
    expect(prompt).toContain('Extract the decision structure');
    expect(prompt).not.toContain('content_flags');
  });

  it('should generate prompt with card-declared values', () => {
    const card = {
      aap_version: '1.0',
      card_id: 'test',
      agent_id: 'test',
      issued_at: '2024-01-01',
      principal: { type: 'human', relationship: 'delegated_authority' },
      values: { declared: ['transparency', 'accuracy'] },
      autonomy_envelope: {
        bounded_actions: [],
        escalation_triggers: [],
      },
      audit_commitment: { retention_days: 90, queryable: true },
    } as AlignmentCard;

    const prompt = buildObserverSystemPrompt(card);
    expect(prompt).toContain('Pick ONLY from');
    expect(prompt).toContain('transparency');
    expect(prompt).toContain('accuracy');
  });

  it('should include value definitions from card', () => {
    const card = {
      aap_version: '1.0',
      card_id: 'test',
      agent_id: 'test',
      issued_at: '2024-01-01',
      principal: { type: 'human', relationship: 'delegated_authority' },
      values: {
        declared: ['safety'],
        definitions: {
          safety: { name: 'Safety', description: 'Prioritize user well-being', priority: 1 },
        },
      },
      autonomy_envelope: {
        bounded_actions: [],
        escalation_triggers: [],
      },
      audit_commitment: { retention_days: 90, queryable: true },
    } as AlignmentCard;

    const prompt = buildObserverSystemPrompt(card);
    expect(prompt).toContain('Value definitions:');
    expect(prompt).toContain('Prioritize user well-being');
  });

  it('should add content_flags for boolean escalation triggers', () => {
    const card = {
      aap_version: '1.0',
      card_id: 'test',
      agent_id: 'test',
      issued_at: '2024-01-01',
      principal: { type: 'human', relationship: 'delegated_authority' },
      values: { declared: ['safety'] },
      autonomy_envelope: {
        bounded_actions: [],
        escalation_triggers: [
          { condition: 'pii_detected', action: 'escalate', reason: 'PII' },
          { condition: 'nsfw_content', action: 'escalate', reason: 'NSFW' },
        ],
      },
      audit_commitment: { retention_days: 90, queryable: true },
    } as AlignmentCard;

    const prompt = buildObserverSystemPrompt(card);
    expect(prompt).toContain('content_flags');
    expect(prompt).toContain('pii_detected');
    expect(prompt).toContain('nsfw_content');
  });

  it('should NOT add content_flags for non-boolean escalation conditions', () => {
    const card = {
      aap_version: '1.0',
      card_id: 'test',
      agent_id: 'test',
      issued_at: '2024-01-01',
      principal: { type: 'human', relationship: 'delegated_authority' },
      values: { declared: ['safety'] },
      autonomy_envelope: {
        bounded_actions: [],
        escalation_triggers: [
          { condition: 'uncertainty > 0.8', action: 'escalate', reason: 'High uncertainty' },
        ],
      },
      audit_commitment: { retention_days: 90, queryable: true },
    } as AlignmentCard;

    const prompt = buildObserverSystemPrompt(card);
    expect(prompt).not.toContain('content_flags');
  });

  it('should handle empty declared values', () => {
    const card = {
      aap_version: '1.0',
      card_id: 'test',
      agent_id: 'test',
      issued_at: '2024-01-01',
      principal: { type: 'human', relationship: 'delegated_authority' },
      values: { declared: [] },
      autonomy_envelope: {
        bounded_actions: [],
        escalation_triggers: [],
      },
      audit_commitment: { retention_days: 90, queryable: true },
    } as AlignmentCard;

    const prompt = buildObserverSystemPrompt(card);
    expect(prompt).toContain('Infer the most relevant values');
  });
});

// ============================================================================
// Tests: sanitizeJson
// ============================================================================

describe('sanitizeJson', () => {
  it('should remove trailing comma before }', () => {
    expect(sanitizeJson('{"a": 1,}')).toBe('{"a": 1}');
  });

  it('should remove trailing comma before ]', () => {
    expect(sanitizeJson('[1, 2, 3,]')).toBe('[1, 2, 3]');
  });

  it('should handle trailing comma with whitespace', () => {
    expect(sanitizeJson('{"a": 1 , }')).toBe('{"a": 1 }');
  });

  it('should handle multiple trailing commas', () => {
    expect(sanitizeJson('{"a": [1, 2,], "b": {"c": 3,}}')).toBe('{"a": [1, 2], "b": {"c": 3}}');
  });

  it('should not modify valid JSON', () => {
    const valid = '{"a": 1, "b": [1, 2, 3]}';
    expect(sanitizeJson(valid)).toBe(valid);
  });

  it('should handle trailing comma with newlines', () => {
    const input = `{
  "a": 1,
  "b": 2,
}`;
    const result = sanitizeJson(input);
    // Regex replaces ",\n}" with "}" — whitespace between comma and brace is consumed
    expect(JSON.parse(result)).toEqual({ a: 1, b: 2 });
  });
});

// ============================================================================
// Tests: extractToolsFromTrace
// ============================================================================

describe('extractToolsFromTrace', () => {
  it('should return empty array when action has no tool_calls', () => {
    const trace = {
      trace_id: 'tr-test',
      agent_id: 'agent-1',
      card_id: 'card-1',
      timestamp: '2024-01-01T00:00:00Z',
      action: { type: 'execute', name: 'inference', category: 'bounded' },
      decision: {
        alternatives_considered: [],
        selected: 'a',
        selection_reasoning: 'reason',
        values_applied: [],
      },
    } as APTrace;

    expect(extractToolsFromTrace(trace)).toEqual([]);
  });

  it('should extract tools from tool_calls with tool_name field', () => {
    const trace = {
      trace_id: 'tr-test',
      agent_id: 'agent-1',
      card_id: 'card-1',
      timestamp: '2024-01-01T00:00:00Z',
      action: {
        type: 'execute',
        name: 'tools',
        category: 'bounded',
        tool_calls: [
          { tool_name: 'search' },
          { tool_name: 'edit_file' },
        ],
      },
      decision: {
        alternatives_considered: [],
        selected: 'a',
        selection_reasoning: 'reason',
        values_applied: [],
      },
    } as unknown as APTrace;

    const tools = extractToolsFromTrace(trace);
    expect(tools).toHaveLength(2);
    expect(tools[0].name).toBe('search');
    expect(tools[1].name).toBe('edit_file');
  });

  it('should extract tools using name field as fallback', () => {
    const trace = {
      trace_id: 'tr-test',
      agent_id: 'agent-1',
      card_id: 'card-1',
      timestamp: '2024-01-01T00:00:00Z',
      action: {
        type: 'execute',
        name: 'tools',
        category: 'bounded',
        tool_calls: [{ name: 'my_tool' }],
      },
      decision: {
        alternatives_considered: [],
        selected: 'a',
        selection_reasoning: 'reason',
        values_applied: [],
      },
    } as unknown as APTrace;

    const tools = extractToolsFromTrace(trace);
    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe('my_tool');
  });

  it('should filter out tool_calls without names', () => {
    const trace = {
      trace_id: 'tr-test',
      agent_id: 'agent-1',
      card_id: 'card-1',
      timestamp: '2024-01-01T00:00:00Z',
      action: {
        type: 'execute',
        name: 'tools',
        category: 'bounded',
        tool_calls: [
          { tool_name: 'valid' },
          { other: 'no name' },
        ],
      },
      decision: {
        alternatives_considered: [],
        selected: 'a',
        selection_reasoning: 'reason',
        values_applied: [],
      },
    } as unknown as APTrace;

    const tools = extractToolsFromTrace(trace);
    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe('valid');
  });
});
