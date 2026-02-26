import { describe, it, expect } from 'vitest';
import { toolMatchesPattern, toolMatchesAny } from '../src/glob';

describe('toolMatchesPattern', () => {
  it('matches exact tool names', () => {
    expect(toolMatchesPattern('Read', 'Read')).toBe(true);
    expect(toolMatchesPattern('Write', 'Write')).toBe(true);
    expect(toolMatchesPattern('WebFetch', 'WebFetch')).toBe(true);
  });

  it('does not match different exact names', () => {
    expect(toolMatchesPattern('Read', 'Write')).toBe(false);
    expect(toolMatchesPattern('WebFetch', 'WebSearch')).toBe(false);
  });

  it('matches wildcard at end', () => {
    expect(toolMatchesPattern('mcp__browser__navigate', 'mcp__browser__*')).toBe(true);
    expect(toolMatchesPattern('mcp__browser__click', 'mcp__browser__*')).toBe(true);
    expect(toolMatchesPattern('mcp__filesystem__read', 'mcp__browser__*')).toBe(false);
  });

  it('matches wildcard at start', () => {
    expect(toolMatchesPattern('mcp__fs__delete_file', '*delete*')).toBe(true);
    expect(toolMatchesPattern('delete_everything', '*delete*')).toBe(true);
    expect(toolMatchesPattern('Read', '*delete*')).toBe(false);
  });

  it('matches wildcard in middle', () => {
    expect(toolMatchesPattern('mcp__chrome__evaluate_script', 'mcp__*__evaluate_script')).toBe(true);
    expect(toolMatchesPattern('mcp__node__evaluate_script', 'mcp__*__evaluate_script')).toBe(true);
    expect(toolMatchesPattern('mcp__chrome__navigate', 'mcp__*__evaluate_script')).toBe(false);
  });

  it('matches catch-all wildcard', () => {
    expect(toolMatchesPattern('anything', '*')).toBe(true);
    expect(toolMatchesPattern('', '*')).toBe(true);
  });

  it('handles multiple wildcards', () => {
    expect(toolMatchesPattern('mcp__fs__execute_cmd', 'mcp__*__execute*')).toBe(true);
    expect(toolMatchesPattern('mcp__shell__execute_script', 'mcp__*__execute*')).toBe(true);
    expect(toolMatchesPattern('mcp__fs__read_file', 'mcp__*__execute*')).toBe(false);
  });

  it('escapes regex special characters in patterns', () => {
    expect(toolMatchesPattern('file.txt', 'file.txt')).toBe(true);
    expect(toolMatchesPattern('filextxt', 'file.txt')).toBe(false);
    expect(toolMatchesPattern('tool(1)', 'tool(1)')).toBe(true);
  });

  it('is case-sensitive', () => {
    expect(toolMatchesPattern('read', 'Read')).toBe(false);
    expect(toolMatchesPattern('READ', 'Read')).toBe(false);
  });
});

describe('toolMatchesAny', () => {
  it('returns true if tool matches any pattern', () => {
    expect(toolMatchesAny('WebFetch', ['Read', 'WebFetch', 'Write'])).toBe(true);
    expect(toolMatchesAny('mcp__browser__click', ['mcp__browser__*', 'Read'])).toBe(true);
  });

  it('returns false if tool matches no pattern', () => {
    expect(toolMatchesAny('Bash', ['Read', 'Write', 'WebFetch'])).toBe(false);
    expect(toolMatchesAny('Read', ['mcp__*'])).toBe(false);
  });

  it('handles empty patterns list', () => {
    expect(toolMatchesAny('Read', [])).toBe(false);
  });
});
