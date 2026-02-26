/**
 * Minimal glob matching for tool names.
 * Supports `*` wildcard only (tool names are flat strings, not paths).
 *
 * Examples:
 *   toolMatchesPattern("WebFetch", "WebFetch")           → true
 *   toolMatchesPattern("mcp__browser__navigate", "mcp__browser__*") → true
 *   toolMatchesPattern("Read", "mcp__*")                 → false
 *   toolMatchesPattern("mcp__fs__delete_file", "*delete*") → true
 */
export function toolMatchesPattern(toolName: string, pattern: string): boolean {
  // Exact match fast path
  if (pattern === toolName) return true;
  if (pattern === '*') return true;

  // Escape regex special chars except *, then replace * with .*
  const regex =
    '^' +
    pattern
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*') +
    '$';
  return new RegExp(regex).test(toolName);
}

/**
 * Check if a tool matches any pattern in a list.
 */
export function toolMatchesAny(toolName: string, patterns: string[]): boolean {
  return patterns.some((p) => toolMatchesPattern(toolName, p));
}
