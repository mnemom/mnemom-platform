/**
 * Fetch Interceptor — AI Gateway URL Rewriting
 *
 * The gateway worker constructs Cloudflare AI Gateway URLs like:
 *   ${CF_AI_GATEWAY_URL}/${provider}${path}
 * and sets cf-aig-metadata / cf-aig-authorization headers.
 *
 * For self-hosted deployments there is no CF AI Gateway. This interceptor
 * monkey-patches globalThis.fetch to:
 *   1. Detect requests targeting the sentinel AI Gateway URL
 *   2. Rewrite them to the real upstream provider API
 *   3. Strip CF-specific headers that upstream APIs do not understand
 *   4. Pass all other requests through unchanged
 */

/** Sentinel URL used as CF_AI_GATEWAY_URL in self-hosted mode. */
export const AI_GATEWAY_SENTINEL = 'https://self-hosted-gateway.internal';

/** Provider prefix -> upstream base URL mapping. */
const PROVIDER_URLS: Record<string, string> = {
  anthropic: 'https://api.anthropic.com',
  openai: 'https://api.openai.com',
  gemini: 'https://generativelanguage.googleapis.com',
};

/** Headers injected by the gateway for CF AI Gateway that must be stripped. */
const STRIP_HEADERS = ['cf-aig-metadata', 'cf-aig-authorization'];

/**
 * Install the fetch interceptor. Safe to call multiple times —
 * subsequent calls are no-ops if already installed.
 */
export function installFetchInterceptor(): void {
  // Guard: only install once
  if ((globalThis as any).__fetchInterceptorInstalled) return;

  const originalFetch = globalThis.fetch;

  globalThis.fetch = async function interceptedFetch(
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    const request =
      input instanceof Request ? input : new Request(input, init);
    const url = request.url;

    // Fast path: not targeting the sentinel — use URL parsing for safe comparison
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      return originalFetch(input, init);
    }
    const sentinelOrigin = new URL(AI_GATEWAY_SENTINEL).origin;
    if (parsedUrl.origin !== sentinelOrigin) {
      return originalFetch(input, init);
    }

    // Parse the sentinel URL to extract provider and path
    // Format: https://self-hosted-gateway.internal/{provider}{/api/path}
    const suffix = url.slice(AI_GATEWAY_SENTINEL.length);
    // suffix looks like: /anthropic/v1/messages or /openai/v1/chat/completions
    const match = suffix.match(/^\/(anthropic|openai|gemini)(\/.*)?$/);

    if (!match) {
      console.warn(
        '[FetchInterceptor] Unrecognized AI Gateway path, passing through:',
        suffix,
      );
      return originalFetch(input, init);
    }

    const provider = match[1];
    const apiPath = match[2] ?? '';
    const upstreamBase = PROVIDER_URLS[provider];

    if (!upstreamBase) {
      console.warn(
        `[FetchInterceptor] Unknown provider "${provider}", passing through`,
      );
      return originalFetch(input, init);
    }

    const upstreamUrl = `${upstreamBase}${apiPath}`;

    // Clone headers and strip CF-specific ones
    const headers = new Headers(request.headers);
    for (const header of STRIP_HEADERS) {
      headers.delete(header);
    }

    // Build the rewritten request
    const rewrittenInit: RequestInit = {
      method: request.method,
      headers,
      redirect: request.redirect,
      signal: request.signal,
    };

    // Only attach body for methods that support it
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      rewrittenInit.body = request.body;
      // Preserve duplex for streaming bodies (Node.js 22+)
      (rewrittenInit as any).duplex = 'half';
    }

    return originalFetch(upstreamUrl, rewrittenInit);
  };

  (globalThis as any).__fetchInterceptorInstalled = true;
}

/**
 * Remove the fetch interceptor (useful for tests).
 */
export function uninstallFetchInterceptor(): void {
  // We cannot easily restore the original fetch after patching in a module scope,
  // but we can flag it so it won't re-install.
  (globalThis as any).__fetchInterceptorInstalled = false;
}
