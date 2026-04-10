/**
 * Mnemom Proxy Worker
 *
 * Transparent HTTP proxy for reaching hosts unreachable from Fly.io
 * (e.g. Vercel-hosted sites that block datacenter IPs).
 *
 * Usage: POST/GET https://<worker>/rentahuman.ai/api/v1/bounties
 *   → proxied to https://rentahuman.ai/api/v1/bounties
 *
 * Auth: X-Proxy-Token header (so Authorization passes through to target).
 * Allowed targets: locked to ALLOWED_TARGETS env var.
 */

export interface Env {
  PROXY_TOKEN: string;
  ALLOWED_TARGETS: string;
}

/**
 * Constant-time string comparison using SHA-256 digest comparison.
 * Prevents timing attacks on secret token validation.
 */
async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ]);
  const arrA = new Uint8Array(hashA);
  const arrB = new Uint8Array(hashB);
  if (arrA.length !== arrB.length) return false;
  let result = 0;
  for (let i = 0; i < arrA.length; i++) {
    result |= arrA[i] ^ arrB[i];
  }
  return result === 0;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Proxy-Token',
        },
      });
    }

    // Health check
    const url = new URL(request.url);
    if (url.pathname === '/health') {
      return Response.json({ status: 'ok', service: 'mnemom-proxy' });
    }

    // Auth check — uses X-Proxy-Token so Authorization passes through to target
    // Uses constant-time comparison to prevent timing attacks
    const proxyToken = request.headers.get('X-Proxy-Token');
    if (!env.PROXY_TOKEN || !proxyToken || !(await timingSafeEqual(proxyToken, env.PROXY_TOKEN))) {
      return Response.json({ error: 'unauthorized' }, { status: 401 });
    }

    // Parse target from path: /<host>/<path...>
    // e.g. /rentahuman.ai/api/v1/bounties → https://rentahuman.ai/api/v1/bounties
    const pathWithoutLeadingSlash = url.pathname.slice(1);
    const slashIndex = pathWithoutLeadingSlash.indexOf('/');
    const targetHost = slashIndex === -1
      ? pathWithoutLeadingSlash
      : pathWithoutLeadingSlash.slice(0, slashIndex);
    const targetPath = slashIndex === -1
      ? '/'
      : pathWithoutLeadingSlash.slice(slashIndex);

    if (!targetHost) {
      return Response.json(
        { error: 'missing target host', usage: 'GET /<host>/<path>' },
        { status: 400 },
      );
    }

    // Allowlist check
    const allowed = env.ALLOWED_TARGETS.split(',').map(s => s.trim());
    if (!allowed.includes(targetHost)) {
      return Response.json(
        { error: 'target not allowed', allowed },
        { status: 403 },
      );
    }

    // Build proxied request
    const targetUrl = `https://${targetHost}${targetPath}${url.search}`;

    const proxyHeaders = new Headers(request.headers);
    proxyHeaders.delete('X-Proxy-Token');  // Don't leak proxy token to target
    proxyHeaders.set('Host', targetHost);

    try {
      const resp = await fetch(targetUrl, {
        method: request.method,
        headers: proxyHeaders,
        body: request.body,
      });

      // Pass through response with CORS
      const respHeaders = new Headers(resp.headers);
      respHeaders.set('Access-Control-Allow-Origin', '*');
      respHeaders.set('X-Proxied-Via', 'mnemom-proxy');

      return new Response(resp.body, {
        status: resp.status,
        statusText: resp.statusText,
        headers: respHeaders,
      });
    } catch (err) {
      return Response.json(
        { error: 'proxy_error', message: err instanceof Error ? err.message : 'unknown' },
        { status: 502 },
      );
    }
  },
};
