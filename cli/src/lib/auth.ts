import * as http from "node:http";
import * as crypto from "node:crypto";
import { exec } from "node:child_process";
import { getApiUrl, getWebsiteUrl, getAuthInfo, saveAuthTokens, type AuthTokens } from "./config.js";

/**
 * Get a valid access token, or null if not authenticated.
 *
 * Resolution order:
 *  1. SMOLTBOT_TOKEN environment variable (CI / non-interactive)
 *  2. Stored token from config (auto-refreshes if expired)
 */
export async function getAccessToken(): Promise<string | null> {
  // 1. Env var override (CI / non-interactive)
  const envToken = process.env.SMOLTBOT_TOKEN;
  if (envToken) return envToken;

  // 2. Stored token
  const auth = getAuthInfo();
  if (!auth) return null;

  // Check expiry (with 60s buffer)
  const now = Math.floor(Date.now() / 1000);
  if (auth.expiresAt > now + 60) {
    return auth.accessToken;
  }

  // 3. Auto-refresh
  const refreshed = await refreshAccessToken(auth.refreshToken);
  if (refreshed) return refreshed.accessToken;

  return null;
}

/**
 * Get a valid access token or exit with a helpful message.
 */
export async function requireAccessToken(): Promise<string> {
  const token = await getAccessToken();
  if (!token) {
    console.error("Authentication required. Run `smoltbot login` first.");
    process.exit(1);
  }
  return token;
}

/**
 * Authenticate via browser-based login flow.
 *
 * 1. Start a local HTTP server on a random port
 * 2. Generate a random `state` nonce for CSRF protection
 * 3. Open the browser to the API's CLI login page
 * 4. Wait for the login page to POST tokens back to localhost
 * 5. Verify state, store tokens, and close the server
 */
export async function loginWithBrowser(): Promise<AuthTokens> {
  const state = crypto.randomBytes(16).toString("hex");

  const { port, tokenPromise, close } = await startCallbackServer(state);
  const callbackUrl = `http://127.0.0.1:${port}/callback`;
  const loginUrl = `${getWebsiteUrl()}/login?cli_callback=${encodeURIComponent(callbackUrl)}&state=${encodeURIComponent(state)}`;

  console.log("Opening browser to authenticate...");
  console.log(`If the browser doesn't open, visit:\n  ${loginUrl}\n`);
  openBrowser(loginUrl);

  console.log("Waiting for authentication...");
  try {
    const tokens = await tokenPromise;
    saveAuthTokens(tokens);
    return tokens;
  } finally {
    close();
  }
}

/**
 * Start a local HTTP server that listens for the auth callback POST.
 * Returns the assigned port, a promise that resolves with tokens, and a close function.
 */
async function startCallbackServer(expectedState: string): Promise<{
  port: number;
  tokenPromise: Promise<AuthTokens>;
  close: () => void;
}> {
  let resolveTokens: (tokens: AuthTokens) => void;
  let rejectTokens: (err: Error) => void;
  const tokenPromise = new Promise<AuthTokens>((resolve, reject) => {
    resolveTokens = resolve;
    rejectTokens = reject;
  });

  const server = http.createServer((req, res) => {
    // Handle CORS preflight for the POST from the browser page
    if (req.method === "OPTIONS") {
      res.writeHead(200, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      });
      res.end();
      return;
    }

    if (req.method !== "POST" || req.url !== "/callback") {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
      return;
    }

    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      // Limit body size to prevent abuse
      if (body.length > 1_000_000) {
        req.destroy();
        rejectTokens(new Error("Callback body too large"));
      }
    });

    req.on("end", () => {
      try {
        const data = JSON.parse(body) as {
          access_token: string;
          refresh_token: string;
          expires_in: number;
          user_id: string;
          user_email: string;
          state: string;
        };

        if (data.state !== expectedState) {
          res.writeHead(403, {
            "Content-Type": "text/html",
            "Access-Control-Allow-Origin": "*",
          });
          res.end("<html><body><h2>Authentication failed</h2><p>State mismatch. Please try again.</p></body></html>");
          rejectTokens(new Error("State mismatch — possible CSRF attack"));
          return;
        }

        const tokens: AuthTokens = {
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
          expiresAt: Math.floor(Date.now() / 1000) + data.expires_in,
          userId: data.user_id,
          email: data.user_email,
        };

        res.writeHead(200, {
          "Content-Type": "text/html",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(`<html><body style="font-family:system-ui;text-align:center;padding:60px">
<h2>Authenticated!</h2>
<p>You can close this tab and return to the terminal.</p>
</body></html>`);

        resolveTokens(tokens);
      } catch {
        res.writeHead(400, {
          "Content-Type": "text/html",
          "Access-Control-Allow-Origin": "*",
        });
        res.end("<html><body><h2>Authentication failed</h2><p>Invalid callback data.</p></body></html>");
        rejectTokens(new Error("Invalid callback data"));
      }
    });
  });

  // Listen on port 0, wait for the server to be ready before reading the address
  const port = await new Promise<number>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve((server.address() as { port: number }).port);
    });
  });

  // Auto-timeout after 5 minutes
  const timeout = setTimeout(() => {
    rejectTokens(new Error("Login timed out. Please try again."));
    server.close();
  }, 5 * 60 * 1000);

  return {
    port,
    tokenPromise,
    close: () => {
      clearTimeout(timeout);
      server.close();
    },
  };
}

/**
 * Open a URL in the user's default browser.
 */
function openBrowser(url: string): void {
  const cmd =
    process.platform === "darwin"
      ? "open"
      : process.platform === "win32"
        ? "start"
        : "xdg-open";

  exec(`${cmd} ${JSON.stringify(url)}`);
}

/**
 * Authenticate with email + password via the API auth proxy.
 * Used by --no-browser fallback.
 */
export async function loginWithPassword(
  email: string,
  password: string
): Promise<AuthTokens> {
  const url = `${getApiUrl()}/v1/auth/login`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as any;
    throw new Error(body.error || body.message || "Login failed");
  }

  const data = (await res.json()) as {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    user: { id: string; email: string };
  };

  const tokens: AuthTokens = {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: Math.floor(Date.now() / 1000) + data.expires_in,
    userId: data.user.id,
    email: data.user.email,
  };

  saveAuthTokens(tokens);
  return tokens;
}

/**
 * Refresh an expired access token.
 * Returns new tokens on success, null on failure.
 */
async function refreshAccessToken(
  refreshToken: string
): Promise<AuthTokens | null> {
  const url = `${getApiUrl()}/v1/auth/refresh`;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!res.ok) return null;

    const data = (await res.json()) as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };

    // Preserve existing user info from stored auth
    const existing = getAuthInfo();
    const tokens: AuthTokens = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: Math.floor(Date.now() / 1000) + data.expires_in,
      userId: existing?.userId ?? "",
      email: existing?.email ?? "",
    };

    saveAuthTokens(tokens);
    return tokens;
  } catch {
    return null;
  }
}
