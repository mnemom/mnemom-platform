/**
 * Auth credential management.
 *
 * Stores auth tokens in ~/.mnemom/auth.json (UC-9: no more config.json).
 * License JWTs are stored alongside auth tokens.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as http from "node:http";
import * as crypto from "node:crypto";
import { exec } from "node:child_process";
import { getApiUrl, getWebsiteUrl, MNEMOM_DIR } from "./config.js";

// ============================================================================
// Auth Store (persisted to ~/.mnemom/auth.json)
// ============================================================================

const AUTH_FILE = path.join(MNEMOM_DIR, "auth.json");

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;  // unix seconds
  userId: string;
  email: string;
}

export interface AuthStore {
  auth?: AuthTokens;
  licenseJwt?: string;
}

function loadAuthStore(): AuthStore | null {
  try {
    if (!fs.existsSync(AUTH_FILE)) return null;
    const content = fs.readFileSync(AUTH_FILE, "utf-8");
    return JSON.parse(content) as AuthStore;
  } catch {
    return null;
  }
}

function saveAuthStore(store: AuthStore): void {
  if (!fs.existsSync(MNEMOM_DIR)) {
    fs.mkdirSync(MNEMOM_DIR, { recursive: true });
  }
  const resolvedPath = path.resolve(AUTH_FILE);
  const sanitized = JSON.parse(JSON.stringify(store)) as AuthStore;
  const tmpFile = `${resolvedPath}.${process.pid}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(sanitized, null, 2));
  fs.renameSync(tmpFile, resolvedPath);
}

// ============================================================================
// Auth token helpers
// ============================================================================

export function saveAuthTokens(tokens: AuthTokens): void {
  const store = loadAuthStore() ?? {};
  store.auth = tokens;
  saveAuthStore(store);
}

export function clearAuthTokens(): void {
  const store = loadAuthStore();
  if (!store) return;
  delete store.auth;
  saveAuthStore(store);
}

export function getAuthInfo(): AuthTokens | null {
  return loadAuthStore()?.auth ?? null;
}

// ============================================================================
// License JWT helpers
// ============================================================================

export function saveLicenseJwt(jwt: string): void {
  const store = loadAuthStore() ?? {};
  store.licenseJwt = jwt;
  saveAuthStore(store);
}

export function clearLicenseJwt(): void {
  const store = loadAuthStore();
  if (!store) return;
  delete store.licenseJwt;
  saveAuthStore(store);
}

export function getLicenseJwt(): string | null {
  return loadAuthStore()?.licenseJwt ?? null;
}

// ============================================================================
// Auth Credential Types
// ============================================================================

export type AuthCredential =
  | { type: "jwt"; token: string }
  | { type: "api-key"; key: string }
  | { type: "none" };

/** Sanitize file-sourced data before use in outbound HTTP requests. */
function sanitizeForHttp(data: string): string {
  return String(data).trim();
}

/**
 * Get a valid access token, or null if not authenticated.
 *
 * Resolution order:
 *  1. MNEMOM_TOKEN environment variable (CI / non-interactive)
 *  2. Stored token from auth store (auto-refreshes if expired)
 */
export async function getAccessToken(): Promise<string | null> {
  const envToken = process.env.MNEMOM_TOKEN;
  if (envToken) return envToken;

  const auth = getAuthInfo();
  if (!auth) return null;

  // Check expiry (with 60s buffer)
  const now = Math.floor(Date.now() / 1000);
  if (auth.expiresAt > now + 60) {
    return auth.accessToken;
  }

  // Auto-refresh
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
    console.error("Authentication required. Run `mnemom login` first.");
    process.exit(1);
  }
  return token;
}

/**
 * Get the Mnemom API key from env var.
 */
export function getMnemomApiKey(): string | null {
  return process.env.MNEMOM_API_KEY ?? null;
}

/**
 * Resolve the best available auth credential.
 *
 * Resolution order:
 *  1. JWT (MNEMOM_TOKEN env or stored token with auto-refresh)
 *  2. API key (MNEMOM_API_KEY env)
 *  3. None
 */
export async function resolveAuth(): Promise<AuthCredential> {
  const jwt = await getAccessToken();
  if (jwt) return { type: "jwt", token: jwt };

  const apiKey = getMnemomApiKey();
  if (apiKey) return { type: "api-key", key: apiKey };

  return { type: "none" };
}

/**
 * Require authentication (JWT or API key) or exit with a helpful message.
 */
export async function requireAuth(): Promise<AuthCredential & { type: "jwt" | "api-key" }> {
  const cred = await resolveAuth();
  if (cred.type === "none") {
    console.error("Authentication required. Run `mnemom login` or set MNEMOM_API_KEY.");
    process.exit(1);
  }
  return cred as AuthCredential & { type: "jwt" | "api-key" };
}

/**
 * Check if the user is logged in (has any credential).
 */
export async function isLoggedIn(): Promise<boolean> {
  const cred = await resolveAuth();
  return cred.type !== "none";
}

// ============================================================================
// Browser login flow
// ============================================================================

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
          res.end("<html><body><h2>Authentication failed</h2><p>State mismatch.</p></body></html>");
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

  const port = await new Promise<number>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve((server.address() as { port: number }).port);
    });
  });

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

function openBrowser(url: string): void {
  const cmd =
    process.platform === "darwin"
      ? "open"
      : process.platform === "win32"
        ? "start"
        : "xdg-open";
  exec(`${cmd} ${JSON.stringify(url)}`);
}

// ============================================================================
// Password login
// ============================================================================

export async function loginWithPassword(
  email: string,
  password: string,
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

// ============================================================================
// Token refresh
// ============================================================================

async function refreshAccessToken(
  refreshToken: string,
): Promise<AuthTokens | null> {
  if (!refreshToken || typeof refreshToken !== "string") {
    return null;
  }
  const url = new URL(`${getApiUrl()}/v1/auth/refresh`).href;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: sanitizeForHttp(JSON.stringify({ refresh_token: String(refreshToken) })),
    });

    if (!res.ok) return null;

    const data = (await res.json()) as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };

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
