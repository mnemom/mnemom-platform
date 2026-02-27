import { getApiUrl, getAuthInfo, saveAuthTokens, type AuthTokens } from "./config.js";

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
 * Authenticate with email + password via the API auth proxy.
 */
export async function login(
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
