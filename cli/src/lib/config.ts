/**
 * Environment resolution and URL constants.
 *
 * UC-9 simplification: this module no longer manages a config file.
 * Auth tokens live in auth.ts → ~/.mnemom/auth.json.
 * Agent resolution is server-side via api.ts → resolveAgentId().
 */

import * as path from "node:path";
import * as os from "node:os";

/** Base directory for mnemom CLI state (auth tokens, caches). */
export const MNEMOM_DIR = path.join(os.homedir(), ".mnemom");

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

export type Environment = "production" | "staging" | "local";

const API_URLS: Record<Environment, string> = {
  production: "https://api.mnemom.ai",
  staging: "https://api-staging.mnemom.ai",
  local: "http://localhost:8787",
};

const GATEWAY_URLS: Record<Environment, string> = {
  production: "https://gateway.mnemom.ai",
  staging: "https://gateway-staging.mnemom.ai",
  local: "http://localhost:8787",
};

const WEBSITE_URLS: Record<Environment, string> = {
  production: "https://www.mnemom.ai",
  staging: "https://staging.mnemom.ai",
  local: "http://localhost:5173",
};

/**
 * Resolve the active environment from MNEMOM_ENV.
 * Defaults to production.
 */
export function getEnvironment(): Environment {
  const env = process.env.MNEMOM_ENV;
  if (env === "staging" || env === "local") return env;
  return "production";
}

export function getApiUrl(): string {
  return API_URLS[getEnvironment()];
}

export function getGatewayUrl(): string {
  return GATEWAY_URLS[getEnvironment()];
}

export function getWebsiteUrl(): string {
  return WEBSITE_URLS[getEnvironment()];
}
