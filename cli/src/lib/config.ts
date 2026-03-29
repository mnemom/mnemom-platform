import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import type { AgentListItem } from "./api.js";

export const CONFIG_DIR = path.join(os.homedir(), ".smoltbot");
export const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");

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
 * Resolve the active environment.
 *
 * Resolution order:
 *  1. `SMOLTBOT_ENV` environment variable
 *  2. Defaults to `production`
 */
export function getEnvironment(): Environment {
  const env = process.env.SMOLTBOT_ENV;
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

// ---------------------------------------------------------------------------
// V1 config (legacy single-agent format)
// ---------------------------------------------------------------------------

export interface ConfigV1 {
  agentId: string;
  email?: string;
  gateway?: string;
  openclawConfigured?: boolean;
  providers?: string[];  // e.g. ['anthropic', 'openai'] — standalone mode
  mnemomApiKey?: string; // mnm_ key for gateway billing identity
  licenseJwt?: string;   // Enterprise license JWT
  configuredAt?: string;
}

// ---------------------------------------------------------------------------
// V2 config (multi-agent format)
// ---------------------------------------------------------------------------

export interface AgentConfig {
  agentId: string;
  openclawConfigured?: boolean;
  providers?: string[];
  configuredAt?: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;  // unix seconds
  userId: string;
  email: string;
}

export interface ConfigV2 {
  version: 2;
  defaultAgent: string;
  gateway: string;
  mnemomApiKey?: string;
  licenseJwt?: string;
  agents: Record<string, AgentConfig>;
  auth?: AuthTokens;
}

/** Backward-compatible alias so existing imports keep working. */
export type Config = ConfigV2;

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/**
 * Migrate a v1 config into v2 format.
 * All agent-specific fields move into `agents.default`.
 */
export function migrateConfig(raw: ConfigV1): ConfigV2 {
  return {
    version: 2,
    defaultAgent: "default",
    gateway: raw.gateway ?? "https://gateway.mnemom.ai",
    mnemomApiKey: raw.mnemomApiKey,
    licenseJwt: raw.licenseJwt,
    agents: {
      default: {
        agentId: raw.agentId,
        openclawConfigured: raw.openclawConfigured,
        providers: raw.providers,
        configuredAt: raw.configuredAt,
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export function configExists(): boolean {
  return fs.existsSync(CONFIG_FILE);
}

/**
 * Load the config file.
 * If the file is v1 (no `version` field), it is automatically migrated to v2
 * and written back to disk before returning.
 */
export function loadConfig(): ConfigV2 | null {
  if (!configExists()) {
    return null;
  }

  try {
    const content = fs.readFileSync(CONFIG_FILE, "utf-8");
    const raw = JSON.parse(content);

    // Detect v1: no `version` field present
    if (!raw.version) {
      const migrated = migrateConfig(raw as ConfigV1);
      saveConfig(migrated);
      return migrated;
    }

    return raw as ConfigV2;
  } catch {
    return null;
  }
}

export function saveConfig(config: ConfigV2): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }

  // Validate write path stays within expected directory
  const resolvedPath = path.resolve(CONFIG_FILE);
  if (!resolvedPath.startsWith(path.resolve(CONFIG_DIR))) {
    throw new Error("Config file path escapes expected directory");
  }

  // Re-serialize to sanitize any HTTP-sourced data before writing to disk
  const sanitizedConfig = JSON.parse(JSON.stringify(config)) as ConfigV2;

  const tmpFile = `${resolvedPath}.${process.pid}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(sanitizedConfig, null, 2));
  fs.renameSync(tmpFile, resolvedPath);
}

// ---------------------------------------------------------------------------
// Agent resolution
// ---------------------------------------------------------------------------

/**
 * Resolve the active agent config.
 *
 * Resolution order:
 *  1. Explicit `agentName` parameter (--agent flag)
 *  2. `SMOLTBOT_AGENT` environment variable
 *
 * Returns `null` if no agent is specified or the agent is not found.
 * Callers must require --agent or SMOLTBOT_AGENT for agent-scoped commands.
 */
export function getActiveAgent(agentName?: string): AgentConfig | null {
  const config = loadConfig();
  if (!config) {
    return null;
  }

  const name =
    agentName ??
    process.env.SMOLTBOT_AGENT;

  if (!name) {
    return null;
  }

  return config.agents[name] ?? null;
}

/**
 * Require an explicit agent selection. Exits with a helpful error if
 * no agent was specified via --agent or SMOLTBOT_AGENT.
 *
 * Falls back to API lookup if the agent is not in local config:
 *  - smolt-XXXXXXXX IDs: public endpoint, no auth required
 *  - Names: authenticated account listing (requires `smoltbot login`)
 */
export async function requireAgent(agentName?: string): Promise<AgentConfig> {
  if (!configExists()) {
    console.error("\nsmoltbot is not initialized. Run `smoltbot init` first.\n");
    process.exit(1);
  }

  // Fast path: local config hit — no network call needed
  const localAgent = getActiveAgent(agentName);
  if (localAgent) return localAgent;

  const name = agentName ?? process.env.SMOLTBOT_AGENT;

  if (!name) {
    console.error("\nAgent required. Use --agent <name> or set SMOLTBOT_AGENT.\n");
    console.error("Available agents:");
    const config = loadConfig();
    if (config) {
      for (const [n, a] of Object.entries(config.agents)) {
        console.error(`  ${n} (${a.agentId})`);
      }
    }
    console.error();
    process.exit(1);
  }

  // API fallback: resolve from account
  try {
    const { getAgent, getAgentByName } = await import("./api.js");
    let found: AgentListItem | { id: string; created_at: string } | null = null;

    if (/^smolt-[0-9a-f]{8}$/.test(name)) {
      // Public endpoint — no auth needed
      found = await getAgent(name);
    } else {
      found = await getAgentByName(name);
    }

    if (found) {
      return { agentId: found.id };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("Not logged in")) {
      console.error(`\n${msg}\n`);
      process.exit(1);
    }
    // Other API errors: fall through to "not found" message
  }

  console.error(`\nAgent not found: ${name}`);
  console.error(`Run \`smoltbot agents add ${name}\` to register it locally,`);
  console.error(`or check \`smoltbot agents\` to see agents in your account.\n`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

export function generateAgentId(): string {
  const randomHex = crypto.randomBytes(4).toString("hex");
  return `smolt-${randomHex}`;
}

/**
 * Derive agent ID deterministically from an API key.
 * Uses SHA-256 to match the gateway's hashApiKey (Web Crypto SHA-256, first 16 hex chars).
 * The agent ID is "smolt-" + first 8 hex chars of the SHA-256 digest.
 */
export function deriveAgentId(apiKey: string): string {
  // eslint-disable-next-line -- not password hashing: deterministic ID derivation must match gateway SHA-256
  const hash = crypto.createHash("sha256").update(apiKey).digest("hex");
  return `smolt-${hash.slice(0, 8)}`;
}

/**
 * Derive agent ID deterministically from an API key *and* a name.
 * Allows multiple named agents to share one API key with distinct IDs.
 * Uses SHA-256 to match the gateway's hashApiKey(apiKey + '|' + name).
 */
export function deriveAgentIdWithName(apiKey: string, name: string): string {
  // eslint-disable-next-line -- not password hashing: deterministic ID derivation must match gateway SHA-256
  const hash = crypto.createHash("sha256").update(`${apiKey}|${name}`).digest("hex");
  return `smolt-${hash.slice(0, 8)}`;
}

// ---------------------------------------------------------------------------
// Auth token helpers
// ---------------------------------------------------------------------------

export function saveAuthTokens(tokens: AuthTokens): void {
  const config = loadConfig();
  if (!config) {
    throw new Error("Config not initialized. Run `smoltbot init` first.");
  }
  config.auth = tokens;
  saveConfig(config);
}

export function clearAuthTokens(): void {
  const config = loadConfig();
  if (!config) return;
  delete config.auth;
  saveConfig(config);
}

export function getAuthInfo(): AuthTokens | null {
  const config = loadConfig();
  return config?.auth ?? null;
}
