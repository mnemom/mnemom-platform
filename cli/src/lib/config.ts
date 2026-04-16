import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import type { AgentListItem } from "./api.js";

export const CONFIG_DIR = path.join(os.homedir(), ".mnemom");
export const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");

// Legacy config path — auto-migrated on first run (UC-9)
export const LEGACY_CONFIG_DIR = path.join(os.homedir(), ".smoltbot");
const LEGACY_CONFIG_FILE = path.join(LEGACY_CONFIG_DIR, "config.json");

// ---------------------------------------------------------------------------
// Env var deprecation helper
// ---------------------------------------------------------------------------

const _warnedEnvVars = new Set<string>();

/**
 * Read an env var with fallback to a deprecated name.
 * Prints a one-time stderr warning when the legacy name is used.
 */
export function envWithDeprecation(newName: string, legacyName: string): string | undefined {
  const val = process.env[newName];
  if (val !== undefined) return val;

  const legacy = process.env[legacyName];
  if (legacy !== undefined) {
    if (!_warnedEnvVars.has(legacyName)) {
      _warnedEnvVars.add(legacyName);
      console.error(`Warning: ${legacyName} is deprecated, use ${newName} instead`);
    }
    return legacy;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Config directory migration (~/.smoltbot → ~/.mnemom)
// ---------------------------------------------------------------------------

let _migrationChecked = false;

/**
 * Auto-migrate config from ~/.smoltbot/ to ~/.mnemom/ on first run.
 * Copies config.json and models-cache.json if present.
 * Does NOT delete the old directory.
 */
export function migrateConfigDir(): void {
  if (_migrationChecked) return;
  _migrationChecked = true;

  // Only migrate if old exists and new does not
  if (!fs.existsSync(LEGACY_CONFIG_FILE) || fs.existsSync(CONFIG_FILE)) return;

  fs.mkdirSync(CONFIG_DIR, { recursive: true });

  // Copy config.json
  fs.copyFileSync(LEGACY_CONFIG_FILE, CONFIG_FILE);

  // Copy models-cache.json if present
  const legacyCache = path.join(LEGACY_CONFIG_DIR, "models-cache.json");
  const newCache = path.join(CONFIG_DIR, "models-cache.json");
  if (fs.existsSync(legacyCache)) {
    fs.copyFileSync(legacyCache, newCache);
  }

  console.error("Migrated config from ~/.smoltbot/ to ~/.mnemom/");
}

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
 *  1. `MNEMOM_ENV` environment variable (preferred)
 *  2. `SMOLTBOT_ENV` (deprecated fallback)
 *  3. Defaults to `production`
 */
export function getEnvironment(): Environment {
  const env = envWithDeprecation("MNEMOM_ENV", "SMOLTBOT_ENV");
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
 * Auto-migrates ~/.smoltbot/ → ~/.mnemom/ on first call.
 * If the file is v1 (no `version` field), it is automatically migrated to v2
 * and written back to disk before returning.
 */
export function loadConfig(): ConfigV2 | null {
  migrateConfigDir();

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
 *  2. `MNEMOM_AGENT` env var (preferred) or `SMOLTBOT_AGENT` (deprecated)
 *
 * Returns `null` if no agent is specified or the agent is not found.
 * Callers must require --agent or MNEMOM_AGENT for agent-scoped commands.
 */
export function getActiveAgent(agentName?: string): AgentConfig | null {
  const config = loadConfig();
  if (!config) {
    return null;
  }

  const name =
    agentName ??
    envWithDeprecation("MNEMOM_AGENT", "SMOLTBOT_AGENT");

  if (!name) {
    return null;
  }

  return config.agents[name] ?? null;
}

/**
 * Require an explicit agent selection. Exits with a helpful error if
 * no agent was specified via --agent or MNEMOM_AGENT.
 *
 * Falls back to API lookup if the agent is not in local config:
 *  - smolt-XXXXXXXX / mnm-UUID IDs: public endpoint, no auth required
 *  - Names: authenticated account listing (requires `mnemom login`)
 */
export async function requireAgent(agentName?: string): Promise<AgentConfig> {
  if (!configExists()) {
    console.error("\nmnemom is not configured. Run `mnemom register <name>` first.\n");
    process.exit(1);
  }

  // Fast path: local config hit — no network call needed
  const localAgent = getActiveAgent(agentName);
  if (localAgent) return localAgent;

  const name = agentName ?? envWithDeprecation("MNEMOM_AGENT", "SMOLTBOT_AGENT");

  if (!name) {
    console.error("\nAgent required. Use --agent <name> or set MNEMOM_AGENT.\n");
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

    if (/^(smolt-[0-9a-f]{8}|mnm-[0-9a-f-]{36})$/.test(name)) {
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
  console.error(`Run \`mnemom agents add ${name}\` to register it locally,`);
  console.error(`or check \`mnemom agents\` to see agents in your account.\n`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

export function generateAgentId(): string {
  // New format per ADR-019 (scale/step-25b): mnm-{uuid_v4} for all new agents.
  // crypto.randomUUID() is a Node.js built-in (>=14.17), no new dependencies.
  return `mnm-${crypto.randomUUID()}`;
}

/**
 * Compute the 16-char agent_hash for a given API key and optional agent name.
 * Matches the gateway's hashApiKey() and the POST /v1/agents/:id/rekey expected format.
 *
 * Unnamed agent:  SHA256(apiKey).slice(0, 16)
 * Named agent:    SHA256(apiKey + '|' + name).slice(0, 16)
 */
export function computeAgentHash(apiKey: string, name?: string | null): string {
  const input = name ? `${apiKey}|${name}` : apiKey;
  // eslint-disable-next-line -- deterministic ID derivation must match gateway SHA-256
  return crypto.createHash("sha256").update(input).digest("hex").slice(0, 16); // lgtm[js/insufficient-password-hash]
}

/**
 * Derive agent ID deterministically from an API key.
 * Uses SHA-256 to match the gateway's hashApiKey (Web Crypto SHA-256, first 16 hex chars).
 * The agent ID is "smolt-" + first 8 hex chars of the SHA-256 digest.
 */
export function deriveAgentId(apiKey: string): string {
  return `smolt-${computeAgentHash(apiKey).slice(0, 8)}`;
}

/**
 * Derive agent ID deterministically from an API key *and* a name.
 * Allows multiple named agents to share one API key with distinct IDs.
 * Uses SHA-256 to match the gateway's hashApiKey(apiKey + '|' + name).
 */
export function deriveAgentIdWithName(apiKey: string, name: string): string {
  return `smolt-${computeAgentHash(apiKey, name).slice(0, 8)}`;
}

// ---------------------------------------------------------------------------
// Auth token helpers
// ---------------------------------------------------------------------------

export function saveAuthTokens(tokens: AuthTokens): void {
  const config = loadConfig();
  if (!config) {
    throw new Error("Config not initialized. Run `mnemom register <name>` first.");
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
