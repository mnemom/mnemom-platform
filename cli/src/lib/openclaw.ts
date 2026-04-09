import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { getGatewayUrl } from "./config.js";

// OpenClaw paths
export const OPENCLAW_DIR = path.join(os.homedir(), ".openclaw");
export const OPENCLAW_CONFIG_FILE = path.join(OPENCLAW_DIR, "openclaw.json");
export const AUTH_PROFILES_FILE = path.join(
  OPENCLAW_DIR,
  "agents",
  "main",
  "agent",
  "auth-profiles.json"
);

// ============================================================================
// Provider Types
// ============================================================================

export type Provider = "anthropic" | "openai" | "gemini";

function buildProviderRoutes(): Record<Provider, { baseUrl: string; apiType: string }> {
  const gw = getGatewayUrl();
  return {
    anthropic: { baseUrl: `${gw}/anthropic`, apiType: "anthropic-messages" },
    openai: { baseUrl: `${gw}/openai`, apiType: "openai-chat" },
    gemini: { baseUrl: `${gw}/gemini`, apiType: "gemini-messages" },
  };
}

export const PROVIDER_ROUTES = buildProviderRoutes();

/**
 * Mnemom provider key names in OpenClaw config (canonical, new installs).
 * mnemom -> Anthropic
 * mnemom-openai -> OpenAI
 * mnemom-gemini -> Gemini
 */
export const PROVIDER_CONFIG_KEYS: Record<Provider, string> = {
  anthropic: "mnemom",
  openai: "mnemom-openai",
  gemini: "mnemom-gemini",
};

/**
 * Legacy smoltbot provider key names — used for backward-compat detection
 * of existing configurations and migration source keys.
 */
export const LEGACY_PROVIDER_CONFIG_KEYS: Record<Provider, string> = {
  anthropic: "smoltbot",
  openai: "smoltbot-openai",
  gemini: "smoltbot-gemini",
};

// ============================================================================
// Type Definitions
// ============================================================================

export interface AuthProfile {
  type: "api_key" | "oauth";
  provider: string;
  key?: string; // Only present for api_key type
}

export interface AuthProfilesFile {
  version: number;
  profiles: Record<string, AuthProfile>;
  lastGood?: Record<string, string>;
  usageStats?: Record<string, unknown>;
}

export interface ModelDefinition {
  id: string;
  name: string;
  provider?: Provider;
  reasoning?: boolean;
  input?: string[];
  contextWindow?: number;
  maxTokens?: number;
  cost?: {
    input: number;
    output: number;
    cacheRead?: number;
    cacheWrite?: number;
  };
}

export interface SmoltbotProvider {
  baseUrl: string;
  apiKey: string;
  api: string;
  defaultHeaders?: Record<string, string>;
  models: ModelDefinition[];
}

export interface OpenClawConfig {
  meta?: {
    lastTouchedVersion?: string;
    lastTouchedAt?: string;
  };
  wizard?: Record<string, unknown>;
  update?: Record<string, unknown>;
  auth?: {
    profiles?: Record<string, { provider: string; mode: string }>;
  };
  models?: {
    mode?: string;
    providers?: Record<string, SmoltbotProvider>;
  };
  agents?: {
    defaults?: {
      workspace?: string;
      compaction?: Record<string, unknown>;
      maxConcurrent?: number;
      subagents?: Record<string, unknown>;
      model?: {
        primary?: string;
      };
      models?: Record<string, unknown>;
    };
  };
  messages?: Record<string, unknown>;
  commands?: Record<string, unknown>;
  gateway?: Record<string, unknown>;
  [key: string]: unknown; // Allow other unknown fields
}

export interface OpenClawDetectionResult {
  installed: boolean;
  hasApiKey: boolean;
  isOAuth: boolean;
  apiKey?: string;
  currentModel?: string;
  currentModelId?: string;
  currentProvider?: string;
  smoltbotAlreadyConfigured: boolean;
  error?: string;
}

export interface ProviderDetectionResult {
  installed: boolean;
  providers: Record<
    Provider,
    {
      hasApiKey: boolean;
      apiKey?: string;
      isOAuth?: boolean;
      invalidFormat?: boolean;
    }
  >;
  currentModel?: string;
  currentModelId?: string;
  currentProvider?: string;
  smoltbotConfiguredProviders: Provider[];
  error?: string;
}

// ============================================================================
// API Key Configuration per Provider
// ============================================================================

const PROVIDER_KEY_CONFIG: Record<
  Provider,
  { profileKey: string; profileProvider: string; validate: (key: string) => boolean }
> = {
  anthropic: {
    profileKey: "anthropic:default",
    profileProvider: "anthropic",
    validate: (key: string) => key.startsWith("sk-ant-"),
  },
  openai: {
    profileKey: "openai:default",
    profileProvider: "openai",
    validate: (key: string) => key.startsWith("sk-") && !key.startsWith("sk-ant-"),
  },
  gemini: {
    profileKey: "google:default",
    profileProvider: "google",
    validate: (key: string) => key.startsWith("AIza"),
  },
};

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Check if OpenClaw is installed
 */
export function openclawExists(): boolean {
  return fs.existsSync(OPENCLAW_DIR) && fs.existsSync(OPENCLAW_CONFIG_FILE);
}

/**
 * Load and parse auth-profiles.json
 */
export function loadAuthProfiles(): AuthProfilesFile | null {
  if (!fs.existsSync(AUTH_PROFILES_FILE)) {
    return null;
  }

  try {
    const content = fs.readFileSync(AUTH_PROFILES_FILE, "utf-8");
    return JSON.parse(content) as AuthProfilesFile;
  } catch {
    return null;
  }
}

/**
 * Get API key for a specific provider from auth-profiles.json.
 */
export function getProviderApiKey(
  provider: Provider
): { key: string | null; isOAuth: boolean; invalidFormat?: boolean } {
  const profiles = loadAuthProfiles();
  if (!profiles) {
    return { key: null, isOAuth: false };
  }

  const config = PROVIDER_KEY_CONFIG[provider];

  // Look for provider:default or any matching provider profile
  const profile =
    profiles.profiles[config.profileKey] ||
    Object.values(profiles.profiles).find(
      (p) => p.provider === config.profileProvider
    );

  if (!profile) {
    return { key: null, isOAuth: false };
  }

  if (profile.type === "oauth" || !profile.key) {
    return { key: null, isOAuth: true };
  }

  // Validate key format
  if (!config.validate(profile.key)) {
    return { key: null, isOAuth: false, invalidFormat: true };
  }

  return { key: profile.key, isOAuth: false };
}

/**
 * Get the Anthropic API key from auth-profiles.json.
 * Backward-compatible wrapper around getProviderApiKey().
 */
export function getAnthropicApiKey(): {
  key: string | null;
  isOAuth: boolean;
  invalidFormat?: boolean;
} {
  return getProviderApiKey("anthropic");
}

/**
 * Load openclaw.json config
 */
export function loadOpenClawConfig(): OpenClawConfig | null {
  if (!fs.existsSync(OPENCLAW_CONFIG_FILE)) {
    return null;
  }

  try {
    const content = fs.readFileSync(OPENCLAW_CONFIG_FILE, "utf-8");
    return JSON.parse(content) as OpenClawConfig;
  } catch {
    return null;
  }
}

/**
 * Save openclaw.json config (preserves all existing fields)
 */
export function saveOpenClawConfig(config: OpenClawConfig): void {
  // Update meta timestamp
  if (!config.meta) {
    config.meta = {};
  }
  config.meta.lastTouchedAt = new Date().toISOString();

  fs.writeFileSync(OPENCLAW_CONFIG_FILE, JSON.stringify(config, null, 2));
}

/**
 * Get the current default model from OpenClaw config
 * Returns both the full model path (provider/model) and parsed parts
 */
export function getCurrentModel(): {
  fullPath: string | null;
  provider: string | null;
  modelId: string | null;
} {
  const config = loadOpenClawConfig();
  if (!config) {
    return { fullPath: null, provider: null, modelId: null };
  }

  const primary = config.agents?.defaults?.model?.primary;
  if (!primary) {
    return { fullPath: null, provider: null, modelId: null };
  }

  // Parse provider/model format (e.g., "anthropic/claude-opus-4-5-20251101")
  const parts = primary.split("/");
  if (parts.length === 2) {
    return {
      fullPath: primary,
      provider: parts[0],
      modelId: parts[1],
    };
  }

  // No provider prefix, assume it's just the model ID
  return {
    fullPath: primary,
    provider: null,
    modelId: primary,
  };
}

/**
 * Check if smoltbot/mnemom provider is already configured (any provider).
 * Returns true if either mnemom* OR smoltbot* provider keys exist in the OpenClaw config.
 */
export function isSmoltbotConfigured(): boolean {
  const config = loadOpenClawConfig();
  if (!config?.models?.providers) return false;
  const allKeys = [
    ...Object.values(PROVIDER_CONFIG_KEYS),
    ...Object.values(LEGACY_PROVIDER_CONFIG_KEYS),
  ];
  return allKeys.some((key) => !!config.models?.providers?.[key]);
}

/**
 * Get list of smoltbot/mnemom-configured providers.
 * Checks both new mnemom* keys and legacy smoltbot* keys.
 */
export function getSmoltbotConfiguredProviders(): Provider[] {
  const config = loadOpenClawConfig();
  if (!config?.models?.providers) return [];

  const configured = new Set<Provider>();
  for (const [provider, key] of Object.entries(PROVIDER_CONFIG_KEYS)) {
    if (config.models.providers[key]) {
      configured.add(provider as Provider);
    }
  }
  for (const [provider, key] of Object.entries(LEGACY_PROVIDER_CONFIG_KEYS)) {
    if (config.models.providers[key]) {
      configured.add(provider as Provider);
    }
  }
  return Array.from(configured);
}

/**
 * Get the existing mnemom/smoltbot provider config (Anthropic provider).
 * Checks mnemom key first, falls back to legacy smoltbot key.
 */
export function getSmoltbotProvider(): SmoltbotProvider | null {
  const config = loadOpenClawConfig();
  return (
    config?.models?.providers?.mnemom ||
    config?.models?.providers?.smoltbot ||
    null
  );
}

/**
 * Comprehensive detection of OpenClaw setup (backward compatible)
 */
export function detectOpenClaw(): OpenClawDetectionResult {
  // Check if OpenClaw is installed
  if (!openclawExists()) {
    return {
      installed: false,
      hasApiKey: false,
      isOAuth: false,
      smoltbotAlreadyConfigured: false,
      error: "OpenClaw is not installed. Install from https://openclaw.ai",
    };
  }

  // Check auth profile
  const { key, isOAuth, invalidFormat } = getAnthropicApiKey();

  if (invalidFormat) {
    return {
      installed: true,
      hasApiKey: false,
      isOAuth: false,
      smoltbotAlreadyConfigured: isSmoltbotConfigured(),
      error:
        "Invalid API key format. Anthropic API keys start with 'sk-ant-'.\n" +
        "Get a valid key from https://console.anthropic.com/settings/keys",
    };
  }

  if (isOAuth) {
    return {
      installed: true,
      hasApiKey: false,
      isOAuth: true,
      smoltbotAlreadyConfigured: isSmoltbotConfigured(),
      error:
        "OAuth authentication detected. smoltbot only supports API key authentication.\n" +
        "To use smoltbot, add an API key to your Anthropic auth profile.",
    };
  }

  if (!key) {
    return {
      installed: true,
      hasApiKey: false,
      isOAuth: false,
      smoltbotAlreadyConfigured: isSmoltbotConfigured(),
      error:
        "No Anthropic API key found in auth-profiles.json.\n" +
        "Run `openclaw auth` to configure your API key.",
    };
  }

  // Get current model
  const { fullPath, provider, modelId } = getCurrentModel();

  return {
    installed: true,
    hasApiKey: true,
    isOAuth: false,
    apiKey: key,
    currentModel: fullPath || undefined,
    currentModelId: modelId || undefined,
    currentProvider: provider || undefined,
    smoltbotAlreadyConfigured: isSmoltbotConfigured(),
  };
}

/**
 * Detect all available providers.
 * Checks for API keys across Anthropic, OpenAI, and Gemini.
 */
export function detectProviders(): ProviderDetectionResult {
  if (!openclawExists()) {
    return {
      installed: false,
      providers: {
        anthropic: { hasApiKey: false },
        openai: { hasApiKey: false },
        gemini: { hasApiKey: false },
      },
      smoltbotConfiguredProviders: [],
      error: "OpenClaw is not installed. Install from https://openclaw.ai",
    };
  }

  const providers: ProviderDetectionResult["providers"] = {
    anthropic: { hasApiKey: false },
    openai: { hasApiKey: false },
    gemini: { hasApiKey: false },
  };

  for (const provider of ["anthropic", "openai", "gemini"] as Provider[]) {
    const result = getProviderApiKey(provider);
    providers[provider] = {
      hasApiKey: !!result.key,
      apiKey: result.key || undefined,
      isOAuth: result.isOAuth || undefined,
      invalidFormat: result.invalidFormat || undefined,
    };
  }

  const { fullPath, provider: currentProvider, modelId } = getCurrentModel();

  return {
    installed: true,
    providers,
    currentModel: fullPath || undefined,
    currentModelId: modelId || undefined,
    currentProvider: currentProvider || undefined,
    smoltbotConfiguredProviders: getSmoltbotConfiguredProviders(),
  };
}

/**
 * Configure the smoltbot provider in OpenClaw config.
 * Backward-compatible — configures the Anthropic ("smoltbot") provider.
 */
export function configureSmoltbotProvider(
  apiKey: string,
  models: ModelDefinition[]
): void {
  configureSmoltbotProviderForType("anthropic", apiKey, models);
}

/**
 * Configure a smoltbot provider for a specific provider type.
 */
export function configureSmoltbotProviderForType(
  provider: Provider,
  apiKey: string,
  models: ModelDefinition[]
): void {
  const config = loadOpenClawConfig();
  if (!config) {
    throw new Error("Could not load OpenClaw config");
  }

  // Ensure models section exists
  if (!config.models) {
    config.models = {};
  }
  if (!config.models.providers) {
    config.models.providers = {};
  }

  // Set mode to merge if not set
  if (!config.models.mode) {
    config.models.mode = "merge";
  }

  const route = PROVIDER_ROUTES[provider];
  const configKey = PROVIDER_CONFIG_KEYS[provider];

  config.models.providers[configKey] = {
    baseUrl: route.baseUrl,
    apiKey: apiKey,
    api: route.apiType,
    models: models,
  };

  saveOpenClawConfig(config);
}

/**
 * Configure all available providers at once.
 * Returns the list of providers that were configured.
 */
export function configureSmoltbotProviders(
  providerKeys: Partial<Record<Provider, { apiKey: string; models: ModelDefinition[] }>>
): Provider[] {
  const config = loadOpenClawConfig();
  if (!config) {
    throw new Error("Could not load OpenClaw config");
  }

  // Ensure models section exists
  if (!config.models) {
    config.models = {};
  }
  if (!config.models.providers) {
    config.models.providers = {};
  }
  if (!config.models.mode) {
    config.models.mode = "merge";
  }

  const configured: Provider[] = [];

  for (const [provider, data] of Object.entries(providerKeys) as [
    Provider,
    { apiKey: string; models: ModelDefinition[] },
  ][]) {
    if (!data) continue;
    const route = PROVIDER_ROUTES[provider];
    const configKey = PROVIDER_CONFIG_KEYS[provider];

    config.models.providers[configKey] = {
      baseUrl: route.baseUrl,
      apiKey: data.apiKey,
      api: route.apiType,
      models: data.models,
    };

    configured.push(provider);
  }

  saveOpenClawConfig(config);
  return configured;
}

// ============================================================================
// Named Agent Provider Functions
// ============================================================================

/**
 * Get provider routes for a named agent.
 * Named agents use the same base URLs as default, but add x-mnemom-agent header.
 */
export function getProviderRoutes(
  agentName?: string
): Record<Provider, { baseUrl: string; apiType: string }> {
  // Same URLs for all agents — agent identity is in the x-mnemom-agent header
  return PROVIDER_ROUTES;
}

/**
 * Get provider config keys for a named agent.
 * Default agent uses mnemom* keys (PROVIDER_CONFIG_KEYS).
 * Named agents use: mnemom-{name}, mnemom-{name}-openai, mnemom-{name}-gemini.
 */
export function getProviderConfigKeys(
  agentName?: string
): Record<Provider, string> {
  if (!agentName) {
    return PROVIDER_CONFIG_KEYS;
  }

  return {
    anthropic: `mnemom-${agentName}`,
    openai: `mnemom-${agentName}-openai`,
    gemini: `mnemom-${agentName}-gemini`,
  };
}

/**
 * Configure OpenClaw providers for a named agent.
 * Each named agent gets its own provider entries with URL-prefixed base URLs.
 */
export function configureNamedAgentProviders(
  agentName: string,
  providerKeys: Partial<Record<Provider, { apiKey: string; models: ModelDefinition[] }>>
): Provider[] {
  const config = loadOpenClawConfig();
  if (!config) {
    throw new Error("Could not load OpenClaw config");
  }

  if (!config.models) {
    config.models = {};
  }
  if (!config.models.providers) {
    config.models.providers = {};
  }
  if (!config.models.mode) {
    config.models.mode = "merge";
  }

  const routes = getProviderRoutes(agentName);
  const keys = getProviderConfigKeys(agentName);
  const configured: Provider[] = [];

  for (const [provider, data] of Object.entries(providerKeys) as [
    Provider,
    { apiKey: string; models: ModelDefinition[] },
  ][]) {
    if (!data) continue;
    const route = routes[provider];
    const configKey = keys[provider];

    config.models.providers[configKey] = {
      baseUrl: route.baseUrl,
      apiKey: data.apiKey,
      api: route.apiType,
      defaultHeaders: { "x-mnemom-agent": agentName },
      models: data.models,
    };

    configured.push(provider);
  }

  saveOpenClawConfig(config);
  return configured;
}

/**
 * Set the default model in OpenClaw config
 */
export function setDefaultModel(modelPath: string): void {
  const config = loadOpenClawConfig();
  if (!config) {
    throw new Error("Could not load OpenClaw config");
  }

  // Ensure agents.defaults.model section exists
  if (!config.agents) {
    config.agents = {};
  }
  if (!config.agents.defaults) {
    config.agents.defaults = {};
  }
  if (!config.agents.defaults.model) {
    config.agents.defaults.model = {};
  }

  // Also add to models map if not present
  if (!config.agents.defaults.models) {
    config.agents.defaults.models = {};
  }

  config.agents.defaults.model.primary = modelPath;
  config.agents.defaults.models[modelPath] = {};

  saveOpenClawConfig(config);
}
