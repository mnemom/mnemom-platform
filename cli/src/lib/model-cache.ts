import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import type { ModelDefinition, Provider } from "./openclaw.js";
import { MODEL_REGISTRY, getModelDefinition as getStaticModelDefinition, detectProvider, formatModelName } from "./models.js";

const SMOLTBOT_DIR = path.join(os.homedir(), ".smoltbot");
const CACHE_FILE = path.join(SMOLTBOT_DIR, "models-cache.json");
const MODELS_URL = "https://gateway.mnemom.ai/models.json";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

interface ModelCache {
  fetchedAt: string;
  models: Record<Provider, Record<string, ModelDefinition>>;
}

/**
 * Load the cached model registry from disk.
 * Returns null if cache doesn't exist or is expired.
 */
function loadCache(): ModelCache | null {
  if (!fs.existsSync(CACHE_FILE)) {
    return null;
  }

  try {
    const content = fs.readFileSync(CACHE_FILE, "utf-8");
    const cache = JSON.parse(content) as ModelCache;

    // Check TTL
    const fetchedAt = new Date(cache.fetchedAt).getTime();
    if (Date.now() - fetchedAt > CACHE_TTL_MS) {
      return null; // Expired
    }

    return cache;
  } catch {
    return null;
  }
}

/**
 * Save model registry to disk cache.
 */
function saveCache(models: Record<Provider, Record<string, ModelDefinition>>): void {
  if (!models || typeof models !== "object") {
    return;
  }

  // Ensure directory exists
  if (!fs.existsSync(SMOLTBOT_DIR)) {
    fs.mkdirSync(SMOLTBOT_DIR, { recursive: true });
  }

  // Validate write path stays within expected directory
  const resolvedCachePath = path.resolve(CACHE_FILE);
  if (!resolvedCachePath.startsWith(path.resolve(SMOLTBOT_DIR))) {
    throw new Error("Cache file path escapes expected directory");
  }

  // Re-serialize HTTP-sourced data to sanitize before writing to disk
  const sanitizedModels = JSON.parse(JSON.stringify(models)) as Record<Provider, Record<string, ModelDefinition>>;

  const cache: ModelCache = {
    fetchedAt: new Date().toISOString(),
    models: sanitizedModels,
  };

  // Atomic write: temp file + rename to prevent corruption
  const tmpFile = `${resolvedCachePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(cache, null, 2));
  fs.renameSync(tmpFile, resolvedCachePath);
}

/**
 * Fetch fresh model registry from the gateway.
 * Fails silently on network errors — returns null.
 */
async function fetchRemoteModels(): Promise<Record<Provider, Record<string, ModelDefinition>> | null> {
  try {
    const response = await fetch(MODELS_URL, {
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      return null;
    }

    const data = (await response.json()) as Record<Provider, Record<string, ModelDefinition>>;

    // Basic validation
    if (!data.anthropic && !data.openai && !data.gemini) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

/**
 * Refresh the model cache in the background.
 * Fetches from the gateway and saves to disk.
 * Fails silently — never blocks the caller.
 */
export async function refreshModelCache(): Promise<void> {
  const remote = await fetchRemoteModels();
  if (remote) {
    saveCache(remote);
  }
}

/**
 * Get a model definition, checking: static registry -> cache -> inference fallback.
 * This is the primary entry point for looking up model definitions.
 */
export function getCachedModelDefinition(modelId: string): ModelDefinition {
  // 1. Check static registry first (always up to date with code)
  for (const provider of Object.values(MODEL_REGISTRY)) {
    const known = provider[modelId];
    if (known) return known;
  }

  // 2. Check disk cache
  const cache = loadCache();
  if (cache) {
    for (const provider of Object.values(cache.models)) {
      const cached = provider[modelId];
      if (cached) return cached;
    }
  }

  // 3. Fall back to inference (same as static getModelDefinition)
  return getStaticModelDefinition(modelId);
}

/**
 * Get all known models from both static registry and cache.
 */
export function getAllCachedModels(): Record<Provider, Record<string, ModelDefinition>> {
  const result: Record<Provider, Record<string, ModelDefinition>> = {
    anthropic: { ...MODEL_REGISTRY.anthropic },
    openai: { ...MODEL_REGISTRY.openai },
    gemini: { ...MODEL_REGISTRY.gemini },
  };

  // Merge cache (cache entries don't override static entries)
  const cache = loadCache();
  if (cache) {
    for (const [provider, models] of Object.entries(cache.models) as [Provider, Record<string, ModelDefinition>][]) {
      if (!result[provider]) continue;
      for (const [id, model] of Object.entries(models)) {
        if (!(id in result[provider])) {
          result[provider][id] = model;
        }
      }
    }
  }

  return result;
}
