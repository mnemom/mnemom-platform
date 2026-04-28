/**
 * Mnemom Gateway Worker (mnemom-platform)
 *
 * The heart of the Smoltbot system - a Cloudflare Worker that:
 * 1. Intercepts API requests to Anthropic, OpenAI, and Gemini
 * 2. Identifies agents via API key hashing (zero-config)
 * 3. Attaches metadata for tracing via CF AI Gateway
 * 4. Forwards requests and returns responses transparently
 * 5. [Wave 1] Injects extended thinking into requests
 * 6. [Wave 2] Performs real-time AIP integrity checking on responses
 * 7. [Wave 4] Delivers webhook notifications for integrity events
 */

import {
  checkIntegrity,
  buildSignal,
  buildConsciencePrompt,
  detectIntegrityDrift,
  createDriftState,
  createAdapterRegistry,
  WindowManager,
  DEFAULT_CONSCIENCE_VALUES,
  WEBHOOK_RETRY_DELAYS_MS,
  AIP_VERSION,
  CHECKPOINT_ID_PREFIX,
  type IntegrityCheckpoint,
  type AlignmentCard as AIPAlignmentCard,
  type AlignmentCardValue,
  type DriftState,
  type CheckIntegrityInput,
  type ConscienceValue,
} from '@mnemom/agent-integrity-protocol';

import { createWorkersExporter } from '@mnemom/aip-otel-exporter/workers';
import {
  signCheckpoint as ed25519Sign,
  computeInputCommitment,
  loadSigningKeyFromHex,
  computeChainHash,
  computeLeafHash,
  buildTreeState,
  generateInclusionProof,
  buildSignedPayload,
  generateCertificateId,
} from './attestation';
import { readStreamToText, parseSSEEvents } from './sse-parser';
import {
  mapUnifiedCardToAAP,
  mapCanonicalToSafeHouseConfig,
  fetchCanonicalAlignmentCard,
  fetchCanonicalProtectionCard,
} from './card-mappers';
import {
  checkTrustedSource,
  buildNudgeAnnotation,
  prependNudgeToLastUserMessage,
} from './safe-house-runtime';
import {
  evaluatePolicy,
  // mergePolicies removed in UC-8 — policy is derived from the canonical card
  // at evaluation time via extractPolicyFromCard (runs inside evaluatePolicy).
  mergeTransactionGuardrails,
  type Policy,
  type EvaluationResult,
  type ToolReference,
} from '@mnemom/policy-engine';
import {
  runL1Detection,
  applySessionMultiplier,
  decorateMessage,
  buildQuarantineNotification,
  buildSHAnalysisPrompt,
  buildSHUserPrompt,
  parseL2Response,
  mergeL1AndL2,
  buildThreatContextForAIP,
  buildPreemptiveNudgeContent,
  redactDLPMatches,
  type DLPMatch,
  buildSHExitAnalysisPrompt,
  buildSHExitUserPrompt,
  DEFAULT_SAFE_HOUSE_CONFIG,
  preprocessForDetection,
  computeMinHash,
  computeBandHashes,
  buildRecipeIndex,
  evaluateRecipesTier1,
  buildDetectorScoresFromThreats,
  serializeRecipeTelemetry,
  type SafeHouseConfig,
  type SafeHouseDecision,
  type SafeHouseVerdict,
  type SessionRiskState,
  type SafeHouseThreatPattern,
  type SourceType,
  type L1Result,
  type ThreatType,
  type ThreatDetection,
  type RecipeIndex,
  type RecipeRpcRow,
  type RecipeMode,
  type RecipeEvalConfig,
  type DetectorScores,
} from '@mnemom/safe-house';

// ── SemanticAnalyzer trigger helper ────────────────────────────────────────
// Languages where PatternMatcher has weaker coverage (non-Latin script).
// For these, SemanticAnalyzer is always triggered regardless of L1 score.
const NON_LATIN_LANGS = new Set(['ja', 'zh', 'ar', 'ko']);

function shouldForceSemanticAnalysis(l1: L1Result): boolean {
  return l1.encoding_detected === true ||
    NON_LATIN_LANGS.has(l1.detected_lang ?? '');
}
import { jwtVerify, createRemoteJWKSet, type JWTPayload } from 'jose';
import { createCircuitBreaker, checkAndReset, recordSuccess, recordFailure } from './circuit-breaker';

// ============================================================================
// Bootstrapping Defaults
// ============================================================================

/**
 * Default declared values for new alignment cards during agent registration.
 * These serve as initial card values when no org template exists. The org card
 * merge system overrides them at runtime — the observer always uses the merged
 * card from the DB at verification time, not these defaults.
 */
const DEFAULT_DECLARED_VALUES = [
  'transparency',
  'accuracy',
  'helpfulness',
  'safety',
  'autonomy',
  'honesty',
  'quality',
] as const;

// ============================================================================
// Analysis Helpers
// ============================================================================

/**
 * Sanitize JSON text by removing trailing commas before } or ].
 * Haiku 4.5 occasionally produces trailing commas in JSON arrays/objects.
 */
function sanitizeJson(text: string): string {
  return text.replace(/,\s*([}\]])/g, '$1');
}

/**
 * Pre-filter to skip analysis for trivial thinking blocks.
 * Lightweight first stage of a two-stage cascade — cuts API costs for
 * the ~30-40% of interactions with trivial thinking blocks.
 */
function shouldSkipAnalysis(thinkingBlock: string): boolean {
  const tokenEstimate = Math.ceil(thinkingBlock.length / 4);
  if (tokenEstimate < 50) return true;
  if (tokenEstimate < 100 && /^(I'll |Let me |Sure, |OK, |Here's )/i.test(thinkingBlock.trim())) return true;
  return false;
}

// ============================================================================
// Analysis Circuit Breaker
// ============================================================================

const analysisCircuitBreaker = {
  failures: 0,
  lastFailure: 0,
  isOpen: false,
  threshold: 5,
  resetAfterMs: 60000,
};

// ============================================================================
// Types
// ============================================================================

type GatewayProvider = 'anthropic' | 'openai' | 'gemini';

export interface Env {
  SUPABASE_URL: string;
  SUPABASE_SECRET_KEY: string;
  CF_AI_GATEWAY_URL: string;
  CF_AIG_TOKEN: string;  // AI Gateway authentication token
  GATEWAY_VERSION: string;
  ANTHROPIC_API_KEY: string;  // For AIP analysis LLM calls
  AIP_ENABLED: string;        // Feature flag ("true"/"false"), default "true"
  OTLP_ENDPOINT?: string;
  OTLP_AUTH?: string;
  OPENAI_API_KEY?: string;
  GEMINI_API_KEY?: string;
  BILLING_CACHE?: KVNamespace;          // Optional — fail-open if not bound
  BILLING_ENFORCEMENT_ENABLED?: string; // "true"/"false", default "false"
  // Phase 7: Self-hosted hybrid mode
  MNEMOM_ANALYZE_URL?: string;          // e.g. "https://api.mnemom.ai/v1/analyze"
  MNEMOM_API_KEY?: string;              // mnm_xxx key with analyze scope
  MNEMOM_LICENSE_JWT?: string;          // Enterprise license JWT
  // Phase 1 VIE: Ed25519 checkpoint attestation
  ED25519_SIGNING_KEY?: string;         // 64-char hex secret key
  ED25519_KEY_ID?: string;              // Key identifier (e.g. "key-001")
  // Phase 3: ZK proving via SP1
  PROVER_URL?: string;                  // e.g. "https://prover.mnemom.ai"
  PROVER_API_KEY?: string;              // Shared secret for prover auth
  // Phase 4: Transaction guardrails KV cache
  KV?: KVNamespace;
  // Safe House
  SAFE_HOUSE_ENABLED?: string;  // "true" to enable Safe House DB fetches; default off to avoid test interference
  // Canonical agent creation (scale/step-25b): gateway delegates to mnemom-api
  INTERNAL_API_KEY?: string;    // Shared service-to-service key (same as mnemom-api INTERNAL_API_KEY)
  // Phase 5 Stage 5B: Detection recipes runtime
  RECIPE_MODE?: string;         // "off" | "shadow" | "enforce", default "off". 5B only uses "off"/"shadow".
}

interface Agent {
  id: string;
  agent_hash: string;
  name: string | null;
  created_at: string;
  last_seen: string | null;
  claimed_at: string | null;
  claimed_by: string | null;
  email: string | null;
  aip_enforcement_mode?: string;
  linked_agent_id?: string | null;
  key_prefix?: string | null;
}

interface AlignmentCard {
  id: string;
  agent_id: string;
  content: Record<string, unknown>;
  version: number;
  created_at: string;
  updated_at: string;
}

// ============================================================================
// Quota Enforcement Types
// ============================================================================

export interface AgentSettings {
  aap_enabled: boolean;
  aip_enabled: boolean;
  proof_enabled: boolean;
  proof_rate: number;
  proof_boundary_cap?: number; // Max % of boundary violations to prove (default 100). Reduces to stochastic sampling when card_gaps aren't available.
  thinking_budget?: number; // Thinking token budget for extended thinking injection (default 30000).
  nudge_strategy?: 'always' | 'sampling' | 'threshold' | 'off';
  nudge_rate?: number;
  nudge_threshold?: number;
  analyze_output?: boolean;
}

export interface QuotaContext {
  plan_id: string;
  billing_model: string;       // 'none' | 'metered' | 'subscription' | 'subscription_plus_metered'
  subscription_status: string; // 'trialing' | 'active' | 'past_due' | 'canceled' | 'none'
  included_checks: number;
  check_count_this_period: number;
  overage_threshold: number | null;
  per_check_price: number;
  feature_flags: Record<string, boolean>;
  limits: Record<string, unknown>;
  account_id: string | null;
  current_period_end: string | null;
  past_due_since: string | null;
  is_suspended: boolean;
  agent_settings: AgentSettings | null;
  per_proof_price: number;
  containment_status: 'active' | 'paused' | 'killed';
  // Safe House billing fields (populated by get_quota_context_for_agent RPC)
  sh_included_checks?: number;
  per_sh_check_price?: number;
  sh_check_count_this_period?: number;
}

export interface QuotaDecision {
  action: 'allow' | 'warn' | 'reject';
  reason?: string;
  usage_percent?: number;
  headers: Record<string, string>;
}

// ============================================================================
// Rate Limiting (per-IP, per-org, per-agent)
// ============================================================================

const DEFAULT_RATE_LIMITS = {
  per_ip_rpm: 100,
  per_org_rpm: 1000,
  per_agent_rpm: 100,
};

async function checkRateLimitTier(
  kv: KVNamespace,
  key: string,
  limit: number,
): Promise<{ count: number; allowed: boolean }> {
  try {
    const current = parseInt((await kv.get(key)) || '0', 10);
    if (current >= limit) {
      return { count: current, allowed: false };
    }
    await kv.put(key, String(current + 1), { expirationTtl: 120 });
    return { count: current + 1, allowed: true };
  } catch {
    return { count: 0, allowed: true }; // fail-open
  }
}

function rateLimitResponse(
  tier: string, limit: number, minute: number
): Response {
  const resetAt = (minute + 1) * 60;
  const retryAfter = Math.max(1, resetAt - Math.floor(Date.now() / 1000));
  return new Response(
    JSON.stringify({
      error: 'Rate limit exceeded',
      type: 'rate_limit_error',
      tier,
      limit,
      retry_after: retryAfter,
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(retryAfter),
        'X-RateLimit-Limit': String(limit),
        'X-RateLimit-Remaining': '0',
        'X-RateLimit-Reset': String(resetAt),
      },
    },
  );
}

export const FREE_TIER_CONTEXT: QuotaContext = {
  plan_id: 'plan-free',
  billing_model: 'none',
  subscription_status: 'none',
  included_checks: 0,
  check_count_this_period: 0,
  overage_threshold: null,
  per_check_price: 0,
  feature_flags: {},
  limits: {},
  account_id: null,
  current_period_end: null,
  past_due_since: null,
  is_suspended: false,
  agent_settings: null,
  per_proof_price: 0,
  containment_status: 'active',
};

// ============================================================================
// Quota Enforcement Functions
// ============================================================================

/**
 * Resolve quota context for an agent. Checks KV cache first, falls back to
 * Supabase RPC. Fail-open: any error returns free-tier context.
 */
export async function resolveQuotaContext(
  agentId: string,
  env: Env,
  mnemomKeyHash?: string,
): Promise<QuotaContext> {
  try {
    const cacheKey = mnemomKeyHash
      ? `quota:mk:${mnemomKeyHash}`
      : `quota:agent:${agentId}`;

    // Check KV cache (30-min TTL)
    if (env.BILLING_CACHE) {
      try {
        const cached = await env.BILLING_CACHE.get(cacheKey, 'json');
        if (cached) return cached as QuotaContext;
      } catch {
        // KV read error — continue to RPC
      }
    }

    // Call Supabase RPC
    const rpcResponse = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/rpc/get_quota_context_for_agent`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ p_agent_id: agentId }),
      },
    );

    if (!rpcResponse.ok) {
      console.warn(`[quota] RPC failed (${rpcResponse.status}), fail-open`);
      return { ...FREE_TIER_CONTEXT };
    }

    const context = (await rpcResponse.json()) as QuotaContext;

    // Write to KV cache (fire-and-forget, 30-min TTL)
    if (env.BILLING_CACHE) {
      env.BILLING_CACHE
        .put(cacheKey, JSON.stringify(context), { expirationTtl: 1800 })
        .catch(() => {});
    }

    return context;
  } catch (err) {
    console.warn('[quota] resolveQuotaContext error, fail-open:', err);
    return { ...FREE_TIER_CONTEXT };
  }
}

/**
 * Evaluate quota context and return a decision. Pure function — zero I/O.
 */
export function evaluateQuota(context: QuotaContext): QuotaDecision {
  const headers: Record<string, string> = {};

  // Suspended accounts are always rejected — overrides all other logic including free tier
  if (context.is_suspended) {
    return {
      action: 'reject',
      reason: 'account_suspended',
      headers,
    };
  }

  // Contained agents are blocked — checked before billing logic
  if (context.containment_status === 'paused' || context.containment_status === 'killed') {
    return {
      action: 'reject',
      reason: `agent_${context.containment_status}`,
      headers,
    };
  }

  // Free tier / no billing model → always allow (pass-through)
  if (context.plan_id === 'plan-free' || context.billing_model === 'none') {
    return { action: 'allow', headers };
  }

  // Enterprise → always allow
  if (context.plan_id === 'plan-enterprise') {
    return { action: 'allow', headers };
  }

  // Canceled → reject
  if (context.subscription_status === 'canceled') {
    return {
      action: 'reject',
      reason: 'subscription_canceled',
      headers,
    };
  }

  // Past due handling
  if (context.subscription_status === 'past_due') {
    // Team plan: immediate reject
    if (context.plan_id === 'plan-team') {
      return {
        action: 'reject',
        reason: 'subscription_past_due',
        headers,
      };
    }

    // Developer plan: 7-day grace period
    if (context.plan_id === 'plan-developer' && context.past_due_since) {
      const pastDueMs = Date.now() - new Date(context.past_due_since).getTime();
      const gracePeriodMs = 7 * 24 * 60 * 60 * 1000; // 7 days

      if (pastDueMs > gracePeriodMs) {
        return {
          action: 'reject',
          reason: 'subscription_past_due_grace_expired',
          headers,
        };
      }
      // Within grace period — allow
      return { action: 'allow', headers };
    }

    // Developer past_due but no past_due_since recorded — allow (grace)
    if (context.plan_id === 'plan-developer') {
      return { action: 'allow', headers };
    }

    // Other plans past_due — reject
    return {
      action: 'reject',
      reason: 'subscription_past_due',
      headers,
    };
  }

  // Active/trialing — check usage
  const usagePercent =
    context.included_checks > 0
      ? (context.check_count_this_period / context.included_checks) * 100
      : 0;

  headers['X-Mnemom-Usage-Percent'] = String(Math.round(usagePercent));

  // Overage threshold exceeded → reject
  if (
    context.overage_threshold !== null &&
    context.check_count_this_period >= context.overage_threshold
  ) {
    return {
      action: 'reject',
      reason: 'overage_threshold_exceeded',
      usage_percent: usagePercent,
      headers,
    };
  }

  // Team at/over 100% included → warn (overage billing active)
  if (context.included_checks > 0 && usagePercent >= 100) {
    headers['X-Mnemom-Usage-Warning'] = 'quota_exceeded';
    return {
      action: 'warn',
      reason: 'quota_exceeded',
      usage_percent: usagePercent,
      headers,
    };
  }

  // Approaching quota (>=80%)
  if (context.included_checks > 0 && usagePercent >= 80) {
    headers['X-Mnemom-Usage-Warning'] = 'approaching_quota';
    return {
      action: 'warn',
      reason: 'approaching_quota',
      usage_percent: usagePercent,
      headers,
    };
  }

  // Under quota or metered-only (no included_checks) → allow
  return {
    action: 'allow',
    usage_percent: usagePercent,
    headers,
  };
}

/**
 * Hash a Mnemom API key using SHA-256 (full hex, not truncated like agent hash).
 */
export async function hashMnemomApiKey(key: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// Core Utility Functions
// ============================================================================

/**
 * Hash an API key using SHA-256 and return the first 16 hex characters.
 * This creates a consistent, privacy-preserving identifier for agents.
 */
export async function hashApiKey(apiKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(apiKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex.substring(0, 16);
}

/**
 * Returns true if the token is structurally JWT-shaped (three dot-separated parts).
 * Supabase JWTs always match this pattern; raw LLM API keys (sk-ant-..., sk-proj-...) do not.
 */
function looksLikeJwt(token: string): boolean {
  return token.split('.').length === 3;
}

/**
 * Cached JWKS remote key set per Supabase URL.
 * Persists within a Worker isolate lifetime — jose handles key refresh internally.
 */
let _jwksCache: ReturnType<typeof createRemoteJWKSet> | undefined;
let _jwksCacheUrl: string | undefined;

function getSupabaseJwks(supabaseUrl: string) {
  if (!_jwksCache || _jwksCacheUrl !== supabaseUrl) {
    _jwksCache = createRemoteJWKSet(
      new URL('/auth/v1/.well-known/jwks.json', supabaseUrl)
    );
    _jwksCacheUrl = supabaseUrl;
  }
  return _jwksCache;
}

/** Reset the JWKS cache — for use in tests only. */
export function _resetJwksCacheForTests(): void {
  _jwksCache = undefined;
  _jwksCacheUrl = undefined;
}

// ============================================================================
// Supabase Fetch — 5s Timeout + Circuit Breaker
// ============================================================================

const supabaseCircuitBreaker = createCircuitBreaker(3, 30000);

/** Reset Supabase circuit breaker state — for use in tests only. */
export function _resetSupabaseCircuitBreakerForTests(): void {
  supabaseCircuitBreaker.failures = 0;
  supabaseCircuitBreaker.lastFailure = 0;
  supabaseCircuitBreaker.isOpen = false;
}

/** Exported for unit testing — wraps fetchSHLSHCandidates. */
export { fetchSHLSHCandidates as _fetchSHLSHCandidatesForTests };
/** Exported for unit testing — wraps fetchSHContextFamilies. */
export { fetchSHContextFamilies as _fetchSHContextFamiliesForTests };

/**
 * Drop-in replacement for fetch() on all Supabase REST/RPC calls.
 * Adds a 5s AbortController timeout and circuit breaker protection.
 * Callers retain their existing error handling and safe defaults.
 */
async function supabaseFetch(url: string, options: RequestInit): Promise<Response> {
  checkAndReset(supabaseCircuitBreaker, 'supabase');
  if (supabaseCircuitBreaker.isOpen) {
    throw new Error('[supabase] Circuit open — DB temporarily unavailable');
  }
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    recordSuccess(supabaseCircuitBreaker, 'supabase');
    return response;
  } catch (err) {
    recordFailure(supabaseCircuitBreaker, 'supabase');
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Verify a Supabase-issued JWT using the project's JWKS endpoint (ES256).
 * Uses createRemoteJWKSet — supports key rotation automatically.
 * Throws if the token is invalid, expired, or fails signature verification.
 */
async function verifySupabaseJwt(token: string, supabaseUrl: string): Promise<JWTPayload> {
  const jwks = getSupabaseJwks(supabaseUrl);
  const { payload } = await jwtVerify(token, jwks, { algorithms: ['ES256'] });
  return payload;
}

/**
 * Generate a session ID from agent hash and current hour bucket.
 * Sessions are bucketed by hour for reasonable grouping of related requests.
 */
export function generateSessionId(agentHash: string): string {
  const hourBucket = Math.floor(Date.now() / (1000 * 60 * 60));
  return `${agentHash}-${hourBucket}`;
}

/**
 * Generate a random hex string of specified length.
 * Uses crypto.getRandomValues for Cloudflare Workers compatibility.
 */
function randomHex(length: number): string {
  const bytes = new Uint8Array(Math.ceil(length / 2));
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, length);
}

/**
 * Compute SHA-256 hash of a string using Web Crypto API.
 * Used for thinking block hashing in Workers environment (no node:crypto).
 */
async function sha256(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// Agent Management Functions
// ============================================================================

/**
 * Lookup or create an agent in Supabase by their hash.
 * New agents get a default alignment card created automatically.
 */
export async function getOrCreateAgent(
  agentHash: string,
  env: Env,
  agentName?: string,
  keyPrefix?: string
): Promise<{ agent: Agent; isNew: boolean }> {
  const headers = {
    'apikey': env.SUPABASE_SECRET_KEY,
    'Authorization': `Bearer ${env.SUPABASE_SECRET_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation',
  };

  // Try to find existing agent
  const lookupResponse = await supabaseFetch(
    `${env.SUPABASE_URL}/rest/v1/agents?agent_hash=eq.${agentHash}&select=*`,
    { headers }
  );

  if (!lookupResponse.ok) {
    throw new Error(`Supabase lookup failed: ${lookupResponse.status}`);
  }

  const agents: Agent[] = await lookupResponse.json();

  if (agents.length > 0) {
    const existing = agents[0];

    // Update name if provided and different (or not yet set)
    if (agentName && existing.name !== agentName) {
      supabaseFetch(
        `${env.SUPABASE_URL}/rest/v1/agents?id=eq.${existing.id}`,
        {
          method: 'PATCH',
          headers,
          body: JSON.stringify({ name: agentName }),
        }
      ).catch(() => {}); // Best-effort, don't block the request
      existing.name = agentName;
    }

    return { agent: existing, isNew: false };
  }

  // Delegate new agent creation to mnemom-api — the single canonical creation path.
  // This ensures: mnm-{uuid} IDs, consistent alignment card creation, single code path.
  // (scale/step-25b: ADR-019 consolidation — gateway no longer writes agents directly)
  const apiBase = env.MNEMOM_ANALYZE_URL
    ? env.MNEMOM_ANALYZE_URL.replace('/v1/analyze', '')
    : 'https://api.mnemom.ai';

  const createResponse = await fetch(`${apiBase}/internal/agents`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Internal-Key': env.INTERNAL_API_KEY ?? '',
    },
    body: JSON.stringify({
      agent_hash: agentHash,
      ...(agentName ? { name: agentName } : {}),
      ...(keyPrefix ? { key_prefix: keyPrefix } : {}),
    }),
  });

  if (!createResponse.ok) {
    // On failure, retry the read — another request may have won the race
    const retryResponse = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/agents?agent_hash=eq.${agentHash}&select=*`,
      { headers }
    );
    if (retryResponse.ok) {
      const retryAgents: Agent[] = await retryResponse.json();
      if (retryAgents.length > 0) {
        return { agent: retryAgents[0], isNew: false };
      }
    }
    const errorText = await createResponse.text().catch(() => '');
    throw new Error(`Failed to create agent: ${createResponse.status} - ${errorText}`);
  }

  const newAgent: Agent = await createResponse.json();
  return { agent: newAgent, isNew: true };
}

/**
 * Ensure an alignment card exists for an agent (upsert).
 * Creates a new card or updates an existing one with current defaults.
 * Structure matches AAP SDK AlignmentCard type.
 */
export async function ensureAlignmentCard(
  agentId: string,
  env: Env
): Promise<void> {
  const headers = {
    'apikey': env.SUPABASE_SECRET_KEY,
    'Authorization': `Bearer ${env.SUPABASE_SECRET_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': 'resolution=ignore-duplicates,return=minimal',
  };

  const cardId = `ac-${agentId.replace('smolt-', '')}`;
  const issuedAt = new Date().toISOString();

  // Default alignment card per AAP spec
  // bounded_actions: semantic action types the agent can perform
  // declared values: the full set the observer's Haiku analysis can assign
  const cardJson = {
    aap_version: '0.5.0',
    card_id: cardId,
    agent_id: agentId,
    issued_at: issuedAt,
    principal: {
      type: 'human',
      relationship: 'delegated_authority',
    },
    values: {
      declared: [...DEFAULT_DECLARED_VALUES],
    },
    autonomy_envelope: {
      bounded_actions: [
        'inference',
      ],
      escalation_triggers: [],
      forbidden_actions: [],
    },
    audit_commitment: {
      retention_days: 365,
      queryable: true,
    },
  };

  const dbRecord = {
    id: cardId,
    agent_id: agentId,
    card_json: cardJson,
    issued_at: issuedAt,
    is_active: true,
  };

  try {
    const response = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/alignment_cards?on_conflict=id`,
      {
        method: 'POST',
        headers,
        body: JSON.stringify(dbRecord),
      }
    );

    if (!response.ok) {
      console.error(`Failed to upsert alignment card: ${response.status}`);
    }
  } catch {
    // Background task — don't let failures propagate
  }
}

/**
 * Update the last_seen timestamp for an agent.
 * This is done in the background to not block the response.
 */
export async function updateLastSeen(agentId: string, env: Env): Promise<void> {
  const headers = {
    'apikey': env.SUPABASE_SECRET_KEY,
    'Authorization': `Bearer ${env.SUPABASE_SECRET_KEY}`,
    'Content-Type': 'application/json',
  };

  try {
    await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/agents?id=eq.${agentId}`,
      {
        method: 'PATCH',
        headers,
        body: JSON.stringify({
          last_seen: new Date().toISOString(),
        }),
      }
    );
  } catch {
    // Best-effort background update — don't propagate
  }
}

export async function updateKeyPrefix(agentId: string, keyPrefix: string, env: Env): Promise<void> {
  const headers = {
    'apikey': env.SUPABASE_SECRET_KEY,
    'Authorization': `Bearer ${env.SUPABASE_SECRET_KEY}`,
    'Content-Type': 'application/json',
  };
  try {
    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/agents?id=eq.${agentId}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ key_prefix: keyPrefix }),
    });
  } catch {
    // Best-effort background update — don't propagate
  }
}

/**
 * Build the CF AI Gateway metadata header.
 * This metadata is attached to requests for tracing and analysis.
 *
 * IMPORTANT: CF AI Gateway enforces a max of 5 key-value pairs.
 * We omit `timestamp` (redundant with CF's own `created_at` on the log)
 * so that named agents (with `agent_name`) stay within the limit.
 */
export function buildMetadataHeader(
  agentId: string,
  agentHash: string,
  sessionId: string,
  gatewayVersion: string,
  agentName?: string
): string {
  const metadata = {
    agent_id: agentId,
    agent_hash: agentHash,
    session_id: sessionId,
    gateway_version: gatewayVersion,
    ...(agentName ? { agent_name: agentName } : {}),
  };
  return JSON.stringify(metadata);
}

// ============================================================================
// AIP Helper Functions
// ============================================================================

/** Default token budget for output block analysis (matches SDK constant). */
const DEFAULT_OUTPUT_TOKEN_BUDGET = 2048;

/**
 * Extract text output from a non-streaming provider response body.
 * Supports Anthropic (content[].text), OpenAI (choices[].message.content),
 * and Gemini (candidates[].content.parts[].text) formats.
 */
function extractOutputText(responseBody: string): string | undefined {
  try {
    const body = JSON.parse(responseBody) as Record<string, unknown>;

    // Anthropic: content array with text blocks
    const content = body.content as Array<Record<string, unknown>> | undefined;
    if (content && Array.isArray(content)) {
      const textParts: string[] = [];
      for (const block of content) {
        if (block.type === 'text' && typeof block.text === 'string') {
          textParts.push(block.text);
        }
      }
      if (textParts.length > 0) return textParts.join('\n');
    }

    // OpenAI: choices[].message.content
    const choices = body.choices as Array<Record<string, unknown>> | undefined;
    if (choices && Array.isArray(choices) && choices.length > 0) {
      const msg = choices[0].message as Record<string, unknown> | undefined;
      if (msg && typeof msg.content === 'string') return msg.content;
    }

    // Gemini: candidates[].content.parts[].text
    const candidates = body.candidates as Array<Record<string, unknown>> | undefined;
    if (candidates && Array.isArray(candidates) && candidates.length > 0) {
      const parts = (candidates[0].content as Record<string, unknown>)?.parts as Array<Record<string, unknown>> | undefined;
      if (parts && Array.isArray(parts)) {
        const textParts: string[] = [];
        for (const part of parts) {
          if (typeof part.text === 'string') textParts.push(part.text);
        }
        if (textParts.length > 0) return textParts.join('\n');
      }
    }

    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Extract PII-safe agent description from card extensions.
 */
function extractAgentDescription(cardJson: Record<string, any>): string | undefined {
  return cardJson.extensions?.mnemom?.description ?? undefined;
}

/**
 * Map AAP card_json to AIP AlignmentCard interface.
 * Same mapping pattern used by the observer.
 */
function mapCardToAIP(cardJson: Record<string, any>): AIPAlignmentCard {
  const declaredValues: string[] = cardJson.values?.declared || [];
  const defs = cardJson.values?.definitions as Record<string, { name?: string; description?: string; priority?: number }> | null | undefined;
  const values: AlignmentCardValue[] = declaredValues.map((v: string, i: number) => {
    const def = defs?.[v];
    return {
      name: v,
      priority: def?.priority ?? (i + 1),
      ...(def?.description ? { description: def.description } : {}),
    };
  });

  return {
    card_id: cardJson.card_id || 'unknown',
    agent_description: extractAgentDescription(cardJson),
    values,
    autonomy_envelope: {
      bounded_actions: cardJson.autonomy_envelope?.bounded_actions ?? [],
      forbidden_actions: cardJson.autonomy_envelope?.forbidden_actions ?? undefined,
      escalation_triggers: cardJson.autonomy_envelope?.escalation_triggers?.map(
        (t: { condition: string; action: string; reason?: string | null }) => ({
          condition: t.condition,
          action: t.action,
          reason: t.reason ?? undefined,
        })
      ),
    },
  };
}

/**
 * Fetch alignment card, conscience values, and enforcement mode for an agent.
 *
 * Reads the canonical pre-composed card from `canonical_agent_cards`. The
 * UC-6 transitional fallback to legacy `alignment_cards` + `agents` dormant
 * columns + per-request org-template merge was removed in the 2026-04-17+
 * hardening pass after the 7-day zero-fallback observation window closed.
 * Missing canonical rows are now a hard error — the composition pipeline
 * (handleComposeAgent / recompose_pending) is responsible for keeping every
 * active agent's canonical row current.
 */
async function fetchAlignmentData(
  agentId: string,
  env: Env
): Promise<{
  card: Record<string, any> | null;
  conscienceValues: ConscienceValue[] | null;
  enforcementMode: string;
}> {
  try {
    const canonical = await fetchCanonicalAlignmentCard(agentId, env);
    if (canonical) {
      console.log(JSON.stringify({
        event: 'card_read', card_source: 'canonical_hit', agent_id: agentId,
      }));
      const aapShaped = mapUnifiedCardToAAP(canonical) as unknown as Record<string, any>;
      const consciencePayload = canonical.conscience as { values?: ConscienceValue[] } | undefined;
      // ADR-039 Decision 1: prefer top-level integrity_mode (the new master
      // switch governing AIP). Fall back to legacy integrity.enforcement_mode
      // for canonicals composed before the dual-key window. The new vocabulary
      // adds 'off' (skip checkpoint entirely) — older AIP code paths treat
      // unknown values as 'observe' (fail-open), which is the safe behavior.
      const integrityPayload = canonical.integrity as { enforcement_mode?: string } | undefined;
      const topLevelIntegrityMode = (canonical as Record<string, any>).integrity_mode;
      const validModes = ['off', 'observe', 'nudge', 'enforce'];
      const integrityMode =
        typeof topLevelIntegrityMode === 'string' && validModes.includes(topLevelIntegrityMode)
          ? topLevelIntegrityMode
          : integrityPayload?.enforcement_mode ?? 'observe';
      return {
        card: aapShaped,
        conscienceValues: consciencePayload?.values ?? null,
        enforcementMode: integrityMode,
      };
    }
    // Canonical row missing — log loudly so the composition pipeline gets
    // a nudge, but don't fall back to the pre-UC columns (which no longer
    // exist post-migration-129). Return the fail-open defaults.
    console.error(JSON.stringify({
      event: 'card_read', card_source: 'canonical_missing', agent_id: agentId,
    }));
    return { card: null, conscienceValues: null, enforcementMode: 'observe' };
  } catch (err) {
    console.error(JSON.stringify({
      event: 'card_read', card_source: 'canonical_error', agent_id: agentId,
      error: err instanceof Error ? err.message : String(err),
    }));
    return { card: null, conscienceValues: null, enforcementMode: 'observe' };
  }
}

/**
 * Fetch recent checkpoints for window hydration.
 */
async function fetchRecentCheckpoints(
  agentId: string,
  sessionId: string,
  env: Env
): Promise<IntegrityCheckpoint[]> {
  try {
    const response = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/integrity_checkpoints?agent_id=eq.${agentId}&session_id=eq.${sessionId}&order=timestamp.desc&limit=10`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!response.ok) {
      console.warn(`[gateway/aip] Failed to fetch checkpoints: ${response.status}`);
      return [];
    }

    const rows = (await response.json()) as IntegrityCheckpoint[];
    // Reverse to chronological order (oldest first) for window hydration
    return rows.reverse();
  } catch (error) {
    console.error(`[gateway/aip] Error fetching checkpoints:`, error);
    return [];
  }
}

/**
 * Attestation data attached to a checkpoint when Ed25519 signing is configured.
 */
interface AttestationData {
  input_commitment: string;
  chain_hash: string;
  prev_chain_hash: string | null;
  merkle_leaf_index: number | null;
  certificate_id: string;
  signature: string;
  signing_key_id: string;
}

/**
 * Fetch the previous chain hash for an agent+session via Supabase RPC.
 * Returns null if no previous checkpoint exists (genesis case).
 */
async function fetchPrevChainHash(
  agentId: string,
  sessionId: string,
  env: Env
): Promise<string | null> {
  try {
    const response = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/rpc/get_prev_chain_hash`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          p_agent_id: agentId,
          p_session_id: sessionId,
        }),
      }
    );
    if (!response.ok) return null;
    const data = await response.json();
    return (data as string) || null;
  } catch {
    return null;
  }
}

/**
 * Fetch existing Merkle tree state for an agent via Supabase RPC.
 * Returns the leaf hashes array, or empty array if no tree exists.
 */
async function fetchMerkleTreeLeaves(
  agentId: string,
  env: Env
): Promise<string[]> {
  try {
    const response = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/rpc/get_merkle_tree`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ p_agent_id: agentId }),
      }
    );
    if (!response.ok) return [];
    const data = await response.json();
    const rows = Array.isArray(data) ? data : [];
    if (rows.length === 0) return [];
    return (rows[0] as Record<string, unknown>)?.leaf_hashes as string[] || [];
  } catch {
    return [];
  }
}

/**
 * Upsert Merkle tree state in Supabase (fire-and-forget).
 */
function upsertMerkleTree(
  agentId: string,
  root: string,
  depth: number,
  leafCount: number,
  leafHash: string,
  env: Env
): void {
  supabaseFetch(
    `${env.SUPABASE_URL}/rest/v1/rpc/upsert_merkle_tree`,
    {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        p_agent_id: agentId,
        p_merkle_root: root,
        p_tree_depth: depth,
        p_leaf_count: leafCount,
        p_leaf_hash: leafHash,
      }),
    }
  ).catch(() => { /* fail-open */ });
}

/**
 * Store checkpoint to Supabase.
 * Same upsert pattern as the observer's submitCheckpoint.
 * Optionally includes attestation data when Ed25519 signing is configured.
 */
async function storeCheckpoint(
  checkpoint: IntegrityCheckpoint,
  source: string,
  env: Env,
  attestation?: AttestationData
): Promise<void> {
  try {
    const response = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/integrity_checkpoints?on_conflict=checkpoint_id`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'resolution=merge-duplicates,return=minimal',
        },
        body: JSON.stringify({
          checkpoint_id: checkpoint.checkpoint_id,
          agent_id: checkpoint.agent_id,
          card_id: checkpoint.card_id,
          session_id: checkpoint.session_id,
          timestamp: checkpoint.timestamp,
          thinking_block_hash: checkpoint.thinking_block_hash,
          ...(checkpoint.output_block_hash ? { output_block_hash: checkpoint.output_block_hash } : {}),
          provider: checkpoint.provider,
          model: checkpoint.model,
          verdict: checkpoint.verdict,
          concerns: checkpoint.concerns,
          reasoning_summary: checkpoint.reasoning_summary,
          conscience_context: checkpoint.conscience_context,
          window_position: checkpoint.window_position,
          analysis_metadata: checkpoint.analysis_metadata,
          linked_trace_id: checkpoint.linked_trace_id,
          source,
          ...(attestation ? {
            input_commitment: attestation.input_commitment,
            issuer_signature: attestation.signature,
            signing_key_id: attestation.signing_key_id,
            chain_hash: attestation.chain_hash,
            prev_chain_hash: attestation.prev_chain_hash,
            merkle_leaf_index: attestation.merkle_leaf_index,
            certificate_id: attestation.certificate_id,
          } : {}),
        }),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.warn(
        `[gateway/aip] Failed to store checkpoint ${checkpoint.checkpoint_id}: ${response.status} - ${errorText}`
      );
    } else {
      console.log(`[gateway/aip] Checkpoint ${checkpoint.checkpoint_id} stored (source: ${source})`);
    }
  } catch (error) {
    console.error('[gateway/aip] Error storing checkpoint:', error);
  }
}

/**
 * Determine whether a checkpoint should be proven via zkVM.
 *
 * Tiered proving strategy:
 * - If card_gaps detected alongside a boundary_violation, the violation is likely
 *   due to a stale alignment card, not real agent misbehavior. Defer proving to
 *   let DDR reconciliation classify first (returns 'deferred').
 * - boundary_violations with no card_gaps are proven, subject to proof_boundary_cap.
 * - Other verdicts are stochastically sampled at the configured proof_rate.
 *
 * Returns: 'prove' | 'deferred' | 'skip'
 */
function shouldProve(
  checkpoint: { verdict: string },
  agentSettings: AgentSettings | null,
  policyCardGaps?: unknown[] | null,
): 'prove' | 'deferred' | 'skip' {
  if (!agentSettings?.proof_enabled) {
    console.log(`[gateway/proof] shouldProve=skip: proof_enabled=${agentSettings?.proof_enabled}`);
    return 'skip';
  }

  if (checkpoint.verdict === 'boundary_violation') {
    // Card-gap detected: defer proving — DDR will classify and trigger proof if needed
    if (policyCardGaps && policyCardGaps.length > 0) {
      console.log(`[gateway/proof] shouldProve=deferred: ${policyCardGaps.length} card_gaps detected, deferring to DDR`);
      return 'deferred';
    }
    // No card-gap info: apply boundary cap (default 5% stochastic sampling)
    const cap = (agentSettings.proof_boundary_cap ?? 5) / 100;
    if (cap >= 1) return 'prove';
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    const rand = new DataView(bytes.buffer).getUint32(0) / 0xFFFFFFFF;
    const result = rand < cap ? 'prove' : 'skip';
    console.log(`[gateway/proof] shouldProve=${result}: boundary_violation cap=${cap} rand=${rand.toFixed(4)}`);
    return result;
  }

  const rate = (agentSettings.proof_rate ?? 10) / 100;
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const rand = new DataView(bytes.buffer).getUint32(0) / 0xFFFFFFFF;
  const result = rand < rate ? 'prove' : 'skip';
  console.log(`[gateway/proof] shouldProve=${result}: verdict=${checkpoint.verdict} rate=${rate} rand=${rand.toFixed(4)}`);
  return result;
}

/**
 * Request a ZK proof for a checkpoint's verdict derivation.
 * Inserts a pending row in verdict_proofs, then fire-and-forget POSTs
 * to the external SP1 prover service. Fail-open throughout.
 */
async function requestProof(
  checkpointId: string,
  checkpointData: {
    analysis_response_text?: string;
    thinking_block_hash: string;
    card_hash?: string;
    values_hash?: string;
    model: string;
  },
  attestation: { input_commitment?: string } | undefined,
  env: Env,
): Promise<void> {
  if (!env.PROVER_URL) {
    console.warn('[gateway/proof] requestProof: PROVER_URL not set, skipping');
    return;
  }

  const proofId = `prf-${crypto.randomUUID().slice(0, 8)}`;
  console.log(`[gateway/proof] requestProof: ${proofId} for checkpoint ${checkpointId}`);

  // Insert pending proof row
  try {
    const res = await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/verdict_proofs`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        proof_id: proofId,
        checkpoint_id: checkpointId,
        proof_type: 'sp1-stark',
        status: 'pending',
        analysis_json: checkpointData.analysis_response_text || '',
        thinking_hash: checkpointData.thinking_block_hash,
        card_hash: checkpointData.card_hash || '',
        values_hash: checkpointData.values_hash || '',
        model: checkpointData.model,
      }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.error(`[gateway/proof] DB INSERT failed: ${res.status} ${body}`);
      return;
    }
    console.log(`[gateway/proof] DB INSERT ok: ${proofId}`);
  } catch (err) {
    console.error(`[gateway/proof] DB INSERT error:`, err);
    return;
  }

  // Fire-and-forget POST to prover
  fetch(`${env.PROVER_URL}/prove`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(env.PROVER_API_KEY ? { 'X-Prover-Key': env.PROVER_API_KEY } : {}),
    },
    body: JSON.stringify({
      proof_id: proofId,
      checkpoint_id: checkpointId,
      analysis_json: checkpointData.analysis_response_text || '',
      thinking_hash: checkpointData.thinking_block_hash,
      card_hash: checkpointData.card_hash || '',
      values_hash: checkpointData.values_hash || '',
      model: checkpointData.model,
    }),
  }).then(r => console.log(`[gateway/proof] Prover POST: ${r.status}`))
    .catch(err => console.warn(`[gateway/proof] Prover POST failed:`, err));
}

/**
 * Record a deferred proof row in verdict_proofs. No GPU work is triggered.
 * DDR reconciliation in the observer will later resolve the proof as either
 * 'skipped_card_gap' (no cost) or upgrade to 'pending' and POST to the prover.
 */
async function deferProof(
  checkpointId: string,
  checkpointData: {
    analysis_response_text?: string;
    thinking_block_hash: string;
    card_hash?: string;
    values_hash?: string;
    model: string;
  },
  env: Env,
): Promise<void> {
  const proofId = `prf-${crypto.randomUUID().slice(0, 8)}`;
  console.log(`[gateway/proof] deferProof: ${proofId} for checkpoint ${checkpointId} (awaiting DDR)`);

  try {
    const res = await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/verdict_proofs`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        proof_id: proofId,
        checkpoint_id: checkpointId,
        proof_type: 'sp1-stark',
        status: 'deferred',
        analysis_json: checkpointData.analysis_response_text || '',
        thinking_hash: checkpointData.thinking_block_hash,
        card_hash: checkpointData.card_hash || '',
        values_hash: checkpointData.values_hash || '',
        model: checkpointData.model,
      }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.error(`[gateway/proof] deferProof DB INSERT failed: ${res.status} ${body}`);
    }
  } catch (err) {
    console.error(`[gateway/proof] deferProof DB INSERT error:`, err);
  }
}

/**
 * Submit a metering event for billing. Non-blocking, fail-open.
 */
export async function submitMeteringEvent(
  agentId: string,
  checkpointId: string,
  source: string,
  env: Env
): Promise<void> {
  try {
    // Resolve agent → billing account
    const rpcResponse = await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/get_billing_account_for_agent`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ p_agent_id: agentId }),
    });

    if (!rpcResponse.ok) {
      console.warn(`[gateway/metering] Failed to resolve billing account for agent ${agentId}`);
      return;
    }

    const result = (await rpcResponse.json()) as { account_id: string | null };
    if (!result.account_id) return;

    // Generate event ID using crypto.getRandomValues
    const eventIdSuffix = randomHex(8);

    // Insert metering event
    const insertResponse = await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/metering_events`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        event_id: `me-${eventIdSuffix}`,
        account_id: result.account_id,
        agent_id: agentId,
        event_type: 'integrity_check',
        metadata: { checkpoint_id: checkpointId, source },
      }),
    });

    if (!insertResponse.ok) {
      console.warn(`[gateway/metering] Failed to insert metering event: ${insertResponse.status}`);
    }
  } catch (error) {
    console.warn('[gateway/metering] Error submitting metering event:', error);
  }
}

// ============================================================================
// Wave 3: Conscience Nudge Functions
// ============================================================================

/**
 * Build the text injected into the system prompt when delivering a nudge.
 * IMPORTANT: No PII, no specific data — generic concern categories only.
 */
function buildNudgeText(
  nudges: Array<{ id: string; checkpoint_id: string; concerns_summary: string }>
): string {
  const header = '[INTEGRITY NOTICE — Conscience Protocol]';
  const lines = nudges.map(
    (n) =>
      `Your previous response (checkpoint ${n.checkpoint_id}) was flagged as a boundary violation.\nConcern: ${n.concerns_summary}\nReview your approach and self-correct. This notice is visible in your transparency timeline.`
  );
  return `${header}\n${lines.join('\n\n')}`;
}

/**
 * Inject nudge text into the request body's system parameter.
 * Handles string, array-of-content-blocks, or absent system field.
 */
function injectNudgeIntoSystem(
  requestBody: Record<string, any>,
  nudgeText: string
): void {
  const existing = requestBody.system;
  if (!existing) {
    requestBody.system = nudgeText;
  } else if (typeof existing === 'string') {
    requestBody.system = `${existing}\n\n${nudgeText}`;
  } else if (Array.isArray(existing)) {
    existing.push({ type: 'text', text: nudgeText });
  }
}

/**
 * Inject nudge text into the request body in a provider-appropriate way.
 * - Anthropic: inject into system parameter
 * - OpenAI: prepend as a system message in the messages array
 * - Gemini: no-op (format differs, skipped for now)
 */
function injectNudgeForProvider(
  requestBody: Record<string, any>,
  nudgeText: string,
  provider: GatewayProvider
): void {
  switch (provider) {
    case 'anthropic':
      injectNudgeIntoSystem(requestBody, nudgeText);
      break;
    case 'openai':
      if (!requestBody.messages) {
        requestBody.messages = [];
      }
      requestBody.messages.unshift({ role: 'system', content: nudgeText });
      break;
    case 'gemini':
      // No-op for now — Gemini format differs
      break;
  }
}

/**
 * Query pending nudges for an agent and inject them into the request body.
 * Returns the IDs of injected nudges (for later marking as delivered).
 * Fail-open: errors logged, request proceeds unmodified.
 */
async function injectPendingNudges(
  requestBody: Record<string, any>,
  agentId: string,
  enforcementMode: string,
  env: Env,
  provider: GatewayProvider = 'anthropic',
  options?: { includePreemptive?: boolean }
): Promise<string[]> {
  const shouldInject =
    enforcementMode === 'nudge' ||
    enforcementMode === 'enforce' ||
    options?.includePreemptive === true;
  if (!shouldInject) {
    return [];
  }

  try {
    const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString();
    const response = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/enforcement_nudges?agent_id=eq.${agentId}&status=eq.pending&created_at=gte.${fourHoursAgo}&order=created_at.asc&limit=5`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!response.ok) {
      console.warn(`[gateway/nudge] Failed to fetch pending nudges: ${response.status}`);
      return [];
    }

    const nudges = (await response.json()) as Array<{
      id: string;
      checkpoint_id: string;
      concerns_summary: string;
    }>;

    if (nudges.length === 0) return [];

    const nudgeText = buildNudgeText(nudges);
    injectNudgeForProvider(requestBody, nudgeText, provider);
    console.log(`[gateway/nudge] Injected ${nudges.length} nudge(s) for ${agentId} (provider: ${provider})`);

    return nudges.map((n) => n.id);
  } catch (error) {
    console.error('[gateway/nudge] Error injecting nudges (fail-open):', error);
    return [];
  }
}

/**
 * Create a pending nudge record for a boundary violation.
 * Called when enforcement mode is 'nudge' or 'enforce'.
 */
async function createPendingNudge(
  checkpoint: IntegrityCheckpoint,
  agentId: string,
  sessionId: string,
  env: Env
): Promise<void> {
  try {
    const nudgeId = `nudge-${randomHex(8)}`;
    const concerns = checkpoint.concerns || [];
    const concernsSummary = concerns.length > 0
      ? concerns.map((c: any) => `${c.category || 'unknown'}: ${c.description || 'unspecified'}`).join('; ')
      : 'Boundary violation detected';
    const nudgeContent = buildNudgeText([{
      id: nudgeId,
      checkpoint_id: checkpoint.checkpoint_id,
      concerns_summary: concernsSummary,
    }]);

    const response = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/enforcement_nudges`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({
          id: nudgeId,
          agent_id: agentId,
          checkpoint_id: checkpoint.checkpoint_id,
          session_id: sessionId,
          status: 'pending',
          nudge_content: nudgeContent,
          concerns_summary: concernsSummary,
        }),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.warn(`[gateway/nudge] Failed to create nudge: ${response.status} - ${errorText}`);
    } else {
      console.log(`[gateway/nudge] Created pending nudge ${nudgeId} for checkpoint ${checkpoint.checkpoint_id}`);
    }
  } catch (error) {
    console.error('[gateway/nudge] Error creating nudge:', error);
  }
}

/**
 * Reusable attestation: Ed25519 signing, chain hash, Merkle tree, certificate.
 * Called from both the non-streaming and streaming (background) AIP paths.
 * Fail-open: returns undefined on any error.
 */
async function attestCheckpoint(
  checkpoint: IntegrityCheckpoint,
  agent: { id: string },
  sessionId: string,
  thinkingHash: string,
  card: AIPAlignmentCard,
  conscienceValues: ConscienceValue[],
  windowCheckpoints: Array<{ checkpoint_id: string; verdict: string; reasoning_summary: string }>,
  quotaContext: QuotaContext,
  env: Env
): Promise<AttestationData | undefined> {
  const attestationEnabled = quotaContext.feature_flags?.cryptographic_attestation !== false;
  try {
    const signingKeyHex = env.ED25519_SIGNING_KEY;
    if (!signingKeyHex || !attestationEnabled) return undefined;

    const signingKeyId = env.ED25519_KEY_ID || 'key-001';

    // 1. Compute input commitment over analysis inputs
    const inputCommitment = await computeInputCommitment({
      card: card as unknown as { card_id: string; values: unknown[]; [key: string]: unknown },
      conscienceValues: (conscienceValues || []) as Array<{ type: string; content: string; id?: string }>,
      windowContext: windowCheckpoints,
      modelVersion: 'claude-haiku-4-5-20251001',
      promptTemplateVersion: '1.0.0',
    });

    // 2. Fetch previous chain hash (genesis if first checkpoint)
    const prevChainHash = await fetchPrevChainHash(agent.id, sessionId, env);

    // 3. Compute chain hash linking to previous checkpoint
    const chainHash = await computeChainHash({
      prevChainHash,
      checkpointId: checkpoint.checkpoint_id,
      verdict: checkpoint.verdict,
      thinkingBlockHash: thinkingHash,
      inputCommitment,
      timestamp: checkpoint.timestamp,
    });

    // 4. Build canonical payload and sign with Ed25519
    const signedPayload = buildSignedPayload({
      checkpointId: checkpoint.checkpoint_id,
      agentId: checkpoint.agent_id,
      verdict: checkpoint.verdict,
      thinkingBlockHash: thinkingHash,
      inputCommitment,
      chainHash,
      timestamp: checkpoint.timestamp,
    });
    const secretKey = loadSigningKeyFromHex(signingKeyHex);
    const signatureValue = await ed25519Sign(signedPayload, secretKey);

    // 5. Merkle tree update — append leaf and recompute root
    const leafHash = computeLeafHash({
      checkpointId: checkpoint.checkpoint_id,
      verdict: checkpoint.verdict,
      thinkingBlockHash: thinkingHash,
      chainHash,
      timestamp: checkpoint.timestamp,
    });
    const existingLeaves = await fetchMerkleTreeLeaves(agent.id, env);
    const allLeaves = [...existingLeaves, leafHash];
    const newTreeState = buildTreeState(allLeaves);
    const merkleLeafIndex = allLeaves.length - 1;

    // Fire-and-forget: update Merkle tree in DB
    upsertMerkleTree(
      agent.id,
      newTreeState.root,
      newTreeState.depth,
      newTreeState.leafCount,
      leafHash,
      env
    );

    // 6. Generate certificate ID
    const certificateId = generateCertificateId();

    const attestation: AttestationData = {
      input_commitment: inputCommitment,
      chain_hash: chainHash,
      prev_chain_hash: prevChainHash,
      merkle_leaf_index: merkleLeafIndex,
      certificate_id: certificateId,
      signature: signatureValue,
      signing_key_id: signingKeyId,
    };

    console.log(`[attestation] ${checkpoint.checkpoint_id} cert=${certificateId}`);
    return attestation;
  } catch (attestError) {
    const errMsg = attestError instanceof Error ? `${attestError.message}\n${attestError.stack}` : String(attestError);
    console.warn('[gateway/attestation] Attestation failed (fail-open):', errMsg);
    return undefined;
  }
}

/**
 * Check if an agent should be auto-contained based on consecutive boundary violations.
 * Pauses the agent and logs the containment action.
 */
async function checkAutoContainment(
  agentId: string,
  sessionId: string,
  checkpoint: IntegrityCheckpoint,
  env: Env
): Promise<void> {
  try {
    const agentRes = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/agents?id=eq.${agentId}&select=auto_containment_threshold,containment_status`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!agentRes.ok) return;

    const agents = (await agentRes.json()) as Array<Record<string, unknown>>;
    if (agents.length === 0) return;

    const agent = agents[0];
    const threshold = agent.auto_containment_threshold as number | null;
    const currentStatus = agent.containment_status as string;

    if (!threshold || currentStatus === 'paused' || currentStatus === 'killed') return;

    const checkpointRes = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/integrity_checkpoints?agent_id=eq.${agentId}&order=created_at.desc&limit=${threshold + 5}&select=verdict`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!checkpointRes.ok) return;

    const checkpoints = (await checkpointRes.json()) as Array<{ verdict: string }>;

    let consecutiveCount = 0;
    for (const cp of checkpoints) {
      if (cp.verdict === 'boundary_violation') {
        consecutiveCount++;
      } else {
        break;
      }
    }

    if (consecutiveCount < threshold) return;

    console.log(`[gateway/containment] Auto-pausing agent ${agentId}: ${consecutiveCount} consecutive boundary violations (threshold: ${threshold})`);

    const now = new Date().toISOString();
    const reason = `Auto-contained: ${consecutiveCount} consecutive boundary violations`;

    const updateUrl = new URL(`${env.SUPABASE_URL}/rest/v1/agents`);
    updateUrl.searchParams.set('id', `eq.${agentId}`);

    await supabaseFetch(updateUrl.toString(), {
      method: 'PATCH',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        containment_status: 'paused',
        contained_at: now,
        contained_by: 'system',
        containment_reason: reason,
      }),
    });

    const logId = `ctl-${randomHex(6)}`;

    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/agent_containment_log`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        id: logId,
        agent_id: agentId,
        action: 'auto_pause',
        actor: 'system',
        reason,
        previous_status: currentStatus,
        new_status: 'paused',
        metadata: JSON.stringify({ checkpoint_id: checkpoint.checkpoint_id }),
      }),
    });

    // Purge KV cache if available
    if (env.BILLING_CACHE) {
      await env.BILLING_CACHE.delete(`quota:agent:${agentId}`).catch(() => {});
    }

    console.log(`[gateway/containment] Agent ${agentId} auto-paused successfully`);
  } catch (err) {
    console.warn('[gateway/containment] checkAutoContainment error (fail-open):', err);
  }
}

/**
 * Determine whether a nudge should be created based on the agent's nudge strategy.
 */
function shouldCreateNudge(
  agentSettings: AgentSettings | null,
  sessionViolationCount: number
): boolean {
  const strategy = agentSettings?.nudge_strategy || 'always';

  switch (strategy) {
    case 'off':
      return false;
    case 'sampling': {
      const rate = agentSettings?.nudge_rate ?? agentSettings?.proof_rate ?? 100;
      const bytes = new Uint8Array(4);
      crypto.getRandomValues(bytes);
      const rand = (new DataView(bytes.buffer).getUint32(0) / 0xFFFFFFFF) * 100;
      return rand < rate;
    }
    case 'threshold': {
      const threshold = agentSettings?.nudge_threshold ?? 3;
      return sessionViolationCount >= threshold;
    }
    case 'always':
    default:
      return true;
  }
}

/**
 * Count boundary violations in the current session for threshold-based nudging.
 */
async function countSessionViolations(
  agentId: string,
  sessionId: string,
  env: Env
): Promise<number> {
  try {
    const res = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/integrity_checkpoints?agent_id=eq.${agentId}&session_id=eq.${sessionId}&verdict=eq.boundary_violation&select=checkpoint_id`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          Prefer: 'count=exact',
        },
      }
    );
    if (!res.ok) return 0;
    const countHeader = res.headers.get('content-range');
    if (countHeader) {
      const match = countHeader.match(/\/(\d+)/);
      if (match) return parseInt(match[1], 10);
    }
    const data = (await res.json()) as unknown[];
    return data.length;
  } catch {
    return 0;
  }
}

/**
 * Background analysis for tee'd streaming responses.
 * Reads the analysis fork of the stream, parses SSE, extracts thinking,
 * runs the full AIP pipeline with attestation, creates nudges if needed.
 * Entirely fail-open — errors are logged but never affect the client stream.
 */
async function analyzeStreamInBackground(
  stream: ReadableStream,
  provider: string,
  agent: { id: string },
  sessionId: string,
  agentSettings: AgentSettings | null,
  quotaContext: QuotaContext,
  requestBody: Record<string, any> | null,
  otelExporter: ReturnType<typeof createWorkersExporter> | null,
  env: Env,
  /** Canaries already checked inline by the CBD stream transform — skip redundant re-check */
  alreadyCheckedCanaries?: string[],
): Promise<void> {
  try {
    // 1. Read the tee'd stream to completion
    const sseText = await readStreamToText(stream);

    // 2. Parse SSE events
    const parsed = parseSSEEvents(sseText, provider);

    // 3. Skip if no thinking content
    if (!parsed.thinking) {
      console.log(`[gateway/stream-aip] No thinking block in streaming response (provider: ${provider})`);
      return;
    }

    // 4. Fetch alignment data and recent checkpoints in parallel
    const [alignmentData, historicalCheckpoints] = await Promise.all([
      fetchAlignmentData(agent.id, env),
      fetchRecentCheckpoints(agent.id, sessionId, env),
    ]);

    const { card, conscienceValues, enforcementMode } = alignmentData;

    if (!card) {
      console.log('[gateway/stream-aip] No alignment card found, skipping');
      return;
    }

    // ADR-039 Decision 1: integrity_mode === 'off' means the customer / org /
    // platform has opted out of AIP for this agent. Skip the checkpoint
    // entirely — no Haiku call, no DB write, no telemetry.
    if (enforcementMode === 'off') {
      console.log(JSON.stringify({
        event: 'aip_skipped', agent_id: agent.id, reason: 'integrity_mode_off',
      }));
      return;
    }

    const aipCard = mapCardToAIP(card);

    // 5. Create WindowManager and hydrate
    const windowConfig = {
      max_size: 10,
      mode: 'sliding' as const,
      session_boundary: 'reset' as const,
      max_age_seconds: 3600,
    };
    const window = new WindowManager(windowConfig, sessionId);
    for (const cp of historicalCheckpoints) {
      window.push(cp);
    }

    // 6. Hash thinking block + extract output for analysis
    const thinkingHash = await sha256(parsed.thinking);
    const analyzeOutput = agentSettings?.analyze_output === true;
    const outputText = analyzeOutput && parsed.text ? parsed.text : undefined;
    const outputHash = outputText ? await sha256(outputText) : undefined;

    // CBD Canary detection — streaming path (post-assembly check as a belt-and-suspenders backstop).
    // Primary detection: createCBDStreamTransform (inline, aborts stream on hit).
    // This secondary check catches any edge cases the inline transform missed.
    // Skip if the inline transform already checked with the same canary list.
    if (env.BILLING_CACHE && outputText && !alreadyCheckedCanaries) {
      try {
        const streamCanaries = await fetchAgentCanaries(agent.id, env);
        if (streamCanaries.length > 0) {
          const streamTriggered = scanForCanaryUse(outputText, streamCanaries);
          if (streamTriggered) {
            console.log(JSON.stringify({
              event: 'sh_canary_triggered',
              agent_id: agent.id,
              session_id: sessionId,
              path: 'streaming_background',
              canary_prefix: streamTriggered.slice(0, 6) + '****',
            }));
            void markCanaryTriggered(agent.id, streamTriggered, env);
            void logCBDEvaluation(agent.id, sessionId, 'block',
              { CanaryMatcher: 1.0, PatternMatcher: null, SemanticAnalyzer: null },
              ['CanaryMatcher'], 'outbound_stream',
              [{ type: 'data_exfiltration' as ThreatType, confidence: 1.0,
                 reasoning: 'Canary credential detected in streaming response (background check)' }],
              1.0, env);
          }
        }
      } catch { /* fail-open */ }
    }

    // CBD Outbound DLP — streaming path (write to sh_exit_evaluations)
    if (env.SAFE_HOUSE_ENABLED === 'true' && env.BILLING_CACHE && outputText) {
      try {
        const { matches: dlpMatches } = redactDLPMatches(outputText);
        if (dlpMatches.length > 0) {
          void logCBDEvaluation(agent.id, sessionId, 'warn',
            { DLPScanner: 0.9, PatternMatcher: null, SemanticAnalyzer: null },
            ['DLPScanner'], 'outbound',
            dlpMatches.map(m => ({
              type: 'pii_in_inbound' as ThreatType,
              confidence: 0.95,
              reasoning: `Outbound DLP: ${m.type} detected`,
            })),
            0.9, env);
        }
      } catch { /* fail-open */ }
    }

    // CBD Semantic analysis — async, never blocks (checks for laundered outputs, PHI, etc.)
    if (env.SAFE_HOUSE_ENABLED === 'true' && outputText) {
      void runCBDSemanticAnalysis(outputText, agent.id, sessionId, env);
    }

    // 7. Hybrid mode — call hosted /v1/analyze if no local ANTHROPIC_API_KEY
    if (!env.ANTHROPIC_API_KEY && env.MNEMOM_ANALYZE_URL && env.MNEMOM_API_KEY) {
      try {
        const hybridController = new AbortController();
        const hybridTimeout = setTimeout(() => hybridController.abort(), 10000);
        const values: ConscienceValue[] = conscienceValues || [...DEFAULT_CONSCIENCE_VALUES];
        const hybridResponse = await fetch(env.MNEMOM_ANALYZE_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Mnemom-Api-Key': env.MNEMOM_API_KEY,
          },
          body: JSON.stringify({
            thinking_block: parsed.thinking,
            thinking_metadata: { provider, model: requestBody?.model || 'streaming' },
            agent_id: agent.id,
            session_id: sessionId,
            card: aipCard,
            conscience_values: values,
            ...(outputText ? { output_block: outputText } : {}),
            task_context: (() => {
              const desc = card?.extensions?.mnemom?.description || card?.extensions?.mnemom?.role || '';
              return desc ? desc.toString().slice(0, 200) : undefined;
            })(),
            window_context: window.getState().checkpoints.map((cp: IntegrityCheckpoint) => ({
              checkpoint_id: cp.checkpoint_id,
              verdict: cp.verdict,
              reasoning_summary: cp.reasoning_summary,
            })),
            store_checkpoint: true,
          }),
          signal: hybridController.signal,
        });
        clearTimeout(hybridTimeout);

        if (hybridResponse.ok) {
          const hybridResult = (await hybridResponse.json()) as Record<string, unknown>;
          const hybridCheckpoint = hybridResult.checkpoint as IntegrityCheckpoint;

          // Create nudge for violations
          if (
            hybridCheckpoint.verdict === 'boundary_violation' &&
            (enforcementMode === 'nudge' || enforcementMode === 'enforce')
          ) {
            const violationCount = await countSessionViolations(agent.id, sessionId, env);
            if (shouldCreateNudge(agentSettings, violationCount)) {
              await createPendingNudge(hybridCheckpoint, agent.id, sessionId, env);
            }
            await checkAutoContainment(agent.id, sessionId, hybridCheckpoint, env);
          }
          console.log(`[gateway/stream-aip] Hybrid analysis complete: verdict=${hybridCheckpoint.verdict}`);
          return;
        }
        console.error(`[gateway/stream-aip] Hybrid analyze returned ${hybridResponse.status}`);
      } catch (hybridErr) {
        console.error('[gateway/stream-aip] Hybrid analyze failed:', hybridErr);
      }
      return; // fail-open for hybrid
    }

    // 8. Skip if no analysis capability configured
    if (!env.ANTHROPIC_API_KEY) {
      console.log('[gateway/stream-aip] No analysis capability configured, skipping');
      return;
    }

    // 9. Build conscience prompt and call analysis LLM
    const values: ConscienceValue[] = conscienceValues || [...DEFAULT_CONSCIENCE_VALUES];

    const gatewayAgentDesc = card?.extensions?.mnemom?.description
      || card?.extensions?.mnemom?.role
      || '';
    let gatewayUserQuery = '';
    try {
      const msgs = requestBody?.messages;
      if (Array.isArray(msgs) && msgs.length > 0) {
        const lastUserMsg = [...msgs].reverse().find((m: any) => m.role === 'user');
        if (lastUserMsg) {
          const content = typeof lastUserMsg.content === 'string'
            ? lastUserMsg.content
            : Array.isArray(lastUserMsg.content)
              ? lastUserMsg.content.filter((b: any) => b.type === 'text').map((b: any) => b.text).join(' ')
              : '';
          gatewayUserQuery = content.slice(0, 200);
        }
      }
    } catch { /* fail-open */ }

    const gatewayTaskParts = [
      gatewayAgentDesc ? `${gatewayAgentDesc}.` : '',
      gatewayUserQuery ? `User request: ${gatewayUserQuery}` : '',
      parsed.toolCalls.length > 0 ? `RESPONSE TYPE: The agent responded with ${parsed.toolCalls.length} tool call(s): ${parsed.toolCalls.map(t => t.name).join(', ')}. Tool call responses are expected to have minimal visible text output — the agent's action IS the tool invocation. Do not flag low output volume as undeclared intent when tool calls are present.` : '',
    ].filter(Boolean);
    const gatewayTaskContext = gatewayTaskParts.length > 0 ? gatewayTaskParts.join(' ') : undefined;

    // Retrieve cached Safe House result for this session (written during pre-check, Phase 0.5)
    const cachedCFDResult = await env.BILLING_CACHE?.get(`sh:result:${sessionId}:latest`)
      .then(raw => raw ? JSON.parse(raw) as SafeHouseDecision : null)
      .catch(() => null) ?? null;
    const cfdThreatContext = cachedCFDResult ? buildThreatContextForAIP(cachedCFDResult) : undefined;
    const enrichedTaskContext = [gatewayTaskContext, cfdThreatContext].filter(Boolean).join('\n\n') || undefined;

    const prompt = buildConsciencePrompt({
      card: aipCard,
      conscienceValues: values,
      windowContext: window.getState().checkpoints,
      thinkingBlock: parsed.thinking,
      taskContext: enrichedTaskContext,
      ...(outputText ? { outputBlock: outputText, outputTokenBudget: DEFAULT_OUTPUT_TOKEN_BUDGET } : {}),
    });

    // Call analysis LLM (Haiku)
    console.log(`[gateway/stream-aip] Calling analysis LLM for agent=${agent.id} session=${sessionId} thinking_chars=${parsed.thinking.length} output_analysis=${!!outputText}`);
    const analysisStartTime = Date.now();
    const rawAnalysisResponse = await callAnalysisLLM(prompt.system, prompt.user, env, { analyzeOutput });
    const analysisDurationMs = Date.now() - analysisStartTime;

    const jsonMatch = rawAnalysisResponse.match(/\{[\s\S]*\}/);
    const analysisResponseText = jsonMatch ? sanitizeJson(jsonMatch[0]) : rawAnalysisResponse;
    console.log(`[gateway/stream-aip] Analysis complete in ${analysisDurationMs}ms, json_extracted=${!!jsonMatch}`);

    // 10. Build checkpoint
    const windowState = window.getState();
    const checkpoint = checkIntegrity({
      analysisResponse: analysisResponseText,
      thinking: {
        hash: thinkingHash,
        provider,
        model: 'streaming',
        tokensOriginal: prompt.originalTokens,
        tokensAnalyzed: prompt.analyzedTokens,
        truncated: prompt.truncated,
        confidence: 1.0,
      },
      ...(outputHash && prompt.outputOriginalTokens != null ? {
        output: {
          hash: outputHash,
          tokensOriginal: prompt.outputOriginalTokens,
          tokensAnalyzed: prompt.outputAnalyzedTokens ?? 0,
          truncated: prompt.outputTruncated ?? false,
        },
      } : {}),
      agentId: agent.id,
      cardId: aipCard.card_id,
      sessionId,
      windowPosition: {
        index: windowState.size,
        window_size: windowState.size + 1,
      },
      analysisModel: 'claude-haiku-4-5-20251001',
      analysisDurationMs,
    });

    window.push(checkpoint);
    const summary = window.getSummary();
    const signal = buildSignal(checkpoint, summary);

    if (otelExporter) {
      otelExporter.recordIntegrityCheck(signal);
    }

    // 11. Detect drift
    let driftState: DriftState = createDriftState();
    const driftResult = detectIntegrityDrift(
      driftState,
      checkpoint,
      window.getState().checkpoints,
    );
    driftState = driftResult.state;

    if (driftResult.alert) {
      summary.drift_alert_active = true;
    }

    // 12. Attestation
    const windowContext = [
      ...window.getState().checkpoints.map((cp: IntegrityCheckpoint) => ({
        checkpoint_id: cp.checkpoint_id,
        verdict: cp.verdict,
        reasoning_summary: cp.reasoning_summary,
      })),
      ...(cachedCFDResult ? [{
        checkpoint_id: `sh:${sessionId}:latest`,
        verdict: cachedCFDResult.verdict as string,
        reasoning_summary: `Safe House pre-screen: risk=${cachedCFDResult.overall_risk.toFixed(2)} threats=${cachedCFDResult.threats.map((t: { type: string }) => t.type).join(',')}`,
      }] : []),
    ];
    const attestation = await attestCheckpoint(
      checkpoint, agent, sessionId, thinkingHash,
      aipCard, values, windowContext, quotaContext, env
    );

    // 13. Store checkpoint, submit metering, deliver webhooks
    await storeCheckpoint(checkpoint, 'gateway', env, attestation);

    await submitMeteringEvent(agent.id, checkpoint.checkpoint_id, 'gateway', env);
    await deliverWebhooks(checkpoint, env);
    if (otelExporter) {
      await otelExporter.flush();
    }

    // 13b. Request ZK proof if enabled
    // Streaming path has no policy eval, so card_gaps are unknown.
    // Defer all streaming boundary violations to DDR reconciliation,
    // which will classify as card_gap/noise (skip) or aip_miss (prove).
    const proofDecision = checkpoint.verdict === 'boundary_violation'
      ? 'deferred' as const
      : shouldProve(checkpoint, agentSettings, null);
    if (proofDecision === 'prove') {
      await requestProof(
        checkpoint.checkpoint_id,
        {
          analysis_response_text: analysisResponseText,
          thinking_block_hash: thinkingHash,
          card_hash: await sha256(JSON.stringify(aipCard)),
          values_hash: await sha256(JSON.stringify(values)),
          model: 'streaming',
        },
        attestation ? { input_commitment: attestation.input_commitment } : undefined,
        env,
      ).catch(() => { /* fail-open */ });
    } else if (proofDecision === 'deferred') {
      await deferProof(
        checkpoint.checkpoint_id,
        {
          analysis_response_text: analysisResponseText,
          thinking_block_hash: thinkingHash,
          card_hash: await sha256(JSON.stringify(aipCard)),
          values_hash: await sha256(JSON.stringify(values)),
          model: 'streaming',
        },
        env,
      ).catch(() => { /* fail-open */ });
    }

    // 14. Create nudge for boundary violations
    if (
      checkpoint.verdict === 'boundary_violation' &&
      (enforcementMode === 'nudge' || enforcementMode === 'enforce')
    ) {
      const violationCount = await countSessionViolations(agent.id, sessionId, env);
      if (shouldCreateNudge(agentSettings, violationCount)) {
        await createPendingNudge(checkpoint, agent.id, sessionId, env);
      }
      await checkAutoContainment(agent.id, sessionId, checkpoint, env);
    }

    console.log(`[gateway/stream-aip] Analysis complete: verdict=${checkpoint.verdict}, cert=${attestation?.certificate_id || 'none'}`);
  } catch (error) {
    console.error('[gateway/stream-aip] Background analysis failed (fail-open):', error);
  }
}

/**
 * Mark nudges as delivered after successful injection.
 * Called via ctx.waitUntil() after the forward completes.
 */
async function markNudgesDelivered(
  nudgeIds: string[],
  sessionId: string,
  env: Env
): Promise<void> {
  if (nudgeIds.length === 0) return;

  try {
    for (const nudgeId of nudgeIds) {
      const response = await supabaseFetch(
        `${env.SUPABASE_URL}/rest/v1/enforcement_nudges?id=eq.${nudgeId}`,
        {
          method: 'PATCH',
          headers: {
            apikey: env.SUPABASE_SECRET_KEY,
            Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=minimal',
          },
          body: JSON.stringify({
            status: 'delivered',
            delivered_at: new Date().toISOString(),
            delivery_session_id: sessionId,
          }),
        }
      );

      if (!response.ok) {
        console.warn(`[gateway/nudge] Failed to mark nudge ${nudgeId} delivered: ${response.status}`);
      }
    }
    console.log(`[gateway/nudge] Marked ${nudgeIds.length} nudge(s) as delivered`);
  } catch (error) {
    console.error('[gateway/nudge] Error marking nudges delivered:', error);
  }
}

/**
 * Call analysis LLM (Haiku) with system+user prompt.
 * POSTs directly to Anthropic API (NOT through the gateway — that would be recursive).
 * Uses AbortController with 10000ms timeout.
 */
async function callAnalysisLLM(
  system: string,
  user: string,
  env: Env,
  options?: { analyzeOutput?: boolean }
): Promise<string> {
  // Circuit breaker: skip calls during sustained API failures
  if (analysisCircuitBreaker.isOpen) {
    if (Date.now() - analysisCircuitBreaker.lastFailure > analysisCircuitBreaker.resetAfterMs) {
      analysisCircuitBreaker.isOpen = false;
      analysisCircuitBreaker.failures = 0;
    } else {
      throw new Error('Analysis circuit breaker open — skipping call');
    }
  }

  const controller = new AbortController();
  const timeoutMs = options?.analyzeOutput ? 15000 : 10000;
  const maxTokens = options?.analyzeOutput ? 2048 : 1024;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: maxTokens,
        system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
        messages: [{ role: 'user', content: user }],
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Analysis LLM returned ${response.status}: ${errorText}`);
    }

    const body = (await response.json()) as Record<string, unknown>;
    const stopReason = body.stop_reason as string | undefined;
    const content = body.content as Array<Record<string, unknown>> | undefined;

    if (stopReason === 'max_tokens') {
      console.warn(`[gateway/aip] Analysis LLM hit max_tokens — response may be truncated`);
    }

    if (!content || content.length === 0) {
      throw new Error('Analysis LLM returned empty content');
    }

    const textBlock = content.find((b) => b.type === 'text');
    if (!textBlock || typeof textBlock.text !== 'string') {
      throw new Error('Analysis LLM returned no text content');
    }

    // Reset circuit breaker on success
    analysisCircuitBreaker.failures = 0;

    return textBlock.text;
  } catch (error) {
    // Track failures for circuit breaker
    const errMsg = error instanceof Error ? error.message : String(error);
    console.error(`[gateway/aip] callAnalysisLLM failed (attempt ${analysisCircuitBreaker.failures + 1}): ${errMsg}`);
    analysisCircuitBreaker.failures++;
    analysisCircuitBreaker.lastFailure = Date.now();
    if (analysisCircuitBreaker.failures >= analysisCircuitBreaker.threshold) {
      analysisCircuitBreaker.isOpen = true;
      console.warn(`[gateway/aip] Circuit breaker OPEN after ${analysisCircuitBreaker.failures} consecutive failures`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Call Haiku for Safe House L2 threat analysis.
 * Uses the existing Anthropic API key — NOT routed through CF AI Gateway
 * (to avoid the gateway calling itself in an infinite loop).
 * Separate from the AIP circuit breaker — Safe House failures never block AIP.
 * Fail-open: returns null on any error.
 */
async function callSHAnalysisLLM(
  content: string,
  sourceType: string,
  env: Env
): Promise<string | null> {
  if (!env.ANTHROPIC_API_KEY) return null;

  const systemPrompt = buildSHAnalysisPrompt();
  const userPrompt = buildSHUserPrompt(content, sourceType);

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8s timeout for Safe House
    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 512,
          system: [{ type: 'text', text: systemPrompt, cache_control: { type: 'ephemeral' } }],
          messages: [{ role: 'user', content: userPrompt }],
        }),
        signal: controller.signal,
      });

      if (!response.ok) return null;
      const body = (await response.json()) as Record<string, unknown>;
      const content_blocks = body.content as Array<Record<string, unknown>> | undefined;
      const textBlock = content_blocks?.find(b => b.type === 'text');
      return typeof textBlock?.text === 'string' ? textBlock.text : null;
    } finally {
      clearTimeout(timeoutId);
    }
  } catch {
    return null;
  }
}

/**
 * HMAC sign payload using Web Crypto API (Cloudflare Workers compatible).
 */
async function hmacSign(secret: string, payload: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Deliver webhooks for a checkpoint (Wave 4).
 *
 * 1. Query registered webhooks for the agent
 * 2. Filter by matching event types
 * 3. Sign and POST each webhook with retry
 * 4. Track deliveries in aip_webhook_deliveries table
 * 5. Increment failure_count on registration if all retries exhausted
 */
async function deliverWebhooks(
  checkpoint: IntegrityCheckpoint,
  env: Env
): Promise<void> {
  try {
    // 1. Fetch webhook registrations for this agent
    const regResponse = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/aip_webhook_registrations?agent_id=eq.${checkpoint.agent_id}&select=*`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!regResponse.ok) {
      console.warn(`[gateway/webhook] Failed to fetch registrations: ${regResponse.status}`);
      return;
    }

    const registrations = (await regResponse.json()) as Array<{
      id: string;
      agent_id: string;
      callback_url: string;
      secret: string;
      event_types: string[];
      failure_count: number;
    }>;

    if (registrations.length === 0) return;

    // 2. Determine event type for this checkpoint
    const eventType = `verdict.${checkpoint.verdict}`;

    // 3. Filter registrations by matching event types
    const matchingRegistrations = registrations.filter(reg => {
      return reg.event_types.some(et =>
        et === '*' ||
        et === 'verdict.*' ||
        et === eventType
      );
    });

    if (matchingRegistrations.length === 0) return;

    // 4. Build webhook payload
    const webhookPayload = {
      event: eventType,
      timestamp: new Date().toISOString(),
      checkpoint: {
        checkpoint_id: checkpoint.checkpoint_id,
        agent_id: checkpoint.agent_id,
        verdict: checkpoint.verdict,
        concerns: checkpoint.concerns,
        reasoning_summary: checkpoint.reasoning_summary,
      },
    };

    const payloadString = JSON.stringify(webhookPayload);

    // 5. Deliver to each matching registration
    for (const reg of matchingRegistrations) {
      let delivered = false;
      let lastError: string | null = null;
      const retryDelays = [...WEBHOOK_RETRY_DELAYS_MS];

      // Sign the payload
      const signature = await hmacSign(reg.secret, payloadString);

      // Initial attempt + retries
      for (let attempt = 0; attempt <= retryDelays.length; attempt++) {
        try {
          const webhookResponse = await fetch(reg.callback_url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-AIP-Signature': `sha256=${signature}`,
              'X-AIP-Version': AIP_VERSION,
            },
            body: payloadString,
          });

          if (webhookResponse.ok || (webhookResponse.status >= 200 && webhookResponse.status < 300)) {
            delivered = true;
            break;
          }

          lastError = `HTTP ${webhookResponse.status}`;
        } catch (error) {
          lastError = error instanceof Error ? error.message : String(error);
        }

        // Wait before retry (skip delay after last attempt)
        if (attempt < retryDelays.length) {
          await new Promise(resolve => setTimeout(resolve, retryDelays[attempt]));
        }
      }

      // 6. Track delivery in aip_webhook_deliveries
      try {
        await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/aip_webhook_deliveries`, {
          method: 'POST',
          headers: {
            apikey: env.SUPABASE_SECRET_KEY,
            Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=minimal',
          },
          body: JSON.stringify({
            id: `del-${randomHex(12)}`,
            registration_id: reg.id,
            checkpoint_id: checkpoint.checkpoint_id,
            event_type: eventType,
            delivered,
            attempts: delivered ? 1 : retryDelays.length + 1,
            last_error: lastError,
          }),
        });
      } catch (error) {
        console.warn(`[gateway/webhook] Failed to record delivery:`, error);
      }

      // 7. On all retries exhausted, increment failure_count
      if (!delivered) {
        console.warn(
          `[gateway/webhook] All retries exhausted for registration ${reg.id} -> ${reg.callback_url}`
        );
        try {
          await supabaseFetch(
            `${env.SUPABASE_URL}/rest/v1/aip_webhook_registrations?id=eq.${reg.id}`,
            {
              method: 'PATCH',
              headers: {
                apikey: env.SUPABASE_SECRET_KEY,
                Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                failure_count: reg.failure_count + 1,
              }),
            }
          );
        } catch (error) {
          console.warn(`[gateway/webhook] Failed to increment failure_count:`, error);
        }
      }
    }
  } catch (error) {
    console.error('[gateway/webhook] Webhook delivery failed:', error);
  }
}

/**
 * Deliver Safe House-specific webhook events to registered endpoints.
 * Reuses the same aip_webhook_registrations table and HMAC signing.
 * Safe House events use event types: safe_house.evaluation.warn, safe_house.evaluation.quarantine,
 * safe_house.evaluation.block, safe_house.canary.triggered, safe_house.session.escalated
 */
async function deliverSHWebhooks(
  decision: SafeHouseDecision,
  agentId: string,
  sessionId: string,
  env: Env
): Promise<void> {
  // Only deliver for non-pass verdicts
  if (decision.verdict === 'pass') return;

  try {
    // Fetch registrations that have Safe House events enabled
    const regResponse = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/aip_webhook_registrations?agent_id=eq.${agentId}&select=*`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );

    if (!regResponse.ok) return;
    const registrations = (await regResponse.json()) as Array<{
      id: string;
      agent_id: string;
      callback_url: string;
      secret: string;
      event_types: string[];
      failure_count: number;
    }>;
    if (registrations.length === 0) return;

    // Map verdict to event type
    const eventType = decision.verdict === 'quarantine' || decision.verdict === 'block'
      ? `safe_house.evaluation.${decision.verdict}`
      : 'safe_house.evaluation.warn';

    // Filter registrations that subscribe to this event type
    const matching = registrations.filter(reg =>
      reg.event_types.some(et =>
        et === '*' || et === 'safe_house.*' || et === eventType
      )
    );
    if (matching.length === 0) return;

    // Build payload
    const topThreat = decision.threats.sort((a, b) => b.confidence - a.confidence)[0];
    const webhookPayload = {
      event: eventType,
      timestamp: new Date().toISOString(),
      agent_id: agentId,
      session_id: sessionId,
      data: {
        verdict: decision.verdict,
        quarantine_id: decision.quarantine_id ?? null,
        overall_risk: decision.overall_risk,
        top_threat: topThreat
          ? { type: topThreat.type, confidence: topThreat.confidence, reasoning: topThreat.reasoning }
          : null,
        detection_sources: decision.detection_sources,
        ...(decision.quarantine_id
          ? { review_url: `https://app.mnemom.com/safe-house/quarantine/${decision.quarantine_id}` }
          : {}),
      },
    };
    const payloadString = JSON.stringify(webhookPayload);

    // Deliver to each matching registration (same retry pattern as AIP webhooks)
    for (const reg of matching) {
      let delivered = false;
      let lastError: string | null = null;
      const retryDelays = [...WEBHOOK_RETRY_DELAYS_MS];
      const signature = await hmacSign(reg.secret, payloadString);

      for (let attempt = 0; attempt <= retryDelays.length; attempt++) {
        if (attempt > 0) {
          await new Promise(r => setTimeout(r, retryDelays[attempt - 1]));
        }
        try {
          const webhookResponse = await fetch(reg.callback_url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-AIP-Signature': `sha256=${signature}`,
              'X-Safe-House-Event': eventType,
            },
            body: payloadString,
          });
          if (webhookResponse.ok) { delivered = true; break; }
          lastError = `HTTP ${webhookResponse.status}`;
        } catch (err) {
          lastError = err instanceof Error ? err.message : 'Unknown error';
        }
      }

      // Track delivery (fire-and-forget)
      supabaseFetch(`${env.SUPABASE_URL}/rest/v1/aip_webhook_deliveries`, {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({
          registration_id: reg.id,
          event_type: eventType,
          payload: webhookPayload,
          delivered,
          error: lastError,
          attempts: delivered ? 1 : retryDelays.length + 1,
        }),
      }).catch(() => {});
    }
  } catch (err) {
    console.warn('[safe-house/webhooks] Error delivering Safe House webhooks:', err);
  }
}

// ============================================================================
// OTel Exporter
// ============================================================================

function createOTelExporter(env: Env) {
  if (!env.OTLP_ENDPOINT) return null;
  return createWorkersExporter({
    endpoint: env.OTLP_ENDPOINT,
    authorization: env.OTLP_AUTH,
    serviceName: 'mnemom-gateway',
  });
}

// ============================================================================
// Health Check
// ============================================================================

/**
 * Handle the health check endpoint.
 */
export function handleHealthCheck(env: Env): Response {
  return new Response(
    JSON.stringify({
      status: 'ok',
      version: env.GATEWAY_VERSION,
      timestamp: new Date().toISOString(),
      aip_enabled: (env.AIP_ENABLED ?? 'true') !== 'false',
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}

// ============================================================================
// Models Endpoint
// ============================================================================

/**
 * Handle the /models.json endpoint.
 * Returns a static model registry as JSON.
 */
function handleModelsEndpoint(env: Env): Response {
  const models = {
    anthropic: [
      { id: 'claude-sonnet-4-20250514', name: 'Claude Sonnet 4', thinking: true },
      { id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet', thinking: true },
      { id: 'claude-haiku-4-5-20251001', name: 'Claude Haiku 4.5', thinking: true },
      { id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', thinking: false },
    ],
    openai: [
      { id: 'gpt-5', name: 'GPT-5', thinking: true },
      { id: 'gpt-5-mini', name: 'GPT-5 Mini', thinking: true },
      { id: 'gpt-4o', name: 'GPT-4o', thinking: false },
      { id: 'o3', name: 'o3', thinking: true },
      { id: 'o3-mini', name: 'o3 Mini', thinking: true },
    ],
    gemini: [
      { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', thinking: true },
      { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', thinking: true },
      { id: 'gemini-3-pro', name: 'Gemini 3 Pro', thinking: true },
      { id: 'gemini-3-flash', name: 'Gemini 3 Flash', thinking: true },
    ],
  };

  return new Response(JSON.stringify(models), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}

// ============================================================================
// Multi-Provider Proxy Handler (Waves 1, 2, 3, 4)
// ============================================================================

/**
 * Extract API key from the request based on provider conventions.
 * - Anthropic: x-api-key header
 * - OpenAI: Authorization: Bearer <key> header
 * - Gemini: x-goog-api-key header
 */
function extractApiKey(request: Request, provider: GatewayProvider): string | null {
  switch (provider) {
    case 'anthropic':
      return request.headers.get('x-api-key');
    case 'openai': {
      const authHeader = request.headers.get('authorization');
      if (!authHeader) return null;
      const match = authHeader.match(/^Bearer\s+(.+)$/i);
      return match ? match[1] : null;
    }
    case 'gemini':
      return request.headers.get('x-goog-api-key');
  }
}

/**
 * Inject thinking/reasoning configuration into the request body
 * based on the provider. (Wave 1)
 *
 * - Anthropic: thinking.type = 'enabled', budget_tokens = 10000
 * - OpenAI: reasoning_effort = 'medium' (for GPT-5 models)
 * - Gemini 2.5: thinkingBudget + includeThoughts
 * - Gemini 3: thinkingLevel = 'HIGH'
 */
function injectThinkingForProvider(
  requestBody: Record<string, any>,
  provider: GatewayProvider,
  thinkingBudget: number = 30000
): void {
  switch (provider) {
    case 'anthropic':
      if (!requestBody.thinking) {
        requestBody.thinking = { type: 'enabled', budget_tokens: thinkingBudget };
      }
      // Anthropic requires temperature=1 and max_tokens > budget_tokens
      // when thinking is enabled. Since the gateway injects thinking,
      // enforce the constraints here so clients don't need to know about it.
      if (requestBody.thinking?.type === 'enabled') {
        delete requestBody.temperature;
        const budget = requestBody.thinking.budget_tokens || thinkingBudget;
        if (typeof requestBody.max_tokens === 'number' && requestBody.max_tokens <= budget) {
          requestBody.max_tokens = budget + 1024;
        }
      }
      break;
    case 'openai': {
      const model = requestBody.model || '';
      if (typeof model === 'string' && model.includes('gpt-5')) {
        if (!requestBody.reasoning_effort) {
          requestBody.reasoning_effort = 'medium';
        }
      }
      break;
    }
    case 'gemini': {
      const model = requestBody.model || '';
      if (typeof model === 'string' && model.includes('gemini-3')) {
        // Gemini 3: use thinkingLevel
        requestBody.generationConfig = {
          ...requestBody.generationConfig,
          thinkingConfig: { thinkingLevel: 'HIGH' },
        };
      } else {
        // Gemini 2.5 and other versions: use thinkingBudget
        requestBody.generationConfig = {
          ...requestBody.generationConfig,
          thinkingConfig: { thinkingBudget: 16384, includeThoughts: true },
        };
      }
      break;
    }
  }
}

// ============================================================================
// Policy Engine Functions (CLPI Phase 2)
// ============================================================================

/**
 * Extract tool names from request body for policy evaluation.
 * Handles all three provider formats.
 */
function extractToolsFromRequest(
  requestBody: Record<string, any> | null,
  provider: GatewayProvider
): ToolReference[] {
  if (!requestBody) return [];

  const tools: string[] = [];

  switch (provider) {
    case 'anthropic': {
      // Anthropic: tools[].name
      const anthropicTools = requestBody.tools;
      if (Array.isArray(anthropicTools)) {
        for (const t of anthropicTools) {
          if (t?.name) tools.push(t.name);
        }
      }
      break;
    }
    case 'openai': {
      // OpenAI: tools[].function.name
      const openaiTools = requestBody.tools;
      if (Array.isArray(openaiTools)) {
        for (const t of openaiTools) {
          if (t?.function?.name) tools.push(t.function.name);
        }
      }
      break;
    }
    case 'gemini': {
      // Gemini: tools[].functionDeclarations[].name + flat tools[].name
      const geminiTools = requestBody.tools;
      if (Array.isArray(geminiTools)) {
        for (const t of geminiTools) {
          if (t?.functionDeclarations && Array.isArray(t.functionDeclarations)) {
            for (const fd of t.functionDeclarations) {
              if (fd?.name) tools.push(fd.name);
            }
          }
          if (t?.name) tools.push(t.name);
        }
      }
      break;
    }
  }

  return tools.map((name) => ({ name }));
}

/**
 * Build a synthetic 200 response that names what was prevented when CLPI
 * fails under autonomy_mode=enforce (T0-4, ADR-040).
 *
 * Replaces the prior 403 path. The chat completes 2xx with an
 * assistant-shaped message that explains the prevention; the customer's
 * agent runtime can render it like any other model response. Per-provider
 * shape so customers don't have to special-case the gateway intervention.
 *
 * NOTE: today's CLPI runs on the request's *declared* tool list (before
 * forwarding to the provider), not on the model's emitted tool_use blocks.
 * The "synthetic tool-result" framing in ADR-040 doesn't fit this code
 * path — the model never emits the tool_use to begin with. Returning a
 * text-only assistant message is the honest CAC-compliant alternative:
 * the chat completes, the agent's response names the prevention, no
 * fabricated tool calls.
 *
 * Streaming (`stream: true`) requests today receive the same buffered
 * 403 JSON regardless of mode; this synthetic 200 keeps the same shape
 * (no SSE), preserving the existing contract. SSE-shaped synthesis is
 * a follow-up.
 */
export function buildAutonomyEnforceResponse(
  provider: GatewayProvider,
  evalResult: { verdict: string; violations: Array<{ tool_name?: string; type?: string; reason?: string; rule_id?: string; severity?: string }> },
  requestBody: Record<string, any> | null,
): { body: string; contentType: string } {
  // Compose the agent-facing text. Lists up to three violating tools;
  // names rule_id when present so reviewers can trace back to the card.
  const violations = evalResult.violations.slice(0, 3);
  const violationLines = violations.map((v) => {
    const tool = v.tool_name ? `\`${v.tool_name}\`` : 'a tool';
    const reason = v.reason || v.type || 'policy violation';
    const ruleSuffix = v.rule_id ? ` (rule: ${v.rule_id})` : '';
    return `- ${tool}: ${reason}${ruleSuffix}`;
  });
  const intervention =
    `[Mnemom Intervention: I cannot proceed with this request. ` +
    `My alignment card prevents the following tool${violations.length === 1 ? '' : 's'}:\n` +
    `${violationLines.join('\n')}\n\n` +
    `The tool side effect did not happen. If you'd like to continue, ` +
    `you can either remove the disallowed capabilities from the request ` +
    `or update the alignment card to permit them.]`;

  const requestedModel: string =
    (requestBody && typeof (requestBody as any).model === 'string'
      ? ((requestBody as any).model as string)
      : '') || 'unknown';

  const id = `mn-${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const nowSeconds = Math.floor(Date.now() / 1000);

  switch (provider) {
    case 'anthropic': {
      // Anthropic Messages API non-stream response shape.
      const body = {
        id: `msg_${id}`,
        type: 'message',
        role: 'assistant',
        content: [{ type: 'text', text: intervention }],
        model: requestedModel,
        stop_reason: 'end_turn',
        stop_sequence: null,
        usage: { input_tokens: 0, output_tokens: 0 },
      };
      return { body: JSON.stringify(body), contentType: 'application/json' };
    }
    case 'openai': {
      // OpenAI Chat Completions non-stream response shape.
      const body = {
        id: `chatcmpl-${id}`,
        object: 'chat.completion',
        created: nowSeconds,
        model: requestedModel,
        choices: [
          {
            index: 0,
            message: { role: 'assistant', content: intervention },
            finish_reason: 'stop',
          },
        ],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      };
      return { body: JSON.stringify(body), contentType: 'application/json' };
    }
    case 'gemini': {
      // Gemini generateContent non-stream response shape.
      const body = {
        candidates: [
          {
            content: {
              parts: [{ text: intervention }],
              role: 'model',
            },
            finishReason: 'STOP',
            index: 0,
          },
        ],
        usageMetadata: {
          promptTokenCount: 0,
          candidatesTokenCount: 0,
          totalTokenCount: 0,
        },
      };
      return { body: JSON.stringify(body), contentType: 'application/json' };
    }
  }
}

/**
 * Fetch policy data for an agent from Supabase RPC.
 * Fail-open: returns null on error so agents without policies continue normally.
 */
async function fetchPolicyForAgent(
  agentId: string,
  env: Env,
  linkedAgentId?: string | null
): Promise<{
  orgPolicy: Policy | null;
  agentPolicy: Policy | null;
  exempt: boolean;
  dbPolicyId: string | null;
  dbPolicyVersion: number | null;
} | null> {
  try {
    // If a linked_agent_id exists, try that first (permanent identity link)
    const lookupId = linkedAgentId || agentId;

    const response = await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/get_policy_for_agent`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ p_agent_id: lookupId }),
    });

    if (!response.ok) {
      console.warn(`[gateway/policy] RPC failed for ${lookupId}: ${response.status}`);
      return null;
    }

    const data = await response.json() as Record<string, unknown> | null;
    if (!data) {
      // If we used linkedAgentId and got nothing, try original agentId
      if (linkedAgentId && linkedAgentId !== agentId) {
        return fetchPolicyForAgent(agentId, env);
      }
      return null;
    }

    return {
      orgPolicy: (data.org_policy as Policy) ?? null,
      agentPolicy: (data.agent_policy as Policy) ?? null,
      exempt: (data.exempt as boolean) ?? false,
      dbPolicyId: ((data.agent_policy_id ?? data.org_policy_id) as string) ?? null,
      dbPolicyVersion: ((data.agent_policy_version ?? data.org_policy_version) as number) ?? null,
    };
  } catch (error) {
    console.warn('[gateway/policy] fetchPolicyForAgent failed (fail-open):', error);
    return null;
  }
}

/**
 * Fetch policy by looking up the agent's registered name.
 * Used as fallback when the gateway-generated smolt-* ID has no policy.
 * If a match is found, auto-links the IDs so future lookups are instant.
 * Fail-open: returns null on error.
 */
async function fetchPolicyByAgentName(
  agentName: string,
  currentAgentId: string,
  env: Env
): Promise<{
  orgPolicy: Policy | null;
  agentPolicy: Policy | null;
  exempt: boolean;
  dbPolicyId: string | null;
  dbPolicyVersion: number | null;
} | null> {
  try {
    const headers = {
      apikey: env.SUPABASE_SECRET_KEY,
      Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
      'Content-Type': 'application/json',
    };

    // Look up agents by name
    const lookupResponse = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/agents?name=eq.${encodeURIComponent(agentName)}&select=id`,
      { headers }
    );

    if (!lookupResponse.ok) {
      console.warn(`[gateway/policy] Agent name lookup failed for "${agentName}": ${lookupResponse.status}`);
      return null;
    }

    const agents: { id: string }[] = await lookupResponse.json();
    if (agents.length === 0) return null;

    // Try each matching agent's policy
    for (const candidate of agents) {
      if (candidate.id === currentAgentId) continue; // Skip self
      const result = await fetchPolicyForAgent(candidate.id, env);
      if (result) {
        // Auto-link: PATCH current agent with linked_agent_id for future lookups
        supabaseFetch(
          `${env.SUPABASE_URL}/rest/v1/agents?id=eq.${currentAgentId}`,
          {
            method: 'PATCH',
            headers: { ...headers, 'Prefer': 'return=minimal' },
            body: JSON.stringify({ linked_agent_id: candidate.id }),
          }
        ).catch(() => {}); // Best-effort, don't block
        console.log(`[gateway/policy] Name fallback matched "${agentName}" → ${candidate.id}, linked from ${currentAgentId}`);
        return result;
      }
    }

    return null;
  } catch (error) {
    console.warn('[gateway/policy] fetchPolicyByAgentName failed (fail-open):', error);
    return null;
  }
}

/**
 * Fetch transaction-scoped guardrails for an agent.
 * Fail-open: returns null on error so requests proceed without guardrails.
 */
async function fetchTransactionGuardrails(
  agentId: string,
  transactionId: string,
  env: Env
): Promise<{ policy: Policy; conscience_values: Array<{ id: string; content: string; type: string }> } | null> {
  try {
    // Check KV cache first
    const cacheKey = `txn:${transactionId}:agent:${agentId}`;
    const cached = env.KV ? await env.KV.get(cacheKey, 'json') as {
      policy: Policy;
      conscience_values: Array<{ id: string; content: string; type: string }>;
      expires_at: string;
    } | null : null;

    if (cached) {
      // Check if expired
      if (cached.expires_at && new Date(cached.expires_at).getTime() < Date.now()) {
        return null;
      }
      return { policy: cached.policy, conscience_values: cached.conscience_values };
    }

    // Fall back to Supabase RPC
    const response = await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/get_transaction_guardrails`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ p_transaction_id: transactionId, p_agent_id: agentId }),
    });

    if (!response.ok) {
      console.warn(`[gateway/policy] Transaction guardrails RPC failed for txn=${transactionId} agent=${agentId}: ${response.status}`);
      return null;
    }

    const data = await response.json() as {
      policy: Policy;
      conscience_values: Array<{ id: string; content: string; type: string }>;
      expires_at: string;
    } | null;

    if (!data) return null;

    // Check if expired
    if (data.expires_at && new Date(data.expires_at).getTime() < Date.now()) {
      return null;
    }

    // Cache in KV with 5min TTL
    if (env.KV) {
      await env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 300 });
    }

    return { policy: data.policy, conscience_values: data.conscience_values };
  } catch (error) {
    console.warn('[gateway/policy] fetchTransactionGuardrails failed (fail-open):', error);
    return null;
  }
}

/**
 * Submit a gateway policy evaluation result to Supabase.
 * Non-blocking, fail-open.
 */
async function submitGatewayPolicyEvaluation(
  result: EvaluationResult,
  agentId: string,
  dbPolicyId: string,
  dbPolicyVersion: number,
  env: Env,
  transactionId?: string | null
): Promise<void> {
  try {
    const evalId = `pe-${crypto.randomUUID().slice(0, 8)}`;
    const response = await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/policy_evaluations`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        id: evalId,
        policy_id: dbPolicyId,
        policy_version: dbPolicyVersion,
        agent_id: agentId,
        trace_id: null,
        context: 'gateway',
        verdict: result.verdict,
        violations: result.violations,
        warnings: result.warnings,
        card_gaps: result.card_gaps,
        coverage: result.coverage,
        duration_ms: result.duration_ms,
        dry_run: false,
        ...(transactionId ? { transaction_id: transactionId } : {}),
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.warn(`[gateway/policy] Failed to store evaluation: ${response.status} - ${errorText}`);
    }
  } catch (error) {
    console.warn('[gateway/policy] submitGatewayPolicyEvaluation failed (fail-open):', error);
  }
}

/**
 * Fetch tool_first_seen records for an agent and apply grace period logic.
 * Returns updated violations array with in-grace tools downgraded to warnings.
 */
async function applyGracePeriod(
  agentId: string,
  violations: EvaluationResult['violations'],
  warnings: EvaluationResult['warnings'],
  gracePeriodHours: number,
  env: Env
): Promise<{ violations: EvaluationResult['violations']; warnings: EvaluationResult['warnings'] }> {
  if (violations.length === 0 || gracePeriodHours <= 0) {
    return { violations, warnings };
  }

  const violatingTools = [...new Set(violations.map((v) => v.tool))];

  // Batch-fetch tool_first_seen records for this agent
  let firstSeenMap = new Map<string, string>(); // tool_name -> first_seen_at
  try {
    const toolFilter = violatingTools.map((t) => `"${t}"`).join(',');
    const resp = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/tool_first_seen?agent_id=eq.${agentId}&tool_name=in.(${toolFilter})`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );
    if (resp.ok) {
      const rows = (await resp.json()) as Array<{ tool_name: string; first_seen_at: string }>;
      for (const row of rows) {
        firstSeenMap.set(row.tool_name, row.first_seen_at);
      }
    }
  } catch {
    // Fail-open: no grace period data → violations stand
    return { violations, warnings };
  }

  const now = Date.now();
  const graceMs = gracePeriodHours * 60 * 60 * 1000;
  const remainingViolations: EvaluationResult['violations'] = [];
  const newWarnings = [...warnings];
  const newTools: string[] = [];

  for (const v of violations) {
    const firstSeen = firstSeenMap.get(v.tool);

    if (!firstSeen) {
      // New tool — mark as in-grace, downgrade to warning
      newTools.push(v.tool);
      newWarnings.push({
        type: 'unmapped_tool',
        tool: v.tool,
        reason: `${v.reason} (in grace period — first seen now)`,
      });
    } else if (now - new Date(firstSeen).getTime() < graceMs) {
      // Still within grace period — downgrade to warning
      newWarnings.push({
        type: 'unmapped_tool',
        tool: v.tool,
        reason: `${v.reason} (in grace period — first seen ${firstSeen})`,
      });
    } else {
      // Grace period expired — violation stands
      remainingViolations.push(v);
    }
  }

  // Insert new tools (idempotent — ON CONFLICT DO NOTHING)
  if (newTools.length > 0) {
    try {
      const inserts = newTools.map((t) => ({
        id: `tfs-${crypto.randomUUID().slice(0, 12)}`,
        agent_id: agentId,
        tool_name: t,
        source: 'gateway',
      }));
      await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/tool_first_seen`, {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal,resolution=ignore-duplicates',
        },
        body: JSON.stringify(inserts),
      });
    } catch {
      // Fail-open: insert errors don't block the request
    }
  }

  return { violations: remainingViolations, warnings: newWarnings };
}

// ============================================================================
// Safe House — inbound threat screening helpers
// ============================================================================

/**
 * Fetch Safe House config for an agent (org-level fallback). KV cached 5 min.
 * Requires SAFE_HOUSE_ENABLED='true' env var and BILLING_CACHE binding.
 * Returns disabled default without any fetch in other environments (tests,
 * local dev) to avoid inserting extra calls into test mock sequences.
 */
async function fetchSHConfig(agentId: string, env: Env): Promise<SafeHouseConfig> {
  if (env.SAFE_HOUSE_ENABLED !== 'true' || !env.BILLING_CACHE) return { ...DEFAULT_SAFE_HOUSE_CONFIG };

  // UC-6: prefer the pre-composed canonical protection card. XFD detectors
  // build against the SafeHouseConfig type, so mapCanonicalToSafeHouseConfig
  // is the only adapter that needs to exist at this seam.
  try {
    const canonical = await fetchCanonicalProtectionCard(agentId, env);
    if (canonical) {
      return mapCanonicalToSafeHouseConfig(canonical);
    }
  } catch (err) {
    console.warn(
      `[gateway/safe-house] canonical_protection_cards fetch errored for ${agentId}; falling back:`,
      err instanceof Error ? err.message : err,
    );
  }

  const cacheKey = `sh:config:${agentId}`;
  try {
    const cached = await env.BILLING_CACHE.get(cacheKey);
    if (cached) return JSON.parse(cached) as SafeHouseConfig;
    const resp = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/rpc/get_sh_config_for_agent`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ p_agent_id: agentId }),
      }
    );
    if (!resp.ok) return { ...DEFAULT_SAFE_HOUSE_CONFIG };
    const config = await resp.json() as SafeHouseConfig;
    await env.BILLING_CACHE.put(cacheKey, JSON.stringify(config), { expirationTtl: 300 }).catch(() => {});
    return config;
  } catch {
    return { ...DEFAULT_SAFE_HOUSE_CONFIG };
  }
}

/** Fetch active Safe House threat patterns (KV cached 5 min). */
async function fetchSHThreatPatterns(env: Env): Promise<SafeHouseThreatPattern[]> {
  const cacheKey = 'sh:threat-patterns';
  try {
    if (env.BILLING_CACHE) {
      const cached = await env.BILLING_CACHE.get(cacheKey);
      if (cached) return JSON.parse(cached) as SafeHouseThreatPattern[];
    }
    const resp = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/sh_threat_patterns?label=eq.malicious&is_active=eq.true&select=id,threat_type,label,content,minhash,pattern_family&order=created_at.desc&limit=500`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );
    if (!resp.ok) return [];
    const patterns = await resp.json() as SafeHouseThreatPattern[];
    if (env.BILLING_CACHE) {
      await env.BILLING_CACHE.put(cacheKey, JSON.stringify(patterns), { expirationTtl: 300 }).catch(() => {});
    }
    return patterns;
  } catch {
    return [];
  }
}

// ── Detection recipe index (Stage 5A — Phase 5) ────────────────────────
//
// Isolate-scope cache of the compiled recipe index. One build per cold
// start; subsequent requests in the same isolate reuse the Promise. The
// KV cache under `sh:active-recipes:v1` is the secondary layer (shared
// across isolates) with a 5-minute TTL — matches fetchSHThreatPatterns.
//
// Stage 5A does NOT call this from the request path. It's exposed via
// fetchActiveRecipes(env) for the Stage 5B tier1 evaluator to consume.

let _recipeIndexPromise: Promise<RecipeIndex> | null = null;
let _recipeIndexFetchedAt = 0;
const RECIPE_INDEX_MAX_AGE_MS = 5 * 60 * 1000;

/**
 * Fetch + compile the active detection recipe index.
 *
 * Caching layers (outer to inner):
 *   1. Isolate-local Promise (this variable) — single compile per cold start
 *   2. BILLING_CACHE (KV) — `sh:active-recipes:v1`, 300s TTL, shared isolates
 *   3. mnemom-api `/v1/internal/active-recipes` — authoritative RPC
 *
 * Returns an empty index on any failure (fail-open; Safe-House recipes are
 * additive signals, never the only defense).
 */
async function fetchActiveRecipes(env: Env): Promise<RecipeIndex> {
  const now = Date.now();
  if (_recipeIndexPromise && now - _recipeIndexFetchedAt < RECIPE_INDEX_MAX_AGE_MS) {
    return _recipeIndexPromise;
  }
  _recipeIndexFetchedAt = now;
  _recipeIndexPromise = (async (): Promise<RecipeIndex> => {
    const cacheKey = 'sh:active-recipes:v1';
    try {
      if (env.BILLING_CACHE) {
        const cached = await env.BILLING_CACHE.get(cacheKey);
        if (cached) {
          const rows = JSON.parse(cached) as RecipeRpcRow[];
          return buildRecipeIndex(rows, now);
        }
      }
      const apiBase = env.MNEMOM_ANALYZE_URL
        ? env.MNEMOM_ANALYZE_URL.replace('/v1/analyze', '')
        : 'https://api.mnemom.ai';
      const resp = await fetch(`${apiBase}/v1/internal/active-recipes`, {
        method: 'GET',
        headers: {
          'X-Internal-Key': env.INTERNAL_API_KEY ?? '',
        },
      });
      if (!resp.ok) return buildRecipeIndex([], now);
      const body = (await resp.json()) as { recipes?: RecipeRpcRow[] };
      const rows = Array.isArray(body.recipes) ? body.recipes : [];
      if (env.BILLING_CACHE) {
        await env.BILLING_CACHE
          .put(cacheKey, JSON.stringify(rows), { expirationTtl: 300 })
          .catch(() => {});
      }
      return buildRecipeIndex(rows, now);
    } catch {
      return buildRecipeIndex([], now);
    }
  })();
  return _recipeIndexPromise;
}

/** Exported for unit testing — allows forcing a refetch in tests. */
export function _resetRecipeIndexForTests(): void {
  _recipeIndexPromise = null;
  _recipeIndexFetchedAt = 0;
}

/** Exported for Stage 5B tier1 evaluator wiring. */
export { fetchActiveRecipes };

/**
 * Query the LSH inverted index in KV to find candidate patterns for a given normalized text.
 * Returns the subset of allPatterns whose IDs appear in any of the 16 band bucket lists.
 * Falls back to the full allPatterns list when the KV index is unavailable or not yet built.
 *
 * @param normalizedContent - Content AFTER preprocessForDetection (same normalization as detector)
 */
async function fetchSHLSHCandidates(
  normalizedContent: string,
  allPatterns: SafeHouseThreatPattern[],
  env: Env,
): Promise<SafeHouseThreatPattern[]> {
  if (!env.BILLING_CACHE || allPatterns.length === 0) return allPatterns;
  try {
    const sig = computeMinHash(normalizedContent);
    const bandHashes = computeBandHashes(sig);
    const keys = bandHashes.map((h, i) => `sh_lsh:band:${i}:${h}`);
    const results = await Promise.all(keys.map(k => env.BILLING_CACHE!.get(k)));
    const candidateIds = new Set<string>();
    for (const r of results) {
      if (r) {
        try { (JSON.parse(r) as string[]).forEach(id => candidateIds.add(id)); } catch { /* skip malformed */ }
      }
    }
    if (candidateIds.size === 0) return allPatterns; // index not yet built — fail open
    return allPatterns.filter(p => candidateIds.has(p.id));
  } catch {
    return allPatterns; // fail open on any KV error
  }
}

/**
 * Fetch the relevant card family names for a given surface type and agent industry.
 * Calls the get_cards_for_context Supabase RPC, cached in KV for 15 minutes.
 * Returns an empty set on failure (fail-open: no family filtering applied).
 */
async function fetchSHContextFamilies(
  surface: string,
  industry: string | undefined,
  env: Env,
): Promise<Set<string>> {
  const cacheKey = `sh:ctx:${surface}:${industry ?? ''}`;
  try {
    if (env.BILLING_CACHE) {
      const cached = await env.BILLING_CACHE.get(cacheKey);
      if (cached) return new Set(JSON.parse(cached) as string[]);
    }
    const resp = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/rpc/get_cards_for_context`,
      {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ p_surface: surface, p_industry: industry ?? null }),
      }
    );
    if (!resp.ok) return new Set();
    const families = await resp.json() as string[];
    if (env.BILLING_CACHE) {
      await env.BILLING_CACHE.put(cacheKey, JSON.stringify(families), { expirationTtl: 900 }).catch(() => {});
    }
    return new Set(families);
  } catch {
    return new Set(); // fail open
  }
}

/**
 * Three-phase threat pattern pre-filter for a given content string.
 *
 * Phase 1 — Context family filter: restrict to families relevant for this surface/industry.
 * Phase 2 — LSH candidate filter: use KV band index to narrow to ~20-50 near-duplicate candidates.
 *
 * The returned subset is passed to runL1Detection, replacing the full allPatterns list.
 * Fails open at every step: always returns a valid (possibly full) pattern list.
 *
 * IMPORTANT: normalizes content internally via preprocessForDetection, matching the
 * normalization runL1Detection applies — LSH lookup and detector see the same text.
 */
async function getSHCandidatePatterns(
  rawContent: string,
  surface: 'user_message' | 'tool_result',
  allPatterns: SafeHouseThreatPattern[],
  agentIndustry: string | undefined,
  env: Env,
): Promise<SafeHouseThreatPattern[]> {
  // Normalize — same transform the detector applies before MinHash
  const { normalized } = preprocessForDetection(rawContent);

  // Phase 1: context family filter (surface + industry)
  const families = await fetchSHContextFamilies(surface, agentIndustry, env);
  const familyFiltered = families.size > 0
    ? allPatterns.filter(p => !p.pattern_family || families.has(p.pattern_family))
    : allPatterns;

  // Phase 2: LSH candidate filter
  return fetchSHLSHCandidates(normalized, familyFiltered, env);
}

/** Read session risk state from KV. */
async function getSHSessionState(sessionId: string, env: Env): Promise<SessionRiskState | null> {
  try {
    const raw = await env.BILLING_CACHE?.get(`sh:session:${sessionId}`);
    return raw ? JSON.parse(raw) as SessionRiskState : null;
  } catch {
    return null;
  }
}

/** Update session risk state in KV after a Safe House check. */
async function updateSHSessionState(
  sessionId: string,
  agentId: string,
  score: number,
  env: Env
): Promise<void> {
  try {
    const existing = await getSHSessionState(sessionId, env);
    const now = Date.now();
    const windowScores = [
      ...(existing?.window_scores ?? []).filter(s => now - s.timestamp < 3600_000),
      { score, timestamp: now },
    ].slice(-20); // keep last 20
    const tenMinAgo = now - 600_000;
    const recentHigh = windowScores.filter(s => s.score >= 0.6 && s.timestamp >= tenMinAgo).length;
    const level = recentHigh >= 3 ? 'high' : recentHigh >= 2 ? 'medium' : 'low';
    const state: SessionRiskState = {
      session_id: sessionId,
      agent_id: agentId,
      window_scores: windowScores,
      session_threat_level: level as SessionRiskState['session_threat_level'],
      escalation_triggered: recentHigh >= 3,
      last_updated: now,
    };
    await env.BILLING_CACHE?.put(
      `sh:session:${sessionId}`,
      JSON.stringify(state),
      { expirationTtl: 3600 }
    );
  } catch {
    // Non-blocking
  }
}

/** Generate a human-readable quarantine ID. */
function generateQuarantineId(): string {
  const hex = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return `qid_${hex}`;
}

/** Extract the last user message content from a parsed request body (provider-agnostic). */
function extractLastUserMessage(body: Record<string, unknown>, provider: string): string | null {
  try {
    // Anthropic / OpenAI: body.messages is an array
    const messages = body.messages as Array<{ role: string; content: unknown }> | undefined;
    if (messages && Array.isArray(messages)) {
      for (let i = messages.length - 1; i >= 0; i--) {
        if (messages[i].role === 'user') {
          const content = messages[i].content;
          if (typeof content === 'string') return content;
          if (Array.isArray(content)) {
            // Multi-part content — extract text blocks
            const texts = content
              .filter((c: unknown) => typeof c === 'object' && c !== null && (c as Record<string, unknown>).type === 'text')
              .map((c: unknown) => (c as Record<string, unknown>).text as string);
            if (texts.length > 0) return texts.join('\n');
          }
        }
      }
    }
    // Gemini: body.contents
    if (provider === 'gemini') {
      const contents = body.contents as Array<{ role: string; parts: Array<{ text?: string }> }> | undefined;
      if (contents && Array.isArray(contents)) {
        for (let i = contents.length - 1; i >= 0; i--) {
          if (contents[i].role === 'user') {
            const text = contents[i].parts?.map(p => p.text ?? '').join('\n');
            if (text) return text;
          }
        }
      }
    }
  } catch {
    // Fall through
  }
  return null;
}

/** Replace the last user message content in-place in a request body. */
function replaceLastUserMessageContent(
  body: Record<string, unknown>,
  newContent: string,
  provider: string
): void {
  try {
    const messages = body.messages as Array<{ role: string; content: unknown }> | undefined;
    if (messages && Array.isArray(messages)) {
      for (let i = messages.length - 1; i >= 0; i--) {
        if (messages[i].role === 'user') {
          messages[i] = { ...messages[i], content: newContent };
          return;
        }
      }
    }
    if (provider === 'gemini') {
      const contents = body.contents as Array<{ role: string; parts: Array<{ text?: string }> }> | undefined;
      if (contents && Array.isArray(contents)) {
        for (let i = contents.length - 1; i >= 0; i--) {
          if (contents[i].role === 'user') {
            contents[i] = { ...contents[i], parts: [{ text: newContent }] };
            return;
          }
        }
      }
    }
  } catch {
    // Non-blocking: if replacement fails, original content passes through
  }
}

// (helpers moved to safe-house-runtime.ts)

/**
 * Extract tool call results from a request body.
 * These are returned by the application when it sends tool_result blocks
 * back to the model — a high-risk injection surface.
 *
 * Anthropic: user messages containing content blocks with type='tool_result'
 * OpenAI: messages with role='tool'
 * Returns only results with substantive content (>20 chars).
 */
function extractToolResults(body: Record<string, unknown>, provider: string): string[] {
  const results: string[] = [];
  try {
    const messages = body.messages as Array<{ role: string; content: unknown }> | undefined;
    if (!messages || !Array.isArray(messages)) return results;

    if (provider === 'anthropic') {
      // Tool results arrive as user messages with tool_result content blocks
      for (const msg of messages) {
        if (msg.role !== 'user' || !Array.isArray(msg.content)) continue;
        for (const block of msg.content as Array<{ type: string; content?: unknown }>) {
          if (block.type !== 'tool_result') continue;
          const content = block.content;
          if (typeof content === 'string' && content.length > 20) {
            results.push(content);
          } else if (Array.isArray(content)) {
            for (const part of content as Array<{ type: string; text?: string }>) {
              if (part.type === 'text' && part.text && part.text.length > 20) {
                results.push(part.text);
              }
            }
          }
        }
      }
    } else if (provider === 'openai') {
      // Tool results are messages with role='tool'
      for (const msg of messages) {
        if (msg.role !== 'tool') continue;
        if (typeof msg.content === 'string' && msg.content.length > 20) {
          results.push(msg.content);
        }
      }
    }
  } catch {
    // Non-blocking
  }
  return results;
}

/** Replace a specific tool result's content in-place. Matches by original content substring. */
function replaceToolResultContent(
  body: Record<string, unknown>,
  originalContent: string,
  newContent: string,
  provider: string
): void {
  try {
    const messages = body.messages as Array<{ role: string; content: unknown }> | undefined;
    if (!messages || !Array.isArray(messages)) return;
    if (provider === 'anthropic') {
      for (const msg of messages) {
        if (msg.role !== 'user' || !Array.isArray(msg.content)) continue;
        for (const block of msg.content as Array<{ type: string; content?: unknown }>) {
          if (block.type !== 'tool_result') continue;
          if (typeof block.content === 'string' && block.content === originalContent) {
            block.content = newContent;
            return;
          }
        }
      }
    } else if (provider === 'openai') {
      for (const msg of messages) {
        if (msg.role !== 'tool') continue;
        if (msg.content === originalContent) {
          (msg as Record<string, unknown>).content = newContent;
          return;
        }
      }
    }
  } catch { /* non-blocking */ }
}

// ADR-037 helpers (checkTrustedSource, ipInCidr, buildNudgeAnnotation,
// prependNudgeToLastUserMessage) live in safe-house-runtime.ts so they're
// directly unit-testable. Imported below at the existing import block.

/** Log a Safe House evaluation to the sh_evaluations table (fire-and-forget). */
async function logSHEvaluation(
  agentId: string,
  sessionId: string,
  mode: string,
  decision: SafeHouseDecision,
  surface: string,
  env: Env
): Promise<void> {
  try {
    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/sh_evaluations`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        agent_id: agentId,
        session_id: sessionId,
        mode,
        surface,
        verdict: decision.verdict,
        threats: decision.threats,
        overall_risk: decision.overall_risk,
        detector_scores: decision.detector_scores,
        detection_sources: decision.detection_sources,
        session_multiplier: decision.session_multiplier,
        decorated: decision.verdict === 'warn',
        quarantine_id: decision.quarantine_id ?? null,
        duration_ms: decision.duration_ms,
      }),
    });
  } catch {
    // Non-blocking
  }
}

/** Increment Safe House usage counter for billing (fire-and-forget). */
async function incrementSHUsage(agentId: string, env: Env): Promise<void> {
  try {
    const today = new Date().toISOString().slice(0, 10);
    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/rpc/increment_sh_usage`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ p_agent_id: agentId, p_period_start: today }),
    });
  } catch {
    // Non-blocking
  }
}

// ── CBD (Context Back Door) helpers ──────────────────────────────────────────

/**
 * Log a CBD outbound screening event to sh_exit_evaluations (fire-and-forget).
 * Called from both streaming and non-streaming paths.
 */
async function logCBDEvaluation(
  agentId: string,
  sessionId: string,
  verdict: string,
  detectorScores: Record<string, number | null>,
  detectionSources: string[],
  surface: string,
  threats: ThreatDetection[],
  overallRisk: number,
  env: Env
): Promise<void> {
  try {
    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/sh_exit_evaluations`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        agent_id: agentId,
        session_id: sessionId,
        verdict,
        detector_scores: detectorScores,
        detection_sources: detectionSources,
        surface,
        threats,
        overall_risk: overallRisk,
        session_multiplier: 1.0,
        duration_ms: 0,
      }),
    });
  } catch { /* Non-blocking */ }
}

/**
 * Create a TransformStream that scans each streaming chunk for canary values.
 * If a canary is detected, the stream is aborted (client receives an error).
 * Uses a rolling tail buffer to catch canary values that span chunk boundaries.
 * Cost: ~0ms on miss (string search, zero API calls).
 */
function createCBDStreamTransform(
  agentId: string,
  sessionId: string,
  canaries: string[],
  env: Env,
  ctx: ExecutionContext,
): TransformStream<Uint8Array, Uint8Array> {
  const decoder = new TextDecoder();
  let tailBuffer = '';    // last N chars of previous chunk for overlap detection
  const TAIL_SIZE = 80;   // comfortably exceeds any canary value length

  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      const text = decoder.decode(chunk, { stream: true });
      const toScan = tailBuffer + text;

      if (canaries.length > 0) {
        const hit = scanForCanaryUse(toScan, canaries);
        if (hit) {
          ctx.waitUntil(Promise.all([
            markCanaryTriggered(agentId, hit, env),
            logCBDEvaluation(agentId, sessionId, 'block',
              { CanaryMatcher: 1.0, PatternMatcher: null, SemanticAnalyzer: null },
              ['CanaryMatcher'], 'outbound_stream',
              [{ type: 'data_exfiltration' as ThreatType, confidence: 1.0,
                 reasoning: 'Canary credential in streaming response — confirmed compromise' }],
              1.0, env),
          ]));
          // Abort the stream — client receives an incomplete/errored response
          controller.error(new Error('CBD_CANARY_TRIGGERED'));
          return;
        }
      }

      tailBuffer = toScan.length >= TAIL_SIZE ? toScan.slice(-TAIL_SIZE) : toScan;
      controller.enqueue(chunk);
    },
  });
}

/**
 * Run async CBD semantic analysis on assembled output text (never blocks user).
 * Calls Haiku with an outbound-focused threat detection prompt.
 * Results written to sh_exit_evaluations; only logs on non-pass verdict.
 */
async function runCBDSemanticAnalysis(
  outputText: string,
  agentId: string,
  sessionId: string,
  env: Env,
): Promise<void> {
  if (!outputText || !env.ANTHROPIC_API_KEY) return;
  try {
    const systemPrompt = buildSHExitAnalysisPrompt();
    const userPrompt   = buildSHExitUserPrompt(outputText);
    const controller   = new AbortController();
    const timeoutId    = setTimeout(() => controller.abort(), 8000);
    try {
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 512,
          system: [{ type: 'text', text: systemPrompt, cache_control: { type: 'ephemeral' } }],
          messages: [{ role: 'user', content: userPrompt }],
        }),
        signal: controller.signal,
      });
      if (!resp.ok) return;
      const body = (await resp.json()) as Record<string, unknown>;
      const blocks = body.content as Array<Record<string, unknown>> | undefined;
      const rawText = typeof blocks?.find(b => b.type === 'text')?.text === 'string'
        ? (blocks!.find(b => b.type === 'text')!.text as string)
        : null;
      if (!rawText) return;
      const result = parseL2Response(rawText);
      if (!result || result.recommendation === 'pass') return;
      await logCBDEvaluation(agentId, sessionId, result.recommendation,
        { SemanticAnalyzer: result.overall_risk, PatternMatcher: null, CanaryMatcher: null },
        ['SemanticAnalyzer'], 'outbound', result.threats, result.overall_risk, env);
    } finally {
      clearTimeout(timeoutId);
    }
  } catch { /* fail-open */ }
}

/** Fetch canary values for an agent (KV cached 10 min). Returns empty array on error. */
async function fetchAgentCanaries(agentId: string, env: Env): Promise<string[]> {
  if (!env.BILLING_CACHE) return [];
  const cacheKey = `sh:canaries:${agentId}`;
  try {
    const cached = await env.BILLING_CACHE.get(cacheKey);
    if (cached) return JSON.parse(cached) as string[];

    const resp = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/sh_canaries?agent_id=eq.${agentId}&triggered=eq.false&select=canary_value`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );
    if (!resp.ok) return [];
    const rows = await resp.json() as Array<{ canary_value: string }>;
    const values = rows.map(r => r.canary_value).filter(Boolean);
    await env.BILLING_CACHE.put(cacheKey, JSON.stringify(values), { expirationTtl: 600 }).catch(() => {});
    return values;
  } catch {
    return [];
  }
}

/** Scan text for any canary values. Returns the first triggered canary value or null. */
function scanForCanaryUse(text: string, canaries: string[]): string | null {
  if (!text || canaries.length === 0) return null;
  for (const canary of canaries) {
    if (canary.length >= 8 && text.includes(canary)) return canary;
  }
  return null;
}

/** Mark a canary as triggered (fire-and-forget). */
async function markCanaryTriggered(agentId: string, canaryValue: string, env: Env): Promise<void> {
  try {
    await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/sh_canaries?agent_id=eq.${agentId}&canary_value=eq.${encodeURIComponent(canaryValue)}`,
      {
        method: 'PATCH',
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify({ triggered: true, triggered_at: new Date().toISOString() }),
      }
    );
    // Invalidate KV cache
    await env.BILLING_CACHE?.delete(`sh:canaries:${agentId}`);
  } catch {
    // Fire-and-forget
  }
}

/**
 * Read the platform-wide pending advisory TTL (ADR-040, T0-2).
 *
 * Backed by `platform_settings.pending_advisory_ttl_hours` (single-row,
 * platform-admin-configurable only). KV-cached for one hour so the
 * advisory write path does not hammer Supabase. Falls back to the
 * ADR-040 default of 24 hours on any failure (KV miss + unreachable
 * Supabase, malformed row, out-of-bound value) so misconfiguration
 * cannot block intervention.
 */
export async function getPendingAdvisoryTtlHours(env: Env): Promise<number> {
  const DEFAULT_TTL_HOURS = 24;
  const cacheKey = 'platform:pending-advisory-ttl';
  if (env.BILLING_CACHE) {
    try {
      const cached = (await env.BILLING_CACHE.get(cacheKey, 'json')) as
        | { ttl_hours: number }
        | null;
      if (cached && Number.isInteger(cached.ttl_hours)) {
        return cached.ttl_hours;
      }
    } catch {
      // Cache read failure: fall through to Supabase.
    }
  }
  try {
    const res = await supabaseFetch(
      `${env.SUPABASE_URL}/rest/v1/platform_settings?id=eq.default&select=pending_advisory_ttl_hours`,
      {
        headers: {
          apikey: env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        },
      }
    );
    if (!res.ok) return DEFAULT_TTL_HOURS;
    const rows = (await res.json()) as Array<{ pending_advisory_ttl_hours: number }>;
    const ttl = rows[0]?.pending_advisory_ttl_hours;
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > 168) {
      return DEFAULT_TTL_HOURS;
    }
    if (env.BILLING_CACHE) {
      await env.BILLING_CACHE.put(
        cacheKey,
        JSON.stringify({ ttl_hours: ttl }),
        { expirationTtl: 3600 }
      ).catch(() => {});
    }
    return ttl;
  } catch {
    return DEFAULT_TTL_HOURS;
  }
}

/**
 * Compose the agent-facing advisory text for a front-door enforce
 * intervention. The text becomes the row injected into the agent's
 * context on the next turn so the agent has cross-turn context for
 * what was prevented.
 */
export function buildFrontDoorAdvisoryContent(decision: SafeHouseDecision): {
  text: string;
  summary: string;
} {
  const threatTypes = Array.from(
    new Set(decision.threats.map((t) => t.type))
  ).slice(0, 3);
  const verdictWord = decision.verdict === 'block' ? 'blocked' : 'quarantined';
  const threatStr = threatTypes.length > 0 ? threatTypes.join(', ') : 'unspecified';
  const text =
    `[Mnemom advisory: an incoming message on the previous turn was ` +
    `${verdictWord} by the front-door Safe House check ` +
    `(threats: ${threatStr}; risk: ${decision.overall_risk.toFixed(2)}). ` +
    `The intervention has already been applied; this note is for context.]`;
  const summary =
    `Front-door ${verdictWord}: ${threatStr} ` +
    `(overall_risk=${decision.overall_risk.toFixed(2)})`;
  return { text, summary };
}

/**
 * Write a front-door enforce advisory (ADR-040, T0-3).
 *
 * Per ADR-040 §"Sources", an enforce-mode same-turn intervention at the
 * front door also writes a pending_advisories row with
 * `source='runtime.front_door.enforce'` so the agent has cross-turn
 * context next turn for what was quarantined or blocked.
 *
 * Writes directly to `pending_advisories` (not the legacy
 * `enforcement_nudges` compatibility view) so source / source_ref /
 * expires_at populate correctly. Best-effort: failures are swallowed
 * because the same-turn intervention is the actual enforcement
 * mechanism; this carryover row is informational and must never
 * affect the current turn's response path.
 *
 * Fires only on `verdict === 'block' || verdict === 'quarantine'` —
 * warn paths use the legacy `writePreemptiveNudge` until T0-7
 * consolidates writers onto pending_advisories directly.
 */
export async function writeFrontDoorAdvisory(
  agentId: string,
  sessionId: string,
  decision: SafeHouseDecision,
  env: Env
): Promise<void> {
  if (decision.verdict !== 'block' && decision.verdict !== 'quarantine') {
    return;
  }
  try {
    const ttlHours = await getPendingAdvisoryTtlHours(env);
    const expiresAt = new Date(
      Date.now() + ttlHours * 60 * 60 * 1000
    ).toISOString();
    const { text, summary } = buildFrontDoorAdvisoryContent(decision);
    const id = `pa-${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/pending_advisories`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        id,
        agent_id: agentId,
        session_id: sessionId,
        // checkpoint_id intentionally omitted — NULL means non-AIP-originated
        // (front door has no integrity checkpoint to reference; migration 107
        // made checkpoint_id nullable for this case).
        status: 'pending',
        nudge_content: text,
        concerns_summary: summary,
        source: 'runtime.front_door.enforce',
        source_ref: {
          quarantine_id: decision.quarantine_id ?? null,
          verdict: decision.verdict,
          overall_risk: decision.overall_risk,
          detection_sources: decision.detection_sources,
          threat_types: Array.from(
            new Set(decision.threats.map((t) => t.type))
          ),
        },
        expires_at: expiresAt,
      }),
    });
  } catch {
    // Non-blocking. See ADR-040: pending advisories are best-effort
    // cross-turn context. The same-turn enforce mechanism is the chat
    // completion path, not this row.
  }
}

/**
 * Write an inside.autonomy enforce advisory (T0-4, ADR-040).
 *
 * Companion to writeFrontDoorAdvisory. Fires when CLPI evaluation under
 * `autonomy_mode=enforce` returns `fail` and the gateway has just
 * synthesized a same-turn intervention response (via
 * `buildAutonomyEnforceResponse`). The advisory carries cross-turn
 * context so the agent's NEXT turn knows which tools were refused and
 * why, even though the agent never saw an actual tool error this turn
 * (CLPI gates the request, not the model's emitted tool_use).
 *
 * Best-effort: errors are swallowed because the same-turn synthetic
 * response is the actual enforcement mechanism; the carryover row is
 * informational and must never affect the current turn.
 */
export async function writeAutonomyEnforceAdvisory(
  agentId: string,
  sessionId: string,
  evalResult: {
    verdict: string;
    violations: Array<{ tool_name?: string; type?: string; reason?: string; rule_id?: string; severity?: string }>;
  },
  env: Env
): Promise<void> {
  if (evalResult.verdict !== 'fail') return;
  try {
    const ttlHours = await getPendingAdvisoryTtlHours(env);
    const expiresAt = new Date(
      Date.now() + ttlHours * 60 * 60 * 1000
    ).toISOString();

    const violations = evalResult.violations.slice(0, 3);
    const toolList = violations
      .map((v) => v.tool_name)
      .filter((n): n is string => typeof n === 'string')
      .join(', ');
    const reasons = violations
      .map((v) => v.reason || v.type)
      .filter((r): r is string => typeof r === 'string');
    const reasonStr = reasons.length > 0 ? reasons.join(' / ') : 'policy violation';
    const text =
      `[Mnemom advisory: on the previous turn the alignment card ` +
      `refused the following tool${violations.length === 1 ? '' : 's'} ` +
      `(${toolList || 'unspecified'}). Reason: ${reasonStr}. ` +
      `The tool side effect did not happen; this note is for context.]`;
    const summary = `Inside.autonomy refused: ${toolList || 'unspecified'} (${reasonStr})`;

    const id = `pa-${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/pending_advisories`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        id,
        agent_id: agentId,
        session_id: sessionId,
        // checkpoint_id intentionally omitted — NULL means non-AIP-originated
        // (CLPI is the autonomy gate; not an integrity checkpoint).
        status: 'pending',
        nudge_content: text,
        concerns_summary: summary,
        source: 'runtime.inside.autonomy.enforce',
        source_ref: {
          verdict: evalResult.verdict,
          violations: violations.map((v) => ({
            tool_name: v.tool_name ?? null,
            type: v.type ?? null,
            severity: v.severity ?? null,
            rule_id: v.rule_id ?? null,
          })),
        },
        expires_at: expiresAt,
      }),
    });
  } catch {
    // Non-blocking. The same-turn synthetic 200 is the enforcement
    // mechanism; this carryover row is informational only.
  }
}

/**
 * Extract the BOUNDARY value name an integrity checkpoint flagged.
 *
 * The checkpoint object doesn't carry an explicit "boundary that was
 * violated" field — it's inferred from concerns and conscience_context.
 * Strategy:
 *   1. Scan `concerns[]` for the highest-severity entry with a
 *      `relevant_conscience_value` matching `BOUNDARY:*`.
 *   2. Fall back to `conscience_context.conflicts[]` for any entry
 *      starting with `BOUNDARY:`.
 *   3. Return null if no BOUNDARY value can be identified — the
 *      intervention text falls back to a generic phrasing.
 */
export function extractBoundaryValueName(
  checkpoint: { concerns?: Array<{ relevant_conscience_value?: string | null; severity?: string | null }>; conscience_context?: { conflicts?: string[] } } | null | undefined,
): string | null {
  if (!checkpoint) return null;
  const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  let best: { name: string; rank: number } | null = null;
  for (const concern of checkpoint.concerns ?? []) {
    const raw = concern.relevant_conscience_value;
    if (typeof raw !== 'string' || !raw.startsWith('BOUNDARY:')) continue;
    const name = raw.slice('BOUNDARY:'.length).trim();
    if (!name) continue;
    const rank = SEVERITY_RANK[concern.severity ?? ''] ?? 0;
    if (!best || rank > best.rank) {
      best = { name, rank };
    }
  }
  if (best) return best.name;
  for (const c of checkpoint.conscience_context?.conflicts ?? []) {
    if (typeof c === 'string' && c.startsWith('BOUNDARY:')) {
      const name = c.slice('BOUNDARY:'.length).trim();
      if (name) return name;
    }
  }
  return null;
}

/**
 * Build the agent-voice intervention text used to replace the model's
 * response when AIP fires `boundary_violation` under `integrity_mode=enforce`.
 *
 * Per ADR-040 the text takes the agent's voice ("I noticed I was
 * reasoning toward X, which violates BOUNDARY value Y. I'm not going to
 * act on that."). Falls back to a generic phrasing when the BOUNDARY
 * value cannot be identified or the reasoning summary is missing.
 */
export function buildIntegrityInterventionText(
  checkpoint: { concerns?: Array<{ relevant_conscience_value?: string | null; severity?: string | null; description?: string | null }>; reasoning_summary?: string | null; conscience_context?: { conflicts?: string[] } } | null | undefined,
): string {
  const boundary = extractBoundaryValueName(checkpoint);
  const summary = (checkpoint?.reasoning_summary ?? '').trim();
  // Cap the embedded summary so the intervention text stays a digestible
  // single paragraph; the full reasoning lives on the integrity_checkpoints row.
  const summaryClause = summary
    ? ` (${summary.length > 240 ? `${summary.slice(0, 237)}...` : summary})`
    : '';
  if (boundary) {
    return (
      `[Mnemom Intervention: I noticed I was reasoning toward an action that violates ` +
      `the BOUNDARY value \`${boundary}\`${summaryClause}. ` +
      `I'm not going to act on that. The original response was prevented ` +
      `from delivery; this message replaces it.]`
    );
  }
  return (
    `[Mnemom Intervention: an integrity checkpoint flagged a boundary violation ` +
    `in my reasoning${summaryClause}. ` +
    `I'm not going to act on that. The original response was prevented from delivery; ` +
    `this message replaces it.]`
  );
}

/**
 * Replace the model-response content slot in a buffered provider
 * response with the integrity intervention text. Preserves the rest of
 * the response shape so customer SDKs continue to parse it.
 *
 * Provider format is detected by inspecting the parsed body (matches
 * the existing canary-scanner pattern at the top of the AIP block):
 *   - Anthropic: `content[]` array of `{type:'text',text}` blocks. Replaces
 *     all text blocks with one intervention block; keeps non-text blocks
 *     stripped (they're typically tool_use, which we don't want to deliver
 *     when the response is being intervened on).
 *   - OpenAI: `choices[].message.content` string fields. Replaces all
 *     choices' content with the intervention text and clears any
 *     tool_calls field on the message.
 *   - Gemini: `candidates[].content.parts[].text`. Replaces all parts
 *     with one text part containing the intervention.
 *   - Unrecognized: returns an Anthropic-shaped envelope wrapping the
 *     intervention text so the response is still parseable.
 *
 * Returns the new body as a JSON string. On parse failure (e.g., the
 * upstream returned non-JSON) returns a wrapping envelope so the
 * customer never sees the original violating content.
 */
export function replaceIntegrityViolationContent(
  originalBody: string,
  interventionText: string,
): string {
  const fallbackEnvelope = JSON.stringify({
    type: 'message',
    role: 'assistant',
    content: [{ type: 'text', text: interventionText }],
    stop_reason: 'end_turn',
    stop_sequence: null,
  });
  let parsed: unknown;
  try {
    parsed = JSON.parse(originalBody);
  } catch {
    return fallbackEnvelope;
  }
  if (!parsed || typeof parsed !== 'object') {
    return fallbackEnvelope;
  }
  const obj = parsed as Record<string, unknown>;

  // Anthropic Messages API
  if (Array.isArray(obj.content)) {
    obj.content = [{ type: 'text', text: interventionText }];
    obj.stop_reason = 'end_turn';
    return JSON.stringify(obj);
  }

  // OpenAI Chat Completions
  if (Array.isArray(obj.choices)) {
    obj.choices = (obj.choices as Array<Record<string, unknown>>).map((c) => ({
      ...c,
      message: {
        role: 'assistant',
        content: interventionText,
      },
      finish_reason: 'stop',
    }));
    return JSON.stringify(obj);
  }

  // Gemini generateContent
  if (Array.isArray(obj.candidates)) {
    obj.candidates = (obj.candidates as Array<Record<string, unknown>>).map((c) => ({
      ...c,
      content: { parts: [{ text: interventionText }], role: 'model' },
      finishReason: 'STOP',
    }));
    return JSON.stringify(obj);
  }

  // Unrecognized shape — return the wrapping envelope so the customer
  // SDK still has something parseable to render.
  return fallbackEnvelope;
}

/**
 * Write an inside.integrity enforce advisory (T0-5, ADR-040).
 *
 * Companion to writeAutonomyEnforceAdvisory + writeFrontDoorAdvisory.
 * Fires when AIP returns `boundary_violation` under `integrity_mode=enforce`
 * and the gateway has just replaced the response body with the
 * intervention text. Carries cross-turn context so the agent's NEXT
 * turn knows which boundary was crossed and what reasoning triggered
 * the intervention.
 *
 * Best-effort: errors swallowed so the same-turn intervention (the
 * actual enforcement mechanism) is never affected.
 */
export async function writeIntegrityEnforceAdvisory(
  agentId: string,
  sessionId: string,
  checkpoint: {
    checkpoint_id: string;
    verdict: string;
    concerns?: Array<{ category?: string | null; severity?: string | null; description?: string | null; relevant_conscience_value?: string | null }>;
    reasoning_summary?: string | null;
  },
  env: Env
): Promise<void> {
  if (checkpoint.verdict !== 'boundary_violation') return;
  try {
    const ttlHours = await getPendingAdvisoryTtlHours(env);
    const expiresAt = new Date(
      Date.now() + ttlHours * 60 * 60 * 1000
    ).toISOString();
    const boundary = extractBoundaryValueName(checkpoint);
    const concerns = (checkpoint.concerns ?? []).slice(0, 3);
    const text = buildIntegrityInterventionText(checkpoint);
    const summary = boundary
      ? `Inside.integrity boundary violation: ${boundary}`
      : 'Inside.integrity boundary violation (boundary value unidentified)';
    const id = `pa-${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;

    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/pending_advisories`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        id,
        agent_id: agentId,
        session_id: sessionId,
        checkpoint_id: checkpoint.checkpoint_id,
        status: 'pending',
        nudge_content: text,
        concerns_summary: summary,
        source: 'runtime.inside.integrity.enforce',
        source_ref: {
          checkpoint_id: checkpoint.checkpoint_id,
          verdict: checkpoint.verdict,
          boundary_value: boundary,
          concerns: concerns.map((c) => ({
            category: c.category ?? null,
            severity: c.severity ?? null,
            relevant_conscience_value: c.relevant_conscience_value ?? null,
          })),
        },
        expires_at: expiresAt,
      }),
    });
  } catch {
    // Non-blocking. The same-turn response replacement is the actual
    // enforcement mechanism; this carryover row is informational.
  }
}

/**
 * Apply back-door DLP redaction to a buffered provider response (T0-6,
 * ADR-040). Walks the per-provider text slot(s) and applies
 * `redactDLPMatches` to each, leaving the rest of the response shape
 * intact so customer SDKs continue to parse it.
 *
 *   - Anthropic: `content[]` text blocks
 *   - OpenAI:    `choices[].message.content`
 *   - Gemini:    `candidates[].content.parts[].text`
 *
 * Returns the (possibly modified) body, the aggregated DLP matches
 * across all redacted segments, and a `modified` flag the caller can
 * use to decide whether to write the cross-turn advisory.
 *
 * If the body fails to parse as JSON or doesn't match a known shape,
 * falls back to running `redactDLPMatches` on the raw text — better
 * to over-redact than to leak PII because the response shape was
 * unrecognized.
 */
export function applyBackDoorRedaction(originalBody: string): {
  body: string;
  matches: DLPMatch[];
  modified: boolean;
} {
  const allMatches: DLPMatch[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(originalBody);
  } catch {
    const result = redactDLPMatches(originalBody);
    return {
      body: result.redacted,
      matches: result.matches,
      modified: result.matches.length > 0,
    };
  }
  if (!parsed || typeof parsed !== 'object') {
    return { body: originalBody, matches: [], modified: false };
  }
  const obj = parsed as Record<string, unknown>;
  let changed = false;

  // Anthropic content[]
  if (Array.isArray(obj.content)) {
    obj.content = (obj.content as Array<Record<string, unknown>>).map((block) => {
      if (block.type === 'text' && typeof block.text === 'string') {
        const result = redactDLPMatches(block.text);
        if (result.matches.length > 0) {
          allMatches.push(...result.matches);
          changed = true;
          return { ...block, text: result.redacted };
        }
      }
      return block;
    });
  }

  // OpenAI choices[].message.content
  if (Array.isArray(obj.choices)) {
    obj.choices = (obj.choices as Array<Record<string, unknown>>).map((choice) => {
      const message = choice.message as Record<string, unknown> | undefined;
      if (message && typeof message.content === 'string') {
        const result = redactDLPMatches(message.content);
        if (result.matches.length > 0) {
          allMatches.push(...result.matches);
          changed = true;
          return { ...choice, message: { ...message, content: result.redacted } };
        }
      }
      return choice;
    });
  }

  // Gemini candidates[].content.parts[].text
  if (Array.isArray(obj.candidates)) {
    obj.candidates = (obj.candidates as Array<Record<string, unknown>>).map((candidate) => {
      const content = candidate.content as Record<string, unknown> | undefined;
      const parts = content?.parts as Array<Record<string, unknown>> | undefined;
      if (Array.isArray(parts)) {
        const newParts = parts.map((part) => {
          if (typeof part.text === 'string') {
            const result = redactDLPMatches(part.text);
            if (result.matches.length > 0) {
              allMatches.push(...result.matches);
              changed = true;
              return { ...part, text: result.redacted };
            }
          }
          return part;
        });
        return { ...candidate, content: { ...content, parts: newParts } };
      }
      return candidate;
    });
  }

  if (!changed) {
    return { body: originalBody, matches: [], modified: false };
  }
  return { body: JSON.stringify(obj), matches: allMatches, modified: true };
}

/**
 * Write a back-door modification advisory (T0-6, ADR-040).
 *
 * Companion to writeFrontDoorAdvisory + writeAutonomyEnforceAdvisory +
 * writeIntegrityEnforceAdvisory. Per ADR-040 §"Sources" the source
 * value is `runtime.back_door.modification`. The advisory tells the
 * agent next turn what was redacted from its response so it doesn't
 * reference the redacted content as if it had been delivered.
 *
 * Mode gating: skip on `observe` (today's behavior — log only, no
 * response mutation, no advisory). Fires under `nudge` and `enforce`
 * because both modes apply the redaction to the response body before
 * delivery; the advisory mirrors that fact for the next turn.
 *
 * Best-effort: errors swallowed so the same-turn redaction (which
 * already happened in the response body) is never affected.
 */
export async function writeBackDoorAdvisory(
  agentId: string,
  sessionId: string,
  modification: { matches: DLPMatch[]; mode: string },
  env: Env,
): Promise<void> {
  if (modification.matches.length === 0) return;
  if (modification.mode !== 'nudge' && modification.mode !== 'enforce') return;
  try {
    const ttlHours = await getPendingAdvisoryTtlHours(env);
    const expiresAt = new Date(
      Date.now() + ttlHours * 60 * 60 * 1000,
    ).toISOString();

    const types = Array.from(new Set(modification.matches.map((m) => m.type)));
    const counts: Record<string, number> = {};
    for (const m of modification.matches) {
      counts[m.type] = (counts[m.type] ?? 0) + 1;
    }
    const typeStr = types.slice(0, 5).join(', ') || 'unspecified';
    const count = modification.matches.length;
    const text =
      `[Mnemom advisory: on the previous turn the back door redacted ` +
      `${count} sensitive item${count === 1 ? '' : 's'} from your response ` +
      `(types: ${typeStr}). The redactions have already been applied; ` +
      `this note is for context so you don't reference the redacted ` +
      `content as if it had been delivered.]`;
    const summary =
      `Back-door redacted ${count} item${count === 1 ? '' : 's'} ` +
      `(${typeStr})`;
    const id = `pa-${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;

    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/pending_advisories`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        id,
        agent_id: agentId,
        session_id: sessionId,
        // checkpoint_id intentionally omitted — back door has no
        // integrity checkpoint to reference.
        status: 'pending',
        nudge_content: text,
        concerns_summary: summary,
        source: 'runtime.back_door.modification',
        source_ref: {
          mode: modification.mode,
          modification_count: count,
          threat_types: types,
          counts,
        },
        expires_at: expiresAt,
      }),
    });
  } catch {
    // Non-blocking. The same-turn redaction (response body already
    // modified) is the actual enforcement mechanism; this carryover
    // row is informational.
  }
}

/** Write a pre-emptive Safe House nudge to the enforcement_nudges table. */
async function writePreemptiveNudge(
  agentId: string,
  sessionId: string,
  nudge: { nudge_content: string; threat_type: string; sh_score: number; pre_emptive: true },
  env: Env
): Promise<void> {
  try {
    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/enforcement_nudges`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        agent_id: agentId,
        session_id: sessionId,
        // checkpoint_id intentionally omitted — NULL means Safe House-originated (see migration 107)
        status: 'pending',
        concerns_summary: nudge.nudge_content,
        metadata: {
          pre_emptive: true,
          threat_type: nudge.threat_type,
          sh_score: nudge.sh_score,
        },
      }),
    });
  } catch {
    // Non-blocking
  }
}

/** Write Safe House result to KV so the AIP analysis (Phase 1+) can enrich its conscience prompt. */
async function cacheSHResultForAIP(
  sessionId: string,
  decision: SafeHouseDecision,
  env: Env
): Promise<void> {
  try {
    await env.BILLING_CACHE?.put(
      `sh:result:${sessionId}:latest`,
      JSON.stringify(decision),
      { expirationTtl: 600 }
    );
  } catch {
    // Non-blocking
  }
}

/** Log a quarantined message to the quarantined_messages table. */
async function logQuarantinedMessage(
  quarantineId: string,
  agentId: string,
  sessionId: string,
  contentHash: string,
  decision: SafeHouseDecision,
  sourceType: string,
  env: Env
): Promise<void> {
  try {
    const topThreat = decision.threats.sort((a, b) => b.confidence - a.confidence)[0];
    await supabaseFetch(`${env.SUPABASE_URL}/rest/v1/quarantined_messages`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify({
        quarantine_id: quarantineId,
        agent_id: agentId,
        session_id: sessionId,
        content_hash: contentHash,
        source_type: sourceType,
        threat_type: topThreat?.type ?? 'unknown',
        confidence: decision.overall_risk,
        reasoning: topThreat?.reasoning ?? null,
        status: 'pending',
      }),
    });
  } catch {
    // Non-blocking
  }
}

/**
 * Run full Safe House analysis in observe mode (fire-and-forget).
 * The message is NOT modified — analysis happens in background.
 * Results are written to sh_evaluations and cached in KV for AIP.
 */
async function runObserveSH(
  agentId: string,
  sessionId: string,
  content: string,
  config: SafeHouseConfig,
  env: Env,
  /** Tool results to screen async alongside the user message (max 3, pre-sliced). */
  toolResultsToScreen?: string[],
): Promise<void> {
  try {
    const t0 = Date.now();
    const [patterns, sessionState] = await Promise.all([
      fetchSHThreatPatterns(env),
      getSHSessionState(sessionId, env),
    ]);

    const userMsgCandidates = await getSHCandidatePatterns(content, 'user_message', patterns, undefined, env);
    const l1 = runL1Detection(content, userMsgCandidates, { surface: 'user_message' });

    let finalThreats = l1.threats;
    let finalScore = l1.score;
    const detectorScores: Record<string, number | null> = { PatternMatcher: l1.score, SemanticAnalyzer: null };
    const detectionSources: string[] = l1.score > 0 ? ['PatternMatcher'] : [];

    if (l1.score >= 0.4 || shouldForceSemanticAnalysis(l1)) {
      const l2Raw = await callSHAnalysisLLM(content, 'user_message', env);
      if (l2Raw) {
        const l2Result = parseL2Response(l2Raw);
        if (l2Result) {
          const merged = mergeL1AndL2(l1.threats, l1.score, l2Result);
          finalThreats = merged.threats;
          finalScore = merged.score;
          detectorScores.SemanticAnalyzer = l2Result.overall_risk;
          if (l2Result.overall_risk > 0) detectionSources.push('SemanticAnalyzer');
        }
      }
    }

    const { multiplied_score, session_multiplier } = applySessionMultiplier(finalScore, sessionState);

    // Phase 5 Stage 5B: recipe tier1 shadow evaluation (observe branch).
    // Mirrors the enforce branch at index.ts:4670+. Observe is already
    // background work (runObserveSH runs inside ctx.waitUntil), so the eval
    // runs inline here — no further ctx.waitUntil wrapping needed.
    // Fail-open on every failure path.
    const observeRecipeMode = (env.RECIPE_MODE ?? 'off') as RecipeMode;
    if (observeRecipeMode === 'shadow') {
      try {
        const recipeIndex = await fetchActiveRecipes(env);
        if (recipeIndex.all.length > 0) {
          const canonicalScores: DetectorScores = buildDetectorScoresFromThreats(finalThreats);
          if (sessionState) {
            canonicalScores.session_tracker =
              sessionState.session_threat_level === 'high' ? 0.85
              : sessionState.session_threat_level === 'medium' ? 0.55
              : 0.20;
          }
          if (typeof detectorScores.SemanticAnalyzer === 'number') {
            canonicalScores.semantic_analyzer = detectorScores.SemanticAnalyzer;
          }
          const evalConfig: RecipeEvalConfig = {
            mode: observeRecipeMode,
            per_threat_type_cap: 5,
            global_cap: 10,
          };
          const tier1Result = evaluateRecipesTier1(
            canonicalScores,
            content,
            recipeIndex,
            evalConfig,
          );
          const telemetry = serializeRecipeTelemetry(
            tier1Result,
            null,
            recipeIndex,
            observeRecipeMode,
          );
          console.log(JSON.stringify({
            ...telemetry,
            agent_id: agentId,
            session_id: sessionId,
            surface: 'user_message',
            sh_mode: 'observe',
          }));
        }
      } catch {
        // Fail open — recipes are additive; failure must never affect the observe flow.
      }
    }

    const thresholds = config.thresholds;
    let verdict: SafeHouseVerdict = 'pass';
    if (multiplied_score >= thresholds.block) verdict = 'block';
    else if (multiplied_score >= thresholds.quarantine) verdict = 'quarantine';
    else if (multiplied_score >= thresholds.warn) verdict = 'warn';

    const decision: SafeHouseDecision = {
      verdict,
      overall_risk: multiplied_score,
      threats: finalThreats,
      detector_scores: detectorScores,
      detection_sources: detectionSources,
      session_multiplier,
      duration_ms: Date.now() - t0,
    };

    await Promise.all([
      logSHEvaluation(agentId, sessionId, 'observe', decision, 'user_message', env),
      cacheSHResultForAIP(sessionId, decision, env),
      updateSHSessionState(sessionId, agentId, multiplied_score, env),
    ]);

    // Deliver Safe House webhooks
    await deliverSHWebhooks(decision, agentId, sessionId, env);

    // Write pre-emptive nudge — will be picked up on the NEXT request for this agent
    const nudge = buildPreemptiveNudgeContent(decision);
    if (nudge) await writePreemptiveNudge(agentId, sessionId, nudge, env);

    console.log(JSON.stringify({
      event: 'sh_observe',
      verdict,
      pattern_score: l1.score,
      multiplied_score,
      detection_sources: detectionSources,
      threat_count: finalThreats.length,
      duration_ms: decision.duration_ms,
    }));
    incrementSHUsage(agentId, env).catch(() => {});

    // Screen tool results async (primary indirect injection surface).
    // Always triggers SemanticAnalyzer for tool results regardless of L1 score.
    if (toolResultsToScreen && toolResultsToScreen.length > 0) {
      await Promise.all(toolResultsToScreen.map(async (tr) => {
        const trCandidates = await getSHCandidatePatterns(tr, 'tool_result', patterns, undefined, env);
        const tl1 = runL1Detection(tr, trCandidates, { surface: 'tool_result' });
        const tDetectorScores: Record<string, number | null> = { PatternMatcher: tl1.score, SemanticAnalyzer: null };
        const tDetectionSources: string[] = tl1.score > 0 ? ['PatternMatcher'] : [];
        // Always semantic for tool results — direct injection via tool output is the primary attack vector
        const tl2Raw = await callSHAnalysisLLM(tr, 'tool_result', env);
        if (tl2Raw) {
          const tl2 = parseL2Response(tl2Raw);
          if (tl2) {
            const merged = mergeL1AndL2(tl1.threats, tl1.score, tl2);
            tDetectorScores.SemanticAnalyzer = tl2.overall_risk;
            if (tl2.overall_risk > 0) tDetectionSources.push('SemanticAnalyzer');
            const tMultiplied = Math.min(merged.score, 1.0);
            const tThresholds = config.thresholds;
            const tVerdict: SafeHouseVerdict =
              tMultiplied >= tThresholds.quarantine ? 'quarantine'
              : tMultiplied >= tThresholds.warn ? 'warn' : 'pass';
            if (tVerdict !== 'pass') {
              const tDecision: SafeHouseDecision = {
                verdict: tVerdict, overall_risk: tMultiplied, threats: merged.threats,
                detector_scores: tDetectorScores, detection_sources: tDetectionSources,
                session_multiplier: 1.0, duration_ms: 0,
              };
              await logSHEvaluation(agentId, sessionId, 'observe', tDecision, 'tool_result', env);
              await deliverSHWebhooks(tDecision, agentId, sessionId, env);
            }
          }
        }
      }));
    }
  } catch (err) {
    console.warn('[safe-house/observe] Error in observe-mode analysis (fail-open):', err);
  }
}

/** Simple content hash for quarantine records (no sensitive content stored). */
async function hashContent(content: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Handle provider API proxy requests (multi-provider).
 *
 * Wave 1: Thinking injection (provider-specific)
 * Wave 2: Real-time AIP integrity checking
 * Wave 3: Conscience nudge injection (pre-forward, provider-specific)
 * Wave 4: Webhook delivery for integrity events
 */
export async function handleProviderProxy(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  provider: GatewayProvider,
  agentName?: string
): Promise<Response> {
  // ====================================================================
  // Phase A: Per-IP rate limit (before any DB calls — DDoS protection)
  // ====================================================================
  const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (env.BILLING_CACHE) {
    const minute = Math.floor(Date.now() / 60000);
    const ipResult = await checkRateLimitTier(
      env.BILLING_CACHE, `rl:ip:${clientIp}:${minute}`, DEFAULT_RATE_LIMITS.per_ip_rpm
    );
    console.log(JSON.stringify({ kv_rate_limit: { tier: 'ip', count: ipResult.count, limit: DEFAULT_RATE_LIMITS.per_ip_rpm, allowed: ipResult.allowed } }));
    if (!ipResult.allowed) {
      return rateLimitResponse('ip', DEFAULT_RATE_LIMITS.per_ip_rpm, minute);
    }
  }

  // Extract API key from header (provider-specific)
  const apiKey = extractApiKey(request, provider);
  if (!apiKey) {
    const headerName = provider === 'anthropic' ? 'x-api-key'
      : provider === 'openai' ? 'Authorization: Bearer <key>'
      : 'x-goog-api-key';
    return new Response(
      JSON.stringify({
        error: `Missing ${headerName} header`,
        type: 'authentication_error',
      }),
      {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  // JWT signature verification for Supabase-issued tokens.
  // Only applies to JWT-shaped Bearer tokens (3 dot-separated parts).
  // Raw LLM provider API keys (sk-ant-..., sk-proj-...) pass through unchanged.
  // Uses JWKS (ES256) — no extra secret needed, key rotation handled automatically.
  // On success, sub claim is captured for use as a meaningful key_prefix.
  const isJwtToken = looksLikeJwt(apiKey);
  let jwtSub: string | undefined;
  if (isJwtToken) {
    try {
      const jwtPayload = await verifySupabaseJwt(apiKey, env.SUPABASE_URL);
      jwtSub = typeof jwtPayload.sub === 'string' ? jwtPayload.sub : undefined;
    } catch {
      return new Response(
        JSON.stringify({ error: 'Invalid or expired token', type: 'authentication_error' }),
        { status: 401, headers: { 'Content-Type': 'application/json' } },
      );
    }
  }

  const otelExporter = createOTelExporter(env);

  try {
    // key_prefix: for JWT tokens, derived from sub claim (Supabase user UUID prefix).
    // For JWT tokens with no sub: undefined — don't store the meaningless JWT header bytes.
    // For raw API keys: first 16 chars of the key. For named agents, hash uses key|name
    // but the prefix stored is always from apiKey alone (not the combined string).
    const keyPrefix = isJwtToken
      ? (jwtSub ? jwtSub.slice(0, 16) : undefined)
      : apiKey.slice(0, 16);

    // Hash the API key for agent identification
    const agentHash = agentName
      ? await hashApiKey(apiKey + '|' + agentName)
      : await hashApiKey(apiKey);

    // Get or create the agent
    const { agent, isNew } = await getOrCreateAgent(agentHash, env, agentName, keyPrefix);

    // Backfill key_prefix for existing agents that predate key prefix tracking
    if (!isNew && !agent.key_prefix && keyPrefix) {
      ctx.waitUntil(updateKeyPrefix(agent.id, keyPrefix, env));
    }

    // Generate session ID
    const sessionId = generateSessionId(agentHash);

    // Safe House state — populated during Phase 0.5 pre-check, used for response headers
    let shVerdict: SafeHouseVerdict | undefined;
    let shQuarantineId: string | undefined;
    let shSessionRisk: string | undefined; // set in observe mode
    let shNudgeAdvisory: string | undefined; // ADR-037: nudge mode response header

    // Fetch Safe House config early (KV cached — negligible latency)
    const shConfig = await fetchSHConfig(agent.id, env);

    // Build metadata header for CF AI Gateway
    const metadataHeader = buildMetadataHeader(
      agent.id,
      agentHash,
      sessionId,
      env.GATEWAY_VERSION,
      agentName
    );

    // ====================================================================
    // Quota Resolution (always — needed for agent_settings even without billing)
    // ====================================================================
    const billingEnabled = (env.BILLING_ENFORCEMENT_ENABLED ?? 'false') === 'true';
    let quotaDecision: QuotaDecision | null = null;
    let mnemomKeyHash: string | undefined;

    // Check for Mnemom API key (billing identity, separate from LLM key)
    const mnemomKey = request.headers.get('x-mnemom-api-key');

    if (billingEnabled && mnemomKey) {
      mnemomKeyHash = await hashMnemomApiKey(mnemomKey);

      // Validate the Mnemom API key via RPC
      try {
        const keyResponse = await supabaseFetch(
          `${env.SUPABASE_URL}/rest/v1/rpc/resolve_mnemom_api_key`,
          {
            method: 'POST',
            headers: {
              apikey: env.SUPABASE_SECRET_KEY,
              Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ p_key_hash: mnemomKeyHash }),
          },
        );

        if (keyResponse.ok) {
          const keyResult = (await keyResponse.json()) as { valid: boolean; account_id?: string };
          if (!keyResult.valid) {
            return new Response(JSON.stringify({
              error: 'Invalid Mnemom API key',
              type: 'authentication_error',
            }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' },
            });
          }
        }
      } catch (err) {
        // Fail-open: log and continue without key validation
        console.warn('[gateway] Mnemom API key validation failed (fail-open):', err);
      }
    }

    // Read transaction ID from request header (used for transaction-scoped guardrails)
    const transactionId = request.headers.get('x-transaction-id');

    // Resolve quota context + transaction guardrails in parallel.
    // UC-8: fetchPolicyForAgent + mergePolicies are no longer on the hot path.
    // Policy is derived from the canonical alignment card inside evaluatePolicy.
    const [quotaContext, txnGuardrails] = await Promise.all([
      resolveQuotaContext(agent.id, env, mnemomKeyHash),
      transactionId ? fetchTransactionGuardrails(agent.id, transactionId, env) : Promise.resolve(null),
    ]);
    const agentSettings = quotaContext.agent_settings;

    if (billingEnabled) {
      quotaDecision = evaluateQuota(quotaContext);

      if (quotaDecision.action === 'reject') {
        const isContainment = quotaDecision.reason === 'agent_paused' || quotaDecision.reason === 'agent_killed';
        return new Response(JSON.stringify({
          error: isContainment ? 'Agent contained' : 'Request blocked by billing policy',
          type: isContainment ? 'containment_error' : 'billing_error',
          reason: quotaDecision.reason,
          ...(quotaDecision.usage_percent !== undefined && { usage_percent: quotaDecision.usage_percent }),
        }), {
          status: isContainment ? 403 : 402,
          headers: { 'Content-Type': 'application/json', ...quotaDecision.headers },
        });
      }
    }

    // ====================================================================
    // Phase B: Per-agent + per-org rate limits (after identity resolution)
    // ====================================================================
    if (env.BILLING_CACHE) {
      const minute = Math.floor(Date.now() / 60000);
      const orgLimits = (quotaContext.limits ?? {}) as { per_org_rpm?: number; per_agent_rpm?: number };

      // Per-agent check
      const agentLimit = orgLimits.per_agent_rpm ?? DEFAULT_RATE_LIMITS.per_agent_rpm;
      const agentResult = await checkRateLimitTier(
        env.BILLING_CACHE, `rl:agent:${agentHash}:${minute}`, agentLimit
      );
      if (!agentResult.allowed) {
        return rateLimitResponse('agent', agentLimit, minute);
      }

      // Per-org check (only if org association exists)
      if (quotaContext.account_id) {
        const orgLimit = orgLimits.per_org_rpm ?? DEFAULT_RATE_LIMITS.per_org_rpm;
        const orgResult = await checkRateLimitTier(
          env.BILLING_CACHE, `rl:org:${quotaContext.account_id}:${minute}`, orgLimit
        );
        if (!orgResult.allowed) {
          return rateLimitResponse('org', orgLimit, minute);
        }
      }
    }

    // ====================================================================
    // Wave 1: Thinking injection (provider-specific)
    // ====================================================================

    // Clone and parse request body for potential modification
    const originalBody = await request.text();
    let requestBody: Record<string, any> | null = null;
    let modifiedBody = originalBody;
    let injectedNudgeIds: string[] = [];

    try {
      requestBody = JSON.parse(originalBody);

      // Inject thinking configuration based on provider
      if (requestBody) {
        injectThinkingForProvider(requestBody, provider, agentSettings?.thinking_budget ?? 30000);
      }

      // ====================================================================
      // Wave 3: Conscience nudge injection (pre-forward, provider-specific)
      // ====================================================================
      const shFeatureEnabled = quotaContext.feature_flags?.sh_enabled === true;
      const agentEnforcementMode = agent.aip_enforcement_mode || 'observe';
      if (requestBody) {
        injectedNudgeIds = await injectPendingNudges(
          requestBody,
          agent.id,
          agentEnforcementMode,
          env,
          provider,
          { includePreemptive: shFeatureEnabled }
        );
      }

      // ====================================================================
      // Phase 0.5: Safe House — inbound threat screening (ADR-037)
      // ====================================================================
      // Mode dispatch under the unified Protection Card canonical form:
      //   off     — skip dispatch entirely (cost / non-applicability)
      //   observe — async detection, no request-path action
      //   nudge   — sync detection, advisory annotation attached, no block
      //   enforce — sync detection, block on quarantine/block verdicts
      //
      // Passive modes (observe / nudge) dispatch regardless of the legacy
      // `feature_flags.sh_enabled` kill-switch so telemetry + recipe shadow
      // eval keep flowing. enforce still requires explicit opt-in until the
      // kill-switch is fully retired (separate audit).
      const surfaces = shConfig.screen_surfaces;
      const incomingGated = surfaces.incoming;
      const isPassiveMode = shConfig.mode === 'observe' || shConfig.mode === 'nudge';
      const shDispatchEnabled = (shFeatureEnabled || isPassiveMode) && incomingGated;
      if (shDispatchEnabled && shConfig.mode !== 'off' && requestBody !== null) {
        const inboundMessage = extractLastUserMessage(requestBody as Record<string, unknown>, provider);
        if (inboundMessage) {
          // ADR-037: trusted_sources short-circuit. Detection is skipped
          // entirely for sources matching the typed allowlist; we still
          // emit a low-priority trust trace so audit can see what was
          // waved through.
          const trustCtx = {
            apparentAgentId: (requestBody as Record<string, unknown>)?.['x_sh_apparent_agent_id'] as string | undefined,
            apparentDomain: (requestBody as Record<string, unknown>)?.['x_sh_apparent_domain'] as string | undefined,
            clientIp: request.headers.get('cf-connecting-ip'),
          };
          const trustMatch = checkTrustedSource(trustCtx, shConfig.trusted_sources);
          if (trustMatch) {
            console.log(JSON.stringify({
              event: 'sh_trusted_source_skip',
              agent_id: agent.id,
              session_id: sessionId,
              surface: 'incoming',
              bucket: trustMatch.bucket,
              matched: trustMatch.entry,
              mode: shConfig.mode,
            }));
            // Skip detection. Continue request normally.
          } else if (shConfig.mode === 'observe') {
            // Observe mode: pass immediately, run full analysis in background.
            // Tool results screened async if the tool_responses surface is on.
            const toolResultsForObserve = surfaces.tool_responses
              ? extractToolResults(requestBody as Record<string, unknown>, provider).slice(0, 3)
              : [];
            ctx.waitUntil(runObserveSH(agent.id, sessionId, inboundMessage, shConfig, env, toolResultsForObserve));
            const observeSession = await getSHSessionState(sessionId, env).catch(() => null);
            shSessionRisk = observeSession?.session_threat_level ?? 'low';
          } else if (shConfig.mode === 'nudge') {
            // Nudge mode (ADR-037 §Decision 6): run full detection synchronously.
            // If a verdict is warn/quarantine/block we attach an advisory
            // annotation to the prompt context (so the model sees the nudge),
            // emit a structured X-Safe-House-Advisory response header (so
            // the principal's SDK can render it), and continue the request.
            // No quarantine, no block — the message proceeds with extra signal
            // attached.
            const t0 = Date.now();
            const [nudgePatterns, nudgeSession] = await Promise.all([
              fetchSHThreatPatterns(env),
              getSHSessionState(sessionId, env),
            ]);
            const nudgeCandidates = await getSHCandidatePatterns(inboundMessage, 'user_message', nudgePatterns, undefined, env);
            const nL1 = runL1Detection(inboundMessage, nudgeCandidates, { surface: 'user_message' });
            let nThreats = nL1.threats;
            let nScore = nL1.score;
            const nDetectorScores: Record<string, number | null> = { PatternMatcher: nL1.score, SemanticAnalyzer: null };
            const nDetectionSources: string[] = nL1.score > 0 ? ['PatternMatcher'] : [];
            if (nL1.score >= 0.4 || shouldForceSemanticAnalysis(nL1)) {
              const nL2Raw = await callSHAnalysisLLM(inboundMessage, 'user_message', env);
              if (nL2Raw) {
                const nL2 = parseL2Response(nL2Raw);
                if (nL2) {
                  const merged = mergeL1AndL2(nL1.threats, nL1.score, nL2);
                  nThreats = merged.threats;
                  nScore = merged.score;
                  nDetectorScores.SemanticAnalyzer = nL2.overall_risk;
                  if (nL2.overall_risk > 0) nDetectionSources.push('SemanticAnalyzer');
                }
              }
            }
            const { multiplied_score: nMultiplied, session_multiplier: nSessionMultiplier } = applySessionMultiplier(nScore, nudgeSession);
            const t = shConfig.thresholds;
            // In nudge mode the verdict ladder is informational — we attach
            // when the score crosses warn; the categorical label is for
            // telemetry consistency.
            let nVerdict: SafeHouseVerdict = 'pass';
            if (nMultiplied >= t.block) nVerdict = 'nudge';        // would-be block
            else if (nMultiplied >= t.quarantine) nVerdict = 'nudge'; // would-be quarantine
            else if (nMultiplied >= t.warn) nVerdict = 'nudge';
            const nDecision: SafeHouseDecision = {
              verdict: nVerdict,
              overall_risk: nMultiplied,
              threats: nThreats,
              detector_scores: nDetectorScores,
              detection_sources: nDetectionSources,
              session_multiplier: nSessionMultiplier,
              duration_ms: Date.now() - t0,
            };

            if (nVerdict === 'nudge') {
              // Attach advisory annotation INTO the agent's prompt context.
              // The model sees this — the security value of nudge depends on
              // the model receiving the warning, so this is the load-bearing
              // injection point.
              const nudgeNote = buildNudgeAnnotation(nDecision);
              prependNudgeToLastUserMessage(requestBody as Record<string, unknown>, nudgeNote, provider);

              // Set response header (compact JSON) for SDK / dashboard rendering.
              // Stored on a local; applied to responseHeaders in the response phase.
              shNudgeAdvisory = JSON.stringify({
                surface: 'incoming',
                verdict: nVerdict,
                score: Number(nMultiplied.toFixed(3)),
                threats: nThreats.map(t => ({ type: t.type, confidence: Number(t.confidence.toFixed(3)) })),
              });

              shVerdict = nVerdict;

              console.log(JSON.stringify({
                event: 'sh_nudge_attached',
                agent_id: agent.id,
                session_id: sessionId,
                surface: 'incoming',
                score: nMultiplied,
                threats: nThreats.map(t => t.type),
                detector_scores: nDetectorScores,
              }));

              // Persist the evaluation + update session like other paths.
              ctx.waitUntil(logSHEvaluation(agent.id, sessionId, 'nudge', nDecision, 'user_message', env));
              ctx.waitUntil(deliverSHWebhooks(nDecision, agent.id, sessionId, env));
              ctx.waitUntil(cacheSHResultForAIP(sessionId, nDecision, env));
            }
            ctx.waitUntil(updateSHSessionState(sessionId, agent.id, nMultiplied, env));
            ctx.waitUntil(incrementSHUsage(agent.id, env));
          } else {
          const t0 = Date.now();
          const [patterns, sessionState] = await Promise.all([
            fetchSHThreatPatterns(env),
            getSHSessionState(sessionId, env),
          ]);
          const enforceCandidates = await getSHCandidatePatterns(inboundMessage, 'user_message', patterns, undefined, env);
          const l1 = runL1Detection(inboundMessage, enforceCandidates, { surface: 'user_message' });

          // SemanticAnalyzer: call Haiku when PatternMatcher score >= 0.4 OR
          // non-Latin language detected (weaker regex coverage) OR encoding trick found.
          let finalThreats = l1.threats;
          let finalScore = l1.score;
          const detectorScores: Record<string, number | null> = { PatternMatcher: l1.score, SemanticAnalyzer: null };
          const detectionSources: string[] = l1.score > 0 ? ['PatternMatcher'] : [];

          if (l1.score >= 0.4 || shouldForceSemanticAnalysis(l1)) {
            const l2Raw = await callSHAnalysisLLM(inboundMessage, 'user_message', env);
            if (l2Raw) {
              const l2Result = parseL2Response(l2Raw);
              if (l2Result) {
                const merged = mergeL1AndL2(l1.threats, l1.score, l2Result);
                finalThreats = merged.threats;
                finalScore = merged.score;
                detectorScores.SemanticAnalyzer = l2Result.overall_risk;
                if (l2Result.overall_risk > 0) detectionSources.push('SemanticAnalyzer');
              }
            }
          }

          const { multiplied_score, session_multiplier } = applySessionMultiplier(finalScore, sessionState);

          // Phase 5 Stage 5B: recipe tier1 shadow evaluation.
          // Runs only when RECIPE_MODE='shadow' (or 'enforce', reserved for Stage 5D).
          // Verdict is NOT affected in shadow mode — we log what would have happened.
          // Fail-open on every failure path.
          const recipeMode = (env.RECIPE_MODE ?? 'off') as RecipeMode;
          if (recipeMode === 'shadow') {
            const canonicalL2Score = typeof detectorScores.SemanticAnalyzer === 'number'
              ? detectorScores.SemanticAnalyzer
              : null;
            ctx.waitUntil(
              (async (): Promise<void> => {
                try {
                  const recipeIndex = await fetchActiveRecipes(env);
                  if (recipeIndex.all.length === 0) return;
                  const canonicalScores: DetectorScores =
                    buildDetectorScoresFromThreats(finalThreats);
                  if (sessionState) {
                    canonicalScores.session_tracker =
                      sessionState.session_threat_level === 'high' ? 0.85
                      : sessionState.session_threat_level === 'medium' ? 0.55
                      : 0.20;
                  }
                  if (canonicalL2Score !== null) {
                    canonicalScores.semantic_analyzer = canonicalL2Score;
                  }
                  const evalConfig: RecipeEvalConfig = {
                    mode: recipeMode,
                    per_threat_type_cap: 5,
                    global_cap: 10,
                  };
                  const tier1Result = evaluateRecipesTier1(
                    canonicalScores,
                    inboundMessage,
                    recipeIndex,
                    evalConfig,
                  );
                  const telemetry = serializeRecipeTelemetry(
                    tier1Result,
                    null,
                    recipeIndex,
                    recipeMode,
                  );
                  console.log(JSON.stringify({
                    ...telemetry,
                    agent_id: agent.id,
                    session_id: sessionId,
                    surface: 'user_message',
                    sh_mode: 'enforce',
                  }));
                } catch {
                  // Fail open — recipes are additive; a failure must never affect the verdict path.
                }
              })(),
            );
          }

          // ADR-037: trusted_sources are checked at the dispatch entry above
          // and short-circuit before reaching detection. By the time we're
          // here we know the source is not on the typed allowlist.
          const trustAdjustedScore = multiplied_score;

          // Determine verdict from thresholds
          const thresholds = shConfig.thresholds;
          let verdict: SafeHouseVerdict = 'pass';
          if (trustAdjustedScore >= thresholds.block) verdict = 'block';
          else if (trustAdjustedScore >= thresholds.quarantine) verdict = 'quarantine';
          else if (trustAdjustedScore >= thresholds.warn) verdict = 'warn';

          const duration_ms = Date.now() - t0;

          if (verdict !== 'pass') {
            let quarantineId: string | undefined;
            if (verdict === 'block' || verdict === 'quarantine') {
              quarantineId = generateQuarantineId();
            }

            const decision: SafeHouseDecision = {
              verdict,
              overall_risk: trustAdjustedScore,
              threats: finalThreats,
              detector_scores: detectorScores,
              detection_sources: detectionSources,
              session_multiplier,
              quarantine_id: quarantineId,
              duration_ms,
            };

            if (verdict === 'block' || verdict === 'quarantine') {
              // Replace user message with quarantine notification
              const notification = buildQuarantineNotification(quarantineId!, decision);
              replaceLastUserMessageContent(requestBody as Record<string, unknown>, notification.xml, provider);
              shVerdict = verdict;
              shQuarantineId = quarantineId;
              // Log quarantine + evaluation (background)
              const contentHash = await hashContent(inboundMessage);
              ctx.waitUntil(logQuarantinedMessage(quarantineId!, agent.id, sessionId, contentHash, decision, 'user_message', env));
              ctx.waitUntil(logSHEvaluation(agent.id, sessionId, shConfig.mode, decision, 'user_message', env));
              // ADR-040 / T0-3: write a pending_advisories row with
              // source=runtime.front_door.enforce so the agent has
              // cross-turn context next turn for what was prevented.
              ctx.waitUntil(writeFrontDoorAdvisory(agent.id, sessionId, decision, env));
            } else {
              // WARN: decorate message with XML Spotlighting annotation
              const annotated = decorateMessage(inboundMessage, decision);
              replaceLastUserMessageContent(requestBody as Record<string, unknown>, annotated.content, provider);
              shVerdict = verdict;
              ctx.waitUntil(logSHEvaluation(agent.id, sessionId, shConfig.mode, decision, 'user_message', env));
            }

            // Deliver Safe House webhooks for warn/quarantine/block events
            ctx.waitUntil(deliverSHWebhooks(decision, agent.id, sessionId, env));

            // Cache Safe House result in KV for AIP enrichment (Phase 1+)
            ctx.waitUntil(cacheSHResultForAIP(sessionId, decision, env));
            // Write pre-emptive nudge to enforcement channel when score >= 0.6
            // Gateway's existing injectPendingNudges() picks this up automatically
            const nudge = buildPreemptiveNudgeContent(decision);
            if (nudge) {
              ctx.waitUntil(writePreemptiveNudge(agent.id, sessionId, nudge, env));
            }
          }

          // Always update session state with this message's score
          ctx.waitUntil(updateSHSessionState(sessionId, agent.id, trustAdjustedScore, env));
          ctx.waitUntil(incrementSHUsage(agent.id, env));

          console.log(JSON.stringify({
            event: 'sh',
            verdict,
            pattern_score: l1.score,
            multiplied_score: trustAdjustedScore,
            session_multiplier,
            threat_count: finalThreats.length,
            detection_sources: detectionSources,
            duration_ms,
          }));

          // Screen tool results in parallel — primary indirect injection surface.
          // Always triggers SemanticAnalyzer (tool results should be data, not instructions).
          // Uses real `patterns` array (not empty []) for MinHash matching.
          if (surfaces.tool_responses) {
            const toolResultsList = extractToolResults(requestBody as Record<string, unknown>, provider).slice(0, 3);
            await Promise.all(toolResultsList.map(async (toolResult) => {
              const trEnforceCandidates = await getSHCandidatePatterns(toolResult, 'tool_result', patterns, undefined, env);
              const tl1 = runL1Detection(toolResult, trEnforceCandidates, { surface: 'tool_result' });
              const tDetectorScores: Record<string, number | null> = { PatternMatcher: tl1.score, SemanticAnalyzer: null };
              const tDetectionSources: string[] = tl1.score > 0 ? ['PatternMatcher'] : [];
              let tFinalThreats = tl1.threats;
              let tFinalScore = tl1.score;
              // Always semantic for tool results
              const tl2Raw = await callSHAnalysisLLM(toolResult, 'tool_result', env);
              if (tl2Raw) {
                const tl2Result = parseL2Response(tl2Raw);
                if (tl2Result) {
                  const tMerged = mergeL1AndL2(tl1.threats, tl1.score, tl2Result);
                  tFinalThreats = tMerged.threats;
                  tFinalScore = tMerged.score;
                  tDetectorScores.SemanticAnalyzer = tl2Result.overall_risk;
                  if (tl2Result.overall_risk > 0) tDetectionSources.push('SemanticAnalyzer');
                }
              }
              const tThresholds = shConfig.thresholds;
              let tVerdict: SafeHouseVerdict = 'pass';
              if (tFinalScore >= tThresholds.quarantine) tVerdict = 'quarantine';
              else if (tFinalScore >= tThresholds.warn) tVerdict = 'warn';
              if (tVerdict !== 'pass') {
                const tDecision: SafeHouseDecision = {
                  verdict: tVerdict, overall_risk: tFinalScore, threats: tFinalThreats,
                  detector_scores: tDetectorScores, detection_sources: tDetectionSources,
                  session_multiplier: 1.0, duration_ms: 0,
                };
                const tAnnotated = decorateMessage(toolResult, tDecision);
                replaceToolResultContent(requestBody as Record<string, unknown>, toolResult, tAnnotated.content, provider);
                ctx.waitUntil(logSHEvaluation(agent.id, sessionId, shConfig.mode, tDecision, 'tool_result', env));
                console.log(JSON.stringify({ event: 'sh_tool_result', verdict: tVerdict, score: tFinalScore }));
              }
            }));
          }
          } // end enforce else
        }
      }

      modifiedBody = JSON.stringify(requestBody);
    } catch {
      // Body is not valid JSON — forward as-is
      console.warn(`[gateway] Request body is not valid JSON, forwarding as-is (provider: ${provider})`);
    }

    // ====================================================================
    // UC-8 gateway policy evaluation — canonical card is the source of
    // truth. The card was already fetched (with KV caching) by
    // fetchAlignmentData above, so this second fetchCanonicalAlignmentCard
    // hits the cache. The evaluator derives a Policy from the card and
    // layers any transaction guardrails via mergeTransactionGuardrails.
    // ====================================================================
    let policyVerdict: string | null = null;
    let policyCardGaps: unknown[] | null = null;

    try {
      const canonicalCard = await fetchCanonicalAlignmentCard(agent.id, env);
      if (!canonicalCard) {
        // No canonical card (e.g. brand-new agent pre-first-compose). Skip
        // policy evaluation; fail-open posture. The fallback lazy-merge in
        // fetchAlignmentData handles request metadata; policy is not enforced.
        console.warn(`[gateway/policy] No canonical card for ${agent.id}; skipping policy enforcement`);
      } else {
        // ADR-039 Decision 1: prefer top-level autonomy_mode (the new master
        // switch governing CLPI policy). Fall back to legacy enforcement.mode
        // for canonicals composed before the dual-key window. Map the new
        // 4-mode vocabulary to the legacy 3-mode CLPI vocabulary so the rest
        // of this branch (which is keyed off off|warn|enforce) keeps working
        // unchanged: nudge → warn (gateway pre-PR-#5 doesn't render advisory
        // annotations for CLPI; warn is the safe fallback that logs but
        // doesn't block), observe → warn (log without blocking), off → off.
        const enforcement = (canonicalCard.enforcement ?? {}) as Record<string, any>;
        const topLevelAutonomyMode = (canonicalCard as Record<string, any>).autonomy_mode;
        const mapAutonomyToLegacy = (m: unknown): 'off' | 'warn' | 'enforce' | undefined => {
          if (m === 'off') return 'off';
          if (m === 'observe' || m === 'nudge') return 'warn';
          if (m === 'enforce') return 'enforce';
          return undefined;
        };
        const enforcementMode: string =
          (agentSettings as any)?.policy_enforcement_mode ??
          mapAutonomyToLegacy(topLevelAutonomyMode) ??
          enforcement.mode ??
          'warn';

        if (enforcementMode !== 'off') {
          const requestTools = extractToolsFromRequest(requestBody, provider);

          if (requestTools.length > 0) {
            let evalResult = evaluatePolicy({
              context: 'gateway',
              card: canonicalCard as Parameters<typeof evaluatePolicy>[0]['card'],
              tools: requestTools,
              transactionGuardrails: txnGuardrails?.policy ?? undefined,
            });

            // Apply grace period if there are violations
            if (evalResult.violations.length > 0) {
              const gracePeriodHours = enforcement.grace_period_hours ?? 24;
              const graceResult = await applyGracePeriod(
                agent.id,
                evalResult.violations,
                evalResult.warnings,
                gracePeriodHours,
                env
              );

              const hasCriticalOrHigh = graceResult.violations.some(
                (v) => v.severity === 'critical' || v.severity === 'high'
              );
              const hasAnyViolation = graceResult.violations.length > 0;
              let newVerdict: 'pass' | 'fail' | 'warn';
              if (hasCriticalOrHigh) {
                newVerdict = 'fail';
              } else if (hasAnyViolation || graceResult.warnings.length > 0) {
                newVerdict = 'warn';
              } else {
                newVerdict = 'pass';
              }

              evalResult = {
                ...evalResult,
                violations: graceResult.violations,
                warnings: graceResult.warnings,
                verdict: newVerdict,
              };
            }

            policyVerdict = evalResult.verdict;
            policyCardGaps = evalResult.card_gaps?.length ? evalResult.card_gaps : null;

            // Store evaluation (non-blocking). Use canonical_id + card_version
            // as the policy identifier; the audit trail now points at the
            // card that produced the verdict.
            const compositionMeta = (canonicalCard._composition ?? {}) as Record<string, any>;
            const canonicalId = typeof compositionMeta.canonical_id === 'string'
              ? compositionMeta.canonical_id
              : (typeof canonicalCard.card_id === 'string' ? canonicalCard.card_id : 'unknown');
            ctx.waitUntil(
              submitGatewayPolicyEvaluation(
                evalResult,
                agent.id,
                canonicalId,
                1,  // card-derived policy has no independent version number
                env,
                transactionId
              )
            );

            // Enforce mode: same-turn intervention on fail (T0-4, ADR-040).
            // Replaces the prior 403 path which violated CAC. Returns a 200
            // with a synthesized assistant-shaped response per provider so
            // the chat completes; the agent's response names the prevention.
            // Best-effort cross-turn advisory writes the violation context
            // for the next turn.
            if (enforcementMode === 'enforce' && evalResult.verdict === 'fail') {
              const synthesized = buildAutonomyEnforceResponse(
                provider,
                evalResult,
                requestBody,
              );
              ctx.waitUntil(
                writeAutonomyEnforceAdvisory(agent.id, sessionId, evalResult, env),
              );
              console.log(JSON.stringify({
                event: 'gateway_autonomy_enforce',
                agent_id: agent.id,
                session_id: sessionId,
                provider,
                violation_count: evalResult.violations.length,
                violation_tools: evalResult.violations
                  .map((v: any) => v.tool_name)
                  .filter((n: unknown) => typeof n === 'string'),
              }));
              return new Response(synthesized.body, {
                status: 200,
                headers: {
                  'Content-Type': synthesized.contentType,
                  'X-Policy-Verdict': 'fail',
                  'X-Mnemom-Autonomy-Verdict': 'enforced',
                },
              });
            }
          }
        }
      }
    } catch (error) {
      // Fail-open: policy evaluation errors never block requests
      console.warn('[gateway/policy] Evaluation failed (fail-open):', error);
    }

    // Build the forwarding URL — strip provider prefix, forward to CF AI Gateway
    // CF AI Gateway requires provider in URL: .../gateway_name/provider/api_path
    // Strip any trailing provider from base URL, then add the correct one
    const url = new URL(request.url);
    const path = url.pathname.replace(new RegExp(`^/${provider}`), '');
    const baseGatewayUrl = env.CF_AI_GATEWAY_URL.replace(/\/(anthropic|openai|gemini)\/?$/, '');
    const forwardUrl = `${baseGatewayUrl}/${provider}${path}${url.search}`;

    // Clone headers and add metadata + AI Gateway auth
    const forwardHeaders = new Headers(request.headers);
    forwardHeaders.delete('x-smoltbot-agent'); // Internal routing headers — don't forward to CF AI Gateway
    forwardHeaders.delete('x-mnemom-agent');   // New canonical name (dual-header transition)
    forwardHeaders.set('cf-aig-metadata', metadataHeader);
    forwardHeaders.set('cf-aig-authorization', `Bearer ${env.CF_AIG_TOKEN}`);

    // Forward the request with potentially modified body
    // GET/HEAD requests cannot have a body per the Fetch spec
    const forwardRequest = new Request(forwardUrl, {
      method: request.method,
      headers: forwardHeaders,
      ...(request.method !== 'GET' && request.method !== 'HEAD' ? { body: modifiedBody } : {}),
    });

    const response = await fetch(forwardRequest);

    // ====================================================================
    // Wave 2: Real-time AIP integrity checking
    // ====================================================================

    const aipEnabled = (env.AIP_ENABLED ?? 'true') !== 'false';
    const isStreaming = requestBody?.stream === true
      || (requestBody === null && response.headers.get('content-type')?.includes('text/event-stream'));

    // Clone response headers as base for our response
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('x-smoltbot-agent', agent.id);    // deprecated: remove after 6-month transition (2026-10)
    responseHeaders.set('x-mnemom-agent', agent.id);      // canonical new name
    responseHeaders.set('x-smoltbot-session', sessionId); // deprecated: remove after 6-month transition (2026-10)
    responseHeaders.set('x-mnemom-session', sessionId);   // canonical new name

    // Add Safe House headers if screening ran (ADR-037 mode set).
    if (shVerdict) {
      responseHeaders.set('X-Safe-House-Verdict', shVerdict);
      if (shQuarantineId) responseHeaders.set('X-Safe-House-Quarantine-Id', shQuarantineId);
    }
    if (shSessionRisk) {
      responseHeaders.set('X-Safe-House-Session-Risk', shSessionRisk);
    }
    if (shConfig.mode === 'observe' || shConfig.mode === 'nudge') {
      responseHeaders.set('X-Safe-House-Mode', shConfig.mode);
    }
    if (shNudgeAdvisory) {
      responseHeaders.set('X-Safe-House-Advisory', shNudgeAdvisory);
    }

    // Add policy verdict header if evaluation ran
    if (policyVerdict) {
      responseHeaders.set('X-Policy-Verdict', policyVerdict);
    }

    // Echo transaction ID back to caller
    if (transactionId) {
      responseHeaders.set('X-Transaction-Id', transactionId);
    }

    // Add nudge headers if any were injected, and mark them delivered
    if (injectedNudgeIds.length > 0) {
      responseHeaders.set('X-AIP-Enforcement', 'nudge');
      responseHeaders.set('X-AIP-Nudge-Count', String(injectedNudgeIds.length));
      ctx.waitUntil(markNudgesDelivered(injectedNudgeIds, sessionId, env));
    }

    // Merge quota enforcement headers into response
    if (quotaDecision) {
      for (const [k, v] of Object.entries(quotaDecision.headers)) {
        responseHeaders.set(k, v);
      }
    }

    // Update last_seen (background)
    ctx.waitUntil(updateLastSeen(agent.id, env));

    // Ensure alignment card only when AAP is enabled for this agent
    if (agentSettings?.aap_enabled !== false) {
      ctx.waitUntil(ensureAlignmentCard(agent.id, env));
    }

    // Skip AIP if globally disabled or disabled for this agent
    const aipDisabledForAgent = agentSettings?.aip_enabled === false;
    if (!aipEnabled || aipDisabledForAgent) {
      responseHeaders.set('X-AIP-Verdict', 'disabled');
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    }

    // Streaming: tee the stream for background AIP analysis (zero latency impact)
    if (isStreaming) {
      if (!response.ok || !response.body) {
        responseHeaders.set('X-AIP-Verdict', 'skipped');
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        });
      }

      // CBD streaming fast path: inline canary scanner before client sees bytes.
      // If a canary is detected, the stream is aborted mid-flight.
      // Cost: ~1ms KV read (cached) + ~0ms per chunk (string search).
      const cbdCanaries = (env.SAFE_HOUSE_ENABLED === 'true' && env.BILLING_CACHE)
        ? await fetchAgentCanaries(agent.id, env).catch(() => [] as string[])
        : [] as string[];
      const cbdFilteredBody = response.body
        ? response.body.pipeThrough(
            createCBDStreamTransform(agent.id, sessionId, cbdCanaries, env, ctx)
          )
        : null;

      // Tee the CBD-filtered stream: one fork to client, one to background analysis
      const [clientStream, analysisStream] = (cbdFilteredBody ?? response.body!).tee();

      ctx.waitUntil(
        analyzeStreamInBackground(
          analysisStream, provider, agent, sessionId,
          agentSettings, quotaContext, requestBody, otelExporter, env,
          cbdCanaries  // pass pre-fetched canaries to avoid redundant KV read
        )
      );

      responseHeaders.set('X-AIP-Verdict', 'pending');
      return new Response(clientStream, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    }

    // Skip AIP for upstream error responses (e.g. 401 from invalid API keys)
    if (!response.ok) {
      responseHeaders.set('X-AIP-Verdict', 'skipped');
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    }

    // Buffer the full response for analysis
    let canaryTriggered = false;
    // Mutable so the back-door (T0-6) can redact PII / secrets in place
    // before downstream paths (AIP, response delivery) operate on the body.
    let responseBodyText = await response.text();

    // Safe House Canary detection: scan response for planted canary credentials
    // This is in the fail-open wrapper — any error continues without blocking
    try {
      const canaries = await fetchAgentCanaries(agent.id, env);
      if (canaries.length > 0) {
        // Scan extracted text content only, not the full JSON envelope
        // (prevents false positives from canary values in JSON metadata fields)
        const canaryTextToScan = (() => {
          try {
            const parsed = JSON.parse(responseBodyText);
            const content = parsed?.content as Array<{ type: string; text?: string }> | undefined;
            if (Array.isArray(content)) {
              return content.filter(b => b.type === 'text').map(b => b.text ?? '').join('\n');
            }
            // OpenAI format
            const choices = parsed?.choices as Array<{ message?: { content?: string } }> | undefined;
            if (Array.isArray(choices)) {
              return choices.map(c => c.message?.content ?? '').join('\n');
            }
          } catch { /* fall through to full text scan */ }
          return responseBodyText;
        })();
        const triggered = scanForCanaryUse(canaryTextToScan, canaries);
        if (triggered) {
          canaryTriggered = true;
          console.log(JSON.stringify({
            event: 'sh_canary_triggered',
            agent_id: agent.id,
            session_id: sessionId,
            canary_prefix: triggered.slice(0, 6) + '****',
          }));
          ctx.waitUntil(markCanaryTriggered(agent.id, triggered, env));
          ctx.waitUntil(logCBDEvaluation(agent.id, sessionId, 'block',
            { CanaryMatcher: 1.0, PatternMatcher: null, SemanticAnalyzer: null },
            ['CanaryMatcher'], 'outbound',
            [{ type: 'data_exfiltration' as ThreatType, confidence: 1.0,
               reasoning: 'Canary credential detected in agent response — confirmed compromise' }],
            1.0, env));
        }
      }
    } catch {
      // Fail-open: canary scan errors never block response
    }

    if (canaryTriggered) {
      // CBD P0: block the response entirely — do not return the compromised content
      responseHeaders.set('X-Safe-House-Canary-Triggered', 'true');
      return new Response(JSON.stringify({
        error: 'Agent response blocked — canary credential detected (confirmed compromise)',
        type: 'sh_canary_triggered',
        agent_id: agent.id,
        session_id: sessionId,
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...Object.fromEntries(responseHeaders.entries()),
        },
      });
    }

    // Fail-open wrapper: entire AIP pipeline wrapped in try/catch
    try {
      // Fetch alignment data and recent checkpoints in parallel
      const [alignmentData, historicalCheckpoints] = await Promise.all([
        fetchAlignmentData(agent.id, env),
        fetchRecentCheckpoints(agent.id, sessionId, env),
      ]);

      const { card, conscienceValues, enforcementMode } = alignmentData;

      // If no card available, forward with clear verdict
      if (!card) {
        console.log('[gateway/aip] No alignment card found, forwarding as clear');
        responseHeaders.set('X-AIP-Verdict', 'clear');
        responseHeaders.set('X-AIP-Synthetic', 'true');
        return new Response(responseBodyText, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        });
      }

      // ADR-039 Decision 1: integrity_mode === 'off' means AIP is fully
      // opted-out for this agent. Skip the checkpoint entirely and forward
      // the response as clear. Distinct from the no-card path (this is an
      // explicit opt-out, not a missing card).
      if (enforcementMode === 'off') {
        console.log(JSON.stringify({
          event: 'aip_skipped', agent_id: agent.id, reason: 'integrity_mode_off',
        }));
        responseHeaders.set('X-AIP-Verdict', 'clear');
        responseHeaders.set('X-AIP-Synthetic', 'true');
        return new Response(responseBodyText, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        });
      }

      // Map AAP card to AIP format
      const aipCard = mapCardToAIP(card);

      // Create WindowManager and hydrate with historical checkpoints
      const windowConfig = {
        max_size: 10,
        mode: 'sliding' as const,
        session_boundary: 'reset' as const,
        max_age_seconds: 3600,
      };
      const window = new WindowManager(windowConfig, sessionId);

      // Hydrate window with historical checkpoints
      for (const cp of historicalCheckpoints) {
        window.push(cp);
      }

      // Extract thinking block from response using provider adapter
      const registry = createAdapterRegistry();
      const adapter = registry.get(provider);
      const thinking = adapter.extractThinking(responseBodyText);

      // If no thinking block found, forward with clear verdict
      if (!thinking) {
        console.log(`[gateway/aip] No thinking block found in response (provider: ${provider})`);
        responseHeaders.set('X-AIP-Verdict', 'clear');
        responseHeaders.set('X-AIP-Synthetic', 'true');
        return new Response(responseBodyText, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        });
      }

      // Extract output text for output-aware analysis (when enabled)
      const analyzeOutput = agentSettings?.analyze_output === true;
      const outputText = analyzeOutput ? extractOutputText(responseBodyText) : undefined;

      // ====================================================================
      // Back door — outbound DLP redaction (Phase 6 per validation-charter,
      // T0-6, ADR-040). Surgical redaction of PII / secret patterns in the
      // agent's response. Modes:
      //   - off:     skip dispatch entirely
      //   - observe: scan + log only, body unchanged
      //   - nudge:   scan + log + redact body in-place + write advisory
      //   - enforce: same as nudge (back door's "intervention" is the
      //              redaction itself; nudge vs enforce on this surface
      //              differs in the upstream policy thresholds, not the
      //              same-turn mechanism)
      // Gated by `screen_surfaces.outgoing` so customers can opt out per
      // protection card.
      // ====================================================================
      let outboundDLPDetected = false;
      let outboundDLPMatches: DLPMatch[] = [];
      const outgoingGated = shConfig.screen_surfaces.outgoing;
      const backDoorActive =
        env.SAFE_HOUSE_ENABLED === 'true' &&
        env.BILLING_CACHE &&
        outgoingGated &&
        shConfig.mode !== 'off';
      if (backDoorActive) {
        try {
          const result = applyBackDoorRedaction(responseBodyText);
          if (result.matches.length > 0) {
            outboundDLPDetected = true;
            outboundDLPMatches = result.matches;
            // Under nudge / enforce, replace the response body with the
            // redacted version so the customer never sees the
            // unredacted content. Under observe, leave the body intact
            // (today's behavior) — detection-only.
            const bodyReplaced =
              shConfig.mode === 'nudge' || shConfig.mode === 'enforce';
            if (bodyReplaced) {
              responseBodyText = result.body;
            }
            ctx.waitUntil(logCBDEvaluation(
              agent.id, sessionId, 'warn',
              { DLPScanner: 0.9, PatternMatcher: null, SemanticAnalyzer: null },
              ['DLPScanner'], 'outbound',
              result.matches.map((m) => ({
                type: 'pii_in_inbound' as ThreatType,
                confidence: 0.95,
                reasoning: `Outbound DLP: ${m.type} detected in agent response`,
              })),
              0.9, env,
            ));
            console.log(JSON.stringify({
              event: 'sh_exit_dlp',
              agent_id: agent.id,
              session_id: sessionId,
              mode: shConfig.mode,
              body_replaced: bodyReplaced,
              match_count: result.matches.length,
              match_types: Array.from(new Set(result.matches.map((m) => m.type))),
            }));
          }
        } catch { /* fail-open */ }
      }

      if (outboundDLPDetected) {
        responseHeaders.set('X-Safe-House-DLP', 'detected');
        // Cross-turn carryover advisory under nudge / enforce so the
        // agent knows next turn what was redacted. Mode is checked
        // inside writeBackDoorAdvisory; observe never reaches here in
        // a way that triggers a write.
        ctx.waitUntil(writeBackDoorAdvisory(
          agent.id,
          sessionId,
          { matches: outboundDLPMatches, mode: shConfig.mode },
          env,
        ));
      }

      // CBD Semantic analysis — async, never blocks the response
      if (env.SAFE_HOUSE_ENABLED === 'true' && outputText) {
        ctx.waitUntil(runCBDSemanticAnalysis(outputText, agent.id, sessionId, env));
      }

      // Phase 7: Hybrid mode — call hosted /v1/analyze if no local ANTHROPIC_API_KEY
      if (!env.ANTHROPIC_API_KEY && env.MNEMOM_ANALYZE_URL && env.MNEMOM_API_KEY) {
        try {
          const hybridController = new AbortController();
          const hybridTimeout = setTimeout(() => hybridController.abort(), 10000);
          const hybridResponse = await fetch(env.MNEMOM_ANALYZE_URL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Mnemom-Api-Key': env.MNEMOM_API_KEY,
            },
            body: JSON.stringify({
              thinking_block: thinking.content,
              thinking_metadata: { provider: thinking.provider, model: thinking.model },
              agent_id: agent.id,
              session_id: sessionId,
              card: aipCard,
              conscience_values: conscienceValues || [...DEFAULT_CONSCIENCE_VALUES],
              ...(outputText ? { output_block: outputText } : {}),
              task_context: (() => {
                const desc = card?.extensions?.mnemom?.description || card?.extensions?.mnemom?.role || '';
                return desc ? desc.toString().slice(0, 200) : undefined;
              })(),
              window_context: window.getState().checkpoints.map((cp: IntegrityCheckpoint) => ({
                checkpoint_id: cp.checkpoint_id,
                verdict: cp.verdict,
                reasoning_summary: cp.reasoning_summary,
              })),
              store_checkpoint: true,
            }),
            signal: hybridController.signal,
          });
          clearTimeout(hybridTimeout);

          if (hybridResponse.ok) {
            const hybridResult = (await hybridResponse.json()) as Record<string, unknown>;
            const hybridCheckpoint = hybridResult.checkpoint as IntegrityCheckpoint;
            const hybridProceed = hybridResult.proceed as boolean;
            const hybridAction = hybridResult.recommended_action as string;

            responseHeaders.set('X-AIP-Verdict', hybridCheckpoint.verdict);
            responseHeaders.set('X-AIP-Checkpoint-Id', hybridCheckpoint.checkpoint_id);
            responseHeaders.set('X-AIP-Action', hybridAction);
            responseHeaders.set('X-AIP-Proceed', String(hybridProceed));
            responseHeaders.set('X-AIP-Source', 'hybrid');
            responseHeaders.set('X-AIP-Analysis-Scope', outputText ? 'thinking_and_output' : 'thinking_only');

            // Pass through attestation data from hybrid API response
            const hybridAttestation = hybridResult.attestation as Record<string, unknown> | undefined;
            if (hybridAttestation) {
              if (hybridAttestation.certificate_id) {
                responseHeaders.set('X-AIP-Certificate-Id', String(hybridAttestation.certificate_id));
              }
              if (hybridAttestation.chain_hash) {
                responseHeaders.set('X-AIP-Chain-Hash', String(hybridAttestation.chain_hash));
              }
            }

            if (enforcementMode === 'enforce' && hybridCheckpoint.verdict === 'boundary_violation') {
              // T0-5 / ADR-040: same-turn response-body replacement
              // (replaces the prior 403 path, CAC-violating). The chat
              // completes 2xx; the agent's voice names the boundary
              // violation. X-AIP-* headers are already set on
              // `responseHeaders` above and pass through unchanged.
              const interventionText = buildIntegrityInterventionText(hybridCheckpoint);
              const replacedBody = replaceIntegrityViolationContent(responseBodyText, interventionText);
              // Hybrid path historically did not persist the checkpoint
              // (the 403 short-circuited before any storeCheckpoint
              // call). Persist now so the audit trail records what was
              // intervened on.
              ctx.waitUntil(storeCheckpoint(hybridCheckpoint, 'gateway', env, hybridAttestation as AttestationData | undefined));
              ctx.waitUntil(writeIntegrityEnforceAdvisory(agent.id, sessionId, hybridCheckpoint, env));
              console.log(JSON.stringify({
                event: 'gateway_integrity_enforce',
                source: 'hybrid',
                agent_id: agent.id,
                session_id: sessionId,
                checkpoint_id: hybridCheckpoint.checkpoint_id,
                boundary_value: extractBoundaryValueName(hybridCheckpoint),
                concern_count: hybridCheckpoint.concerns?.length ?? 0,
              }));
              return new Response(replacedBody, {
                status: 200,
                headers: responseHeaders,
              });
            }

            return new Response(responseBodyText, {
              status: response.status,
              statusText: response.statusText,
              headers: responseHeaders,
            });
          }
          // Non-OK: fall through to fail-open
          console.error(`[gateway/hybrid] Analyze API returned ${hybridResponse.status}`);
        } catch (hybridErr) {
          console.error('[gateway/hybrid] Hybrid analyze failed (fail-open):', hybridErr);
        }

        // Fail-open for hybrid mode
        responseHeaders.set('X-AIP-Verdict', 'error');
        responseHeaders.set('X-AIP-Source', 'hybrid');
        return new Response(responseBodyText, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        });
      }

      // Skip AIP if no analysis capability configured
      if (!env.ANTHROPIC_API_KEY) {
        responseHeaders.set('X-AIP-Verdict', 'skipped');
        responseHeaders.set('X-AIP-Reason', 'no-analysis-configured');
        return new Response(responseBodyText, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        });
      }

      // Build conscience prompt
      const values: ConscienceValue[] = conscienceValues || [...DEFAULT_CONSCIENCE_VALUES];

      // Build task context from request messages and card description (PII-safe)
      const gatewayAgentDesc = card?.extensions?.mnemom?.description
        || card?.extensions?.mnemom?.role
        || '';
      let gatewayUserQuery = '';
      try {
        const msgs = requestBody?.messages;
        if (Array.isArray(msgs) && msgs.length > 0) {
          const lastUserMsg = [...msgs].reverse().find((m: any) => m.role === 'user');
          if (lastUserMsg) {
            const content = typeof lastUserMsg.content === 'string'
              ? lastUserMsg.content
              : Array.isArray(lastUserMsg.content)
                ? lastUserMsg.content.filter((b: any) => b.type === 'text').map((b: any) => b.text).join(' ')
                : '';
            gatewayUserQuery = content.slice(0, 200);
          }
        }
      } catch { /* fail-open */ }
      const gatewayTaskParts = [
        gatewayAgentDesc ? `${gatewayAgentDesc}.` : '',
        gatewayUserQuery ? `User request: ${gatewayUserQuery}` : '',
      ].filter(Boolean);
      const gatewayTaskContext = gatewayTaskParts.length > 0 ? gatewayTaskParts.join(' ') : undefined;

      // Retrieve cached Safe House result for this session (written during pre-check, Phase 0.5)
      const cachedCFDResult = await env.BILLING_CACHE?.get(`sh:result:${sessionId}:latest`)
        .then(raw => raw ? JSON.parse(raw) as SafeHouseDecision : null)
        .catch(() => null) ?? null;
      const cfdThreatContext = cachedCFDResult ? buildThreatContextForAIP(cachedCFDResult) : undefined;
      const enrichedTaskContext = [gatewayTaskContext, cfdThreatContext].filter(Boolean).join('\n\n') || undefined;

      const prompt = buildConsciencePrompt({
        card: aipCard,
        conscienceValues: values,
        windowContext: window.getState().checkpoints,
        thinkingBlock: thinking.content,
        taskContext: enrichedTaskContext,
        ...(outputText ? { outputBlock: outputText, outputTokenBudget: DEFAULT_OUTPUT_TOKEN_BUDGET } : {}),
      });

      // Call analysis LLM (Haiku)
      console.log(`[gateway/aip] Calling analysis LLM for agent=${agent.id} session=${sessionId} thinking_chars=${thinking.content.length} output_analysis=${!!outputText}`);
      const analysisStartTime = Date.now();
      const rawAnalysisResponse = await callAnalysisLLM(prompt.system, prompt.user, env, { analyzeOutput });
      const analysisDurationMs = Date.now() - analysisStartTime;

      // Strip markdown code fences if present (claude-haiku-4-5 wraps JSON in ```json...```)
      const jsonMatch = rawAnalysisResponse.match(/\{[\s\S]*\}/);
      const analysisResponseText = jsonMatch ? sanitizeJson(jsonMatch[0]) : rawAnalysisResponse;
      console.log(`[gateway/aip] Analysis complete in ${analysisDurationMs}ms, json_extracted=${!!jsonMatch}`);

      // Hash thinking block (and output block if present) using Web Crypto API
      const thinkingHash = await sha256(thinking.content);
      const outputHash = outputText ? await sha256(outputText) : undefined;

      // Build checkpoint via checkIntegrity
      const windowState = window.getState();
      const checkpoint = checkIntegrity({
        analysisResponse: analysisResponseText,
        thinking: {
          hash: thinkingHash,
          provider: thinking.provider,
          model: thinking.model,
          tokensOriginal: prompt.originalTokens,
          tokensAnalyzed: prompt.analyzedTokens,
          truncated: prompt.truncated,
          confidence: thinking.confidence,
        },
        ...(outputHash && prompt.outputOriginalTokens != null ? {
          output: {
            hash: outputHash,
            tokensOriginal: prompt.outputOriginalTokens,
            tokensAnalyzed: prompt.outputAnalyzedTokens ?? 0,
            truncated: prompt.outputTruncated ?? false,
          },
        } : {}),
        agentId: agent.id,
        cardId: aipCard.card_id,
        sessionId,
        windowPosition: {
          index: windowState.size,
          window_size: windowState.size + 1,
        },
        analysisModel: 'claude-haiku-4-5-20251001',
        analysisDurationMs,
      });

      // Push to window, get summary, build signal
      window.push(checkpoint);
      const summary = window.getSummary();
      const signal = buildSignal(checkpoint, summary);

      if (otelExporter) {
        otelExporter.recordIntegrityCheck(signal);
      }

      // Detect drift
      let driftState: DriftState = createDriftState();
      const driftResult = detectIntegrityDrift(
        driftState,
        checkpoint,
        window.getState().checkpoints,
      );
      driftState = driftResult.state;

      if (driftResult.alert) {
        summary.drift_alert_active = true;
      }

      // Cryptographic Checkpoint Attestation (extracted to reusable function)
      const windowContext = [
        ...window.getState().checkpoints.map((cp: IntegrityCheckpoint) => ({
          checkpoint_id: cp.checkpoint_id,
          verdict: cp.verdict,
          reasoning_summary: cp.reasoning_summary,
        })),
        ...(cachedCFDResult ? [{
          checkpoint_id: `sh:${sessionId}:latest`,
          verdict: cachedCFDResult.verdict as string,
          reasoning_summary: `Safe House pre-screen: risk=${cachedCFDResult.overall_risk.toFixed(2)} threats=${cachedCFDResult.threats.map((t: { type: string }) => t.type).join(',')}`,
        }] : []),
      ];
      const attestation = await attestCheckpoint(
        checkpoint, agent, sessionId, thinkingHash,
        aipCard, values, windowContext, quotaContext, env
      );

      // Set AIP headers
      responseHeaders.set('X-AIP-Verdict', checkpoint.verdict);
      responseHeaders.set('X-AIP-Checkpoint-Id', checkpoint.checkpoint_id);
      responseHeaders.set('X-AIP-Action', signal.recommended_action);
      responseHeaders.set('X-AIP-Proceed', String(signal.proceed));
      responseHeaders.set('X-AIP-Analysis-Scope', outputText ? 'thinking_and_output' : 'thinking_only');
      if (attestation) {
        responseHeaders.set('X-AIP-Certificate-Id', attestation.certificate_id);
        responseHeaders.set('X-AIP-Chain-Hash', attestation.chain_hash);
      }

      // Background: store checkpoint (with attestation), deliver webhooks, meter, flush OTel
      ctx.waitUntil(storeCheckpoint(checkpoint, 'gateway', env, attestation));
      ctx.waitUntil(submitMeteringEvent(agent.id, checkpoint.checkpoint_id, 'gateway', env));
      ctx.waitUntil(deliverWebhooks(checkpoint, env));
      if (otelExporter) {
        ctx.waitUntil(otelExporter.flush());
      }

      // Request ZK proof if enabled (non-streaming path has policy eval card_gaps)
      const nsProofDecision = shouldProve(checkpoint, agentSettings, policyCardGaps);
      if (nsProofDecision === 'prove') {
        ctx.waitUntil(requestProof(
          checkpoint.checkpoint_id,
          {
            analysis_response_text: analysisResponseText,
            thinking_block_hash: thinkingHash,
            card_hash: await sha256(JSON.stringify(aipCard)),
            values_hash: await sha256(JSON.stringify(values)),
            model: 'claude-haiku-4-5-20251001',
          },
          attestation ? { input_commitment: attestation.input_commitment } : undefined,
          env,
        ).catch(() => { /* fail-open */ }));
      } else if (nsProofDecision === 'deferred') {
        ctx.waitUntil(deferProof(
          checkpoint.checkpoint_id,
          {
            analysis_response_text: analysisResponseText,
            thinking_block_hash: thinkingHash,
            card_hash: await sha256(JSON.stringify(aipCard)),
            values_hash: await sha256(JSON.stringify(values)),
            model: 'claude-haiku-4-5-20251001',
          },
          env,
        ).catch(() => { /* fail-open */ }));
      }

      // Create pending nudge for boundary violations (nudge or enforce mode)
      if (
        checkpoint.verdict === 'boundary_violation' &&
        (enforcementMode === 'nudge' || enforcementMode === 'enforce')
      ) {
        ctx.waitUntil(
          countSessionViolations(agent.id, sessionId, env).then(violationCount => {
            if (shouldCreateNudge(agentSettings, violationCount)) {
              return createPendingNudge(checkpoint, agent.id, sessionId, env);
            }
          })
        );
        ctx.waitUntil(checkAutoContainment(agent.id, sessionId, checkpoint, env));
      }

      // Apply enforcement
      if (enforcementMode === 'enforce' && checkpoint.verdict === 'boundary_violation') {
        // T0-5 / ADR-040: same-turn response-body replacement
        // (replaces the prior 403 path, CAC-violating). The chat
        // completes 2xx; the agent's voice names the boundary
        // violation. X-AIP-* headers are already set on
        // `responseHeaders` above and pass through unchanged.
        // The integrity_checkpoints row is already queued for storage
        // at the storeCheckpoint() ctx.waitUntil higher in this block.
        const interventionText = buildIntegrityInterventionText(checkpoint);
        const replacedBody = replaceIntegrityViolationContent(responseBodyText, interventionText);
        ctx.waitUntil(writeIntegrityEnforceAdvisory(agent.id, sessionId, checkpoint, env));
        console.log(JSON.stringify({
          event: 'gateway_integrity_enforce',
          source: 'sync',
          agent_id: agent.id,
          session_id: sessionId,
          checkpoint_id: checkpoint.checkpoint_id,
          boundary_value: extractBoundaryValueName(checkpoint),
          concern_count: checkpoint.concerns?.length ?? 0,
        }));
        return new Response(replacedBody, {
          status: 200,
          headers: responseHeaders,
        });
      }

      // Observe mode or enforce mode with non-violation: forward response with AIP headers
      return new Response(responseBodyText, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (aipError) {
      // Fail-open: log error, set error header, forward response unchanged
      console.error('[gateway/aip] AIP pipeline error (fail-open):', aipError);
      responseHeaders.set('X-AIP-Verdict', 'error');
      return new Response(responseBodyText, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    }
  } catch (error) {
    // Log full error details server-side, return generic message to client
    console.error('Gateway error:', error);
    return new Response(
      JSON.stringify({
        error: 'An internal error occurred',
        type: 'gateway_error',
      }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }
}

// ============================================================================
// Anthropic Proxy Handler (backward-compat wrapper)
// ============================================================================

/**
 * Handle Anthropic API proxy requests.
 * Thin backward-compatibility wrapper around handleProviderProxy.
 */
export async function handleAnthropicProxy(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  return handleProviderProxy(request, env, ctx, 'anthropic');
}

// ============================================================================
// Phase 7: License Validation (Self-Hosted)
// ============================================================================

/**
 * Validate enterprise license JWT for self-hosted gateways.
 * Caches validation in KV with 24h TTL. 7-day grace period on failure.
 */
async function validateLicense(env: Env): Promise<{ valid: boolean; warning?: string }> {
  if (!env.MNEMOM_LICENSE_JWT) return { valid: true }; // Not a licensed deployment

  const cache = env.BILLING_CACHE;

  // Decode JWT locally (no verification — server validates signature)
  const parts = env.MNEMOM_LICENSE_JWT.split('.');
  if (parts.length !== 3) return { valid: false };

  let claims: Record<string, unknown>;
  try {
    const padded = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padding = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
    claims = JSON.parse(atob(padded + padding));
  } catch {
    return { valid: false };
  }

  const licenseId = claims.license_id as string;
  if (!licenseId) return { valid: false };

  // Check exp claim locally (works offline)
  const now = Math.floor(Date.now() / 1000);
  if (claims.exp && (claims.exp as number) < now) {
    // Check grace period
    if (cache) {
      const lastValid = await cache.get(`license:last_valid:${licenseId}`).catch(() => null);
      if (lastValid) {
        const lastValidDate = new Date(lastValid);
        const daysSince = (Date.now() - lastValidDate.getTime()) / 86400000;
        if (daysSince < 7) {
          return { valid: true, warning: 'license_expired_grace_period' };
        }
      }
    }
    return { valid: false };
  }

  // Check cached validation
  if (cache) {
    const cached = await cache.get(`license:status:${licenseId}`).catch(() => null);
    if (cached === 'valid') return { valid: true };
    if (cached === 'invalid') {
      // Check grace period
      const lastValid = await cache.get(`license:last_valid:${licenseId}`).catch(() => null);
      if (lastValid) {
        const daysSince = (Date.now() - new Date(lastValid).getTime()) / 86400000;
        if (daysSince < 7) return { valid: true, warning: 'license_validation_failed_grace' };
      }
      return { valid: false };
    }
  }

  // Phone-home validation (best effort)
  try {
    const validateUrl = env.MNEMOM_ANALYZE_URL
      ? env.MNEMOM_ANALYZE_URL.replace('/v1/analyze', '/v1/license/validate')
      : 'https://api.mnemom.ai/v1/license/validate';

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await supabaseFetch(validateUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        license: env.MNEMOM_LICENSE_JWT,
        instance_id: env.GATEWAY_VERSION || 'unknown',
        instance_metadata: { gateway_version: env.GATEWAY_VERSION },
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (resp.ok) {
      if (cache) {
        await cache.put(`license:status:${licenseId}`, 'valid', { expirationTtl: 86400 }).catch(() => {});
        await cache.put(`license:last_valid:${licenseId}`, new Date().toISOString(), { expirationTtl: 604800 }).catch(() => {});
      }
      return { valid: true };
    }

    if (cache) {
      await cache.put(`license:status:${licenseId}`, 'invalid', { expirationTtl: 3600 }).catch(() => {});
    }
  } catch {
    // Network failure — check grace period
    if (cache) {
      const lastValid = await cache.get(`license:last_valid:${licenseId}`).catch(() => null);
      if (lastValid) {
        const daysSince = (Date.now() - new Date(lastValid).getTime()) / 86400000;
        if (daysSince < 7) return { valid: true, warning: 'license_validation_unreachable_grace' };
      }
    }
    // If offline license, trust the JWT exp
    if (claims.is_offline) return { valid: true };
  }

  return { valid: false };
}

// ============================================================================
// CORS Origin Whitelist
// ============================================================================

const ALLOWED_ORIGINS = [
  'https://mnemom.ai',
  'https://www.mnemom.ai',
  'https://app.mnemom.ai',
  'https://gateway.mnemom.ai',
];

/**
 * Return the appropriate CORS origin header value.
 * If the request origin is in the whitelist, echo it back.
 * Otherwise, return the primary origin (restricts access).
 */
function getCorsOrigin(request: Request): string {
  const origin = request.headers.get('Origin') || '';
  return ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
}

// ============================================================================
// Main Request Handler
// ============================================================================

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight handling
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': getCorsOrigin(request),
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, x-api-key, anthropic-version, anthropic-beta, authorization, x-goog-api-key, x-mnemom-api-key, x-smoltbot-agent, x-mnemom-agent',
          'Access-Control-Expose-Headers': 'x-smoltbot-agent, x-smoltbot-session, x-mnemom-agent, x-mnemom-session, X-AIP-Verdict, X-AIP-Checkpoint-Id, X-AIP-Action, X-AIP-Proceed, X-AIP-Synthetic, X-AIP-Certificate-Id, X-AIP-Chain-Hash, X-Mnemom-Usage-Warning, X-Mnemom-Usage-Percent, X-Safe-House-Verdict, X-Safe-House-Quarantine-Id, X-Safe-House-Session-Risk, X-Safe-House-Mode, X-Safe-House-Simulated-Verdict, X-Safe-House-Canary-Triggered, X-Safe-House-DLP',
          'Access-Control-Max-Age': '86400',
          'Vary': 'Origin',
        },
      });
    }

    // Health check endpoint
    if (path === '/health' || path === '/health/') {
      return handleHealthCheck(env);
    }

    // Phase 7: License validation for self-hosted deployments
    if (env.MNEMOM_LICENSE_JWT) {
      const licenseResult = await validateLicense(env);
      if (!licenseResult.valid) {
        return new Response(
          JSON.stringify({ error: 'License invalid or expired', type: 'license_error' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      }
    }

    // Models endpoint
    if (path === '/models.json') {
      return handleModelsEndpoint(env);
    }

    // Named agent identification via x-mnemom-agent header (canonical) or
    // x-smoltbot-agent (deprecated, accepted during 6-month transition until 2026-10).
    // URL paths stay the same (/anthropic/*, /openai/*, /gemini/*).
    // NOTE: URL-prefix approaches (/a/{name}/ and /agent/{name}/) don't work
    // because Cloudflare AI Gateway intercepts paths matching /{provider}/v1/...
    // at any depth on this domain.
    const agentName = request.headers.get('x-mnemom-agent') || request.headers.get('x-smoltbot-agent') || undefined;

    // Anthropic API proxy
    if (path.startsWith('/anthropic/') || path === '/anthropic') {
      return handleProviderProxy(request, env, ctx, 'anthropic', agentName);
    }

    // OpenAI API proxy
    if (path.startsWith('/openai/') || path === '/openai') {
      return handleProviderProxy(request, env, ctx, 'openai', agentName);
    }

    // Gemini API proxy
    if (path.startsWith('/gemini/') || path === '/gemini') {
      return handleProviderProxy(request, env, ctx, 'gemini', agentName);
    }

    // 404 for all other paths
    return new Response(
      JSON.stringify({
        error: 'Not found',
        type: 'not_found',
        message: 'This gateway handles /health, /anthropic/*, /openai/*, /gemini/* endpoints. Use x-mnemom-agent header for named agents.',
      }),
      {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  },
};
