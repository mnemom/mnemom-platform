/**
 * UC-6 — Canonical card adapters for the gateway.
 *
 * As of UC-3, every agent has a pre-composed canonical alignment card in
 * `canonical_agent_cards` (unified shape — autonomy, audit, conscience,
 * integrity, capabilities, enforcement) and a canonical protection card
 * in `canonical_protection_cards` (mode, thresholds, screen_surfaces,
 * trusted_sources).
 *
 * The gateway's hot path still wants cards in:
 *   - AAP 1.0.x shape (autonomy_envelope, audit_commitment) for the
 *     existing `mapCardToAIP()` + LLM input builders. We map unified →
 *     AAP via `mapUnifiedCardToAAP()` below.
 *   - SafeHouseConfig shape for the XFD Safe House detector types.
 *     `mapCanonicalToSafeHouseConfig()` produces that.
 *
 * These mappers are the seam between the canonical storage format
 * (unified, per ADR-008) and the locked-protocol / detector shapes that
 * every hot-path consumer expects. Same contracts as the mirror mappers
 * in mnemom-api's src/composition/mappers.ts — keep them in sync if the
 * unified card schema evolves.
 */

import type { SafeHouseConfig, ScreenSurfaces, TrustedSourceBuckets } from '@mnemom/safe-house';

// ── AAP 1.0.x shape (re-declared to avoid importing from the locked pkg) ───

export interface AAPAlignmentCard {
  card_id?: string;
  agent_id: string;
  issued_at?: string;
  expires_at?: string | null;
  aap_version?: string;
  principal?: unknown;
  values?: unknown;
  autonomy_envelope: {
    bounded_actions: string[];
    forbidden_actions?: string[];
    escalation_triggers?: unknown[];
    max_autonomous_value?: { amount: number; currency?: string };
  };
  audit_commitment?: {
    trace_format?: string;
    retention_days?: number;
    queryable?: boolean;
    query_endpoint?: string;
    tamper_evidence?: string | null;
    storage?: unknown;
  };
  extensions?: Record<string, unknown>;
}

export function mapUnifiedCardToAAP(card: Record<string, unknown>): AAPAlignmentCard {
  const c = card as Record<string, any>;
  const composition = (c._composition as Record<string, any> | undefined) ?? {};
  const autonomy = (c.autonomy as Record<string, any> | undefined) ?? {};
  const audit = (c.audit as Record<string, any> | undefined) ?? {};

  return {
    card_id: c.card_id ?? composition.source_card_id ?? composition.canonical_id,
    agent_id: c.agent_id,
    issued_at: c.issued_at,
    expires_at: c.expires_at ?? null,
    aap_version: typeof c.card_version === 'string' ? c.card_version : undefined,
    principal: c.principal,
    values: c.values,
    autonomy_envelope: {
      bounded_actions: Array.isArray(autonomy.bounded_actions) ? autonomy.bounded_actions : [],
      forbidden_actions: Array.isArray(autonomy.forbidden_actions) ? autonomy.forbidden_actions : undefined,
      escalation_triggers: Array.isArray(autonomy.escalation_triggers) ? autonomy.escalation_triggers : undefined,
      max_autonomous_value: autonomy.max_autonomous_value,
    },
    audit_commitment: {
      trace_format: audit.trace_format,
      retention_days: audit.retention_days,
      queryable: audit.queryable,
      query_endpoint: audit.query_endpoint,
      tamper_evidence: audit.tamper_evidence,
      storage: audit.storage,
    },
    extensions: c.extensions as Record<string, unknown> | undefined,
  };
}

// ── Protection card → SafeHouseConfig (ADR-037 canonical form) ─────────────

const DEFAULT_THRESHOLDS = { warn: 0.60, quarantine: 0.80, block: 0.95 };
const DEFAULT_SURFACES: ScreenSurfaces = {
  incoming: true,
  outgoing: true,
  tool_calls: true,
  tool_responses: true,
};
const DEFAULT_TRUSTED: TrustedSourceBuckets = { domains: [], agent_ids: [], ip_ranges: [] };

const MODES = new Set(['off', 'observe', 'nudge', 'enforce']);

export function mapCanonicalToSafeHouseConfig(card: Record<string, unknown>): SafeHouseConfig {
  const c = card as Record<string, any>;
  const mode: SafeHouseConfig['mode'] = MODES.has(c.mode) ? c.mode : 'observe';
  return {
    mode,
    thresholds: {
      warn: typeof c.thresholds?.warn === 'number' ? c.thresholds.warn : DEFAULT_THRESHOLDS.warn,
      quarantine: typeof c.thresholds?.quarantine === 'number' ? c.thresholds.quarantine : DEFAULT_THRESHOLDS.quarantine,
      block: typeof c.thresholds?.block === 'number' ? c.thresholds.block : DEFAULT_THRESHOLDS.block,
    },
    screen_surfaces: mapSurfaces(c.screen_surfaces),
    trusted_sources: mapTrustedSources(c.trusted_sources),
  };
}

function mapSurfaces(s: unknown): ScreenSurfaces {
  if (s && typeof s === 'object' && !Array.isArray(s)) {
    const obj = s as Record<string, unknown>;
    return {
      incoming: typeof obj.incoming === 'boolean' ? obj.incoming : DEFAULT_SURFACES.incoming,
      outgoing: typeof obj.outgoing === 'boolean' ? obj.outgoing : DEFAULT_SURFACES.outgoing,
      tool_calls: typeof obj.tool_calls === 'boolean' ? obj.tool_calls : DEFAULT_SURFACES.tool_calls,
      tool_responses: typeof obj.tool_responses === 'boolean' ? obj.tool_responses : DEFAULT_SURFACES.tool_responses,
    };
  }
  return { ...DEFAULT_SURFACES };
}

function mapTrustedSources(t: unknown): TrustedSourceBuckets {
  if (t && typeof t === 'object' && !Array.isArray(t)) {
    const obj = t as Record<string, unknown>;
    return {
      domains: Array.isArray(obj.domains) ? obj.domains.filter((x): x is string => typeof x === 'string') : [],
      agent_ids: Array.isArray(obj.agent_ids) ? obj.agent_ids.filter((x): x is string => typeof x === 'string') : [],
      ip_ranges: Array.isArray(obj.ip_ranges) ? obj.ip_ranges.filter((x): x is string => typeof x === 'string') : [],
    };
  }
  return { ...DEFAULT_TRUSTED };
}

// ── Canonical-first fetch helpers ──────────────────────────────────────────
// Callers try the canonical path first; on null, fall back to the legacy
// lazy-merge path. Both branches log so we can watch the fallback rate decay
// to zero post-UC-6 rollout.

interface KVEnv {
  SUPABASE_URL: string;
  SUPABASE_SECRET_KEY: string;
  BILLING_CACHE?: KVNamespace;
}

const CANONICAL_CARD_KV_TTL_SECONDS = 300;

/**
 * Read a canonical alignment card. Prefers KV cache; when DB says
 * `needs_recompose = true` (an org template change or exemption mutation
 * is pending fan-out), bypass the cache and return the fresh row without
 * repopulating. The next `recompose_pending()` cron run clears the flag
 * and the subsequent read repopulates the cache.
 */
export async function fetchCanonicalAlignmentCard(
  agentId: string,
  env: KVEnv,
): Promise<Record<string, unknown> | null> {
  const cacheKey = `canonical-align:${agentId}`;
  if (env.BILLING_CACHE) {
    const cached = await env.BILLING_CACHE.get(cacheKey, 'json');
    if (cached) return cached as Record<string, unknown>;
  }
  const url = new URL(`${env.SUPABASE_URL}/rest/v1/canonical_agent_cards`);
  url.searchParams.set('agent_id', `eq.${agentId}`);
  url.searchParams.set('limit', '1');
  url.searchParams.set('select', 'card_json,needs_recompose');
  const resp = await fetch(url.toString(), {
    headers: {
      apikey: env.SUPABASE_SECRET_KEY,
      Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
    },
  });
  if (!resp.ok) return null;
  const rows = (await resp.json()) as Array<{
    card_json?: Record<string, unknown>;
    needs_recompose?: boolean;
  }>;
  const row = rows[0];
  if (!row?.card_json) return null;

  // If a recompose is pending, skip KV cache population — the card we just
  // read is stale-in-intent. The next recompose_pending() cron cycle flips
  // the flag and the subsequent read will repopulate cleanly.
  if (!row.needs_recompose && env.BILLING_CACHE) {
    await env.BILLING_CACHE.put(cacheKey, JSON.stringify(row.card_json), {
      expirationTtl: CANONICAL_CARD_KV_TTL_SECONDS,
    });
  }
  return row.card_json;
}

export async function fetchCanonicalProtectionCard(
  agentId: string,
  env: KVEnv,
): Promise<Record<string, unknown> | null> {
  const cacheKey = `canonical-protect:${agentId}`;
  if (env.BILLING_CACHE) {
    const cached = await env.BILLING_CACHE.get(cacheKey, 'json');
    if (cached) return cached as Record<string, unknown>;
  }
  const url = new URL(`${env.SUPABASE_URL}/rest/v1/canonical_protection_cards`);
  url.searchParams.set('agent_id', `eq.${agentId}`);
  url.searchParams.set('limit', '1');
  url.searchParams.set('select', 'card_json,needs_recompose');
  const resp = await fetch(url.toString(), {
    headers: {
      apikey: env.SUPABASE_SECRET_KEY,
      Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
    },
  });
  if (!resp.ok) return null;
  const rows = (await resp.json()) as Array<{
    card_json?: Record<string, unknown>;
    needs_recompose?: boolean;
  }>;
  const row = rows[0];
  if (!row?.card_json) return null;
  if (!row.needs_recompose && env.BILLING_CACHE) {
    await env.BILLING_CACHE.put(cacheKey, JSON.stringify(row.card_json), {
      expirationTtl: CANONICAL_CARD_KV_TTL_SECONDS,
    });
  }
  return row.card_json;
}
