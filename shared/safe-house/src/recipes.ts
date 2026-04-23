/**
 * Detection Recipe loader + in-memory index.
 *
 * Stage 5A of Phase 5 — pure plumbing. Compiles the JSON rows returned by
 * mnemom-api's `/v1/internal/active-recipes` (backed by the
 * get_active_detection_recipes() RPC, revision 3 from migration 138) into
 * a runtime-ready index. The index is consumed by the tier1 evaluator
 * that lands in Stage 5B; this module does not evaluate or affect verdicts.
 *
 * ## Canonical vocabulary
 *
 * The `CanonicalDetector` / `CanonicalThreatType` / `CanonicalDoor` /
 * `CanonicalVariantClass` / `CanonicalSeverity` string unions below must
 * stay in sync with `mnemom-api/src/arena/recipe-schema.ts`. We duplicate
 * them rather than importing because the safe-house package is vendored
 * into the gateway Worker and should not take a cross-repo TypeScript
 * dependency on mnemom-api. Unknown values on the wire are tolerated —
 * `compileRecipeFromRpcRow()` returns null when a row can't be routed.
 *
 * ## Index shape
 *
 * - `by_detector` — primary tier1 fan-out. For each `CanonicalDetector`,
 *   the list of recipes whose tier1 conditions reference it.
 * - `by_threat_type` — used by the Stage 5B tier2 retrieval path.
 * - `lsh_bands` — reserved for fingerprint-based recipes (populated in
 *   Stage 5B when the evaluator wires up the KV LSH namespace).
 * - `all` — every compiled recipe, ordered by severity (p0 > p1 > p2)
 *   then by version descending. Consumed by the top-K ranker at
 *   evaluation time.
 */

// ── Canonical vocabulary — mirror of mnemom-api/src/arena/recipe-schema.ts ──

export const CANONICAL_DOORS = ['front', 'back'] as const;
export type CanonicalDoor = (typeof CANONICAL_DOORS)[number];

export const CANONICAL_THREAT_TYPES = [
  'prompt_injection',
  'indirect_injection',
  'bec_fraud',
  'social_engineering',
  'multi_turn_hijack',
  'agent_spoofing',
  'data_exfiltration',
  'pii_in_inbound',
  'prompt_leak',
  'regulated_advice',
  'canary_match',
  'multi_vector',
] as const;
export type CanonicalThreatType = (typeof CANONICAL_THREAT_TYPES)[number];

export const CANONICAL_VARIANT_CLASSES = [
  'unicode_obfuscation',
  'encoding_wrap',
  'emoji_injection',
  'multilingual_variant',
  'crescendo_buildup',
  'context_fragmentation',
  'document_embedded',
  'tool_result_spoof',
  'authority_stacking',
  'forged_waiver',
  'sibling_impersonation',
  'credential_in_tool_args',
  'prompt_verbatim_leak',
  'output_laundering',
  'noise_burial',
] as const;
export type CanonicalVariantClass = (typeof CANONICAL_VARIANT_CLASSES)[number];

export const CANONICAL_SEVERITIES_P = ['p0', 'p1', 'p2'] as const;
export type CanonicalSeverity = (typeof CANONICAL_SEVERITIES_P)[number];

export const CANONICAL_DETECTORS = [
  'pattern_matcher',
  'signal_scorer',
  'fingerprint_matcher',
  'canary_matcher',
  'session_tracker',
  'semantic_analyzer',
  'dlp_scanner',
  'prompt_leak_detector',
  'launder_detector',
  'reg_compliance_checker',
] as const;
export type CanonicalDetector = (typeof CANONICAL_DETECTORS)[number];

export const CANONICAL_OPERATORS = [
  'gt', 'lt', 'gte', 'lte', 'eq', 'neq', 'matches', 'contains',
] as const;
export type CanonicalOperator = (typeof CANONICAL_OPERATORS)[number];

export const RECIPE_SCOPES = ['arena_only', 'canary', 'production'] as const;
export type RecipeScope = (typeof RECIPE_SCOPES)[number];

function isMember<T extends readonly string[]>(v: unknown, set: T): v is T[number] {
  return typeof v === 'string' && (set as readonly string[]).includes(v);
}

// ── Wire shape — what `/v1/internal/active-recipes` returns ────────────

export interface RpcTier1Condition {
  detector?: string;
  metric?: string;
  signal?: string;
  operator: string;
  threshold: number | string;
}

export interface RpcTier1 {
  match?: 'any' | 'all';
  conditions?: RpcTier1Condition[];
}

export interface RpcTier2Check {
  id?: string;
  type?: string;
  content?: string;
}

export interface RpcTier2 {
  trigger?: { on_signals?: string[]; on_threat_types?: string[] };
  checks?: RpcTier2Check[];
}

export interface RpcParsedContent {
  tier1?: RpcTier1;
  tier2?: RpcTier2;
  tier3?: unknown;
  door?: string;
  threat_type?: string;
  variant_class?: string;
  evasion_technique?: string;
  severity?: string;
  mitre_atlas?: string;
}

/** Shape of one row from `get_active_detection_recipes()` (migration 138). */
export interface RecipeRpcRow {
  id: string;
  version?: number;
  technique_category?: string;
  technique_ids?: string[];
  severity?: string;        // legacy scale (low/medium/high/critical)
  severity_p?: string | null; // p0/p1/p2 (XFD)
  scope?: string;
  has_tier1?: boolean;
  has_tier2?: boolean;
  has_tier3?: boolean;
  parsed_content?: RpcParsedContent | null;
  yaml_content?: string | null;
  hit_count?: number;
  similarity_hash?: string | null;
  door?: string | null;
  threat_type?: string | null;
  variant_class?: string | null;
  evasion_technique?: string | null;
  mitre_atlas?: string | null;
}

// ── Compiled shape — what the evaluator consumes ──────────────────────

export type CompiledCondition =
  | {
      kind: 'score';
      detector: CanonicalDetector;
      operator: CanonicalOperator;
      threshold: number;
      signal?: string;
    }
  | {
      kind: 'pattern';
      detector: CanonicalDetector;
      operator: 'matches' | 'contains';
      pattern: string;       // raw pattern source (regex or substring)
      regex: RegExp | null;  // null when operator='contains' or when compile failed
      signal?: string;
    }
  | {
      kind: 'fingerprint';
      detector: 'fingerprint_matcher';
      operator: CanonicalOperator;
      threshold: number;
      signal?: string;       // identifier referenced by the evaluator's fingerprint lookup
    };

export interface CompiledTier1 {
  match: 'any' | 'all';
  conditions: CompiledCondition[];
}

/** Stage 5A treats tier2 as opaque passthrough — the Stage 5B evaluator
 *  feeds the raw checks straight into an LLM prompt. */
export interface CompiledTier2Check {
  id?: string;
  type: string;
  content: string;
}

export interface CompiledTier2 {
  on_signals: string[];
  on_threat_types: string[];
  checks: CompiledTier2Check[];
}

export interface CompiledRecipe {
  id: string;
  version: number;
  door: CanonicalDoor;
  threat_type: CanonicalThreatType;
  variant_class: CanonicalVariantClass | null;
  evasion_technique: string | null;
  severity: CanonicalSeverity;
  scope: RecipeScope;
  similarity_hash: string | null;
  hit_count: number;
  technique_category: string | null;

  /** Flags from the RPC row — indicate whether the recipe declared tiers,
   *  independent of whether compile produced runtime-ready structures. */
  has_tier1: boolean;
  has_tier2: boolean;
  has_tier3: boolean;

  /** Null when the row declared tier1 but no conditions compiled cleanly
   *  (e.g. every condition referenced an unknown detector). */
  tier1: CompiledTier1 | null;
  tier2: CompiledTier2 | null;
  /** tier3 is not consumed by Stage 5A/5B. Passthrough for future stages. */
  tier3_raw: unknown;

  /** Raw YAML preserved for tier2 LLM-prompt construction in Stage 5C. */
  yaml_content: string | null;
}

export interface RecipeIndex {
  loaded_at: number;
  by_detector: Map<CanonicalDetector, CompiledRecipe[]>;
  by_threat_type: Map<CanonicalThreatType, CompiledRecipe[]>;
  lsh_bands: Map<string, CompiledRecipe[]>;
  all: CompiledRecipe[];
}

// ── Compile ───────────────────────────────────────────────────────────

function coerceNumber(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string') {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function compileCondition(raw: RpcTier1Condition): CompiledCondition | null {
  const detector = raw.detector;
  if (!detector || !isMember(detector, CANONICAL_DETECTORS)) return null;
  if (!isMember(raw.operator, CANONICAL_OPERATORS)) return null;
  const signal = typeof raw.signal === 'string' ? raw.signal : undefined;

  if (raw.operator === 'matches') {
    const pattern = typeof raw.threshold === 'string' ? raw.threshold : null;
    if (pattern === null) return null;
    let regex: RegExp | null = null;
    try {
      regex = new RegExp(pattern, 'i');
    } catch {
      // Malformed regex — store the raw pattern so the evaluator can log
      // and skip without a throw.
      regex = null;
    }
    return {
      kind: 'pattern',
      detector,
      operator: 'matches',
      pattern,
      regex,
      signal,
    };
  }

  if (raw.operator === 'contains') {
    const pattern = typeof raw.threshold === 'string' ? raw.threshold : null;
    if (pattern === null) return null;
    return {
      kind: 'pattern',
      detector,
      operator: 'contains',
      pattern,
      regex: null,
      signal,
    };
  }

  // Numeric comparator from here down
  const threshold = coerceNumber(raw.threshold);
  if (threshold === null) return null;

  if (detector === 'fingerprint_matcher') {
    return {
      kind: 'fingerprint',
      detector: 'fingerprint_matcher',
      operator: raw.operator,
      threshold,
      signal,
    };
  }

  return {
    kind: 'score',
    detector,
    operator: raw.operator,
    threshold,
    signal,
  };
}

function compileTier1(raw: RpcTier1 | undefined): CompiledTier1 | null {
  if (!raw || !Array.isArray(raw.conditions) || raw.conditions.length === 0) return null;
  const conditions: CompiledCondition[] = [];
  for (const c of raw.conditions) {
    const compiled = compileCondition(c);
    if (compiled) conditions.push(compiled);
  }
  if (conditions.length === 0) return null;
  const match: 'any' | 'all' = raw.match === 'all' ? 'all' : 'any';
  return { match, conditions };
}

function compileTier2(raw: RpcTier2 | undefined): CompiledTier2 | null {
  if (!raw) return null;
  const checks: CompiledTier2Check[] = [];
  if (Array.isArray(raw.checks)) {
    for (const ck of raw.checks) {
      if (typeof ck.type !== 'string' || typeof ck.content !== 'string') continue;
      checks.push({
        id: typeof ck.id === 'string' ? ck.id : undefined,
        type: ck.type,
        content: ck.content,
      });
    }
  }
  if (checks.length === 0) return null;
  const on_signals = Array.isArray(raw.trigger?.on_signals)
    ? raw.trigger!.on_signals!.filter((s): s is string => typeof s === 'string')
    : [];
  const on_threat_types = Array.isArray(raw.trigger?.on_threat_types)
    ? raw.trigger!.on_threat_types!.filter((s): s is string => typeof s === 'string')
    : [];
  return { on_signals, on_threat_types, checks };
}

/** Compile one RPC row. Returns null for rows that can't be routed — e.g.
 *  door missing (pre-XFD recipes not yet backfilled) or threat_type
 *  outside the canonical set. The caller is expected to log these as
 *  `recipe_skipped` for observability. */
export function compileRecipeFromRpcRow(row: RecipeRpcRow): CompiledRecipe | null {
  if (!row.id) return null;
  if (!isMember(row.door, CANONICAL_DOORS)) return null;
  if (!isMember(row.threat_type, CANONICAL_THREAT_TYPES)) return null;

  const severity = isMember(row.severity_p, CANONICAL_SEVERITIES_P) ? row.severity_p : 'p2';
  const variant_class = isMember(row.variant_class, CANONICAL_VARIANT_CLASSES)
    ? row.variant_class
    : null;
  const scope = isMember(row.scope, RECIPE_SCOPES) ? row.scope : 'arena_only';

  const parsed = row.parsed_content ?? {};
  const tier1 = row.has_tier1 ? compileTier1(parsed.tier1) : null;
  const tier2 = row.has_tier2 ? compileTier2(parsed.tier2) : null;

  return {
    id: row.id,
    version: row.version ?? 1,
    door: row.door,
    threat_type: row.threat_type,
    variant_class,
    evasion_technique:
      typeof row.evasion_technique === 'string' && row.evasion_technique.length > 0
        ? row.evasion_technique
        : null,
    severity,
    scope,
    similarity_hash:
      typeof row.similarity_hash === 'string' && row.similarity_hash.length > 0
        ? row.similarity_hash
        : null,
    hit_count: typeof row.hit_count === 'number' ? row.hit_count : 0,
    technique_category:
      typeof row.technique_category === 'string' ? row.technique_category : null,
    has_tier1: !!row.has_tier1,
    has_tier2: !!row.has_tier2,
    has_tier3: !!row.has_tier3,
    tier1,
    tier2,
    tier3_raw: parsed.tier3 ?? null,
    yaml_content: typeof row.yaml_content === 'string' ? row.yaml_content : null,
  };
}

// ── Index ─────────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<CanonicalSeverity, number> = { p0: 0, p1: 1, p2: 2 };

/** Build an index over an array of RPC rows. Rows that can't be compiled
 *  are silently dropped from the indexes (the compiler already returned
 *  null for them). `all` is sorted by severity ascending (p0 first), then
 *  by version descending. */
export function buildRecipeIndex(
  rows: RecipeRpcRow[],
  now: number = Date.now(),
): RecipeIndex {
  const compiled: CompiledRecipe[] = [];
  for (const row of rows) {
    const r = compileRecipeFromRpcRow(row);
    if (r) compiled.push(r);
  }
  compiled.sort((a, b) => {
    const sa = SEVERITY_RANK[a.severity];
    const sb = SEVERITY_RANK[b.severity];
    if (sa !== sb) return sa - sb;
    return b.version - a.version;
  });

  const by_detector = new Map<CanonicalDetector, CompiledRecipe[]>();
  const by_threat_type = new Map<CanonicalThreatType, CompiledRecipe[]>();
  const lsh_bands = new Map<string, CompiledRecipe[]>();

  for (const r of compiled) {
    const bucket = by_threat_type.get(r.threat_type);
    if (bucket) bucket.push(r);
    else by_threat_type.set(r.threat_type, [r]);

    if (r.tier1) {
      const seen = new Set<CanonicalDetector>();
      for (const c of r.tier1.conditions) {
        if (seen.has(c.detector as CanonicalDetector)) continue;
        seen.add(c.detector as CanonicalDetector);
        const b = by_detector.get(c.detector as CanonicalDetector);
        if (b) b.push(r);
        else by_detector.set(c.detector as CanonicalDetector, [r]);
      }
    }
  }

  return {
    loaded_at: now,
    by_detector,
    by_threat_type,
    lsh_bands,
    all: compiled,
  };
}
