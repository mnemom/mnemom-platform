/**
 * Tier1 + Tier2 evaluator for compiled Detection Recipes.
 *
 * Stage 5B of Phase 5. Consumes the `RecipeIndex` produced by `recipes.ts`
 * and a `detector_scores` map built by the gateway. Emits a `Tier1Result`
 * with matched recipes, ranked + capped. A separate tier2 path builds the
 * LLM prompt fragment (piggy-backed on the existing L2 Haiku call) and
 * parses the response.
 *
 * **No verdict impact.** Stage 5B runs in shadow — the gateway logs what
 * fired but doesn't fold the result into the Safe-House score. Stage 5D
 * flips the enforce switch.
 *
 * ## Detector coverage
 *
 * The evaluator speaks the full 10-detector canonical vocabulary at the
 * type level, but only evaluates a subset of those detectors in Stage 5B:
 *
 *   Evaluated:      pattern_matcher, signal_scorer, fingerprint_matcher,
 *                   session_tracker, semantic_analyzer
 *   No-op + logged: canary_matcher, dlp_scanner, prompt_leak_detector,
 *                   launder_detector, reg_compliance_checker
 *
 * "No-op" means the condition contributes nothing to the hit decision;
 * the condition is recorded under `skipped_conditions` in the telemetry.
 * A recipe whose tier1 can't evaluate any condition cleanly is recorded
 * in `skipped_recipes` with a reason.
 *
 * ## Top-K cap (Decision 1 — per-threat-type)
 *
 * Tier1 matches are cheap (map lookups + arithmetic). Tier2 is expensive
 * (LLM call). The cap is on tier2. Rule:
 *
 *   - Group tier1 hits by `threat_type`.
 *   - Within each group, keep the top `per_threat_type_cap` by
 *     (severity asc, version desc, hit_count desc).
 *   - Across groups, keep at most `global_cap` — breaks ties by severity
 *     across groups.
 *
 * ## behavioral_pattern tier2 check
 *
 * Skipped in Stage 5B with a `tier2_check_skipped` telemetry event.
 * Runtime surface for session-trajectory serialization is Phase 6+.
 */

import type {
  CanonicalDetector,
  CanonicalThreatType,
  CanonicalSeverity,
  CompiledCondition,
  CompiledRecipe,
  CompiledTier2Check,
  RecipeIndex,
} from './recipes.js';
import { CANONICAL_DETECTORS } from './recipes.js';

// ── Configuration ───────────────────────────────────────────────────

export type RecipeMode = 'off' | 'shadow' | 'enforce';

export interface RecipeEvalConfig {
  /** `off` — evaluator is a no-op, returns empty result.
   *  `shadow` — evaluate + log, zero verdict impact. (Stage 5B default.)
   *  `enforce` — evaluate + contribute to verdict. (Stage 5D.) */
  mode: RecipeMode;
  /** Max tier1 hits kept per threat_type before tier2 promotion. */
  per_threat_type_cap: number;
  /** Max tier1 hits kept across all threat types before tier2 promotion. */
  global_cap: number;
}

export const DEFAULT_RECIPE_EVAL_CONFIG: RecipeEvalConfig = {
  mode: 'off',
  per_threat_type_cap: 5,
  global_cap: 10,
};

// ── Detector-score input ────────────────────────────────────────────

/** Keyed by canonical detector slug. Absent entries = detector didn't run
 *  this request. `null` = detector ran but produced no score. Numeric =
 *  0.0 to 1.0 confidence. */
export type DetectorScores = Partial<Record<CanonicalDetector, number | null>>;

/** Which detectors Stage 5B actually evaluates. Conditions referencing
 *  any other detector skip with `detector_not_evaluated`. */
const EVALUABLE_DETECTORS: ReadonlySet<CanonicalDetector> = new Set<CanonicalDetector>([
  'pattern_matcher',
  'signal_scorer',
  'fingerprint_matcher',
  'session_tracker',
  'semantic_analyzer',
]);

// ── Result shapes ───────────────────────────────────────────────────

export type ConditionSkipReason =
  | 'detector_not_evaluated'
  | 'detector_not_scored'
  | 'regex_compile_failed'
  | 'missing_signal';

export interface MatchedCondition {
  detector: CanonicalDetector;
  operator: string;
  /** What the condition needed (threshold for score; pattern for regex). */
  expected: number | string;
  /** What the detector produced for this request. `null` for pattern
   *  matches (no numeric value; just a match/no-match). */
  observed: number | null;
  signal?: string;
}

export interface SkippedCondition {
  detector: string;
  operator: string;
  reason: ConditionSkipReason;
  signal?: string;
}

export interface Tier1Hit {
  recipe_id: string;
  recipe_version: number;
  threat_type: CanonicalThreatType;
  severity: CanonicalSeverity;
  door: 'front' | 'back';
  scope: 'arena_only' | 'canary' | 'production';
  matched_conditions: MatchedCondition[];
  skipped_conditions: SkippedCondition[];
  /** Whether the recipe's tier1.match rule (`any` or `all`) was satisfied. */
  matched: boolean;
}

export interface Tier1Result {
  /** All tier1 evaluations for this request — before the top-K cap. */
  all_hits: Tier1Hit[];
  /** Subset of `all_hits` promoted to tier2 eligibility (after cap). */
  capped_hits: Tier1Hit[];
  /** Recipes that couldn't evaluate at all (no compiled tier1, or every
   *  condition skipped). Distinct from non-hits. */
  skipped_recipes: Array<{ recipe_id: string; reason: string }>;
  /** Count of tier1 hits beyond the cap — i.e., would-be-evaluated
   *  tier2 checks that didn't run this request. */
  tier2_skipped_budget: number;
  duration_ms: number;
}

export type Tier2CheckSkipReason =
  | 'behavioral_pattern_unsupported'
  | 'llm_no_response'
  | 'parse_error'
  | 'unknown_check_type';

export interface Tier2CheckResult {
  recipe_id: string;
  check_id?: string;
  check_type: string;
  matched: boolean;
  reasoning?: string;
  skipped?: Tier2CheckSkipReason;
}

export interface Tier2Result {
  /** Checks that produced a verdict (matched=true or matched=false). */
  check_results: Tier2CheckResult[];
  /** Checks skipped entirely — including behavioral_pattern. */
  skipped: Tier2CheckResult[];
  duration_ms: number;
}

// ── Pre-condition evaluator helpers ─────────────────────────────────

function compareScore(
  observed: number,
  operator: string,
  threshold: number,
): boolean {
  switch (operator) {
    case 'gt': return observed > threshold;
    case 'gte': return observed >= threshold;
    case 'lt': return observed < threshold;
    case 'lte': return observed <= threshold;
    case 'eq': return observed === threshold;
    case 'neq': return observed !== threshold;
    default: return false;
  }
}

function evaluateCondition(
  cond: CompiledCondition,
  scores: DetectorScores,
  content: string,
): { matched: boolean; matchedEntry?: MatchedCondition; skippedEntry?: SkippedCondition } {
  const detector = cond.detector;

  if (!EVALUABLE_DETECTORS.has(detector as CanonicalDetector)) {
    return {
      matched: false,
      skippedEntry: {
        detector,
        operator: cond.operator,
        reason: 'detector_not_evaluated',
        signal: cond.signal,
      },
    };
  }

  if (cond.kind === 'pattern') {
    if (cond.operator === 'matches') {
      if (!cond.regex) {
        return {
          matched: false,
          skippedEntry: {
            detector,
            operator: cond.operator,
            reason: 'regex_compile_failed',
            signal: cond.signal,
          },
        };
      }
      const hit = cond.regex.test(content);
      return {
        matched: hit,
        matchedEntry: hit
          ? {
              detector: detector as CanonicalDetector,
              operator: cond.operator,
              expected: cond.pattern,
              observed: null,
              signal: cond.signal,
            }
          : undefined,
      };
    }
    if (cond.operator === 'contains') {
      const hit = content.toLowerCase().includes(cond.pattern.toLowerCase());
      return {
        matched: hit,
        matchedEntry: hit
          ? {
              detector: detector as CanonicalDetector,
              operator: cond.operator,
              expected: cond.pattern,
              observed: null,
              signal: cond.signal,
            }
          : undefined,
      };
    }
    return {
      matched: false,
      skippedEntry: {
        detector,
        operator: cond.operator,
        reason: 'detector_not_evaluated',
        signal: cond.signal,
      },
    };
  }

  // score + fingerprint kinds use numeric comparison
  const raw = scores[detector as CanonicalDetector];
  if (raw === undefined || raw === null) {
    return {
      matched: false,
      skippedEntry: {
        detector,
        operator: cond.operator,
        reason: 'detector_not_scored',
        signal: cond.signal,
      },
    };
  }
  const matched = compareScore(raw, cond.operator, cond.threshold);
  return {
    matched,
    matchedEntry: matched
      ? {
          detector: detector as CanonicalDetector,
          operator: cond.operator,
          expected: cond.threshold,
          observed: raw,
          signal: cond.signal,
        }
      : undefined,
  };
}

function evaluateRecipe(
  recipe: CompiledRecipe,
  scores: DetectorScores,
  content: string,
): Tier1Hit | { skipped: string } {
  if (!recipe.tier1) return { skipped: 'no_compiled_tier1' };
  const matched_conditions: MatchedCondition[] = [];
  const skipped_conditions: SkippedCondition[] = [];
  let conditionMatches = 0;
  for (const cond of recipe.tier1.conditions) {
    const { matched, matchedEntry, skippedEntry } = evaluateCondition(cond, scores, content);
    if (matchedEntry) matched_conditions.push(matchedEntry);
    if (skippedEntry) skipped_conditions.push(skippedEntry);
    if (matched) conditionMatches++;
  }
  const totalConditions = recipe.tier1.conditions.length;
  const evaluableCount = totalConditions - skipped_conditions.length;
  if (evaluableCount === 0) {
    return { skipped: 'all_conditions_skipped' };
  }
  // match=all is strict: every condition in the recipe must have matched.
  // A skipped condition (unscored detector, unevaluable kind) means we
  // can't confirm the assertion — default to no-match rather than
  // firing on partial evidence.
  // match=any is lenient: a single matched condition is enough.
  const hit =
    recipe.tier1.match === 'all'
      ? conditionMatches === totalConditions
      : conditionMatches > 0;

  return {
    recipe_id: recipe.id,
    recipe_version: recipe.version,
    threat_type: recipe.threat_type,
    severity: recipe.severity,
    door: recipe.door,
    scope: recipe.scope,
    matched_conditions,
    skipped_conditions,
    matched: hit,
  };
}

// ── Top-K ranking ───────────────────────────────────────────────────

const SEVERITY_RANK: Record<CanonicalSeverity, number> = { p0: 0, p1: 1, p2: 2 };

function rankHit(a: Tier1Hit, b: Tier1Hit): number {
  const sa = SEVERITY_RANK[a.severity];
  const sb = SEVERITY_RANK[b.severity];
  if (sa !== sb) return sa - sb;
  return b.recipe_version - a.recipe_version;
}

function applyTopKCap(
  hits: Tier1Hit[],
  perThreatCap: number,
  globalCap: number,
): Tier1Hit[] {
  const byThreat = new Map<CanonicalThreatType, Tier1Hit[]>();
  for (const hit of hits) {
    const bucket = byThreat.get(hit.threat_type);
    if (bucket) bucket.push(hit);
    else byThreat.set(hit.threat_type, [hit]);
  }

  const capped: Tier1Hit[] = [];
  for (const [, bucket] of byThreat) {
    bucket.sort(rankHit);
    capped.push(...bucket.slice(0, perThreatCap));
  }

  if (capped.length <= globalCap) {
    capped.sort(rankHit);
    return capped;
  }

  capped.sort(rankHit);
  return capped.slice(0, globalCap);
}

// ── Public API ──────────────────────────────────────────────────────

/**
 * Evaluate recipe tier1 against a detector-score map.
 *
 * `scores` is built by the gateway from runL1Detection output + session
 * state + (optionally) L2 result. See {@link buildDetectorScoresFromThreats}
 * for the baseline mapping.
 */
export function evaluateRecipesTier1(
  scores: DetectorScores,
  content: string,
  index: RecipeIndex,
  config: RecipeEvalConfig,
): Tier1Result {
  const t0 = Date.now();
  if (config.mode === 'off') {
    return {
      all_hits: [],
      capped_hits: [],
      skipped_recipes: [],
      tier2_skipped_budget: 0,
      duration_ms: 0,
    };
  }

  const all_hits: Tier1Hit[] = [];
  const skipped_recipes: Array<{ recipe_id: string; reason: string }> = [];

  for (const recipe of index.all) {
    const result = evaluateRecipe(recipe, scores, content);
    if ('skipped' in result) {
      skipped_recipes.push({ recipe_id: recipe.id, reason: result.skipped });
      continue;
    }
    if (result.matched) all_hits.push(result);
  }

  const capped_hits = applyTopKCap(
    all_hits,
    config.per_threat_type_cap,
    config.global_cap,
  );
  const tier2_skipped_budget = Math.max(0, all_hits.length - capped_hits.length);

  return {
    all_hits,
    capped_hits,
    skipped_recipes,
    tier2_skipped_budget,
    duration_ms: Date.now() - t0,
  };
}

// ── Detector-score derivation helper ───────────────────────────────

/** Map each safe-house ThreatType to the detector that typically produces
 *  it. Used by buildDetectorScoresFromThreats() to map L1 threats to
 *  canonical detector slugs. */
const THREAT_TYPE_TO_DETECTOR: Record<string, CanonicalDetector> = {
  prompt_injection: 'pattern_matcher',
  indirect_injection: 'pattern_matcher',
  agent_spoofing: 'pattern_matcher',
  hijack_attempt: 'pattern_matcher',
  data_exfiltration: 'pattern_matcher',
  bec_fraud: 'signal_scorer',
  social_engineering: 'signal_scorer',
  pii_in_inbound: 'dlp_scanner',
  privilege_escalation: 'pattern_matcher',
};

export interface ThreatLike {
  type: string;
  confidence: number;
  matched_pattern?: string;
}

/**
 * Build a detector-score map from L1 threats. Heuristic:
 *   - matched_pattern starting with "known_pattern:" → fingerprint_matcher
 *   - matched_pattern absent (pure scored signal, e.g. BEC) → signal_scorer
 *   - otherwise → detector implied by threat.type (pattern_matcher for most)
 *
 * For each detector, records the max confidence observed. Caller should
 * merge in session_tracker and semantic_analyzer scores separately.
 */
export function buildDetectorScoresFromThreats(threats: ThreatLike[]): DetectorScores {
  const scores: DetectorScores = {};
  const bump = (det: CanonicalDetector, conf: number): void => {
    const cur = scores[det];
    if (cur === undefined || cur === null || conf > cur) scores[det] = conf;
  };
  for (const t of threats) {
    if (t.matched_pattern?.startsWith('known_pattern:')) {
      bump('fingerprint_matcher', t.confidence);
      continue;
    }
    if (!t.matched_pattern) {
      bump('signal_scorer', t.confidence);
      continue;
    }
    const det = THREAT_TYPE_TO_DETECTOR[t.type];
    if (det && (CANONICAL_DETECTORS as readonly string[]).includes(det)) {
      bump(det, t.confidence);
    } else {
      bump('pattern_matcher', t.confidence);
    }
  }
  return scores;
}

// ── Tier2 prompt + response ────────────────────────────────────────

export interface Tier2Check {
  recipe_id: string;
  check: CompiledTier2Check;
}

/**
 * Collect tier2 checks eligible for evaluation from a set of tier1 hits.
 * Filters out:
 *   - hits without a compiled tier2
 *   - recipes whose tier2.on_threat_types doesn't include the current
 *     request's matched threat_type (if specified)
 *   - `behavioral_pattern` checks (skipped in Stage 5B)
 */
export function collectTier2Checks(
  hits: Tier1Hit[],
  index: RecipeIndex,
): { eligible: Tier2Check[]; skipped: Tier2CheckResult[] } {
  const eligible: Tier2Check[] = [];
  const skipped: Tier2CheckResult[] = [];
  const recipesById = new Map<string, CompiledRecipe>();
  for (const r of index.all) recipesById.set(r.id, r);

  for (const hit of hits) {
    const recipe = recipesById.get(hit.recipe_id);
    if (!recipe || !recipe.tier2) continue;
    for (const check of recipe.tier2.checks) {
      if (check.type === 'behavioral_pattern') {
        skipped.push({
          recipe_id: hit.recipe_id,
          check_id: check.id,
          check_type: check.type,
          matched: false,
          skipped: 'behavioral_pattern_unsupported',
        });
        continue;
      }
      if (check.type !== 'semantic_intent_match' && check.type !== 'conscience_value') {
        skipped.push({
          recipe_id: hit.recipe_id,
          check_id: check.id,
          check_type: check.type,
          matched: false,
          skipped: 'unknown_check_type',
        });
        continue;
      }
      eligible.push({ recipe_id: hit.recipe_id, check });
    }
  }
  return { eligible, skipped };
}

/**
 * Build the prompt fragment the gateway appends to the existing L2 Haiku
 * prompt. Returns `null` when there are no eligible checks.
 *
 * The fragment asks Haiku to emit one JSON object per check — the gateway
 * merges these with its own L2 response parsing.
 */
export function buildRecipeTier2PromptFragment(checks: Tier2Check[]): string | null {
  if (checks.length === 0) return null;
  const lines: string[] = [
    '',
    '## Additional recipe checks',
    'For each check below, return a JSON object { "check_id": "...", "matched": true|false, "reasoning": "short" }. Return them as a JSON array under the key "recipe_checks" at the end of your response.',
    '',
  ];
  let idx = 1;
  for (const { recipe_id, check } of checks) {
    const id = check.id || `${recipe_id}_${idx}`;
    lines.push(`Check ${idx} (id=${id}, type=${check.type}):`);
    lines.push(check.content);
    lines.push('');
    idx++;
  }
  return lines.join('\n');
}

/**
 * Parse the `recipe_checks` array from the L2 response. Tolerant of
 * malformed entries — skips them with `parse_error`.
 */
export function parseRecipeTier2Response(
  raw: string,
  eligible: Tier2Check[],
): Tier2CheckResult[] {
  const results: Tier2CheckResult[] = [];
  const checkById = new Map<string, Tier2Check>();
  let idx = 1;
  for (const c of eligible) {
    const id = c.check.id || `${c.recipe_id}_${idx}`;
    checkById.set(id, c);
    idx++;
  }

  let parsed: unknown;
  try {
    const match = raw.match(/"recipe_checks"\s*:\s*(\[[^\]]*\])/);
    if (!match) return [];
    parsed = JSON.parse(match[1]);
  } catch {
    for (const [id, c] of checkById) {
      results.push({
        recipe_id: c.recipe_id,
        check_id: id,
        check_type: c.check.type,
        matched: false,
        skipped: 'parse_error',
      });
    }
    return results;
  }

  if (!Array.isArray(parsed)) return [];
  for (const item of parsed) {
    if (!item || typeof item !== 'object') continue;
    const it = item as Record<string, unknown>;
    const id = typeof it.check_id === 'string' ? it.check_id : null;
    if (!id) continue;
    const source = checkById.get(id);
    if (!source) continue;
    results.push({
      recipe_id: source.recipe_id,
      check_id: id,
      check_type: source.check.type,
      matched: it.matched === true,
      reasoning: typeof it.reasoning === 'string' ? it.reasoning : undefined,
    });
  }
  return results;
}

// ── Telemetry serialization ────────────────────────────────────────

export interface RecipeTelemetry {
  event: 'sh_recipes';
  mode: RecipeMode;
  recipes_loaded: number;
  tier1_evaluated: number;
  tier1_hits_total: number;
  tier1_hits_capped: number;
  tier2_skipped_budget: number;
  tier2_evaluated: number;
  tier2_matched: number;
  tier2_skipped: number;
  hits: Array<{
    id: string;
    threat_type: string;
    severity: string;
    door: string;
    conditions_matched: number;
    conditions_skipped: number;
  }>;
  tier2_results: Tier2CheckResult[];
  duration_ms: number;
}

export function serializeRecipeTelemetry(
  tier1: Tier1Result,
  tier2: Tier2Result | null,
  index: RecipeIndex,
  mode: RecipeMode,
): RecipeTelemetry {
  const tier2Results = tier2?.check_results ?? [];
  const tier2Skipped = tier2?.skipped ?? [];
  const tier2Matched = tier2Results.filter((r) => r.matched).length;
  return {
    event: 'sh_recipes',
    mode,
    recipes_loaded: index.all.length,
    tier1_evaluated: index.all.length,
    tier1_hits_total: tier1.all_hits.length,
    tier1_hits_capped: tier1.capped_hits.length,
    tier2_skipped_budget: tier1.tier2_skipped_budget,
    tier2_evaluated: tier2Results.length,
    tier2_matched: tier2Matched,
    tier2_skipped: tier2Skipped.length,
    hits: tier1.capped_hits.map((h) => ({
      id: h.recipe_id,
      threat_type: h.threat_type,
      severity: h.severity,
      door: h.door,
      conditions_matched: h.matched_conditions.length,
      conditions_skipped: h.skipped_conditions.length,
    })),
    tier2_results: [...tier2Results, ...tier2Skipped],
    duration_ms: tier1.duration_ms + (tier2?.duration_ms ?? 0),
  };
}
