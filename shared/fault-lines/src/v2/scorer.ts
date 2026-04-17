// Team Coherence v2 — dimensional, evidence-based scoring. See ADR-025.

import type {
  ConflictEvidence,
  MostConflictedAgent,
  OutlierAgent,
  PairwiseCoherence,
  TeamCoherenceInput,
  TeamCoherenceResult,
  WeakestPair,
} from "./types.js";

/** Pair with < MIN_EVIDENCE evidence items returns null rather than a
 * fabricated score. Chosen for the "insufficient_evidence" signal to be
 * distinguishable from "zero agreement." */
export const MIN_EVIDENCE = 2;

/** Pair with ≥ MIN_EVIDENCE + HIGH_CONFIDENCE_DELTA evidence items is
 * reported as "high" confidence. Below that (but ≥ MIN_EVIDENCE) is
 * "moderate." */
const HIGH_CONFIDENCE_DELTA = 3;

/** Pairwise coherence between two agents.
 *
 * Algorithm (ADR-025):
 *
 *   shared      = A.declared ∩ B.declared
 *   a_only      = A.declared \ B.declared
 *   b_only      = B.declared \ A.declared
 *   a_vs_b_conf = A.declared ∩ B.conflicts_with
 *   b_vs_a_conf = B.declared ∩ A.conflicts_with
 *   conflicts   = a_vs_b_conf ∪ b_vs_a_conf
 *
 *   agreement_evidence = |shared|
 *   conflict_evidence  = |conflicts|
 *
 *   if agreement + conflict < MIN_EVIDENCE: governance_score = null
 *   else: governance_score = agreement / (agreement + conflict)   ∈ [0, 1]
 *
 *   diversity_rate = (|a_only| + |b_only|) / |A.declared ∪ B.declared|
 *
 * Silence (values declared by only one side, not listed as conflict by
 * either) is neutral — contributes to `diversity_rate` as positive
 * specialization signal, NOT to the governance denominator. */
export function computePairwiseCoherence(
  a: TeamCoherenceInput,
  b: TeamCoherenceInput,
): PairwiseCoherence {
  const aValues = new Set(a.values.declared ?? []);
  const bValues = new Set(b.values.declared ?? []);
  const aConflicts = new Set(a.values.conflicts_with ?? []);
  const bConflicts = new Set(b.values.conflicts_with ?? []);

  const shared: string[] = [];
  const aOnly: string[] = [];
  for (const v of aValues) {
    if (bValues.has(v)) shared.push(v);
    else aOnly.push(v);
  }
  const bOnly: string[] = [];
  for (const v of bValues) {
    if (!aValues.has(v)) bOnly.push(v);
  }

  const conflicts: ConflictEvidence[] = [];
  for (const v of aValues) {
    if (bConflicts.has(v)) {
      conflicts.push({
        value: v,
        declared_by: a.agent_id,
        listed_as_conflict_by: b.agent_id,
      });
    }
  }
  for (const v of bValues) {
    if (aConflicts.has(v)) {
      conflicts.push({
        value: v,
        declared_by: b.agent_id,
        listed_as_conflict_by: a.agent_id,
      });
    }
  }

  const agreementEvidence = shared.length;
  const conflictEvidence = conflicts.length;
  const totalEvidence = agreementEvidence + conflictEvidence;

  let governance_score: number | null;
  let confidence: PairwiseCoherence["confidence"];
  if (totalEvidence < MIN_EVIDENCE) {
    governance_score = null;
    confidence = "insufficient_evidence";
  } else {
    governance_score = agreementEvidence / totalEvidence;
    confidence =
      totalEvidence >= MIN_EVIDENCE + HIGH_CONFIDENCE_DELTA
        ? "high"
        : "moderate";
  }

  const unionSize = aValues.size + bValues.size - shared.length;
  const diversity_rate =
    unionSize > 0 ? (aOnly.length + bOnly.length) / unionSize : 0;

  // Stable order: agent_a < agent_b alphabetically so results don't flip
  // when callers pass arguments in different order.
  const [agent_a, agent_b] =
    a.agent_id < b.agent_id
      ? [a.agent_id, b.agent_id]
      : [b.agent_id, a.agent_id];

  return {
    agent_a,
    agent_b,
    governance_score,
    diversity_rate,
    conflicts,
    confidence,
  };
}

/** Fleet-level team coherence. Returns a vector with narrative helpers —
 * no headline score. See ADR-025. */
export function computeTeamCoherence(
  cards: TeamCoherenceInput[],
): TeamCoherenceResult {
  if (cards.length < 2) {
    return emptyResult();
  }

  const pairwise: PairwiseCoherence[] = [];
  for (let i = 0; i < cards.length; i++) {
    for (let j = i + 1; j < cards.length; j++) {
      pairwise.push(computePairwiseCoherence(cards[i], cards[j]));
    }
  }

  const scoredPairs = pairwise.filter((p) => p.governance_score !== null);
  const insufficient = pairwise.length - scoredPairs.length;

  const governance_floor =
    scoredPairs.length > 0
      ? Math.min(...scoredPairs.map((p) => p.governance_score as number))
      : null;
  const governance_median = median(
    scoredPairs.map((p) => p.governance_score as number),
  );

  const conflict_edge_count = pairwise.filter(
    (p) => p.conflicts.length > 0,
  ).length;

  const diversity_rate_median = median(pairwise.map((p) => p.diversity_rate));

  // Structural invariants — conscience + integrity
  const { conscience_universal, conscience_divergence } =
    computeConscienceInvariant(cards);
  const { integrity_uniform, integrity_divergence } =
    computeIntegrityInvariant(cards);

  // Per-agent mean pair governance for outlier analysis
  const perAgentScores = computePerAgentMeanGovernance(cards, pairwise);
  const outlier_agents = findOutliers(perAgentScores);

  // Narrative helpers
  const weakest_pair = findWeakestPair(scoredPairs);
  const most_conflicted_agent = findMostConflictedAgent(pairwise);
  const specializations = computeSpecializations(cards);
  const conflict_surface = flattenConflictSurface(pairwise);

  return {
    pair_count: pairwise.length,
    insufficient_evidence_pairs: insufficient,
    pairwise_governance_floor: governance_floor,
    pairwise_governance_median: governance_median,
    conflict_edge_count,
    diversity_rate_median,
    conscience_universal,
    conscience_divergence,
    integrity_uniform,
    integrity_divergence,
    outlier_agents,
    weakest_pair,
    most_conflicted_agent,
    specializations,
    conflict_surface,
    pairwise,
    changes_since: null,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyResult(): TeamCoherenceResult {
  return {
    pair_count: 0,
    insufficient_evidence_pairs: 0,
    pairwise_governance_floor: null,
    pairwise_governance_median: null,
    conflict_edge_count: 0,
    diversity_rate_median: 0,
    conscience_universal: null,
    conscience_divergence: [],
    integrity_uniform: null,
    integrity_divergence: [],
    outlier_agents: [],
    weakest_pair: null,
    most_conflicted_agent: null,
    specializations: {},
    conflict_surface: [],
    pairwise: [],
    changes_since: null,
  };
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

function computeConscienceInvariant(
  cards: TeamCoherenceInput[],
): {
  conscience_universal: boolean | null;
  conscience_divergence: Array<{ agent_id: string; diverges_on: string[] }>;
} {
  // If any card lacks a conscience section, the invariant is undefined —
  // return null rather than fake a score.
  const anyMissing = cards.some((c) => !c.conscience);
  if (anyMissing) {
    return { conscience_universal: null, conscience_divergence: [] };
  }
  // Fingerprint each card's conscience set. If all fingerprints match →
  // universal. Otherwise, identify the modal set as the reference "floor"
  // and flag cards that differ as the divergers (not the majority).
  const fingerprints = cards.map((c) =>
    [...(c.conscience?.declared_values ?? [])].sort().join("\u0000"),
  );
  const unique = new Set(fingerprints);
  if (unique.size === 1) {
    return { conscience_universal: true, conscience_divergence: [] };
  }
  const modal = modeOf(fingerprints);
  const modalSet = new Set(modal.split("\u0000").filter((s) => s.length > 0));
  const divergence: Array<{ agent_id: string; diverges_on: string[] }> = [];
  cards.forEach((c, i) => {
    if (fingerprints[i] === modal) return;
    const theirSet = new Set(c.conscience?.declared_values ?? []);
    const missing = [...modalSet].filter((v) => !theirSet.has(v));
    const extras = [...theirSet].filter((v) => !modalSet.has(v));
    divergence.push({
      agent_id: c.agent_id,
      diverges_on: [...missing, ...extras],
    });
  });
  return { conscience_universal: false, conscience_divergence: divergence };
}

function computeIntegrityInvariant(cards: TeamCoherenceInput[]): {
  integrity_uniform: boolean | null;
  integrity_divergence: Array<{
    agent_id: string;
    enforcement_mode: "observe" | "warn" | "enforce" | null;
  }>;
} {
  const modes = cards.map((c) => c.integrity?.enforcement_mode ?? null);
  const anyMissing = modes.some((m) => m === null);
  if (anyMissing) {
    return { integrity_uniform: null, integrity_divergence: [] };
  }
  const unique = new Set(modes);
  if (unique.size === 1) {
    return { integrity_uniform: true, integrity_divergence: [] };
  }
  const modal = modeOf(modes as string[]);
  const divergence: Array<{
    agent_id: string;
    enforcement_mode: "observe" | "warn" | "enforce" | null;
  }> = [];
  cards.forEach((c, i) => {
    if (modes[i] === modal) return;
    divergence.push({ agent_id: c.agent_id, enforcement_mode: modes[i] });
  });
  return { integrity_uniform: false, integrity_divergence: divergence };
}

/** Most common element in a non-empty list. Ties broken by which element
 * sorts first alphabetically — deterministic. */
function modeOf<T extends string>(values: T[]): T {
  const counts = new Map<T, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  let topCount = 0;
  let topValue: T = values[0];
  // Sort keys so ties are broken deterministically.
  const sortedKeys = [...counts.keys()].sort();
  for (const key of sortedKeys) {
    const count = counts.get(key)!;
    if (count > topCount) {
      topCount = count;
      topValue = key;
    }
  }
  return topValue;
}

function computePerAgentMeanGovernance(
  cards: TeamCoherenceInput[],
  pairwise: PairwiseCoherence[],
): Map<string, number> {
  const scoresByAgent = new Map<string, number[]>();
  for (const card of cards) scoresByAgent.set(card.agent_id, []);
  for (const pair of pairwise) {
    if (pair.governance_score === null) continue;
    scoresByAgent.get(pair.agent_a)?.push(pair.governance_score);
    scoresByAgent.get(pair.agent_b)?.push(pair.governance_score);
  }
  const means = new Map<string, number>();
  for (const [agentId, scores] of scoresByAgent) {
    if (scores.length === 0) continue;
    const mean = scores.reduce((s, v) => s + v, 0) / scores.length;
    means.set(agentId, mean);
  }
  return means;
}

function findOutliers(perAgentMean: Map<string, number>): OutlierAgent[] {
  const values = [...perAgentMean.values()];
  if (values.length < 2) return [];
  const fleetMean = values.reduce((s, v) => s + v, 0) / values.length;
  const variance =
    values.reduce((s, v) => s + (v - fleetMean) ** 2, 0) / values.length;
  const stddev = Math.sqrt(variance);
  if (stddev === 0) return [];
  const outliers: OutlierAgent[] = [];
  for (const [agent_id, mean] of perAgentMean) {
    const deviation_sigma = (fleetMean - mean) / stddev;
    if (deviation_sigma > 1) {
      outliers.push({
        agent_id,
        mean_pair_governance: mean,
        deviation_sigma,
      });
    }
  }
  return outliers;
}

function findWeakestPair(
  scoredPairs: PairwiseCoherence[],
): WeakestPair | null {
  if (scoredPairs.length === 0) return null;
  let weakest = scoredPairs[0];
  for (const pair of scoredPairs) {
    if ((pair.governance_score as number) < (weakest.governance_score as number)) {
      weakest = pair;
    }
  }
  return {
    agent_a: weakest.agent_a,
    agent_b: weakest.agent_b,
    governance_score: weakest.governance_score as number,
    conflicts: weakest.conflicts,
  };
}

function findMostConflictedAgent(
  pairwise: PairwiseCoherence[],
): MostConflictedAgent | null {
  const counts = new Map<string, number>();
  for (const pair of pairwise) {
    if (pair.conflicts.length === 0) continue;
    counts.set(pair.agent_a, (counts.get(pair.agent_a) ?? 0) + 1);
    counts.set(pair.agent_b, (counts.get(pair.agent_b) ?? 0) + 1);
  }
  if (counts.size === 0) return null;
  let topAgent: string | null = null;
  let topCount = 0;
  for (const [agent_id, count] of counts) {
    if (count > topCount) {
      topAgent = agent_id;
      topCount = count;
    }
  }
  return topAgent !== null
    ? { agent_id: topAgent, conflict_count: topCount }
    : null;
}

function computeSpecializations(
  cards: TeamCoherenceInput[],
): Record<string, string[]> {
  // A specialization is a value declared by exactly one agent.
  const declaredBy = new Map<string, Set<string>>(); // value -> agent_ids
  for (const card of cards) {
    for (const v of card.values.declared ?? []) {
      if (!declaredBy.has(v)) declaredBy.set(v, new Set());
      declaredBy.get(v)!.add(card.agent_id);
    }
  }
  const result: Record<string, string[]> = {};
  for (const card of cards) result[card.agent_id] = [];
  for (const [value, agents] of declaredBy) {
    if (agents.size === 1) {
      const [onlyAgent] = agents;
      result[onlyAgent].push(value);
    }
  }
  return result;
}

function flattenConflictSurface(
  pairwise: PairwiseCoherence[],
): Array<ConflictEvidence & { agent_a: string; agent_b: string }> {
  const out: Array<
    ConflictEvidence & { agent_a: string; agent_b: string }
  > = [];
  for (const pair of pairwise) {
    for (const c of pair.conflicts) {
      out.push({
        agent_a: pair.agent_a,
        agent_b: pair.agent_b,
        value: c.value,
        declared_by: c.declared_by,
        listed_as_conflict_by: c.listed_as_conflict_by,
      });
    }
  }
  return out;
}
