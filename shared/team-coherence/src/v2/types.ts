// Team Coherence v2 types — see ADR-025.
//
// Design principles:
//   1. Silence is neutral. A value declared by one agent but not mentioned by
//      another is specialization evidence, not disagreement.
//   2. Only explicit conflicts count against governance. Missing ≠ conflicting.
//   3. Structural invariants (conscience, integrity) are binary checks,
//      reported separately from continuous governance scoring.
//   4. Fleet result is a vector with narrative helpers. No single headline.
//   5. Insufficient evidence returns null, not a fabricated score.

/** Structural subset interface accepted by the v2 scorer. Both AAP
 * AlignmentCard (satisfies at reduced fidelity) and unified cards (full
 * fidelity with conscience + integrity) implement this. */
export interface TeamCoherenceInput {
  agent_id: string;
  values: {
    declared: string[];
    conflicts_with?: string[];
  };
  /** Unified-card conscience section. Optional; absence returns null on
   * conscience structural checks rather than faking a score. */
  conscience?: {
    declared_values: string[];
    mode?: string;
  };
  /** Unified-card integrity section. Optional. */
  integrity?: {
    enforcement_mode?: "observe" | "nudge" | "enforce";
  };
  /** Unified-card autonomy.forbidden_actions. Used as secondary signal. */
  forbidden_actions?: string[];
}

export type CoherenceConfidence =
  | "high"
  | "moderate"
  | "insufficient_evidence";

/** A single conflict between two agents, with evidence attached. */
export interface ConflictEvidence {
  value: string;
  declared_by: string;
  listed_as_conflict_by: string;
}

/** Result of a pairwise coherence computation between two agents. */
export interface PairwiseCoherence {
  agent_a: string;
  agent_b: string;
  /** `null` when agreement_evidence + conflict_evidence < MIN_EVIDENCE. */
  governance_score: number | null;
  /** Fraction of union declared by exactly one agent — positive signal, not
   * blended into governance. */
  diversity_rate: number;
  /** Explicit conflicts only. */
  conflicts: ConflictEvidence[];
  confidence: CoherenceConfidence;
}

/** An agent whose mean pairwise governance is > 1σ below the fleet mean. */
export interface OutlierAgent {
  agent_id: string;
  mean_pair_governance: number;
  deviation_sigma: number;
}

/** A pair of agents flagged as the weakest governance link in the fleet. */
export interface WeakestPair {
  agent_a: string;
  agent_b: string;
  governance_score: number;
  conflicts: ConflictEvidence[];
}

/** Agent flagged for being involved in the most conflicts. */
export interface MostConflictedAgent {
  agent_id: string;
  conflict_count: number;
}

/** Fleet-level coherence result — a vector with narrative helpers.
 *
 * No `headline.score` field exists, and this is intentional. See ADR-025.
 * If a UI surface needs a single number it must derive one from this
 * vector and take responsibility for that compression. */
export interface TeamCoherenceResult {
  // Pair-level aggregates
  pair_count: number;
  insufficient_evidence_pairs: number;
  pairwise_governance_floor: number | null;
  pairwise_governance_median: number | null;

  // Conflict structural signal
  conflict_edge_count: number;

  // Diversity
  diversity_rate_median: number;

  // Structural invariants (binary; null when card sections are absent)
  conscience_universal: boolean | null;
  conscience_divergence: Array<{ agent_id: string; diverges_on: string[] }>;
  integrity_uniform: boolean | null;
  integrity_divergence: Array<{
    agent_id: string;
    enforcement_mode: "observe" | "nudge" | "enforce" | null;
  }>;

  // Outliers
  outlier_agents: OutlierAgent[];

  // Narrative helpers — pre-computed answers so every UI consumer
  // reads the same facts
  weakest_pair: WeakestPair | null;
  most_conflicted_agent: MostConflictedAgent | null;
  specializations: Record<string, string[]>;
  conflict_surface: Array<ConflictEvidence & { agent_a: string; agent_b: string }>;

  // Per-pair detail (for matrix rendering)
  pairwise: PairwiseCoherence[];

  // Reserved for event-based delta surfacing — deferred to UC-11b follow-up.
  changes_since: null;
}
