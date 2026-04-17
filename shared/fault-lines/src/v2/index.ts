// @mnemom/fault-lines/v2 — dimensional, evidence-based team coherence.
// See ADR-025 for the full spec and rationale.

export {
  computePairwiseCoherence,
  computeTeamCoherence,
  MIN_EVIDENCE,
} from "./scorer.js";

export type {
  CoherenceConfidence,
  ConflictEvidence,
  MostConflictedAgent,
  OutlierAgent,
  PairwiseCoherence,
  TeamCoherenceInput,
  TeamCoherenceResult,
  WeakestPair,
} from "./types.js";
