// Baseline coherence — re-exports AAP's naive Jaccard-flavored scorer under
// explicit names so callers know they're using the reference implementation,
// not v2. See ADR-025.
//
// The baseline is the AAP protocol-handshake scorer:
//   pairwise_score = (|A ∩ B| / |A ∪ B|) × (1 − K · conflicts/|union|)
//   fleet_score    = mean of all C(n,2) pairwise scores
//
// It is preserved under the /baseline subpath because:
//   1. It is the canonical reference implementation of the AAP coherence
//      handshake and must remain callable.
//   2. The showcase baseline-vs-v2 panel depends on rendering both readouts
//      in the same file.
//
// For production coherence scoring use @mnemom/fault-lines/v2.

export {
  checkCoherence as checkCoherenceBaseline,
  checkFleetCoherence as checkFleetCoherenceBaseline,
} from "@mnemom/agent-alignment-protocol";

export type {
  CoherenceResult as CoherenceResultBaseline,
  FleetCoherenceResult as FleetCoherenceResultBaseline,
  PairwiseEntry as PairwiseEntryBaseline,
  FleetOutlier as FleetOutlierBaseline,
  FleetCluster as FleetClusterBaseline,
  AgentCoherenceSummary as AgentCoherenceSummaryBaseline,
} from "@mnemom/agent-alignment-protocol";
