// @mnemom/team-coherence — top-level entry point.
//
// Re-exports the v2 scorer so that `import { computeTeamCoherence } from
// "@mnemom/team-coherence"` reaches for the honest, evidence-based scorer
// by default.
//
// The Jaccard-flavored AAP baseline is reachable only via the explicit
// subpath `@mnemom/team-coherence/baseline`. Explicit subpath is intentional
// (ADR-025): users should never accidentally use the baseline when they
// meant v2.

export * from "./v2/index.js";
