import { describe, it, expect } from "vitest";
import {
  computePairwiseCoherence,
  MIN_EVIDENCE,
} from "../../src/v2/index.js";
import type { TeamCoherenceInput } from "../../src/v2/index.js";

// ---------------------------------------------------------------------------
// Property-based axioms (ADR-025)
//
// We implement these as table-driven tests across a broad fixture set rather
// than pulling in fast-check — the scorer is tiny and the property space
// is naturally enumerable. Each axiom is stated explicitly so future work
// can swap in property-based framework without losing the guarantees.
// ---------------------------------------------------------------------------

function card(
  id: string,
  declared: string[],
  conflicts_with: string[] = [],
): TeamCoherenceInput {
  return { agent_id: id, values: { declared, conflicts_with } };
}

// A diverse set of card pairings spanning: full overlap, no overlap, partial
// overlap, one-sided conflicts, mutual conflicts, role specialization, etc.
const FIXTURES: Array<[TeamCoherenceInput, TeamCoherenceInput, string]> = [
  [card("a", ["x", "y"]), card("b", ["x", "y"]), "full overlap"],
  [card("a", ["x", "y", "z"]), card("b", ["x", "y"]), "partial overlap, specialization"],
  [card("a", ["x", "y"]), card("b", ["p", "q"]), "no overlap, no conflicts"],
  [card("a", ["x", "y"]), card("b", ["x", "y", "z"], ["y"]), "overlap + one-sided conflict"],
  [
    card("a", ["x", "y"], ["p"]),
    card("b", ["x", "p"], ["y"]),
    "mutual conflicts",
  ],
  [
    card("a", ["a1", "a2", "a3", "a4", "a5"]),
    card("b", ["a1", "a2", "b1", "b2", "b3"]),
    "5 declared each, 2 shared, 3 role-specific each",
  ],
];

describe("Axiom 1 — Symmetry: pairwise score is order-independent", () => {
  it.each(FIXTURES)(
    "%s — %s (symmetric)",
    (a, b) => {
      const ab = computePairwiseCoherence(a, b);
      const ba = computePairwiseCoherence(b, a);
      expect(ab.governance_score).toBe(ba.governance_score);
      expect(ab.diversity_rate).toBe(ba.diversity_rate);
      expect(ab.conflicts.length).toBe(ba.conflicts.length);
      expect(ab.agent_a).toBe(ba.agent_a);
      expect(ab.agent_b).toBe(ba.agent_b);
    },
  );
});

describe("Axiom 2 — Role specialization invariance", () => {
  it("adding a silent value to one card never decreases governance_score", () => {
    // B picks up a new role-specific value that A does NOT list as a conflict.
    // Governance should be unchanged.
    const a = card("a", ["shared1", "shared2", "shared3"], []);
    const bBefore = card("b", ["shared1", "shared2", "shared3"], []);
    const bAfter = card(
      "b",
      ["shared1", "shared2", "shared3", "specialty"],
      [],
    );
    const before = computePairwiseCoherence(a, bBefore);
    const after = computePairwiseCoherence(a, bAfter);
    expect(after.governance_score).toBe(before.governance_score);
  });

  it("adding a silent value on BOTH sides never decreases governance_score", () => {
    const aBefore = card("a", ["x", "y", "z"], []);
    const bBefore = card("b", ["x", "y", "z"], []);
    const aAfter = card("a", ["x", "y", "z", "a_specialty"], []);
    const bAfter = card("b", ["x", "y", "z", "b_specialty"], []);
    const before = computePairwiseCoherence(aBefore, bBefore);
    const after = computePairwiseCoherence(aAfter, bAfter);
    expect(after.governance_score).toBe(before.governance_score);
    expect(after.diversity_rate).toBeGreaterThan(before.diversity_rate);
  });
});

describe("Axiom 3 — Conflict is load-bearing", () => {
  it("adding a conflict_with entry that hits the other card reduces the score", () => {
    const a = card("a", ["x", "y", "z"], []);
    const bBefore = card("b", ["x", "y", "z"], []);
    const bAfter = card("b", ["x", "y", "z"], ["y"]); // now conflicts with y
    const before = computePairwiseCoherence(a, bBefore);
    const after = computePairwiseCoherence(a, bAfter);
    expect(before.governance_score).toBe(1.0);
    expect(after.governance_score).toBeLessThan(before.governance_score!);
  });

  it("adding a conflict that hits NOTHING does not change the score", () => {
    // B declares conflicts_with: ["unrelated"] — A doesn't declare "unrelated"
    // so there's no actual conflict.
    const a = card("a", ["x", "y", "z"], []);
    const bBefore = card("b", ["x", "y", "z"], []);
    const bAfter = card("b", ["x", "y", "z"], ["unrelated_value"]);
    const before = computePairwiseCoherence(a, bBefore);
    const after = computePairwiseCoherence(a, bAfter);
    expect(after.governance_score).toBe(before.governance_score);
  });
});

describe("Axiom 4 — Insufficient evidence is null, not zero", () => {
  it("pair with zero shared + zero conflicts returns null", () => {
    const result = computePairwiseCoherence(
      card("a", ["x"], []),
      card("b", ["y"], []),
    );
    expect(result.governance_score).toBeNull();
    expect(result.confidence).toBe("insufficient_evidence");
  });

  it(`pair with evidence < MIN_EVIDENCE (${MIN_EVIDENCE}) returns null`, () => {
    // Only 1 shared, 0 conflicts = 1 total evidence < MIN_EVIDENCE (2)
    const result = computePairwiseCoherence(
      card("a", ["shared"], []),
      card("b", ["shared"], []),
    );
    expect(result.governance_score).toBeNull();
  });

  it(`pair with evidence === MIN_EVIDENCE (${MIN_EVIDENCE}) returns a number`, () => {
    // Exactly MIN_EVIDENCE shared values
    const result = computePairwiseCoherence(
      card("a", ["s1", "s2"], []),
      card("b", ["s1", "s2"], []),
    );
    expect(result.governance_score).toBe(1.0);
  });
});

describe("Axiom 5 — Self-pair is idempotent", () => {
  it("pairing a card with a copy of itself scores 1.0 (when evidence sufficient)", () => {
    const a = card("self", ["x", "y", "z"], ["bad1"]);
    const result = computePairwiseCoherence(a, { ...a });
    expect(result.governance_score).toBe(1.0);
    expect(result.conflicts).toEqual([]);
  });
});

describe("Axiom 6 — Bounded in [0, 1]", () => {
  it.each(FIXTURES)(
    "%s — governance_score ∈ [0, 1] when non-null",
    (a, b) => {
      const result = computePairwiseCoherence(a, b);
      if (result.governance_score !== null) {
        expect(result.governance_score).toBeGreaterThanOrEqual(0);
        expect(result.governance_score).toBeLessThanOrEqual(1);
      }
    },
  );

  it.each(FIXTURES)(
    "%s — diversity_rate ∈ [0, 1]",
    (a, b) => {
      const result = computePairwiseCoherence(a, b);
      expect(result.diversity_rate).toBeGreaterThanOrEqual(0);
      expect(result.diversity_rate).toBeLessThanOrEqual(1);
    },
  );
});
