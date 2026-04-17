import { describe, it, expect } from "vitest";
import {
  computePairwiseCoherence,
  computeTeamCoherence,
  MIN_EVIDENCE,
} from "../../src/v2/index.js";
import type { TeamCoherenceInput } from "../../src/v2/index.js";

// ---------------------------------------------------------------------------
// Showcase-agent fixtures (ADR-025 scenario validation)
//
// These mirror the showcase scenario in mnemom-website/client/data/
// showcase-scenario.ts. If those agents change, these tests should change
// with them — the showcase is the reference fleet that drives the
// pedagogical side-by-side panel.
// ---------------------------------------------------------------------------

const CORE_VALUES = [
  "principal_benefit",
  "transparency",
  "harm_prevention",
  "honesty",
  "accountability",
  "data_integrity",
  "incident_containment",
];

const sentinel: TeamCoherenceInput = {
  agent_id: "sentinel",
  values: {
    declared: [...CORE_VALUES, "signal_fidelity", "early_detection"],
    conflicts_with: ["alert_suppression"],
  },
};

const triage: TeamCoherenceInput = {
  agent_id: "triage",
  values: {
    declared: [...CORE_VALUES, "severity_accuracy", "signal_fidelity"],
    conflicts_with: ["alert_suppression", "move_fast_break_things"],
  },
};

const patch: TeamCoherenceInput = {
  agent_id: "patch",
  values: {
    declared: [
      ...CORE_VALUES,
      "rollback_safety",
      "minimal_blast_radius",
      "move_fast_break_things",
    ],
    conflicts_with: ["data_obfuscation"],
  },
};

const herald: TeamCoherenceInput = {
  agent_id: "herald",
  values: {
    declared: [...CORE_VALUES, "stakeholder_clarity", "timely_communication"],
    conflicts_with: ["severity_inflation"],
  },
};

// ---------------------------------------------------------------------------
// ADR-025 scenario validation — the four headline cases
// ---------------------------------------------------------------------------

describe("computePairwiseCoherence — ADR-025 scenarios", () => {
  it("Scenario 1: full agreement (agent paired with itself) scores 1.0", () => {
    const result = computePairwiseCoherence(sentinel, { ...sentinel });
    expect(result.governance_score).toBe(1.0);
    expect(result.conflicts).toEqual([]);
  });

  it("Scenario 2: governance-aligned role specialists (Sentinel ↔ Patch) score 1.0", () => {
    // Both share all 7 CORE_VALUES. Each specializes differently.
    // Neither declares the other's role-specific values.
    // NEITHER lists the other's values in conflicts_with.
    // Expected: governance_score = 7 / (7 + 0) = 1.0
    // (Jaccard would produce ≈ 0.58 — this is the key v2 delta.)
    const result = computePairwiseCoherence(sentinel, patch);
    expect(result.governance_score).toBe(1.0);
    expect(result.conflicts).toEqual([]);
    expect(result.diversity_rate).toBeGreaterThan(0);
  });

  it("Scenario 3: Triage ↔ Patch conflict on move_fast_break_things scores < 1.0", () => {
    // Triage lists move_fast_break_things in conflicts_with.
    // Patch declares move_fast_break_things.
    // One explicit conflict; 7 shared; governance = 7/8 = 0.875.
    const result = computePairwiseCoherence(triage, patch);
    expect(result.governance_score).toBeCloseTo(7 / 8, 5);
    expect(result.conflicts).toHaveLength(1);
    expect(result.conflicts[0].value).toBe("move_fast_break_things");
    expect(result.conflicts[0].declared_by).toBe("patch");
    expect(result.conflicts[0].listed_as_conflict_by).toBe("triage");
  });

  it("Scenario 4: no shared values, no conflicts → insufficient_evidence (null)", () => {
    const a: TeamCoherenceInput = {
      agent_id: "a",
      values: { declared: ["x", "y"], conflicts_with: [] },
    };
    const b: TeamCoherenceInput = {
      agent_id: "b",
      values: { declared: ["p", "q"], conflicts_with: [] },
    };
    const result = computePairwiseCoherence(a, b);
    expect(result.governance_score).toBeNull();
    expect(result.confidence).toBe("insufficient_evidence");
  });
});

// ---------------------------------------------------------------------------
// Fleet-level behavior on the showcase fleet
// ---------------------------------------------------------------------------

describe("computeTeamCoherence — showcase fleet", () => {
  const fleet = [sentinel, triage, patch, herald];
  const result = computeTeamCoherence(fleet);

  it("emits the full expected vector for a 4-agent fleet", () => {
    expect(result.pair_count).toBe(6);
    expect(result.insufficient_evidence_pairs).toBe(0);
    expect(result.pairwise).toHaveLength(6);
  });

  it("does not include a headline or fleet_score field", () => {
    // ADR-025 commitment — no single-number summary in the shape.
    expect((result as unknown as Record<string, unknown>).headline).toBeUndefined();
    expect((result as unknown as Record<string, unknown>).fleet_score).toBeUndefined();
  });

  it("weakest pair is the one with an explicit conflict (Triage ↔ Patch)", () => {
    expect(result.weakest_pair).not.toBeNull();
    const pair = [result.weakest_pair!.agent_a, result.weakest_pair!.agent_b];
    expect(pair.sort()).toEqual(["patch", "triage"]);
    expect(result.weakest_pair!.governance_score).toBeCloseTo(7 / 8, 5);
  });

  it("conflict surface lists every explicit conflict with evidence", () => {
    expect(result.conflict_surface).toHaveLength(1);
    expect(result.conflict_surface[0].value).toBe("move_fast_break_things");
  });

  it("specializations correctly attribute unique values to each agent", () => {
    expect(result.specializations["sentinel"].sort()).toEqual(
      ["early_detection"].sort(),
    );
    expect(result.specializations["triage"].sort()).toEqual(
      ["severity_accuracy"].sort(),
    );
    expect(result.specializations["patch"].sort()).toEqual(
      ["minimal_blast_radius", "move_fast_break_things", "rollback_safety"].sort(),
    );
    expect(result.specializations["herald"].sort()).toEqual(
      ["stakeholder_clarity", "timely_communication"].sort(),
    );
    // "signal_fidelity" is shared by sentinel + triage → not a specialization
    expect(result.specializations["sentinel"]).not.toContain("signal_fidelity");
    expect(result.specializations["triage"]).not.toContain("signal_fidelity");
  });

  it("returns null structural invariants when conscience/integrity sections absent", () => {
    // None of the showcase fixtures have conscience/integrity set yet.
    expect(result.conscience_universal).toBeNull();
    expect(result.integrity_uniform).toBeNull();
  });

  it("governance floor corresponds to the weakest scored pair", () => {
    expect(result.pairwise_governance_floor).toBeCloseTo(7 / 8, 5);
  });

  it("governance median and conflict_edge_count reflect fleet structure", () => {
    // 5 of 6 pairs have governance 1.0; 1 pair has 7/8.
    // Median of 6 values: average of middle two = (1.0 + 1.0) / 2 = 1.0.
    expect(result.pairwise_governance_median).toBe(1.0);
    expect(result.conflict_edge_count).toBe(1);
  });

  it("most_conflicted_agent surfaces the agent in the most conflicts", () => {
    // Both triage and patch are in exactly 1 conflict; either is valid.
    expect(result.most_conflicted_agent).not.toBeNull();
    expect(["triage", "patch"]).toContain(
      result.most_conflicted_agent!.agent_id,
    );
    expect(result.most_conflicted_agent!.conflict_count).toBe(1);
  });

  it("changes_since is null in the v2.0 initial release", () => {
    expect(result.changes_since).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Conscience / integrity structural invariants
// ---------------------------------------------------------------------------

describe("computeTeamCoherence — structural invariants (unified cards)", () => {
  const base: Omit<TeamCoherenceInput, "agent_id"> = {
    values: { declared: ["transparency", "honesty"] },
    conscience: { declared_values: ["harm_prevention", "principal_benefit"] },
    integrity: { enforcement_mode: "enforce" },
  };

  it("reports conscience_universal=true when all agents share the floor", () => {
    const result = computeTeamCoherence([
      { ...base, agent_id: "a" },
      { ...base, agent_id: "b" },
      { ...base, agent_id: "c" },
    ]);
    expect(result.conscience_universal).toBe(true);
    expect(result.conscience_divergence).toEqual([]);
  });

  it("reports conscience_universal=false when one agent diverges", () => {
    const result = computeTeamCoherence([
      { ...base, agent_id: "a" },
      { ...base, agent_id: "b" },
      {
        ...base,
        agent_id: "c",
        conscience: { declared_values: ["harm_prevention"] }, // missing principal_benefit
      },
    ]);
    expect(result.conscience_universal).toBe(false);
    expect(result.conscience_divergence).toHaveLength(1);
    expect(result.conscience_divergence[0].agent_id).toBe("c");
    expect(result.conscience_divergence[0].diverges_on).toContain(
      "principal_benefit",
    );
  });

  it("reports integrity_uniform=false when modes differ", () => {
    const result = computeTeamCoherence([
      { ...base, agent_id: "a" },
      {
        ...base,
        agent_id: "b",
        integrity: { enforcement_mode: "observe" },
      },
    ]);
    expect(result.integrity_uniform).toBe(false);
    expect(result.integrity_divergence).toHaveLength(1);
    expect(result.integrity_divergence[0].agent_id).toBe("b");
    expect(result.integrity_divergence[0].enforcement_mode).toBe("observe");
  });

  it("returns null invariants when one card lacks the section", () => {
    const result = computeTeamCoherence([
      { ...base, agent_id: "a" },
      {
        agent_id: "b",
        values: base.values, // no conscience, no integrity
      },
    ]);
    expect(result.conscience_universal).toBeNull();
    expect(result.integrity_uniform).toBeNull();
  });
});
