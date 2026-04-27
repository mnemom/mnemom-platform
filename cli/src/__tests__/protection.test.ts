import { describe, it, expect } from "vitest";
import { validateProtectionCard } from "../commands/protection.js";

// ============================================================================
// Protection card validation tests (ADR-037 canonical form)
// ============================================================================

const validCard = () => ({
  card_version: "protection/2026-04-26",
  agent_id: "mnm-aabbccdd-eeff-0011-2233-445566778899",
  mode: "enforce",
  thresholds: { warn: 0.6, quarantine: 0.8, block: 0.95 },
  screen_surfaces: {
    incoming: true,
    outgoing: true,
    tool_calls: true,
    tool_responses: true,
  },
  trusted_sources: {
    domains: ["internal.acme.com"],
    agent_ids: ["mnm-aabbccdd-eeff-0011"],
    ip_ranges: ["10.0.0.0/8"],
  },
});

describe("validateProtectionCard — ADR-037 canonical form", () => {
  it("passes for a minimal valid card", () => {
    const checks = validateProtectionCard(validCard());
    const failed = checks.filter(c => !c.passed);
    expect(failed, JSON.stringify(failed, null, 2)).toHaveLength(0);
  });

  it("passes when only the required fields are present", () => {
    const card = {
      card_version: "protection/2026-04-26",
      agent_id: "mnm-test-agent",
      mode: "observe",
    };
    const checks = validateProtectionCard(card);
    const failed = checks.filter(c => !c.passed);
    expect(failed).toHaveLength(0);
  });

  it("requires card_version", () => {
    const card = validCard() as Record<string, unknown>;
    delete card.card_version;
    const checks = validateProtectionCard(card);
    expect(checks.find(c => c.name === "card_version")?.passed).toBe(false);
  });

  it("requires agent_id", () => {
    const card = validCard() as Record<string, unknown>;
    delete card.agent_id;
    const checks = validateProtectionCard(card);
    expect(checks.find(c => c.name === "agent_id")?.passed).toBe(false);
  });

  it("requires mode", () => {
    const card = validCard() as Record<string, unknown>;
    delete card.mode;
    const checks = validateProtectionCard(card);
    const check = checks.find(c => c.name === "mode");
    expect(check?.passed).toBe(false);
    expect(check?.message).toContain("off | observe | nudge | enforce");
  });

  it('rejects legacy mode="block" with a pointer to "enforce"', () => {
    const card = { ...validCard(), mode: "block" };
    const checks = validateProtectionCard(card);
    const check = checks.find(c => c.name === "mode");
    expect(check?.passed).toBe(false);
    expect(check?.message).toContain("enforce");
  });

  it('rejects legacy mode="warn"', () => {
    const card = { ...validCard(), mode: "warn" };
    const checks = validateProtectionCard(card);
    const check = checks.find(c => c.name === "mode");
    expect(check?.passed).toBe(false);
  });

  it("accepts off | observe | nudge | enforce", () => {
    for (const mode of ["off", "observe", "nudge", "enforce"]) {
      const card = { ...validCard(), mode };
      const checks = validateProtectionCard(card);
      const check = checks.find(c => c.name === "mode");
      expect(check?.passed).toBe(true);
    }
  });

  it("rejects array-shaped screen_surfaces (legacy)", () => {
    const card = { ...validCard(), screen_surfaces: ["system_prompt", "tool_input"] as any };
    const checks = validateProtectionCard(card);
    const check = checks.find(c => c.name === "screen_surfaces");
    expect(check?.passed).toBe(false);
    expect(check?.message).toContain("object");
  });

  it("rejects unknown screen_surfaces keys", () => {
    const card = validCard();
    (card.screen_surfaces as any).system_prompt = true;
    const checks = validateProtectionCard(card);
    expect(checks.find(c => c.name === "screen_surfaces.system_prompt")?.passed).toBe(false);
  });

  it("rejects non-boolean screen_surfaces values", () => {
    const card = validCard();
    (card.screen_surfaces as any).incoming = "yes";
    const checks = validateProtectionCard(card);
    expect(checks.find(c => c.name === "screen_surfaces.incoming")?.passed).toBe(false);
  });

  it("rejects array-shaped trusted_sources (legacy [{pattern, ...}] shape)", () => {
    const card = {
      ...validCard(),
      trusted_sources: [{ pattern: "*.example.com", reason: "internal" }] as any,
    };
    const checks = validateProtectionCard(card);
    const check = checks.find(c => c.name === "trusted_sources");
    expect(check?.passed).toBe(false);
    expect(check?.message).toContain("typed buckets");
  });

  it("rejects unknown trusted_sources buckets", () => {
    const card = validCard();
    (card.trusted_sources as any).urls = ["http://example.com"];
    const checks = validateProtectionCard(card);
    expect(checks.find(c => c.name === "trusted_sources.urls")?.passed).toBe(false);
  });

  it("applies the deny-list to trusted_sources.domains", () => {
    const card = validCard();
    (card.trusted_sources as any).domains = ["api.openai.com"];
    const checks = validateProtectionCard(card);
    const check = checks.find(c => c.name === "trusted_sources.domains[0]");
    expect(check?.passed).toBe(false);
    expect(check?.message).toContain("deny-list");
  });

  it("applies the deny-list to trusted_sources.ip_ranges", () => {
    const card = validCard();
    (card.trusted_sources as any).ip_ranges = ["0.0.0.0/0"];
    const checks = validateProtectionCard(card);
    expect(checks.find(c => c.name === "trusted_sources.ip_ranges[0]")?.passed).toBe(false);
  });

  it("validates agent_id format", () => {
    const card = validCard();
    (card.trusted_sources as any).agent_ids = ["not-an-agent-id"];
    const checks = validateProtectionCard(card);
    expect(checks.find(c => c.name === "trusted_sources.agent_ids[0]")?.passed).toBe(false);
  });

  it("rejects out-of-order thresholds", () => {
    const card = { ...validCard(), thresholds: { warn: 0.9, quarantine: 0.5, block: 0.7 } };
    const checks = validateProtectionCard(card);
    expect(checks.find(c => c.name === "thresholds.warn")?.passed).toBe(false);
  });

  it("rejects thresholds outside [0,1]", () => {
    const card = { ...validCard(), thresholds: { warn: -0.1, quarantine: 0.5, block: 1.5 } };
    const checks = validateProtectionCard(card);
    expect(checks.find(c => c.name === "thresholds.warn")?.passed).toBe(false);
    expect(checks.find(c => c.name === "thresholds.block")?.passed).toBe(false);
  });

  it("requires all three threshold values when thresholds is present", () => {
    const card = { ...validCard(), thresholds: { warn: 0.5 } as any };
    const checks = validateProtectionCard(card);
    expect(checks.find(c => c.name === "thresholds.quarantine")?.passed).toBe(false);
    expect(checks.find(c => c.name === "thresholds.block")?.passed).toBe(false);
  });
});
