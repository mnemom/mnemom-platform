import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { validateUnifiedCard, validateCardJson, parseCardFile } from "../commands/card.js";

// ============================================================================
// Unified alignment-card validation tests (ADR-039 canonical form)
// ============================================================================

/** Minimal card that should pass every check. */
const validCard = () => ({
  card_version: "unified/2026-04-26",
  agent_id: "mnm-aabbccdd-eeff-0011-2233-445566778899",
  autonomy_mode: "observe",
  integrity_mode: "observe",
  principal: {
    type: "agent",
    identifier: "mnm-aabbccdd-eeff-0011-2233-445566778899",
    relationship: "delegated_authority",
  },
  values: { declared: ["transparency", "honesty"] },
  autonomy: {
    bounded_actions: ["respond_to_prompts"],
    forbidden_actions: [],
    escalation_triggers: [],
  },
  audit: { retention_days: 30, queryable: false, trace_format: "otel" },
});

describe("validateUnifiedCard — ADR-039 canonical form", () => {
  it("passes for a minimal valid card", () => {
    const checks = validateUnifiedCard(validCard());
    const failed = checks.filter(c => !c.passed);
    expect(failed, JSON.stringify(failed, null, 2)).toHaveLength(0);
  });

  it("requires card_version", () => {
    const card = validCard() as Record<string, unknown>;
    delete card.card_version;
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "card_version")?.passed).toBe(false);
  });

  it("requires agent_id", () => {
    const card = validCard() as Record<string, unknown>;
    delete card.agent_id;
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "agent_id")?.passed).toBe(false);
  });

  it("requires top-level autonomy_mode", () => {
    const card = validCard() as Record<string, unknown>;
    delete card.autonomy_mode;
    const checks = validateUnifiedCard(card);
    const check = checks.find(c => c.name === "autonomy_mode");
    expect(check?.passed).toBe(false);
    expect(check?.message).toMatch(/required/i);
  });

  it("requires top-level integrity_mode", () => {
    const card = validCard() as Record<string, unknown>;
    delete card.integrity_mode;
    const checks = validateUnifiedCard(card);
    const check = checks.find(c => c.name === "integrity_mode");
    expect(check?.passed).toBe(false);
  });

  it("rejects autonomy_mode outside the enum", () => {
    const card = { ...validCard(), autonomy_mode: "block" };
    const checks = validateUnifiedCard(card);
    const check = checks.find(c => c.name === "autonomy_mode");
    expect(check?.passed).toBe(false);
    expect(check?.message).toContain("off | observe | nudge | enforce");
  });

  it("rejects legacy integrity.enforcement_mode with a pointer to integrity_mode", () => {
    const card = { ...validCard(), integrity: { enforcement_mode: "strict" } };
    const checks = validateUnifiedCard(card);
    const check = checks.find(c => c.name === "integrity.enforcement_mode");
    expect(check?.passed).toBe(false);
    expect(check?.message).toContain("integrity_mode");
  });

  it("rejects legacy enforcement.mode", () => {
    const card = { ...validCard(), enforcement: { mode: "observe" } };
    const checks = validateUnifiedCard(card);
    const check = checks.find(c => c.name === "enforcement.mode");
    expect(check?.passed).toBe(false);
    expect(check?.message).toContain("autonomy_mode");
  });

  it("rejects legacy enforcement.unmapped_tool_action", () => {
    const card = { ...validCard(), enforcement: { unmapped_tool_action: "deny" } };
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "enforcement.unmapped_tool_action")?.passed).toBe(false);
  });

  it("rejects legacy enforcement.fail_open", () => {
    const card = { ...validCard(), enforcement: { fail_open: true } };
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "enforcement.fail_open")?.passed).toBe(false);
  });

  it("rejects legacy audit.storage", () => {
    const card = validCard();
    (card.audit as any).storage = "s3://bucket";
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "audit.storage")?.passed).toBe(false);
  });

  it("rejects legacy capabilities.<n>.required_actions", () => {
    const card = {
      ...validCard(),
      capabilities: { web_fetch: { tools: ["WebFetch"], required_actions: ["web_fetch"] } },
    };
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "capabilities.web_fetch.required_actions")?.passed).toBe(false);
  });

  it("rejects _composition on inbound cards", () => {
    const card = { ...validCard(), _composition: { sources: [] } };
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "_composition")?.passed).toBe(false);
  });

  it("requires principal.identifier when type != unspecified", () => {
    const card = validCard();
    delete (card.principal as any).identifier;
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "principal.identifier")?.passed).toBe(false);
  });

  it("does not require principal.identifier when type=unspecified", () => {
    const card = validCard();
    (card.principal as any).type = "unspecified";
    delete (card.principal as any).identifier;
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "principal.identifier")).toBeUndefined();
  });

  it("rejects invalid principal.type", () => {
    const card = validCard();
    (card.principal as any).type = "ai_agent";
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "principal.type")?.passed).toBe(false);
  });

  it("rejects invalid principal.relationship", () => {
    const card = validCard();
    (card.principal as any).relationship = "owner";
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "principal.relationship")?.passed).toBe(false);
  });

  it("requires non-empty values.declared", () => {
    const card = validCard();
    (card.values as any).declared = [];
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "values.declared")?.passed).toBe(false);
  });

  it("requires definitions ⊆ declared", () => {
    const card = validCard();
    (card.values as any).definitions = { transparency: "ok", undefined_value: "extra" };
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "values.definitions.undefined_value")?.passed).toBe(false);
  });

  it("requires non-empty autonomy.bounded_actions", () => {
    const card = validCard();
    (card.autonomy as any).bounded_actions = [];
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "autonomy.bounded_actions")?.passed).toBe(false);
  });

  it("rejects bounded_actions ∩ forbidden_actions", () => {
    const card = validCard();
    (card.autonomy as any).bounded_actions = ["respond_to_prompts", "delete_data"];
    (card.autonomy as any).forbidden_actions = ["delete_data"];
    const checks = validateUnifiedCard(card);
    const overlap = checks.find(c => c.name === "autonomy.bounded_actions" && !c.passed);
    expect(overlap?.message).toContain("disjoint");
  });

  it("rejects BOUNDARY + advisory in conscience", () => {
    const card = validCard() as any;
    card.conscience = {
      mode: "augment",
      values: [{ type: "BOUNDARY", content: "no harm", severity: "advisory" }],
    };
    const checks = validateUnifiedCard(card);
    const idx = checks.findIndex(c => c.name === "conscience.values[0]" && !c.passed);
    expect(idx).toBeGreaterThanOrEqual(0);
    expect(checks[idx].message).toMatch(/BOUNDARY.*advisory/);
  });

  it("requires audit section", () => {
    const card = validCard() as Record<string, unknown>;
    delete card.audit;
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "audit")?.passed).toBe(false);
  });

  it("requires audit.query_endpoint when queryable=true", () => {
    const card = validCard();
    (card.audit as any).queryable = true;
    const checks = validateUnifiedCard(card);
    expect(checks.find(c => c.name === "audit.query_endpoint")?.passed).toBe(false);
  });
});

// ============================================================================
// Deprecated validateCardJson compat
// ============================================================================

describe("validateCardJson (deprecated compat)", () => {
  it("parses JSON and validates", () => {
    const checks = validateCardJson(JSON.stringify(validCard()));
    const failed = checks.filter(c => !c.passed);
    expect(failed, JSON.stringify(failed, null, 2)).toHaveLength(0);
  });
});

// ============================================================================
// YAML/JSON parsing tests
// ============================================================================

describe("parseCardFile", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "card-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const validYaml = `card_version: unified/2026-04-26
agent_id: mnm-aabbccdd-eeff-0011-2233-445566778899
autonomy_mode: observe
integrity_mode: observe
principal:
  type: agent
  identifier: mnm-aabbccdd-eeff-0011-2233-445566778899
  relationship: delegated_authority
values:
  declared:
    - transparency
    - honesty
autonomy:
  bounded_actions:
    - respond_to_prompts
audit:
  retention_days: 30
  queryable: false
  trace_format: otel
`;

  it("parses a valid YAML card file", () => {
    const filePath = path.join(tmpDir, "card.yaml");
    fs.writeFileSync(filePath, validYaml);

    const result = parseCardFile(filePath);
    expect(result.format).toBe("yaml");
    expect(result.parsed.autonomy_mode).toBe("observe");
    expect(result.parsed.integrity_mode).toBe("observe");
  });

  it("treats .yml as YAML", () => {
    const filePath = path.join(tmpDir, "card.yml");
    fs.writeFileSync(filePath, validYaml);
    expect(parseCardFile(filePath).format).toBe("yaml");
  });

  it("parses a valid JSON card file", () => {
    const filePath = path.join(tmpDir, "card.json");
    fs.writeFileSync(filePath, JSON.stringify(validCard()));
    const result = parseCardFile(filePath);
    expect(result.format).toBe("json");
    expect(result.parsed.autonomy_mode).toBe("observe");
  });

  it("includes raw content in the result", () => {
    const filePath = path.join(tmpDir, "card.yaml");
    fs.writeFileSync(filePath, validYaml);
    expect(parseCardFile(filePath).raw).toBe(validYaml);
  });

  it("throws on invalid YAML", () => {
    const filePath = path.join(tmpDir, "bad.yaml");
    fs.writeFileSync(filePath, ":\n  invalid: [yaml\n  broken");
    expect(() => parseCardFile(filePath)).toThrow();
  });

  it("throws on YAML that produces a non-object", () => {
    const filePath = path.join(tmpDir, "scalar.yaml");
    fs.writeFileSync(filePath, "just a string");
    expect(() => parseCardFile(filePath)).toThrow("YAML did not produce a valid object");
  });

  it("produces identical validation results for YAML and JSON of the same card", () => {
    const card = validCard();
    const jsonPath = path.join(tmpDir, "card.json");
    const yamlPath = path.join(tmpDir, "card.yaml");
    fs.writeFileSync(jsonPath, JSON.stringify(card));
    fs.writeFileSync(yamlPath, validYaml);

    const jsonResult = parseCardFile(jsonPath);
    const yamlResult = parseCardFile(yamlPath);

    const jsonChecks = validateUnifiedCard(jsonResult.parsed);
    const yamlChecks = validateUnifiedCard(yamlResult.parsed);

    expect(jsonChecks.length).toBe(yamlChecks.length);
    for (let i = 0; i < jsonChecks.length; i++) {
      expect(yamlChecks[i].name).toBe(jsonChecks[i].name);
      expect(yamlChecks[i].passed).toBe(jsonChecks[i].passed);
    }
  });
});
