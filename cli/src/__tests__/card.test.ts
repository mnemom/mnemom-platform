import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { validateUnifiedCard, validateCardJson, parseCardFile, type ValidationCheck } from "../commands/card.js";

// ============================================================================
// Unified card validation tests (ADR-008 schema)
// ============================================================================

describe("validateUnifiedCard", () => {
  it("should pass for a valid card with all required sections", () => {
    const card = {
      principal: { name: "TestBot", type: "ai_agent" },
      values: {
        declared: ["transparency", "honesty"],
      },
      autonomy: {
        bounded_actions: ["code_generation", "file_read"],
        forbidden_actions: ["delete_data"],
        escalation_triggers: [
          { condition: "high_risk_action", action: "notify_human" },
        ],
      },
    };

    const checks = validateUnifiedCard(card);
    const allPassed = checks.every((c) => c.passed);
    expect(allPassed).toBe(true);
  });

  it("should fail when required sections are missing", () => {
    const card = { principal: { name: "TestBot" } };
    const checks = validateUnifiedCard(card);

    const principalCheck = checks.find((c) => c.name === "Section: principal");
    const valuesCheck = checks.find((c) => c.name === "Section: values");
    const autonomyCheck = checks.find((c) => c.name === "Section: autonomy");

    expect(principalCheck?.passed).toBe(true);
    expect(valuesCheck?.passed).toBe(false);
    expect(autonomyCheck?.passed).toBe(false);
  });

  it("should pass with optional sections present", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy: { bounded_actions: ["x"] },
      conscience: { mode: "advisory" },
      integrity: { enforcement_mode: "strict" },
      capabilities: {},
      enforcement: { mode: "observe" },
      audit: { log_level: "full" },
      extensions: { custom: true },
    };

    const checks = validateUnifiedCard(card);
    expect(checks.every((c) => c.passed)).toBe(true);
  });

  it("should fail when optional section is not an object", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy: { bounded_actions: ["x"] },
      conscience: "invalid",
    };

    const checks = validateUnifiedCard(card);
    const conscienceCheck = checks.find((c) => c.name === "Section: conscience");
    expect(conscienceCheck?.passed).toBe(false);
  });

  it("should fail when values.declared is empty", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: [] },
      autonomy: { bounded_actions: ["x"] },
    };

    const checks = validateUnifiedCard(card);
    const declaredCheck = checks.find((c) => c.name === "values.declared");
    expect(declaredCheck?.passed).toBe(false);
  });

  it("should fail when custom values lack definitions", () => {
    const card = {
      principal: { name: "TestBot" },
      values: {
        declared: ["transparency", "custom_value_1", "custom_value_2"],
        definitions: { custom_value_1: "A custom value" },
      },
      autonomy: { bounded_actions: ["x"] },
    };

    const checks = validateUnifiedCard(card);
    const defCheck = checks.find((c) => c.name === "Custom value definitions");
    expect(defCheck?.passed).toBe(false);
    expect(defCheck?.message).toContain("custom_value_2");
  });

  it("should pass when all custom values have definitions", () => {
    const card = {
      principal: { name: "TestBot" },
      values: {
        declared: ["transparency", "custom_value_1"],
        definitions: { custom_value_1: "A custom value" },
      },
      autonomy: { bounded_actions: ["x"] },
    };

    const checks = validateUnifiedCard(card);
    const defCheck = checks.find((c) => c.name === "Custom value definitions");
    expect(defCheck?.passed).toBe(true);
  });

  it("should pass when all values are standard", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency", "honesty", "safety"] },
      autonomy: { bounded_actions: ["x"] },
    };

    const checks = validateUnifiedCard(card);
    const defCheck = checks.find((c) => c.name === "Custom value definitions");
    expect(defCheck?.passed).toBe(true);
    expect(defCheck?.message).toContain("all standard");
  });

  it("should fail when bounded_actions is empty", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy: { bounded_actions: [] },
    };

    const checks = validateUnifiedCard(card);
    const boundedCheck = checks.find((c) => c.name === "autonomy.bounded_actions");
    expect(boundedCheck?.passed).toBe(false);
  });

  it("should validate capabilities shape", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy: { bounded_actions: ["x"] },
      capabilities: {
        web_fetch: {
          tools: ["WebFetch"],
          required_actions: ["web_fetch"],
        },
        broken: {
          tools: "not-an-array",
        },
      },
    };

    const checks = validateUnifiedCard(card);
    const brokenToolsCheck = checks.find((c) => c.name === "capabilities.broken.tools");
    const brokenActionsCheck = checks.find((c) => c.name === "capabilities.broken.required_actions");
    expect(brokenToolsCheck?.passed).toBe(false);
    expect(brokenActionsCheck?.passed).toBe(false);
  });

  it("should validate enforcement.forbidden_tools shape", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy: { bounded_actions: ["x"] },
      enforcement: {
        forbidden_tools: [
          { pattern: "mcp__*__delete*", reason: "No deletion" },
          { pattern: "missing-reason" },
        ],
      },
    };

    const checks = validateUnifiedCard(card);
    const invalidRule = checks.find((c) => c.name === "enforcement.forbidden_tools[1]");
    expect(invalidRule?.passed).toBe(false);
  });
});

// ============================================================================
// Deprecated validateCardJson compat
// ============================================================================

describe("validateCardJson (deprecated compat)", () => {
  it("should parse JSON and validate", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy: { bounded_actions: ["x"] },
    };

    const checks = validateCardJson(JSON.stringify(card));
    expect(checks.every((c) => c.passed)).toBe(true);
  });
});

// ============================================================================
// YAML card parsing tests
// ============================================================================

describe("parseCardFile", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "card-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const validCard = {
    principal: { name: "TestBot", type: "ai_agent" },
    values: { declared: ["transparency", "honesty"] },
    autonomy: {
      bounded_actions: ["code_generation"],
      escalation_triggers: [{ condition: "high_risk", action: "notify" }],
    },
  };

  const validYaml = `principal:
  name: TestBot
  type: ai_agent
values:
  declared:
    - transparency
    - honesty
autonomy:
  bounded_actions:
    - code_generation
  escalation_triggers:
    - condition: high_risk
      action: notify
`;

  it("should parse a valid YAML card file", () => {
    const filePath = path.join(tmpDir, "card.yaml");
    fs.writeFileSync(filePath, validYaml);

    const result = parseCardFile(filePath);
    expect(result.format).toBe("yaml");
    expect((result.parsed.principal as any).name).toBe("TestBot");
    expect((result.parsed.values as any).declared).toEqual(["transparency", "honesty"]);
  });

  it("should parse a .yml extension as YAML", () => {
    const filePath = path.join(tmpDir, "card.yml");
    fs.writeFileSync(filePath, validYaml);

    const result = parseCardFile(filePath);
    expect(result.format).toBe("yaml");
    expect((result.parsed.principal as any).name).toBe("TestBot");
  });

  it("should parse a valid JSON card file", () => {
    const filePath = path.join(tmpDir, "card.json");
    fs.writeFileSync(filePath, JSON.stringify(validCard));

    const result = parseCardFile(filePath);
    expect(result.format).toBe("json");
    expect((result.parsed.principal as any).name).toBe("TestBot");
  });

  it("should include raw content in result", () => {
    const filePath = path.join(tmpDir, "card.yaml");
    fs.writeFileSync(filePath, validYaml);

    const result = parseCardFile(filePath);
    expect(result.raw).toBe(validYaml);
  });

  it("should throw on invalid YAML", () => {
    const filePath = path.join(tmpDir, "bad.yaml");
    fs.writeFileSync(filePath, ":\n  invalid: [yaml\n  broken");

    expect(() => parseCardFile(filePath)).toThrow();
  });

  it("should throw on YAML that produces a non-object", () => {
    const filePath = path.join(tmpDir, "scalar.yaml");
    fs.writeFileSync(filePath, "just a string");

    expect(() => parseCardFile(filePath)).toThrow("YAML did not produce a valid object");
  });

  it("should produce identical validation results for YAML and JSON of the same card", () => {
    const jsonPath = path.join(tmpDir, "card.json");
    const yamlPath = path.join(tmpDir, "card.yaml");
    fs.writeFileSync(jsonPath, JSON.stringify(validCard));
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
