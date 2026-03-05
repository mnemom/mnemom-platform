import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { validateCardJson, validateCard, validateCardObject, parseCardFile, type ValidationCheck } from "../commands/card.js";

// ============================================================================
// Validation tests
// ============================================================================

describe("validateCardJson", () => {
  it("should pass for a valid card with all required fields", () => {
    const card = {
      principal: { name: "TestBot", type: "assistant" },
      values: {
        declared: ["transparency", "honesty"],
      },
      autonomy_envelope: {
        bounded_actions: ["code_generation", "file_read"],
        forbidden_actions: ["delete_data"],
        escalation_triggers: [
          { condition: "high_risk_action", action: "notify_human" },
        ],
      },
      audit_commitment: {
        log_level: "full",
        retention_days: 90,
        access_policy: "owner_only",
      },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const allPassed = checks.every((c) => c.passed);
    expect(allPassed).toBe(true);
  });

  it("should fail for invalid JSON", () => {
    const checks = validateCardJson("not valid json {{{");
    expect(checks[0].name).toBe("Valid JSON");
    expect(checks[0].passed).toBe(false);
    expect(checks.length).toBe(1); // stops at JSON parse failure
  });

  it("should fail when required blocks are missing", () => {
    const card = { principal: { name: "TestBot" } };
    const checks = validateCardJson(JSON.stringify(card));

    const blockChecks = checks.filter((c) => c.name.startsWith("Block:"));
    const principalCheck = blockChecks.find((c) => c.name === "Block: principal");
    const valuesCheck = blockChecks.find((c) => c.name === "Block: values");
    const autonomyCheck = blockChecks.find(
      (c) => c.name === "Block: autonomy_envelope"
    );
    const auditCheck = blockChecks.find(
      (c) => c.name === "Block: audit_commitment"
    );

    expect(principalCheck?.passed).toBe(true);
    expect(valuesCheck?.passed).toBe(false);
    expect(autonomyCheck?.passed).toBe(false);
    expect(auditCheck?.passed).toBe(false);
  });

  it("should fail when values.declared is empty", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: [] },
      autonomy_envelope: { bounded_actions: ["x"] },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
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
      autonomy_envelope: { bounded_actions: ["x"] },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
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
      autonomy_envelope: { bounded_actions: ["x"] },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const defCheck = checks.find((c) => c.name === "Custom value definitions");
    expect(defCheck?.passed).toBe(true);
  });

  it("should pass when all values are standard (no definitions needed)", () => {
    const card = {
      principal: { name: "TestBot" },
      values: {
        declared: ["transparency", "honesty", "safety"],
      },
      autonomy_envelope: { bounded_actions: ["x"] },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const defCheck = checks.find((c) => c.name === "Custom value definitions");
    expect(defCheck?.passed).toBe(true);
    expect(defCheck?.message).toContain("all standard");
  });

  it("should fail when bounded_actions is empty", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy_envelope: { bounded_actions: [] },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const boundedCheck = checks.find((c) => c.name === "bounded_actions");
    expect(boundedCheck?.passed).toBe(false);
  });

  it("should fail when escalation_triggers have invalid conditions", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy_envelope: {
        bounded_actions: ["x"],
        escalation_triggers: [
          { condition: "valid_trigger", action: "notify" },
          { condition: "invalid trigger with spaces", action: "block" },
        ],
      },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const triggerCheck = checks.find((c) => c.name === "escalation_triggers");
    expect(triggerCheck?.passed).toBe(false);
    expect(triggerCheck?.message).toContain("invalid conditions");
  });

  it("should pass when escalation_triggers have valid conditions", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy_envelope: {
        bounded_actions: ["x"],
        escalation_triggers: [
          { condition: "high_risk", action: "notify" },
          { condition: "safety_concern", action: "block" },
        ],
      },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const triggerCheck = checks.find((c) => c.name === "escalation_triggers");
    expect(triggerCheck?.passed).toBe(true);
  });

  it("should fail when expires_at is in the past", () => {
    const card = {
      expires_at: "2020-01-01T00:00:00Z",
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy_envelope: { bounded_actions: ["x"] },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const expiresCheck = checks.find((c) => c.name === "expires_at");
    expect(expiresCheck?.passed).toBe(false);
    expect(expiresCheck?.message).toContain("expired");
  });

  it("should pass when expires_at is in the future", () => {
    const card = {
      expires_at: "2099-01-01T00:00:00Z",
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy_envelope: { bounded_actions: ["x"] },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const expiresCheck = checks.find((c) => c.name === "expires_at");
    expect(expiresCheck?.passed).toBe(true);
  });

  it("should fail when expires_at has invalid date format", () => {
    const card = {
      expires_at: "not-a-date",
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy_envelope: { bounded_actions: ["x"] },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const expiresCheck = checks.find((c) => c.name === "expires_at");
    expect(expiresCheck?.passed).toBe(false);
    expect(expiresCheck?.message).toContain("Invalid date");
  });
});

// ============================================================================
// Additional validation edge case tests
// ============================================================================

describe("validateCardJson edge cases", () => {
  it("should handle card with only standard values and no definitions key", () => {
    const card = {
      principal: { name: "TestBot" },
      values: {
        declared: ["transparency", "safety", "accountability"],
      },
      autonomy_envelope: {
        bounded_actions: ["code_generation"],
      },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const defCheck = checks.find((c) => c.name === "Custom value definitions");
    expect(defCheck?.passed).toBe(true);
  });

  it("should handle card with no escalation triggers defined", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy_envelope: {
        bounded_actions: ["x"],
        escalation_triggers: [],
      },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const triggerCheck = checks.find((c) => c.name === "escalation_triggers");
    expect(triggerCheck?.passed).toBe(true);
    expect(triggerCheck?.message).toContain("No triggers");
  });

  it("should handle card with no autonomy_envelope.escalation_triggers key", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy_envelope: {
        bounded_actions: ["x"],
      },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    // Should not have an escalation_triggers check when key is missing
    const triggerCheck = checks.find((c) => c.name === "escalation_triggers");
    expect(triggerCheck).toBeUndefined();
  });

  it("should handle card without expires_at", () => {
    const card = {
      principal: { name: "TestBot" },
      values: { declared: ["transparency"] },
      autonomy_envelope: { bounded_actions: ["x"] },
      audit_commitment: { log_level: "full" },
    };

    const checks = validateCardJson(JSON.stringify(card));
    const expiresCheck = checks.find((c) => c.name === "expires_at");
    expect(expiresCheck).toBeUndefined(); // No check when no expires_at
    expect(checks.every((c) => c.passed)).toBe(true);
  });

  it("should count correct number of checks for a complete card", () => {
    const card = {
      expires_at: "2099-01-01T00:00:00Z",
      principal: { name: "TestBot", type: "assistant" },
      values: {
        declared: ["transparency", "custom_one"],
        definitions: { custom_one: "A custom value" },
      },
      autonomy_envelope: {
        bounded_actions: ["code_gen"],
        forbidden_actions: ["delete"],
        escalation_triggers: [
          { condition: "high_risk", action: "notify" },
        ],
      },
      audit_commitment: {
        log_level: "full",
        retention_days: 90,
      },
    };

    const checks = validateCardJson(JSON.stringify(card));
    // JSON + 4 blocks + declared + definitions + bounded + triggers + expires = 10
    expect(checks.length).toBe(10);
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
    principal: { name: "TestBot", type: "assistant" },
    values: { declared: ["transparency", "honesty"] },
    autonomy_envelope: {
      bounded_actions: ["code_generation"],
      escalation_triggers: [{ condition: "high_risk", action: "notify" }],
    },
    audit_commitment: { log_level: "full", retention_days: 90 },
  };

  const validYaml = `principal:
  name: TestBot
  type: assistant
values:
  declared:
    - transparency
    - honesty
autonomy_envelope:
  bounded_actions:
    - code_generation
  escalation_triggers:
    - condition: high_risk
      action: notify
audit_commitment:
  log_level: full
  retention_days: 90
`;

  it("should parse a valid YAML card file", () => {
    const filePath = path.join(tmpDir, "card.yaml");
    fs.writeFileSync(filePath, validYaml);

    const result = parseCardFile(filePath);
    expect(result.format).toBe("yaml");
    expect(result.parsed.principal!.name).toBe("TestBot");
    expect(result.parsed.values!.declared).toEqual(["transparency", "honesty"]);
  });

  it("should parse a .yml extension as YAML", () => {
    const filePath = path.join(tmpDir, "card.yml");
    fs.writeFileSync(filePath, validYaml);

    const result = parseCardFile(filePath);
    expect(result.format).toBe("yaml");
    expect(result.parsed.principal!.name).toBe("TestBot");
  });

  it("should parse a valid JSON card file", () => {
    const filePath = path.join(tmpDir, "card.json");
    fs.writeFileSync(filePath, JSON.stringify(validCard));

    const result = parseCardFile(filePath);
    expect(result.format).toBe("json");
    expect(result.parsed.principal!.name).toBe("TestBot");
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

    const jsonChecks = validateCardObject(jsonResult.parsed);
    const yamlChecks = validateCardObject(yamlResult.parsed);

    expect(jsonChecks.length).toBe(yamlChecks.length);
    for (let i = 0; i < jsonChecks.length; i++) {
      expect(yamlChecks[i].name).toBe(jsonChecks[i].name);
      expect(yamlChecks[i].passed).toBe(jsonChecks[i].passed);
    }
  });
});
