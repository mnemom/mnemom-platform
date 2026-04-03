import * as fs from "node:fs";
import * as path from "node:path";
import yaml from "js-yaml";
import { configExists, loadConfig, requireAgent } from "../lib/config.js";
import {
  getCard,
  updateCard,
  reverifyAgent,
  type AlignmentCard,
  type CardResponse,
} from "../lib/api.js";
import { requireAuth } from "../lib/auth.js";
import { fmt } from "../lib/format.js";
import { askYesNo, isInteractive } from "../lib/prompt.js";

// Standard AAP values that do not require custom definitions
const STANDARD_VALUES = new Set([
  "transparency",
  "honesty",
  "safety",
  "privacy",
  "fairness",
  "accountability",
  "beneficence",
  "non-maleficence",
  "autonomy",
  "justice",
  "reliability",
  "security",
  "human_oversight",
  "explainability",
]);

// ============================================================================
// File parsing
// ============================================================================

export type CardFormat = "json" | "yaml";

export interface ParsedCard {
  format: CardFormat;
  parsed: AlignmentCard;
}

function detectFormat(filePath: string): CardFormat {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".yaml" || ext === ".yml") return "yaml";
  return "json";
}

export function parseCardFile(filePath: string): ParsedCard {
  const raw = fs.readFileSync(filePath, "utf-8");
  const format = detectFormat(filePath);

  if (format === "yaml") {
    const parsed = yaml.load(raw) as AlignmentCard;
    if (!parsed || typeof parsed !== "object") {
      throw new Error("YAML did not produce a valid object");
    }
    return { format, parsed };
  }

  return { format, parsed: JSON.parse(raw) as AlignmentCard };
}

// ============================================================================
// Validation logic
// ============================================================================

export interface ValidationCheck {
  name: string;
  passed: boolean;
  message: string;
}

/** @deprecated Use validateCard instead */
export const validateCardJson = validateCard;

export function validateCard(raw: string): ValidationCheck[] {
  const checks: ValidationCheck[] = [];

  // Check 1: Valid JSON
  let card: AlignmentCard;
  try {
    card = JSON.parse(raw) as AlignmentCard;
    checks.push({ name: "Valid JSON", passed: true, message: "Parsed successfully" });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    checks.push({ name: "Valid JSON", passed: false, message: `Parse error: ${msg}` });
    return checks; // Can't continue without valid JSON
  }

  // Check 2: Required blocks
  const requiredBlocks = ["principal", "values", "autonomy_envelope", "audit_commitment"] as const;
  for (const block of requiredBlocks) {
    if (card[block] && typeof card[block] === "object") {
      checks.push({ name: `Block: ${block}`, passed: true, message: "Present" });
    } else {
      checks.push({ name: `Block: ${block}`, passed: false, message: "Missing or invalid" });
    }
  }

  // Check 3: values.declared is non-empty array
  const declared = card.values?.declared;
  if (Array.isArray(declared) && declared.length > 0) {
    checks.push({
      name: "values.declared",
      passed: true,
      message: `${declared.length} value(s) declared`,
    });
  } else {
    checks.push({
      name: "values.declared",
      passed: false,
      message: "Must be a non-empty array",
    });
  }

  // Check 4: Custom values have definitions
  if (Array.isArray(declared)) {
    const definitions = card.values?.definitions || {};
    const customValues = declared.filter((v) => !STANDARD_VALUES.has(v));
    const missingDefs = customValues.filter((v) => !definitions[v]);

    if (missingDefs.length === 0) {
      checks.push({
        name: "Custom value definitions",
        passed: true,
        message:
          customValues.length === 0
            ? "No custom values (all standard)"
            : `${customValues.length} custom value(s) defined`,
      });
    } else {
      checks.push({
        name: "Custom value definitions",
        passed: false,
        message: `Missing definitions for: ${missingDefs.join(", ")}`,
      });
    }
  }

  // Check 5: bounded_actions is non-empty array
  const bounded = card.autonomy_envelope?.bounded_actions;
  if (Array.isArray(bounded) && bounded.length > 0) {
    checks.push({
      name: "bounded_actions",
      passed: true,
      message: `${bounded.length} bounded action(s)`,
    });
  } else {
    checks.push({
      name: "bounded_actions",
      passed: false,
      message: "Must be a non-empty array",
    });
  }

  // Check 6: escalation_triggers conditions are evaluable
  // Accepts: simple identifiers, tool_matches('...') calls, and logical expressions
  // (comparisons with ==, !=, >, <, and/or, quoted strings, numbers)
  const triggers = card.autonomy_envelope?.escalation_triggers;
  if (Array.isArray(triggers) && triggers.length > 0) {
    const conditionPattern = /^[\w\s\(\)\*\.'",=!><&|]+$/;
    const invalidTriggers = triggers.filter(
      (t) => !t.condition || !conditionPattern.test(t.condition)
    );

    if (invalidTriggers.length === 0) {
      checks.push({
        name: "escalation_triggers",
        passed: true,
        message: `${triggers.length} trigger(s), all valid`,
      });
    } else {
      checks.push({
        name: "escalation_triggers",
        passed: false,
        message: `${invalidTriggers.length} trigger(s) with invalid conditions`,
      });
    }
  } else if (Array.isArray(triggers) && triggers.length === 0) {
    checks.push({
      name: "escalation_triggers",
      passed: true,
      message: "No triggers defined",
    });
  }

  // Check 7: expires_at not already expired
  if (card.expires_at) {
    const expiresDate = new Date(card.expires_at);
    if (isNaN(expiresDate.getTime())) {
      checks.push({
        name: "expires_at",
        passed: false,
        message: "Invalid date format",
      });
    } else if (expiresDate.getTime() < Date.now()) {
      checks.push({
        name: "expires_at",
        passed: false,
        message: `Already expired: ${card.expires_at}`,
      });
    } else {
      checks.push({
        name: "expires_at",
        passed: true,
        message: `Valid until ${card.expires_at}`,
      });
    }
  }

  return checks;
}

/**
 * Validate a pre-parsed card object (used for YAML cards).
 * Re-serializes to JSON so the same checks run identically.
 */
export function validateCardObject(card: AlignmentCard): ValidationCheck[] {
  return validateCard(JSON.stringify(card));
}

// ============================================================================
// Card display
// ============================================================================

function displayCard(cardResponse: CardResponse): void {
  const card = cardResponse.card_json;

  console.log(fmt.header("Alignment Card"));
  console.log();

  // Header info
  console.log(fmt.label("  Card ID: ", cardResponse.card_id));
  if (card.version) {
    console.log(fmt.label("  Version: ", card.version));
  }
  if (card.issued_at) {
    console.log(fmt.label("  Issued:  ", card.issued_at));
  }
  if (card.expires_at) {
    console.log(fmt.label("  Expires: ", card.expires_at));
  }

  // Principal
  if (card.principal) {
    console.log(fmt.section("Principal"));
    console.log();
    if (card.principal.name) {
      console.log(fmt.label("  Name:        ", card.principal.name));
    }
    if (card.principal.type) {
      console.log(fmt.label("  Type:        ", card.principal.type));
    }
    if (card.principal.organization) {
      console.log(fmt.label("  Organization:", ` ${card.principal.organization}`));
    }
  }

  // Values
  if (card.values) {
    console.log(fmt.section("Values"));
    console.log();

    if (Array.isArray(card.values.declared) && card.values.declared.length > 0) {
      const badges = card.values.declared.map((v) => {
        if (STANDARD_VALUES.has(v)) {
          return fmt.badge(v, "cyan");
        }
        return fmt.badge(v, "magenta");
      });
      console.log(`  ${badges.join(" ")}`);

      // Show definitions for custom values
      const definitions = card.values.definitions || {};
      const customValues = card.values.declared.filter((v) => !STANDARD_VALUES.has(v));
      if (customValues.length > 0) {
        console.log();
        for (const v of customValues) {
          if (definitions[v]) {
            console.log(fmt.label(`    ${v}:`, ` ${definitions[v]}`));
          }
        }
      }
    }
  }

  // Autonomy envelope
  if (card.autonomy_envelope) {
    console.log(fmt.section("Autonomy Envelope"));
    console.log();

    const bounded = card.autonomy_envelope.bounded_actions;
    if (Array.isArray(bounded) && bounded.length > 0) {
      console.log("  Bounded actions:");
      for (const action of bounded) {
        console.log(`    ${fmt.success(action)}`);
      }
    }

    const forbidden = card.autonomy_envelope.forbidden_actions;
    if (Array.isArray(forbidden) && forbidden.length > 0) {
      console.log("  Forbidden actions:");
      for (const action of forbidden) {
        console.log(`    ${fmt.error(action)}`);
      }
    }

    const triggers = card.autonomy_envelope.escalation_triggers;
    if (Array.isArray(triggers) && triggers.length > 0) {
      console.log("  Escalation triggers:");
      for (const trigger of triggers) {
        const action = trigger.action ? ` -> ${trigger.action}` : "";
        console.log(`    ${fmt.warn(`${trigger.condition}${action}`)}`);
      }
    }
  }

  // Audit commitment
  if (card.audit_commitment) {
    console.log(fmt.section("Audit Commitment"));
    console.log();
    if (card.audit_commitment.log_level) {
      console.log(fmt.label("  Log level:      ", card.audit_commitment.log_level));
    }
    if (card.audit_commitment.retention_days != null) {
      console.log(fmt.label("  Retention:      ", `${card.audit_commitment.retention_days} days`));
    }
    if (card.audit_commitment.access_policy) {
      console.log(fmt.label("  Access policy:  ", card.audit_commitment.access_policy));
    }
  }

  // Extensions
  if (card.extensions && Object.keys(card.extensions).length > 0) {
    console.log(fmt.section("Extensions"));
    console.log();
    console.log(fmt.json(card.extensions));
  }

  console.log();
}

// ============================================================================
// Subcommands
// ============================================================================

export async function cardShowCommand(agentName?: string): Promise<void> {
  if (!configExists()) {
    console.log("\n" + fmt.error("smoltbot is not initialized") + "\n");
    console.log("Run `smoltbot init` to get started.\n");
    process.exit(1);
  }

  const config = loadConfig();
  if (!config) {
    console.log("\n" + fmt.error("Failed to load configuration") + "\n");
    process.exit(1);
  }

  const agent = await requireAgent(agentName);
  if (!agent) {
    console.log("\n" + fmt.error(`Agent not found${agentName ? `: ${agentName}` : ""}`) + "\n");
    process.exit(1);
  }

  console.log("\nFetching alignment card...\n");

  try {
    const cardResponse = await getCard(agent.agentId);

    if (!cardResponse) {
      console.log(fmt.warn("No custom card -- using default"));
      console.log("\nPublish a custom card with:\n");
      console.log("  smoltbot card publish <file.json>\n");
      return;
    }

    displayCard(cardResponse);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to fetch card: ${message}`) + "\n");
    process.exit(1);
  }
}

export async function cardPublishCommand(file: string, agentName?: string): Promise<void> {
  if (!configExists()) {
    console.log("\n" + fmt.error("smoltbot is not initialized") + "\n");
    console.log("Run `smoltbot init` to get started.\n");
    process.exit(1);
  }

  const config = loadConfig();
  if (!config) {
    console.log("\n" + fmt.error("Failed to load configuration") + "\n");
    process.exit(1);
  }

  const agent = await requireAgent(agentName);
  if (!agent) {
    console.log("\n" + fmt.error(`Agent not found${agentName ? `: ${agentName}` : ""}`) + "\n");
    process.exit(1);
  }

  // Resolve file path
  const filePath = path.resolve(file);
  if (!fs.existsSync(filePath)) {
    console.log("\n" + fmt.error(`File not found: ${filePath}`) + "\n");
    process.exit(1);
  }

  // Parse file (JSON or YAML)
  let parsed: AlignmentCard;
  let format: CardFormat;
  try {
    const result = parseCardFile(filePath);
    parsed = result.parsed;
    format = result.format;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Could not parse file: ${msg}`) + "\n");
    process.exit(1);
  }

  // Validate locally
  const checks = validateCardObject(parsed!);
  const allPassed = checks.every((c) => c.passed);

  console.log(fmt.header("Card Validation"));
  console.log(fmt.label("  Format:", ` ${format!.toUpperCase()}`));
  console.log();
  for (const check of checks) {
    if (check.passed) {
      console.log(fmt.success(`${check.name}: ${check.message}`));
    } else {
      console.log(fmt.error(`${check.name}: ${check.message}`));
    }
  }
  console.log();

  if (!allPassed) {
    console.log(fmt.error("Validation failed. Fix the errors above before publishing.") + "\n");
    process.exit(1);
  }

  // Require authentication
  await requireAuth();

  // Confirm with user
  if (isInteractive()) {
    const confirm = await askYesNo(
      `Publish this card for agent ${agent.agentId}?`,
      false
    );
    if (!confirm) {
      console.log("\nPublish cancelled.\n");
      return;
    }
  }

  // Publish (always sends JSON to API regardless of source format)

  try {
    console.log("\nPublishing card...");
    const result = await updateCard(agent.agentId, parsed);
    console.log(fmt.success(`Card published successfully!`));
    console.log(fmt.label("  Card ID:", ` ${result.card_id}`) + "\n");

    // Trigger re-verification
    try {
      console.log("Triggering re-verification...");
      const reverifyResult = await reverifyAgent(agent.agentId);
      console.log(fmt.success(`Re-verification started (${reverifyResult.reverified} traces queued)`) + "\n");
    } catch {
      console.log(fmt.warn("Could not trigger re-verification (non-critical)") + "\n");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to publish card: ${message}`) + "\n");
    process.exit(1);
  }
}

export async function cardValidateCommand(file: string): Promise<void> {
  // Resolve file path
  const filePath = path.resolve(file);
  if (!fs.existsSync(filePath)) {
    console.log("\n" + fmt.error(`File not found: ${filePath}`) + "\n");
    process.exit(1);
  }

  // Parse file (JSON or YAML)
  let parsed: AlignmentCard;
  let format: CardFormat;
  try {
    const result = parseCardFile(filePath);
    parsed = result.parsed;
    format = result.format;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Could not parse file: ${msg}`) + "\n");
    process.exit(1);
  }

  // Validate the parsed object
  const checks = validateCardObject(parsed!);
  const allPassed = checks.every((c) => c.passed);
  const passCount = checks.filter((c) => c.passed).length;
  const failCount = checks.filter((c) => !c.passed).length;

  console.log(fmt.header("Card Validation Report"));
  console.log();
  console.log(fmt.label("  File:", ` ${filePath}`));
  console.log(fmt.label("  Format:", ` ${format!.toUpperCase()}`));
  console.log();

  for (const check of checks) {
    if (check.passed) {
      console.log(fmt.success(`${check.name}: ${check.message}`));
    } else {
      console.log(fmt.error(`${check.name}: ${check.message}`));
    }
  }

  console.log();

  if (allPassed) {
    console.log(fmt.success(`All ${passCount} checks passed`) + "\n");
  } else {
    console.log(fmt.error(`${failCount} check(s) failed, ${passCount} passed`) + "\n");
    process.exit(1);
  }
}
