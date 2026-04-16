import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { spawnSync } from "node:child_process";
import yaml from "js-yaml";
import {
  getAlignmentCard,
  putAlignmentCard,
  resolveAgentId,
} from "../lib/api.js";
import { requireAuth } from "../lib/auth.js";
import { fmt } from "../lib/format.js";
import { askYesNo, isInteractive } from "../lib/prompt.js";
import {
  evaluatePolicy,
  type EvaluationResult,
} from "@mnemom/policy-engine";

// ============================================================================
// File parsing
// ============================================================================

export type CardFormat = "json" | "yaml";

export interface ParsedCard {
  format: CardFormat;
  parsed: Record<string, unknown>;
  raw: string;
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
    const parsed = yaml.load(raw) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object") {
      throw new Error("YAML did not produce a valid object");
    }
    return { format, parsed, raw };
  }

  return { format, parsed: JSON.parse(raw) as Record<string, unknown>, raw };
}

// ============================================================================
// Unified card validation (ADR-008 schema)
// ============================================================================

export interface ValidationCheck {
  name: string;
  passed: boolean;
  message: string;
}

// Standard AAP values that do not require custom definitions
const STANDARD_VALUES = new Set([
  "transparency", "honesty", "safety", "privacy", "fairness",
  "accountability", "beneficence", "non-maleficence", "autonomy",
  "justice", "reliability", "security", "human_oversight", "explainability",
]);

/**
 * Validate a unified alignment card object against ADR-008 schema.
 * Sections: principal, values, conscience, integrity, autonomy,
 *           capabilities, enforcement, audit, extensions
 */
export function validateUnifiedCard(card: Record<string, unknown>): ValidationCheck[] {
  const checks: ValidationCheck[] = [];

  // Required sections
  const requiredSections = ["principal", "values", "autonomy"] as const;
  for (const section of requiredSections) {
    if (card[section] && typeof card[section] === "object") {
      checks.push({ name: `Section: ${section}`, passed: true, message: "Present" });
    } else {
      checks.push({ name: `Section: ${section}`, passed: false, message: "Missing or invalid" });
    }
  }

  // Optional sections — validate shape if present
  const optionalSections = ["conscience", "integrity", "capabilities", "enforcement", "audit", "extensions"] as const;
  for (const section of optionalSections) {
    if (card[section] !== undefined) {
      if (typeof card[section] === "object" && card[section] !== null) {
        checks.push({ name: `Section: ${section}`, passed: true, message: "Present" });
      } else {
        checks.push({ name: `Section: ${section}`, passed: false, message: "Must be an object" });
      }
    }
  }

  // values.declared is non-empty array
  const values = card.values as Record<string, unknown> | undefined;
  const declared = values?.declared;
  if (Array.isArray(declared) && declared.length > 0) {
    checks.push({
      name: "values.declared",
      passed: true,
      message: `${declared.length} value(s) declared`,
    });
  } else if (values) {
    checks.push({
      name: "values.declared",
      passed: false,
      message: "Must be a non-empty array",
    });
  }

  // Custom values need definitions
  if (Array.isArray(declared)) {
    const definitions = (values?.definitions ?? {}) as Record<string, string>;
    const customValues = declared.filter((v: string) => !STANDARD_VALUES.has(v));
    const missingDefs = customValues.filter((v: string) => !definitions[v]);

    if (missingDefs.length === 0) {
      checks.push({
        name: "Custom value definitions",
        passed: true,
        message: customValues.length === 0
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

  // autonomy.bounded_actions is non-empty
  const autonomy = card.autonomy as Record<string, unknown> | undefined;
  const bounded = autonomy?.bounded_actions;
  if (Array.isArray(bounded) && bounded.length > 0) {
    checks.push({
      name: "autonomy.bounded_actions",
      passed: true,
      message: `${bounded.length} bounded action(s)`,
    });
  } else if (autonomy) {
    checks.push({
      name: "autonomy.bounded_actions",
      passed: false,
      message: "Must be a non-empty array",
    });
  }

  // capabilities shape validation (if present)
  const capabilities = card.capabilities as Record<string, unknown> | undefined;
  if (capabilities && typeof capabilities === "object") {
    for (const [name, mapping] of Object.entries(capabilities)) {
      const m = mapping as Record<string, unknown>;
      if (!Array.isArray(m?.tools)) {
        checks.push({
          name: `capabilities.${name}.tools`,
          passed: false,
          message: "Must be an array",
        });
      }
      if (!Array.isArray(m?.required_actions)) {
        checks.push({
          name: `capabilities.${name}.required_actions`,
          passed: false,
          message: "Must be an array",
        });
      }
    }
  }

  // enforcement.forbidden_tools shape validation (if present)
  const enforcement = card.enforcement as Record<string, unknown> | undefined;
  const forbidden = enforcement?.forbidden_tools;
  if (Array.isArray(forbidden)) {
    for (let i = 0; i < forbidden.length; i++) {
      const rule = forbidden[i] as Record<string, unknown>;
      if (!rule?.pattern || !rule?.reason) {
        checks.push({
          name: `enforcement.forbidden_tools[${i}]`,
          passed: false,
          message: "Must have 'pattern' and 'reason' fields",
        });
      }
    }
  }

  return checks;
}

/** @deprecated Use validateUnifiedCard instead */
export const validateCardJson = (raw: string) => validateUnifiedCard(JSON.parse(raw));

// ============================================================================
// Subcommands
// ============================================================================

export async function cardShowCommand(agentName?: string): Promise<void> {
  const agentId = await resolveAgentId(agentName);

  console.log("\nFetching alignment card...\n");

  try {
    const { body, contentType } = await getAlignmentCard(agentId);

    if (!body) {
      console.log(fmt.warn("No alignment card found"));
      console.log("\nPublish one with:\n");
      console.log("  mnemom card publish <file.yaml>\n");
      return;
    }

    // If the API returned YAML, print directly; otherwise convert
    if (contentType.includes("yaml") || contentType.includes("text/yaml")) {
      console.log(fmt.header("Alignment Card"));
      console.log();
      console.log(body);
    } else {
      // JSON response — convert to YAML for display
      const parsed = JSON.parse(body);
      console.log(fmt.header("Alignment Card"));
      console.log();
      console.log(yaml.dump(parsed, { lineWidth: 120, noRefs: true }));
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to fetch card: ${message}`) + "\n");
    process.exit(1);
  }
}

export async function cardPublishCommand(file: string, agentName?: string): Promise<void> {
  const agentId = await resolveAgentId(agentName);

  // Resolve file path
  const filePath = path.resolve(file);
  if (!fs.existsSync(filePath)) {
    console.log("\n" + fmt.error(`File not found: ${filePath}`) + "\n");
    process.exit(1);
  }

  // Parse file (JSON or YAML)
  let parsed: ParsedCard;
  try {
    parsed = parseCardFile(filePath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Could not parse file: ${msg}`) + "\n");
    process.exit(1);
  }

  // Validate locally
  const checks = validateUnifiedCard(parsed!.parsed);
  const allPassed = checks.every((c) => c.passed);

  console.log(fmt.header("Card Validation"));
  console.log(fmt.label("  Format:", ` ${parsed!.format.toUpperCase()}`));
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
      `Publish this alignment card for agent ${agentId}?`,
      false,
    );
    if (!confirm) {
      console.log("\nPublish cancelled.\n");
      return;
    }
  }

  // Publish — send in source format
  try {
    console.log("\nPublishing alignment card...");
    const contentType = parsed!.format === "yaml" ? "text/yaml" as const : "application/json" as const;
    const body = parsed!.format === "yaml" ? parsed!.raw : JSON.stringify(parsed!.parsed);
    const result = await putAlignmentCard(agentId, body, contentType);
    console.log(fmt.success("Alignment card published!"));
    console.log(fmt.label("  Card ID:", ` ${result.card_id}`));
    if (result.composed) {
      console.log(fmt.success("Canonical card recomposed"));
    }
    console.log();
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
  let parsed: ParsedCard;
  try {
    parsed = parseCardFile(filePath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Could not parse file: ${msg}`) + "\n");
    process.exit(1);
  }

  // Validate the parsed object
  const checks = validateUnifiedCard(parsed!.parsed);
  const allPassed = checks.every((c) => c.passed);
  const passCount = checks.filter((c) => c.passed).length;
  const failCount = checks.filter((c) => !c.passed).length;

  console.log(fmt.header("Card Validation Report"));
  console.log();
  console.log(fmt.label("  File:", ` ${filePath}`));
  console.log(fmt.label("  Format:", ` ${parsed!.format.toUpperCase()}`));
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

export async function cardEditCommand(agentName?: string): Promise<void> {
  const agentId = await resolveAgentId(agentName);
  await requireAuth();

  // Fetch current card as YAML
  console.log("\nFetching current alignment card...\n");
  const { body: original } = await getAlignmentCard(agentId);

  if (!original) {
    console.log(fmt.warn("No alignment card found. Creating a template..."));
  }

  const cardYaml = original || yaml.dump({
    principal: { name: "", type: "ai_agent", organization: "" },
    values: { declared: ["transparency", "safety", "honesty"] },
    autonomy: { bounded_actions: [], forbidden_actions: [], escalation_triggers: [] },
  }, { lineWidth: 120, noRefs: true });

  // Write to temp file
  const tmpDir = os.tmpdir();
  const tmpFile = path.join(tmpDir, `mnemom-card-${agentId}.yaml`);
  fs.writeFileSync(tmpFile, cardYaml);

  // Open in editor
  const editor = process.env.EDITOR || process.env.VISUAL || "vi";
  console.log(`Opening ${editor}...`);
  const result = spawnSync(editor, [tmpFile], { stdio: "inherit" });

  if (result.status !== 0) {
    console.log("\n" + fmt.error("Editor exited with an error") + "\n");
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
    process.exit(1);
  }

  // Read back and compare
  const edited = fs.readFileSync(tmpFile, "utf-8");
  try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }

  if (edited === cardYaml) {
    console.log("\nNo changes made.\n");
    return;
  }

  // Validate
  let parsed: Record<string, unknown>;
  try {
    parsed = yaml.load(edited) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object") throw new Error("Invalid YAML");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Invalid YAML: ${msg}`) + "\n");
    process.exit(1);
  }

  const checks = validateUnifiedCard(parsed);
  const allPassed = checks.every((c) => c.passed);

  if (!allPassed) {
    console.log(fmt.header("Validation Errors"));
    console.log();
    for (const check of checks.filter((c) => !c.passed)) {
      console.log(fmt.error(`${check.name}: ${check.message}`));
    }
    console.log();
    console.log(fmt.error("Validation failed. Card not published.") + "\n");
    process.exit(1);
  }

  // Confirm and publish
  if (isInteractive()) {
    const confirm = await askYesNo("Publish updated alignment card?", true);
    if (!confirm) {
      console.log("\nPublish cancelled.\n");
      return;
    }
  }

  try {
    console.log("\nPublishing alignment card...");
    const putResult = await putAlignmentCard(agentId, edited, "text/yaml");
    console.log(fmt.success("Alignment card published!"));
    console.log(fmt.label("  Card ID:", ` ${putResult.card_id}`) + "\n");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to publish card: ${message}`) + "\n");
    process.exit(1);
  }
}

/**
 * mnemom card evaluate <card-file> --tools <tools> -- local CI/CD evaluation
 *
 * Runs entirely locally using the embedded policy engine. No API key needed.
 * The card IS the policy source -- capabilities and enforcement sections
 * are extracted by @mnemom/policy-engine 0.3.0's evaluatePolicy().
 */
export async function cardEvaluateCommand(
  file: string,
  options: { tools?: string; toolManifest?: string; strict?: boolean },
): Promise<void> {
  // 1. Read + validate card file
  const cardPath = path.resolve(file);
  if (!fs.existsSync(cardPath)) {
    console.log("\n" + fmt.error(`Card file not found: ${cardPath}`) + "\n");
    process.exit(1);
  }

  let parsed: ParsedCard;
  try {
    parsed = parseCardFile(cardPath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Could not parse card file: ${msg}`) + "\n");
    process.exit(1);
  }

  const checks = validateUnifiedCard(parsed!.parsed);
  const allPassed = checks.every((c) => c.passed);
  if (!allPassed) {
    console.log(fmt.error("Card validation failed:"));
    for (const check of checks.filter((c) => !c.passed)) {
      console.log(fmt.error(`  ${check.name}: ${check.message}`));
    }
    console.log();
    process.exit(1);
  }

  // 2. Parse tool list from --tools or --tool-manifest
  let tools: { name: string }[] = [];
  if (options.tools) {
    tools = options.tools.split(",").map((t) => ({ name: t.trim() })).filter((t) => t.name);
  } else if (options.toolManifest) {
    const manifestPath = path.resolve(options.toolManifest);
    if (!fs.existsSync(manifestPath)) {
      console.log("\n" + fmt.error(`Tool manifest file not found: ${manifestPath}`) + "\n");
      process.exit(1);
    }
    try {
      const manifestRaw = fs.readFileSync(manifestPath, "utf-8");
      const manifest = JSON.parse(manifestRaw);
      if (Array.isArray(manifest)) {
        tools = manifest.map((t: string | { name: string }) =>
          typeof t === "string" ? { name: t } : { name: t.name },
        );
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.log("\n" + fmt.error(`Could not read tool manifest: ${msg}`) + "\n");
      process.exit(1);
    }
  }

  if (tools.length === 0) {
    console.log("\n" + fmt.error("No tools specified. Use --tools or --tool-manifest") + "\n");
    process.exit(1);
  }

  // 3. Run evaluation -- card IS the policy source
  const result: EvaluationResult = evaluatePolicy({
    context: "cicd",
    card: parsed!.parsed as Parameters<typeof evaluatePolicy>[0]["card"],
    tools,
  });

  // 4. Display results
  console.log(fmt.header("Card Policy Evaluation"));
  console.log();
  const principal = parsed!.parsed.principal as Record<string, unknown> | undefined;
  console.log(fmt.label("  Card:", ` ${principal?.name ?? path.basename(cardPath)}`));
  console.log(fmt.label("  Context:", " cicd"));
  console.log(fmt.label("  Tools:", ` ${tools.length} (${tools.map((t) => t.name).join(", ")})`));
  console.log();

  // Verdict
  if (result.verdict === "pass") {
    console.log(fmt.success("PASS -- all tools comply with card policy"));
  } else if (result.verdict === "warn") {
    console.log(fmt.warn("WARN -- policy warnings detected"));
  } else {
    console.log(fmt.error("FAIL -- policy violations detected"));
  }
  console.log();

  // Violations
  if (result.violations.length > 0) {
    console.log(fmt.section("Violations"));
    console.log();
    for (const v of result.violations) {
      console.log(fmt.error(`  ${v.tool} [${v.severity}] -- ${v.type}`));
      console.log(`    ${v.reason}`);
    }
  }

  // Warnings
  if (result.warnings.length > 0) {
    console.log(fmt.section("Warnings"));
    console.log();
    for (const w of result.warnings) {
      console.log(fmt.warn(`  ${w.tool} -- ${w.type}`));
      console.log(`    ${w.reason}`);
    }
  }

  // Coverage
  const cov = result.coverage;
  console.log(fmt.section("Coverage"));
  console.log();
  console.log(fmt.label("  Card actions:", ` ${cov.total_card_actions}`));
  console.log(fmt.label("  Mapped:      ", ` ${cov.mapped_card_actions.length}`));
  console.log(fmt.label("  Unmapped:    ", ` ${cov.unmapped_card_actions.length}`));
  console.log(fmt.label("  Coverage:    ", ` ${cov.coverage_pct.toFixed(1)}%`));
  if (cov.unmapped_card_actions.length > 0) {
    console.log(fmt.label("  Unmapped list:", ` ${cov.unmapped_card_actions.join(", ")}`));
  }

  console.log();
  console.log(fmt.label("  Duration:", ` ${result.duration_ms}ms`));
  console.log();

  // 5. Exit code
  if (result.verdict === "fail") {
    process.exit(1);
  }
  if (options.strict && result.verdict === "warn") {
    process.exit(1);
  }
}
