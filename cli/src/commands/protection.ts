import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { spawnSync } from "node:child_process";
import yaml from "js-yaml";
import { configExists, requireAgent } from "../lib/config.js";
import {
  getProtectionCard,
  putProtectionCard,
} from "../lib/api.js";
import { requireAuth } from "../lib/auth.js";
import { fmt } from "../lib/format.js";
import { askYesNo, isInteractive } from "../lib/prompt.js";

// ============================================================================
// Protection card validation
// ============================================================================

export interface ValidationCheck {
  name: string;
  passed: boolean;
  message: string;
}

const VALID_MODES = new Set(["observe", "warn", "block"]);

/**
 * Validate a protection card object.
 * Schema: mode, thresholds, screen_surfaces, trusted_sources
 */
export function validateProtectionCard(card: Record<string, unknown>): ValidationCheck[] {
  const checks: ValidationCheck[] = [];

  // mode: required, must be observe | warn | block
  const mode = card.mode;
  if (typeof mode === "string" && VALID_MODES.has(mode)) {
    checks.push({ name: "mode", passed: true, message: mode });
  } else if (mode === undefined) {
    checks.push({ name: "mode", passed: false, message: "Required (observe | warn | block)" });
  } else {
    checks.push({ name: "mode", passed: false, message: `Invalid: "${mode}". Must be observe | warn | block` });
  }

  // thresholds: optional, if present must have warn/quarantine/block in ascending order (0-1)
  const thresholds = card.thresholds as Record<string, unknown> | undefined;
  if (thresholds !== undefined) {
    if (typeof thresholds !== "object" || thresholds === null) {
      checks.push({ name: "thresholds", passed: false, message: "Must be an object" });
    } else {
      const w = thresholds.warn as number | undefined;
      const q = thresholds.quarantine as number | undefined;
      const b = thresholds.block as number | undefined;

      if (w === undefined || q === undefined || b === undefined) {
        checks.push({ name: "thresholds", passed: false, message: "Must have warn, quarantine, and block fields" });
      } else if (typeof w !== "number" || typeof q !== "number" || typeof b !== "number") {
        checks.push({ name: "thresholds", passed: false, message: "Values must be numbers" });
      } else if (w < 0 || w > 1 || q < 0 || q > 1 || b < 0 || b > 1) {
        checks.push({ name: "thresholds", passed: false, message: "Values must be between 0 and 1" });
      } else if (!(w <= q && q <= b)) {
        checks.push({ name: "thresholds", passed: false, message: `Must be in ascending order (warn=${w} <= quarantine=${q} <= block=${b})` });
      } else {
        checks.push({ name: "thresholds", passed: true, message: `warn=${w}, quarantine=${q}, block=${b}` });
      }
    }
  }

  // screen_surfaces: optional, array of strings
  const surfaces = card.screen_surfaces;
  if (surfaces !== undefined) {
    if (!Array.isArray(surfaces)) {
      checks.push({ name: "screen_surfaces", passed: false, message: "Must be an array" });
    } else if (surfaces.some((s: unknown) => typeof s !== "string")) {
      checks.push({ name: "screen_surfaces", passed: false, message: "All entries must be strings" });
    } else {
      checks.push({ name: "screen_surfaces", passed: true, message: `${surfaces.length} surface(s)` });
    }
  }

  // trusted_sources: optional, array of objects
  const trusted = card.trusted_sources;
  if (trusted !== undefined) {
    if (!Array.isArray(trusted)) {
      checks.push({ name: "trusted_sources", passed: false, message: "Must be an array" });
    } else {
      checks.push({ name: "trusted_sources", passed: true, message: `${trusted.length} source(s)` });
    }
  }

  return checks;
}

// ============================================================================
// File parsing
// ============================================================================

function parseProtectionFile(filePath: string): { parsed: Record<string, unknown>; raw: string; format: "yaml" | "json" } {
  const raw = fs.readFileSync(filePath, "utf-8");
  const ext = path.extname(filePath).toLowerCase();
  const format = (ext === ".yaml" || ext === ".yml") ? "yaml" as const : "json" as const;

  if (format === "yaml") {
    const parsed = yaml.load(raw) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object") {
      throw new Error("YAML did not produce a valid object");
    }
    return { parsed, raw, format };
  }

  return { parsed: JSON.parse(raw), raw, format };
}

// ============================================================================
// Subcommands
// ============================================================================

export async function protectionShowCommand(agentName?: string): Promise<void> {
  if (!configExists()) {
    console.log("\n" + fmt.error("mnemom is not configured") + "\n");
    console.log("Run `mnemom register <name>` to get started.\n");
    process.exit(1);
  }

  const agent = await requireAgent(agentName);

  console.log("\nFetching protection card...\n");

  try {
    const { body, contentType } = await getProtectionCard(agent.agentId);

    if (!body) {
      console.log(fmt.warn("No protection card found"));
      console.log("\nPublish one with:\n");
      console.log("  mnemom protection publish <file.yaml>\n");
      return;
    }

    if (contentType.includes("yaml") || contentType.includes("text/yaml")) {
      console.log(fmt.header("Protection Card"));
      console.log();
      console.log(body);
    } else {
      const parsed = JSON.parse(body);
      console.log(fmt.header("Protection Card"));
      console.log();
      console.log(yaml.dump(parsed, { lineWidth: 120, noRefs: true }));
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to fetch protection card: ${message}`) + "\n");
    process.exit(1);
  }
}

export async function protectionPublishCommand(file: string, agentName?: string): Promise<void> {
  if (!configExists()) {
    console.log("\n" + fmt.error("mnemom is not configured") + "\n");
    console.log("Run `mnemom register <name>` to get started.\n");
    process.exit(1);
  }

  const agent = await requireAgent(agentName);

  const filePath = path.resolve(file);
  if (!fs.existsSync(filePath)) {
    console.log("\n" + fmt.error(`File not found: ${filePath}`) + "\n");
    process.exit(1);
  }

  let parsed: { parsed: Record<string, unknown>; raw: string; format: "yaml" | "json" };
  try {
    parsed = parseProtectionFile(filePath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Could not parse file: ${msg}`) + "\n");
    process.exit(1);
  }

  // Validate locally
  const checks = validateProtectionCard(parsed!.parsed);
  const allPassed = checks.every((c) => c.passed);

  console.log(fmt.header("Protection Card Validation"));
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

  await requireAuth();

  if (isInteractive()) {
    const confirm = await askYesNo(
      `Publish this protection card for agent ${agent.agentId}?`,
      false,
    );
    if (!confirm) {
      console.log("\nPublish cancelled.\n");
      return;
    }
  }

  try {
    console.log("\nPublishing protection card...");
    const contentType = parsed!.format === "yaml" ? "text/yaml" as const : "application/json" as const;
    const body = parsed!.format === "yaml" ? parsed!.raw : JSON.stringify(parsed!.parsed);
    const result = await putProtectionCard(agent.agentId, body, contentType);
    console.log(fmt.success("Protection card published!"));
    console.log(fmt.label("  Card ID:", ` ${result.card_id}`));
    if (result.composed) {
      console.log(fmt.success("Canonical protection card recomposed"));
    }
    console.log();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to publish protection card: ${message}`) + "\n");
    process.exit(1);
  }
}

export async function protectionValidateCommand(file: string): Promise<void> {
  const filePath = path.resolve(file);
  if (!fs.existsSync(filePath)) {
    console.log("\n" + fmt.error(`File not found: ${filePath}`) + "\n");
    process.exit(1);
  }

  let parsed: { parsed: Record<string, unknown>; format: "yaml" | "json" };
  try {
    parsed = parseProtectionFile(filePath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Could not parse file: ${msg}`) + "\n");
    process.exit(1);
  }

  const checks = validateProtectionCard(parsed!.parsed);
  const allPassed = checks.every((c) => c.passed);
  const passCount = checks.filter((c) => c.passed).length;
  const failCount = checks.filter((c) => !c.passed).length;

  console.log(fmt.header("Protection Card Validation Report"));
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

export async function protectionEditCommand(agentName?: string): Promise<void> {
  if (!configExists()) {
    console.log("\n" + fmt.error("mnemom is not configured") + "\n");
    console.log("Run `mnemom register <name>` to get started.\n");
    process.exit(1);
  }

  const agent = await requireAgent(agentName);
  await requireAuth();

  console.log("\nFetching current protection card...\n");
  const { body: original } = await getProtectionCard(agent.agentId);

  if (!original) {
    console.log(fmt.warn("No protection card found. Creating a template..."));
  }

  const cardYaml = original || yaml.dump({
    mode: "observe",
    thresholds: { warn: 0.3, quarantine: 0.6, block: 0.9 },
    screen_surfaces: ["system_prompt", "tool_input", "tool_output"],
    trusted_sources: [],
  }, { lineWidth: 120, noRefs: true });

  const tmpDir = os.tmpdir();
  const tmpFile = path.join(tmpDir, `mnemom-protection-${agent.agentId}.yaml`);
  fs.writeFileSync(tmpFile, cardYaml);

  const editor = process.env.EDITOR || process.env.VISUAL || "vi";
  console.log(`Opening ${editor}...`);
  const result = spawnSync(editor, [tmpFile], { stdio: "inherit" });

  if (result.status !== 0) {
    console.log("\n" + fmt.error("Editor exited with an error") + "\n");
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
    process.exit(1);
  }

  const edited = fs.readFileSync(tmpFile, "utf-8");
  try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }

  if (edited === cardYaml) {
    console.log("\nNo changes made.\n");
    return;
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = yaml.load(edited) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object") throw new Error("Invalid YAML");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Invalid YAML: ${msg}`) + "\n");
    process.exit(1);
  }

  const checks = validateProtectionCard(parsed);
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

  if (isInteractive()) {
    const confirm = await askYesNo("Publish updated protection card?", true);
    if (!confirm) {
      console.log("\nPublish cancelled.\n");
      return;
    }
  }

  try {
    console.log("\nPublishing protection card...");
    const putResult = await putProtectionCard(agent.agentId, edited, "text/yaml");
    console.log(fmt.success("Protection card published!"));
    console.log(fmt.label("  Card ID:", ` ${putResult.card_id}`) + "\n");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to publish protection card: ${message}`) + "\n");
    process.exit(1);
  }
}
