import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { spawnSync } from "node:child_process";
import yaml from "js-yaml";
import {
  PROTECTION_CARD_MAX_BYTES,
  getProtectionCard,
  putProtectionCard,
  resolveAgentId,
} from "../lib/api.js";
import { requireAuth } from "../lib/auth.js";
import { fmt } from "../lib/format.js";
import { askYesNo, isInteractive } from "../lib/prompt.js";

// ============================================================================
// Protection card validation (ADR-037 canonical form)
//
// This validator mirrors the platform's authoritative rules in
// mnemom-api/src/composition/validate.ts:validateUnifiedProtectionCard. The two
// codebases live in different repos so we keep this hand-rolled copy in sync
// rather than depending on a shared package — a candidate for extraction once
// the validator stabilises (TODO: shared/composition-validators package).
// ============================================================================

export interface ValidationCheck {
  name: string;
  passed: boolean;
  message: string;
}

const PROTECTION_MODES = ["off", "observe", "nudge", "enforce"] as const;
const SURFACE_KEYS = ["incoming", "outgoing", "tool_calls", "tool_responses"] as const;

// Per ADR-037 Decision 4: deny public LLM endpoints + public DNS providers,
// and the any-host CIDRs, at write time.
const DENY_DOMAINS = new Set([
  "api.openai.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "api.cohere.ai",
  "api.mistral.ai",
  "api.groq.com",
  "cloud.google.com",
  "dns.google",
  "cloudflare-dns.com",
  "one.one.one.one",
  "dns.quad9.net",
]);
const DENY_IP_PREFIXES = [
  "0.0.0.0/0",
  "::/0",
  "8.8.8.0/24",
  "8.8.4.0/24",
  "1.1.1.0/24",
  "1.0.0.0/24",
  "9.9.9.0/24",
];

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:\d{1,5})?$/i;
const AGENT_ID_RE = /^mnm-[a-z0-9-]{4,}$/i;
const CIDR_RE = /^([0-9]{1,3}(\.[0-9]{1,3}){3})\/([0-9]|[12][0-9]|3[0-2])$|^([0-9a-f:]+)\/(\d{1,3})$/i;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function validateDomain(d: string): string | null {
  const lower = d.toLowerCase();
  if (DENY_DOMAINS.has(lower.split(":")[0])) {
    return "domain is on the static deny-list (public LLM/DNS endpoint)";
  }
  if (!DOMAIN_RE.test(lower)) return "not a valid DNS name (or host:port)";
  return null;
}

function validateAgentId(a: string): string | null {
  if (!AGENT_ID_RE.test(a)) return "must match Mnemom agent ID format (mnm-*)";
  return null;
}

function validateCidr(c: string): string | null {
  if (DENY_IP_PREFIXES.includes(c)) {
    return "CIDR is on the static deny-list (public DNS / 0.0.0.0/0 / ::/0)";
  }
  if (!CIDR_RE.test(c)) return "not a valid CIDR notation";
  return null;
}

function validateTrustedBucket(
  name: string,
  bucket: unknown,
  checks: ValidationCheck[],
  perEntry: (entry: string) => string | null,
): void {
  if (bucket === undefined) return;
  if (!Array.isArray(bucket)) {
    checks.push({
      name: `trusted_sources.${name}`,
      passed: false,
      message: `Must be an array of strings (got ${typeof bucket}). Per ADR-037 trusted_sources is an object of typed buckets — not an array of objects.`,
    });
    return;
  }
  let bad = 0;
  bucket.forEach((entry, i) => {
    if (typeof entry !== "string") {
      checks.push({
        name: `trusted_sources.${name}[${i}]`,
        passed: false,
        message: "Must be a string",
      });
      bad++;
      return;
    }
    const err = perEntry(entry);
    if (err) {
      checks.push({
        name: `trusted_sources.${name}[${i}]`,
        passed: false,
        message: `${entry}: ${err}`,
      });
      bad++;
    }
  });
  if (bad === 0) {
    checks.push({
      name: `trusted_sources.${name}`,
      passed: true,
      message: `${bucket.length} entr${bucket.length === 1 ? "y" : "ies"}`,
    });
  }
}

/**
 * Validate a protection card against ADR-037 canonical form.
 *
 * Required: card_version, agent_id, mode (off|observe|nudge|enforce).
 * Optional: thresholds (warn ≤ quarantine ≤ block, all in [0,1]),
 *           screen_surfaces (object of bools with the four named keys),
 *           trusted_sources (object of typed buckets, per-bucket deny-lists).
 */
export function validateProtectionCard(card: Record<string, unknown>): ValidationCheck[] {
  const checks: ValidationCheck[] = [];

  // ── card_version (required) ──
  if (typeof card.card_version !== "string" || card.card_version.length === 0) {
    checks.push({
      name: "card_version",
      passed: false,
      message: 'Required (string, e.g. "protection/2026-04-26"). See ADR-037.',
    });
  } else {
    checks.push({ name: "card_version", passed: true, message: card.card_version });
  }

  // ── agent_id (required) ──
  if (typeof card.agent_id !== "string" || card.agent_id.length === 0) {
    checks.push({
      name: "agent_id",
      passed: false,
      message: "Required (string).",
    });
  } else {
    checks.push({ name: "agent_id", passed: true, message: card.agent_id });
  }

  // ── mode (required, ADR-037 canonical enum) ──
  const mode = card.mode;
  if (typeof mode !== "string") {
    checks.push({
      name: "mode",
      passed: false,
      message: `Required. Must be one of: ${PROTECTION_MODES.join(" | ")}. Per ADR-037 the legacy "block"/"warn" values are no longer accepted.`,
    });
  } else if (!(PROTECTION_MODES as readonly string[]).includes(mode)) {
    checks.push({
      name: "mode",
      passed: false,
      message: `Invalid: "${mode}". Must be one of: ${PROTECTION_MODES.join(" | ")}. (Per ADR-037 the legacy "block"/"warn" values are no longer accepted; use "enforce"/"nudge".)`,
    });
  } else {
    checks.push({ name: "mode", passed: true, message: mode });
  }

  // ── thresholds (optional) ──
  if (card.thresholds !== undefined) {
    if (!isObject(card.thresholds)) {
      checks.push({ name: "thresholds", passed: false, message: "Must be an object if present" });
    } else {
      const t = card.thresholds as Record<string, unknown>;
      const nums: Record<string, number | undefined> = {};
      let bad = false;
      for (const key of ["warn", "quarantine", "block"] as const) {
        const v = t[key];
        if (v === undefined) {
          checks.push({
            name: `thresholds.${key}`,
            passed: false,
            message: "Required when thresholds is present",
          });
          bad = true;
          continue;
        }
        if (typeof v !== "number" || v < 0 || v > 1 || Number.isNaN(v)) {
          checks.push({
            name: `thresholds.${key}`,
            passed: false,
            message: "Must be a number in [0, 1]",
          });
          bad = true;
          continue;
        }
        nums[key] = v;
      }
      if (nums.warn !== undefined && nums.quarantine !== undefined && nums.warn > nums.quarantine) {
        checks.push({
          name: "thresholds.warn",
          passed: false,
          message: `Must be ≤ thresholds.quarantine (warn=${nums.warn} > quarantine=${nums.quarantine})`,
        });
        bad = true;
      }
      if (nums.quarantine !== undefined && nums.block !== undefined && nums.quarantine > nums.block) {
        checks.push({
          name: "thresholds.quarantine",
          passed: false,
          message: `Must be ≤ thresholds.block (quarantine=${nums.quarantine} > block=${nums.block})`,
        });
        bad = true;
      }
      if (!bad) {
        checks.push({
          name: "thresholds",
          passed: true,
          message: `warn=${nums.warn}, quarantine=${nums.quarantine}, block=${nums.block}`,
        });
      }
    }
  }

  // ── screen_surfaces (optional, object of bools) ──
  if (card.screen_surfaces !== undefined) {
    if (Array.isArray(card.screen_surfaces)) {
      checks.push({
        name: "screen_surfaces",
        passed: false,
        message: 'Must be an object of booleans, not an array. Per ADR-037 use { incoming: true, outgoing: true, tool_calls: true, tool_responses: true }.',
      });
    } else if (!isObject(card.screen_surfaces)) {
      checks.push({ name: "screen_surfaces", passed: false, message: "Must be an object if present" });
    } else {
      const s = card.screen_surfaces as Record<string, unknown>;
      let bad = false;
      for (const key of SURFACE_KEYS) {
        const v = s[key];
        if (v !== undefined && typeof v !== "boolean") {
          checks.push({
            name: `screen_surfaces.${key}`,
            passed: false,
            message: "Must be a boolean",
          });
          bad = true;
        }
      }
      for (const key of Object.keys(s)) {
        if (!(SURFACE_KEYS as readonly string[]).includes(key)) {
          checks.push({
            name: `screen_surfaces.${key}`,
            passed: false,
            message: `Unknown surface (allowed: ${SURFACE_KEYS.join(", ")})`,
          });
          bad = true;
        }
      }
      if (!bad) {
        const enabled = SURFACE_KEYS.filter(k => s[k] === true).length;
        checks.push({
          name: "screen_surfaces",
          passed: true,
          message: `${enabled}/${SURFACE_KEYS.length} surfaces enabled`,
        });
      }
    }
  }

  // ── trusted_sources (optional, typed buckets) ──
  if (card.trusted_sources !== undefined) {
    if (Array.isArray(card.trusted_sources)) {
      checks.push({
        name: "trusted_sources",
        passed: false,
        message: 'Must be an object of typed buckets, not an array. Per ADR-037 use { domains: [...], agent_ids: [...], ip_ranges: [...] } — the legacy [{pattern, ...}] shape is no longer accepted.',
      });
    } else if (!isObject(card.trusted_sources)) {
      checks.push({ name: "trusted_sources", passed: false, message: "Must be an object if present" });
    } else {
      const ts = card.trusted_sources as Record<string, unknown>;
      validateTrustedBucket("domains", ts.domains, checks, validateDomain);
      validateTrustedBucket("agent_ids", ts.agent_ids, checks, validateAgentId);
      validateTrustedBucket("ip_ranges", ts.ip_ranges, checks, validateCidr);
      for (const key of Object.keys(ts)) {
        if (!["domains", "agent_ids", "ip_ranges"].includes(key)) {
          checks.push({
            name: `trusted_sources.${key}`,
            passed: false,
            message: "Unknown bucket (allowed: domains, agent_ids, ip_ranges)",
          });
        }
      }
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
  const agentId = await resolveAgentId(agentName);

  console.log("\nFetching protection card...\n");

  try {
    const { body, contentType } = await getProtectionCard(agentId);

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

export async function protectionPublishCommand(
  file: string,
  agentName?: string,
  options: { idempotencyKey?: string } = {},
): Promise<void> {
  const agentId = await resolveAgentId(agentName);

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
      `Publish this protection card for agent ${agentId}?`,
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
    const bodyBytes = Buffer.byteLength(body, "utf-8");
    if (bodyBytes > PROTECTION_CARD_MAX_BYTES) {
      console.log(
        "\n" +
          fmt.error(
            `Protection card is ${bodyBytes} bytes; limit is ${PROTECTION_CARD_MAX_BYTES} bytes (64 KB). The API will return 413.`,
          ) +
          "\n",
      );
      process.exit(1);
    }
    const result = await putProtectionCard(agentId, body, contentType, {
      idempotencyKey: options.idempotencyKey,
    });
    console.log(fmt.success("Protection card published!"));
    if (typeof result.card_id === "string" && result.card_id.length > 0) {
      console.log(fmt.label("  Card ID:", ` ${result.card_id}`));
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

export async function protectionEditCommand(
  agentName?: string,
  options: { idempotencyKey?: string } = {},
): Promise<void> {
  const agentId = await resolveAgentId(agentName);
  await requireAuth();

  console.log("\nFetching current protection card...\n");
  const { body: original } = await getProtectionCard(agentId);

  if (!original) {
    console.log(fmt.warn("No protection card found. Creating a template..."));
  }

  const cardYaml = original || yaml.dump({
    card_version: "protection/2026-04-26",
    agent_id: agentId,
    mode: "observe",
    thresholds: { warn: 0.3, quarantine: 0.6, block: 0.9 },
    screen_surfaces: {
      incoming: true,
      outgoing: true,
      tool_calls: true,
      tool_responses: true,
    },
    trusted_sources: { domains: [], agent_ids: [], ip_ranges: [] },
  }, { lineWidth: 120, noRefs: true });

  const tmpDir = os.tmpdir();
  const tmpFile = path.join(tmpDir, `mnemom-protection-${agentId}.yaml`);
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
    const editedBytes = Buffer.byteLength(edited, "utf-8");
    if (editedBytes > PROTECTION_CARD_MAX_BYTES) {
      console.log(
        "\n" +
          fmt.error(
            `Protection card is ${editedBytes} bytes; limit is ${PROTECTION_CARD_MAX_BYTES} bytes (64 KB). The API will return 413.`,
          ) +
          "\n",
      );
      process.exit(1);
    }
    const putResult = await putProtectionCard(agentId, edited, "text/yaml", {
      idempotencyKey: options.idempotencyKey,
    });
    console.log(fmt.success("Protection card published!"));
    if (typeof putResult.card_id === "string" && putResult.card_id.length > 0) {
      console.log(fmt.label("  Card ID:", ` ${putResult.card_id}`));
    }
    console.log();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to publish protection card: ${message}`) + "\n");
    process.exit(1);
  }
}
