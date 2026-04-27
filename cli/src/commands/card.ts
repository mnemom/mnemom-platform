import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { spawnSync } from "node:child_process";
import yaml from "js-yaml";
import {
  ALIGNMENT_CARD_MAX_BYTES,
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
// Unified alignment-card validation (ADR-039 canonical form)
//
// This validator mirrors the platform's authoritative rules in
// mnemom-api/src/composition/validate.ts:validateUnifiedAlignmentCard. Post
// migration 146 the dual-key window is closed: top-level autonomy_mode +
// integrity_mode are required, and the legacy locations
// (integrity.enforcement_mode, enforcement.{mode, unmapped_tool_action,
// fail_open}, audit.storage, capabilities.<n>.required_actions) are rejected
// with a pointer to the new field name.
//
// The two codebases live in different repos so we keep this hand-rolled copy
// in sync rather than depending on a shared package — a candidate for
// extraction once the validator stabilises (TODO: shared/composition-validators
// package).
// ============================================================================

export interface ValidationCheck {
  name: string;
  passed: boolean;
  message: string;
}

const ALIGNMENT_MODES = ["off", "observe", "nudge", "enforce"] as const;
const PRINCIPAL_TYPES = ["human", "organization", "agent", "unspecified"] as const;
const PRINCIPAL_RELATIONSHIPS = ["delegated_authority", "advisory", "autonomous"] as const;
const VALUE_HIERARCHIES = ["lexicographic", "weighted", "contextual"] as const;
const ESCALATION_ACTIONS = ["escalate", "deny", "log"] as const;
const CONSCIENCE_MODES = ["augment", "replace"] as const;
const CONSCIENCE_VALUE_TYPES = ["BOUNDARY", "FEAR", "COMMITMENT", "BELIEF", "HOPE"] as const;
const CONSCIENCE_SEVERITIES = ["advisory", "mandatory"] as const;
const TAMPER_EVIDENCE = ["append_only", "signed", "merkle"] as const;
const UNMAPPED_SEVERITIES = ["low", "medium", "high", "critical"] as const;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Validate a unified alignment card against ADR-039 canonical form.
 *
 * Required: card_version, agent_id, autonomy_mode, integrity_mode,
 *           principal (with identifier when type != unspecified),
 *           values.declared (non-empty), autonomy.bounded_actions (non-empty,
 *           disjoint from forbidden_actions), audit (retention_days, queryable,
 *           query_endpoint when queryable=true).
 *
 * Rejected legacy locations: integrity.enforcement_mode,
 *   enforcement.{mode, unmapped_tool_action, fail_open}, _composition.
 */
export function validateUnifiedCard(card: Record<string, unknown>): ValidationCheck[] {
  const checks: ValidationCheck[] = [];

  // ── card_version (required) ──
  if (typeof card.card_version !== "string" || card.card_version.length === 0) {
    checks.push({
      name: "card_version",
      passed: false,
      message: 'Required (string, e.g. "unified/2026-04-26").',
    });
  } else {
    checks.push({ name: "card_version", passed: true, message: card.card_version });
  }

  // ── agent_id (required) ──
  if (typeof card.agent_id !== "string" || card.agent_id.length === 0) {
    checks.push({ name: "agent_id", passed: false, message: "Required (string)." });
  } else {
    checks.push({ name: "agent_id", passed: true, message: card.agent_id });
  }

  // ── autonomy_mode (top-level master switch, ADR-039 Decision 1) ──
  if (typeof card.autonomy_mode !== "string") {
    checks.push({
      name: "autonomy_mode",
      passed: false,
      message: `Required (top-level master switch). Must be one of: ${ALIGNMENT_MODES.join(" | ")}. Per ADR-039 the legacy enforcement.mode location is no longer accepted.`,
    });
  } else if (!(ALIGNMENT_MODES as readonly string[]).includes(card.autonomy_mode)) {
    checks.push({
      name: "autonomy_mode",
      passed: false,
      message: `Invalid: "${card.autonomy_mode}". Must be one of: ${ALIGNMENT_MODES.join(" | ")}.`,
    });
  } else {
    checks.push({ name: "autonomy_mode", passed: true, message: card.autonomy_mode });
  }

  // ── integrity_mode (top-level master switch, ADR-039 Decision 1) ──
  if (typeof card.integrity_mode !== "string") {
    checks.push({
      name: "integrity_mode",
      passed: false,
      message: `Required (top-level master switch). Must be one of: ${ALIGNMENT_MODES.join(" | ")}. Per ADR-039 the legacy integrity.enforcement_mode location is no longer accepted.`,
    });
  } else if (!(ALIGNMENT_MODES as readonly string[]).includes(card.integrity_mode)) {
    checks.push({
      name: "integrity_mode",
      passed: false,
      message: `Invalid: "${card.integrity_mode}". Must be one of: ${ALIGNMENT_MODES.join(" | ")}.`,
    });
  } else {
    checks.push({ name: "integrity_mode", passed: true, message: card.integrity_mode });
  }

  // ── ADR-039 cutover: reject legacy locations with a pointer to the new field ──
  const integ = card.integrity as Record<string, unknown> | undefined;
  if (integ && typeof integ === "object" && integ.enforcement_mode !== undefined) {
    checks.push({
      name: "integrity.enforcement_mode",
      passed: false,
      message: "Legacy field rejected. Use top-level integrity_mode instead (ADR-039).",
    });
  }
  const enf = card.enforcement as Record<string, unknown> | undefined;
  if (enf && typeof enf === "object") {
    if (enf.mode !== undefined) {
      checks.push({
        name: "enforcement.mode",
        passed: false,
        message: "Legacy field rejected. Use top-level autonomy_mode instead (ADR-039).",
      });
    }
    if (enf.unmapped_tool_action !== undefined) {
      checks.push({
        name: "enforcement.unmapped_tool_action",
        passed: false,
        message: "Legacy field rejected. Derived from enforcement.allow_unmapped_tools instead (ADR-039).",
      });
    }
    if (enf.fail_open !== undefined) {
      checks.push({
        name: "enforcement.fail_open",
        passed: false,
        message: "Legacy field rejected. fail_open is a runtime safety knob (gateway env config), not a card field (ADR-039).",
      });
    }
  }
  // _composition is system-managed
  if (card._composition !== undefined) {
    checks.push({
      name: "_composition",
      passed: false,
      message: "System-managed field — cannot be set on inbound cards.",
    });
  }

  // ── principal (required: type + relationship; identifier when type != unspecified) ──
  if (!isObj(card.principal)) {
    checks.push({
      name: "principal",
      passed: false,
      message: "Required (object with at least type + relationship).",
    });
  } else {
    const p = card.principal as Record<string, unknown>;
    if (!(PRINCIPAL_TYPES as readonly string[]).includes(String(p.type))) {
      checks.push({
        name: "principal.type",
        passed: false,
        message: `Must be one of: ${PRINCIPAL_TYPES.join(", ")}.`,
      });
    }
    if (!(PRINCIPAL_RELATIONSHIPS as readonly string[]).includes(String(p.relationship))) {
      checks.push({
        name: "principal.relationship",
        passed: false,
        message: `Must be one of: ${PRINCIPAL_RELATIONSHIPS.join(", ")}.`,
      });
    }
    // ADR-039 Decision 10: identifier required when type != unspecified
    if (
      p.type !== "unspecified" &&
      (PRINCIPAL_TYPES as readonly string[]).includes(String(p.type)) &&
      (typeof p.identifier !== "string" || p.identifier.length === 0)
    ) {
      checks.push({
        name: "principal.identifier",
        passed: false,
        message: 'Required when principal.type is not "unspecified" (ADR-039 Decision 10).',
      });
    }
  }

  // ── values.declared (required, non-empty array of strings) ──
  if (!isObj(card.values) || !Array.isArray((card.values as Record<string, unknown>).declared)) {
    checks.push({
      name: "values.declared",
      passed: false,
      message: "Required (non-empty array of strings).",
    });
  } else {
    const v = card.values as Record<string, unknown>;
    const decl = v.declared as unknown[];
    if (decl.length === 0) {
      checks.push({
        name: "values.declared",
        passed: false,
        message: "Must contain at least one value.",
      });
    } else if (!decl.every(s => typeof s === "string")) {
      checks.push({
        name: "values.declared",
        passed: false,
        message: "All entries must be strings.",
      });
    } else {
      checks.push({
        name: "values.declared",
        passed: true,
        message: `${decl.length} value(s) declared`,
      });
    }
    // definitions ⊆ declared (ADR-039 Decision 10)
    if (v.definitions !== undefined) {
      if (!isObj(v.definitions)) {
        checks.push({
          name: "values.definitions",
          passed: false,
          message: "Must be an object keyed by value names.",
        });
      } else {
        const declSet = new Set(decl.filter((s): s is string => typeof s === "string"));
        for (const key of Object.keys(v.definitions)) {
          if (!declSet.has(key)) {
            checks.push({
              name: `values.definitions.${key}`,
              passed: false,
              message: "Definition key not present in values.declared (ADR-039 Decision 10).",
            });
          }
        }
      }
    }
    // hierarchy enum
    if (v.hierarchy !== undefined && !(VALUE_HIERARCHIES as readonly string[]).includes(String(v.hierarchy))) {
      checks.push({
        name: "values.hierarchy",
        passed: false,
        message: `Must be one of: ${VALUE_HIERARCHIES.join(", ")}.`,
      });
    }
  }

  // ── autonomy.bounded_actions (required, non-empty; disjoint from forbidden_actions) ──
  if (!isObj(card.autonomy) || !Array.isArray((card.autonomy as Record<string, unknown>).bounded_actions)) {
    checks.push({
      name: "autonomy.bounded_actions",
      passed: false,
      message: "Required (non-empty array of strings).",
    });
  } else {
    const a = card.autonomy as Record<string, unknown>;
    const bounded = a.bounded_actions as unknown[];
    if (bounded.length === 0) {
      checks.push({
        name: "autonomy.bounded_actions",
        passed: false,
        message: "Must contain at least one action.",
      });
    } else {
      checks.push({
        name: "autonomy.bounded_actions",
        passed: true,
        message: `${bounded.length} bounded action(s)`,
      });
    }
    // Disjoint check (ADR-039 Decision 10)
    if (Array.isArray(a.forbidden_actions)) {
      const forbidden = new Set(
        (a.forbidden_actions as unknown[]).filter((x): x is string => typeof x === "string"),
      );
      const overlap = bounded.filter((x): x is string => typeof x === "string" && forbidden.has(x));
      if (overlap.length > 0) {
        checks.push({
          name: "autonomy.bounded_actions",
          passed: false,
          message: `bounded_actions and forbidden_actions must be disjoint; both contain: ${overlap.join(", ")} (ADR-039 Decision 10).`,
        });
      }
    }
    // escalation_triggers shape (ADR-039 Decision 10)
    if (a.escalation_triggers !== undefined) {
      if (!Array.isArray(a.escalation_triggers)) {
        checks.push({
          name: "autonomy.escalation_triggers",
          passed: false,
          message: "Must be an array (may be empty).",
        });
      } else {
        (a.escalation_triggers as unknown[]).forEach((t, i) => {
          if (!isObj(t)) {
            checks.push({
              name: `autonomy.escalation_triggers[${i}]`,
              passed: false,
              message: "Must be an object.",
            });
            return;
          }
          const tr = t as Record<string, unknown>;
          if (typeof tr.condition !== "string" || tr.condition.length === 0) {
            checks.push({
              name: `autonomy.escalation_triggers[${i}].condition`,
              passed: false,
              message: "Required (string).",
            });
          }
          if (!(ESCALATION_ACTIONS as readonly string[]).includes(String(tr.action))) {
            checks.push({
              name: `autonomy.escalation_triggers[${i}].action`,
              passed: false,
              message: `Must be one of: ${ESCALATION_ACTIONS.join(", ")}.`,
            });
          }
          if (typeof tr.reason !== "string" || tr.reason.length === 0) {
            checks.push({
              name: `autonomy.escalation_triggers[${i}].reason`,
              passed: false,
              message: "Required (string).",
            });
          }
        });
      }
    }
  }

  // ── audit (required: retention_days, queryable; query_endpoint when queryable=true) ──
  if (!isObj(card.audit)) {
    checks.push({
      name: "audit",
      passed: false,
      message: "Required (object with retention_days, queryable, trace_format).",
    });
  } else {
    const a = card.audit as Record<string, unknown>;
    if (typeof a.retention_days !== "number" || a.retention_days < 0) {
      checks.push({
        name: "audit.retention_days",
        passed: false,
        message: "Required (non-negative number).",
      });
    }
    if (typeof a.queryable !== "boolean") {
      checks.push({
        name: "audit.queryable",
        passed: false,
        message: "Required (boolean).",
      });
    }
    if (a.queryable === true && typeof a.query_endpoint !== "string") {
      checks.push({
        name: "audit.query_endpoint",
        passed: false,
        message: "Required when audit.queryable is true.",
      });
    }
    // ADR-039 Decision 7: tamper_evidence enum
    if (a.tamper_evidence !== undefined && a.tamper_evidence !== null) {
      if (!(TAMPER_EVIDENCE as readonly string[]).includes(String(a.tamper_evidence))) {
        checks.push({
          name: "audit.tamper_evidence",
          passed: false,
          message: `Must be one of: ${TAMPER_EVIDENCE.join(", ")}, or null.`,
        });
      }
    }
    // ADR-039 cutover: audit.storage no longer accepted
    if (a.storage !== undefined) {
      checks.push({
        name: "audit.storage",
        passed: false,
        message: "Legacy field rejected. audit.storage is no longer accepted (ADR-039).",
      });
    }
  }

  // ── conscience (optional, BOUNDARY+advisory rejected per ADR-039 Decision 10) ──
  if (card.conscience !== undefined) {
    if (!isObj(card.conscience)) {
      checks.push({
        name: "conscience",
        passed: false,
        message: "Must be an object if present.",
      });
    } else {
      const cns = card.conscience as Record<string, unknown>;
      if (!(CONSCIENCE_MODES as readonly string[]).includes(String(cns.mode))) {
        checks.push({
          name: "conscience.mode",
          passed: false,
          message: `Must be one of: ${CONSCIENCE_MODES.join(", ")}.`,
        });
      }
      if (!Array.isArray(cns.values)) {
        checks.push({
          name: "conscience.values",
          passed: false,
          message: "Must be an array.",
        });
      } else {
        cns.values.forEach((v, i) => {
          if (!isObj(v)) {
            checks.push({
              name: `conscience.values[${i}]`,
              passed: false,
              message: "Must be an object with type + content.",
            });
            return;
          }
          const cv = v as Record<string, unknown>;
          if (!(CONSCIENCE_VALUE_TYPES as readonly string[]).includes(String(cv.type))) {
            checks.push({
              name: `conscience.values[${i}].type`,
              passed: false,
              message: `Must be one of: ${CONSCIENCE_VALUE_TYPES.join(", ")}.`,
            });
          }
          if (typeof cv.content !== "string" || cv.content.length === 0) {
            checks.push({
              name: `conscience.values[${i}].content`,
              passed: false,
              message: "Required (non-empty string).",
            });
          }
          if (cv.severity !== undefined && !(CONSCIENCE_SEVERITIES as readonly string[]).includes(String(cv.severity))) {
            checks.push({
              name: `conscience.values[${i}].severity`,
              passed: false,
              message: `Must be one of: ${CONSCIENCE_SEVERITIES.join(", ")}.`,
            });
          }
          if (cv.type === "BOUNDARY" && cv.severity === "advisory") {
            checks.push({
              name: `conscience.values[${i}]`,
              passed: false,
              message: "BOUNDARY entries cannot have severity=advisory; BOUNDARY is inviolable by definition (ADR-039 Decision 10).",
            });
          }
        });
      }
    }
  }

  // ── enforcement (optional, ADR-039 Decision 3 user-facing knobs) ──
  if (card.enforcement !== undefined) {
    if (!isObj(card.enforcement)) {
      checks.push({
        name: "enforcement",
        passed: false,
        message: "Must be an object if present.",
      });
    } else {
      const e = card.enforcement as Record<string, unknown>;
      if (e.allow_unmapped_tools !== undefined && typeof e.allow_unmapped_tools !== "boolean") {
        checks.push({
          name: "enforcement.allow_unmapped_tools",
          passed: false,
          message: "Must be a boolean.",
        });
      }
      if (e.default_unmapped_severity !== undefined &&
          !(UNMAPPED_SEVERITIES as readonly string[]).includes(String(e.default_unmapped_severity))) {
        checks.push({
          name: "enforcement.default_unmapped_severity",
          passed: false,
          message: `Must be one of: ${UNMAPPED_SEVERITIES.join(", ")}.`,
        });
      }
    }
  }

  // ── capabilities (optional; ADR-039 cutover rejects required_actions) ──
  if (card.capabilities !== undefined) {
    if (!isObj(card.capabilities)) {
      checks.push({
        name: "capabilities",
        passed: false,
        message: "Must be an object if present.",
      });
    } else {
      for (const [name, mapping] of Object.entries(card.capabilities)) {
        if (!isObj(mapping)) {
          checks.push({
            name: `capabilities.${name}`,
            passed: false,
            message: "Must be an object.",
          });
          continue;
        }
        const m = mapping as Record<string, unknown>;
        if (m.tools !== undefined && !Array.isArray(m.tools)) {
          checks.push({
            name: `capabilities.${name}.tools`,
            passed: false,
            message: "Must be an array.",
          });
        }
        if (m.required_actions !== undefined) {
          checks.push({
            name: `capabilities.${name}.required_actions`,
            passed: false,
            message: "Legacy field rejected. capabilities.<n>.required_actions is no longer accepted (ADR-039).",
          });
        }
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

export async function cardPublishCommand(
  file: string,
  agentName?: string,
  options: { idempotencyKey?: string } = {},
): Promise<void> {
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
    const bodyBytes = Buffer.byteLength(body, "utf-8");
    if (bodyBytes > ALIGNMENT_CARD_MAX_BYTES) {
      console.log(
        "\n" +
          fmt.error(
            `Alignment card is ${bodyBytes} bytes; limit is ${ALIGNMENT_CARD_MAX_BYTES} bytes (128 KB). The API will return 413.`,
          ) +
          "\n",
      );
      process.exit(1);
    }
    const result = await putAlignmentCard(agentId, body, contentType, {
      idempotencyKey: options.idempotencyKey,
    });
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

export async function cardEditCommand(
  agentName?: string,
  options: { idempotencyKey?: string } = {},
): Promise<void> {
  const agentId = await resolveAgentId(agentName);
  await requireAuth();

  // Fetch current card as YAML
  console.log("\nFetching current alignment card...\n");
  const { body: original } = await getAlignmentCard(agentId);

  if (!original) {
    console.log(fmt.warn("No alignment card found. Creating a template..."));
  }

  const cardYaml = original || yaml.dump({
    card_version: "unified/2026-04-26",
    agent_id: agentId,
    autonomy_mode: "observe",
    integrity_mode: "observe",
    principal: { type: "agent", identifier: agentId, relationship: "delegated_authority" },
    values: { declared: ["transparency", "safety", "honesty"] },
    autonomy: {
      bounded_actions: ["respond_to_prompts"],
      forbidden_actions: [],
      escalation_triggers: [],
    },
    audit: { retention_days: 30, queryable: false, trace_format: "otel" },
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
    const editedBytes = Buffer.byteLength(edited, "utf-8");
    if (editedBytes > ALIGNMENT_CARD_MAX_BYTES) {
      console.log(
        "\n" +
          fmt.error(
            `Alignment card is ${editedBytes} bytes; limit is ${ALIGNMENT_CARD_MAX_BYTES} bytes (128 KB). The API will return 413.`,
          ) +
          "\n",
      );
      process.exit(1);
    }
    const putResult = await putAlignmentCard(agentId, edited, "text/yaml", {
      idempotencyKey: options.idempotencyKey,
    });
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
