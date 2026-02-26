import * as fs from "node:fs";
import * as path from "node:path";
import { configExists, loadConfig, getActiveAgent } from "../lib/config.js";
import { fmt } from "../lib/format.js";
import { askYesNo, isInteractive } from "../lib/prompt.js";
import { getPolicy, publishPolicy, type PolicyResponse } from "../lib/api.js";
import { validatePolicySchema, type ValidationResult } from "@mnemom/policy-engine";

// ============================================================================
// YAML parsing (minimal — parse structured YAML without external dep)
// ============================================================================

/**
 * Parse a policy file (JSON or YAML).
 * For YAML, we use a minimal parser that handles the policy schema.
 */
function parsePolicyFile(raw: string, filePath: string): Record<string, unknown> {
  // Try JSON first
  try {
    return JSON.parse(raw);
  } catch {
    // Not JSON — try YAML via JSON conversion (user must install js-yaml or use JSON)
    try {
      // Dynamic import would be async; for simplicity, require JSON for now
      // and provide clear error message
      throw new Error("not json");
    } catch {
      throw new Error(
        `Failed to parse ${path.basename(filePath)}. ` +
        `Policy files must be valid JSON. ` +
        `YAML support coming soon — convert with: npx js-yaml ${filePath}`
      );
    }
  }
}

// ============================================================================
// Policy display
// ============================================================================

function displayPolicy(policy: PolicyResponse): void {
  const p = policy.policy_json as Record<string, any>;

  console.log(fmt.header("Policy"));
  console.log();

  console.log(fmt.label("  Policy ID:", ` ${policy.id}`));
  console.log(fmt.label("  Name:     ", ` ${policy.name}`));
  if (policy.description) {
    console.log(fmt.label("  Desc:     ", ` ${policy.description}`));
  }
  console.log(fmt.label("  Version:  ", ` ${policy.version}`));
  console.log(fmt.label("  Created:  ", ` ${policy.created_at}`));

  // Capability mappings
  const mappings = p.capability_mappings;
  if (mappings && Object.keys(mappings).length > 0) {
    console.log(fmt.section("Capability Mappings"));
    console.log();
    for (const [name, mapping] of Object.entries(mappings) as [string, any][]) {
      console.log(`  ${fmt.success(name)}`);
      if (mapping.description) {
        console.log(`    ${mapping.description}`);
      }
      console.log(`    Tools: ${mapping.tools.join(", ")}`);
      console.log(`    Card actions: ${mapping.card_actions.join(", ")}`);
    }
  }

  // Forbidden rules
  const forbidden = p.forbidden;
  if (Array.isArray(forbidden) && forbidden.length > 0) {
    console.log(fmt.section("Forbidden Rules"));
    console.log();
    for (const rule of forbidden) {
      console.log(`  ${fmt.error(`${rule.pattern} [${rule.severity}]`)}`);
      console.log(`    ${rule.reason}`);
    }
  }

  // Escalation triggers
  const triggers = p.escalation_triggers;
  if (Array.isArray(triggers) && triggers.length > 0) {
    console.log(fmt.section("Escalation Triggers"));
    console.log();
    for (const trigger of triggers) {
      console.log(`  ${fmt.warn(`${trigger.condition} -> ${trigger.action}`)}`);
      console.log(`    ${trigger.reason}`);
    }
  }

  // Defaults
  const defaults = p.defaults;
  if (defaults) {
    console.log(fmt.section("Defaults"));
    console.log();
    console.log(fmt.label("  Unmapped action: ", defaults.unmapped_tool_action));
    console.log(fmt.label("  Unmapped severity:", ` ${defaults.unmapped_severity}`));
    console.log(fmt.label("  Fail open:       ", ` ${defaults.fail_open}`));
  }

  console.log();
}

// ============================================================================
// Subcommands
// ============================================================================

/**
 * smoltbot policy init — scaffold a policy.json with commented examples
 */
export async function policyInitCommand(): Promise<void> {
  const outputPath = path.resolve("policy.json");

  if (fs.existsSync(outputPath)) {
    console.log("\n" + fmt.warn("policy.json already exists in current directory") + "\n");
    if (isInteractive()) {
      const overwrite = await askYesNo("Overwrite?", false);
      if (!overwrite) {
        console.log("\nCancelled.\n");
        return;
      }
    } else {
      process.exit(1);
    }
  }

  const scaffold = {
    meta: {
      schema_version: "1.0",
      name: "my-policy",
      description: "Policy for my agent",
      scope: "agent",
    },
    capability_mappings: {
      web_fetch: {
        description: "Web browsing and fetching",
        tools: [
          "WebFetch",
          "WebSearch",
          "mcp__browser__*",
          "mcp__chrome-devtools__navigate_page",
        ],
        card_actions: ["web_fetch", "web_browse"],
      },
      file_system: {
        description: "File system operations",
        tools: ["Read", "Write", "Edit", "Glob"],
        card_actions: ["file_read", "file_write"],
      },
      code_execution: {
        description: "Code and shell execution",
        tools: ["Bash", "mcp__*__evaluate_script", "mcp__*__execute*"],
        card_actions: ["code_execution"],
      },
    },
    forbidden: [
      {
        pattern: "mcp__*__delete*",
        reason: "Destructive deletion forbidden",
        severity: "critical",
      },
    ],
    escalation_triggers: [
      {
        condition: "tool_matches('*payment*')",
        action: "escalate",
        reason: "Payment tools require human approval",
      },
    ],
    defaults: {
      unmapped_tool_action: "warn",
      unmapped_severity: "medium",
      fail_open: true,
    },
  };

  fs.writeFileSync(outputPath, JSON.stringify(scaffold, null, 2) + "\n");
  console.log(fmt.success(`Created policy.json`));
  console.log(fmt.label("  Path:", ` ${outputPath}`));
  console.log("\nEdit the file, then validate with:\n");
  console.log("  smoltbot policy validate policy.json\n");
}

/**
 * smoltbot policy validate <file> — local-only validation
 */
export async function policyValidateCommand(file: string): Promise<void> {
  const filePath = path.resolve(file);
  if (!fs.existsSync(filePath)) {
    console.log("\n" + fmt.error(`File not found: ${filePath}`) + "\n");
    process.exit(1);
  }

  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf-8");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Could not read file: ${msg}`) + "\n");
    process.exit(1);
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = parsePolicyFile(raw, filePath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(msg) + "\n");
    process.exit(1);
  }

  const result: ValidationResult = validatePolicySchema(parsed);

  console.log(fmt.header("Policy Validation Report"));
  console.log();
  console.log(fmt.label("  File:", ` ${filePath}`));
  console.log();

  if (result.valid) {
    console.log(fmt.success("Policy schema is valid"));
    const meta = (parsed as any).meta;
    if (meta) {
      console.log(fmt.label("  Name: ", ` ${meta.name}`));
      console.log(fmt.label("  Scope:", ` ${meta.scope}`));
    }
    const mappings = (parsed as any).capability_mappings;
    if (mappings) {
      console.log(fmt.label("  Capabilities:", ` ${Object.keys(mappings).length}`));
    }
  } else {
    for (const error of result.errors) {
      console.log(fmt.error(`${error.path}: ${error.message}`));
    }
    console.log();
    console.log(fmt.error(`${result.errors.length} validation error(s)`) + "\n");
    process.exit(1);
  }

  console.log();
}

/**
 * smoltbot policy publish <file> — validate + upload to API
 */
export async function policyPublishCommand(
  file: string,
  agentName?: string
): Promise<void> {
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

  const agent = getActiveAgent(agentName);
  if (!agent) {
    console.log(
      "\n" + fmt.error(`Agent not found${agentName ? `: ${agentName}` : ""}`) + "\n"
    );
    process.exit(1);
  }

  const filePath = path.resolve(file);
  if (!fs.existsSync(filePath)) {
    console.log("\n" + fmt.error(`File not found: ${filePath}`) + "\n");
    process.exit(1);
  }

  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf-8");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Could not read file: ${msg}`) + "\n");
    process.exit(1);
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = parsePolicyFile(raw, filePath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(msg) + "\n");
    process.exit(1);
  }

  // Validate locally first
  const validation = validatePolicySchema(parsed);

  console.log(fmt.header("Policy Validation"));
  console.log();

  if (!validation.valid) {
    for (const error of validation.errors) {
      console.log(fmt.error(`${error.path}: ${error.message}`));
    }
    console.log();
    console.log(fmt.error("Validation failed. Fix the errors above before publishing.") + "\n");
    process.exit(1);
  }

  console.log(fmt.success("Policy schema is valid"));
  console.log();

  // Confirm
  if (isInteractive()) {
    const meta = (parsed as any).meta;
    const confirm = await askYesNo(
      `Publish policy "${meta?.name || "unnamed"}" for agent ${agent.agentId}?`,
      false
    );
    if (!confirm) {
      console.log("\nPublish cancelled.\n");
      return;
    }
  }

  // Publish
  try {
    console.log("\nPublishing policy...");
    const result = await publishPolicy(agent.agentId, parsed);
    console.log(fmt.success("Policy published successfully!"));
    console.log(fmt.label("  Policy ID:", ` ${result.id}`));
    console.log(fmt.label("  Version:  ", ` ${result.version}`) + "\n");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to publish policy: ${message}`) + "\n");
    process.exit(1);
  }
}

/**
 * smoltbot policy list — list active policies for current agent
 */
export async function policyListCommand(agentName?: string): Promise<void> {
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

  const agent = getActiveAgent(agentName);
  if (!agent) {
    console.log(
      "\n" + fmt.error(`Agent not found${agentName ? `: ${agentName}` : ""}`) + "\n"
    );
    process.exit(1);
  }

  console.log("\nFetching policy...\n");

  try {
    const response = await getPolicy(agent.agentId);

    if (!response || !response.policy) {
      console.log(fmt.warn("No active policy"));
      console.log("\nCreate a policy with:\n");
      console.log("  smoltbot policy init");
      console.log("  smoltbot policy publish policy.json\n");
      return;
    }

    displayPolicy(response.policy);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to fetch policy: ${message}`) + "\n");
    process.exit(1);
  }
}

/**
 * smoltbot policy test <file> --against-traces — dry-run against historical traces
 */
export async function policyTestCommand(
  file: string,
  agentName?: string
): Promise<void> {
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

  const agent = getActiveAgent(agentName);
  if (!agent) {
    console.log(
      "\n" + fmt.error(`Agent not found${agentName ? `: ${agentName}` : ""}`) + "\n"
    );
    process.exit(1);
  }

  const filePath = path.resolve(file);
  if (!fs.existsSync(filePath)) {
    console.log("\n" + fmt.error(`File not found: ${filePath}`) + "\n");
    process.exit(1);
  }

  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf-8");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(`Could not read file: ${msg}`) + "\n");
    process.exit(1);
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = parsePolicyFile(raw, filePath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.log("\n" + fmt.error(msg) + "\n");
    process.exit(1);
  }

  // Validate first
  const validation = validatePolicySchema(parsed);
  if (!validation.valid) {
    console.log(fmt.error("Policy validation failed:"));
    for (const error of validation.errors) {
      console.log(fmt.error(`  ${error.path}: ${error.message}`));
    }
    console.log();
    process.exit(1);
  }

  console.log(`\nTesting policy against historical traces for agent ${agent.agentId}...\n`);

  try {
    const { testPolicyHistorical } = await import("../lib/api.js");
    const result = await testPolicyHistorical(agent.agentId, parsed);

    console.log(fmt.header("Policy Test Results"));
    console.log();
    console.log(fmt.label("  Policy:      ", ` ${result.policy_name}`));
    console.log(fmt.label("  Total traces:", ` ${result.total_traces}`));
    console.log();

    const s = result.summary;
    if (s.pass > 0) console.log(fmt.success(`${s.pass} passed`));
    if (s.warn > 0) console.log(fmt.warn(`${s.warn} warnings`));
    if (s.fail > 0) console.log(fmt.error(`${s.fail} failed`));
    if (s.skipped > 0) console.log(fmt.label("  Skipped:", ` ${s.skipped} (no tools)`));

    // Show first few failures
    const failures = result.results.filter((r: any) => r.verdict === "fail");
    if (failures.length > 0) {
      console.log(fmt.section("Failed Traces (first 5)"));
      console.log();
      for (const f of failures.slice(0, 5)) {
        console.log(fmt.error(`  ${f.trace_id}`));
        for (const v of f.violations ?? []) {
          console.log(`    ${v.type}: ${v.tool} — ${v.reason}`);
        }
      }
    }

    console.log();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Failed to test policy: ${message}`) + "\n");
    process.exit(1);
  }
}
