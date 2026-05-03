#!/usr/bin/env node

import { program } from "commander";
import { statusCommand } from "./commands/status.js";
import { integrityCommand } from "./commands/integrity.js";
import { logsCommand } from "./commands/logs.js";
import { licenseActivateCommand, licenseStatusCommand, licenseDeactivateCommand } from "./commands/license.js";
import { cardShowCommand, cardPublishCommand, cardValidateCommand, cardEditCommand, cardEvaluateCommand } from "./commands/card.js";
import {
  policyInitCommand,
  policyValidateCommand,
  policyPublishCommand,
  policyListCommand,
  policyTestCommand,
  policyEvaluateCommand,
} from "./commands/policy.js";
import { protectionShowCommand, protectionPublishCommand, protectionValidateCommand, protectionEditCommand } from "./commands/protection.js";
import { agentsListCommand } from "./commands/agents.js";
import { orgListCommand, orgShowCommand } from "./commands/org.js";
import {
  teamListCommand,
  teamShowCommand,
  teamTemplateCommand,
  teamPreviewComposeCommand,
} from "./commands/team.js";
import { loginCommand, logoutCommand, whoamiCommand } from "./commands/auth.js";

program
  .name("mnemom")
  .description("Transparent AI agent tracing")
  .version("0.9.1")
  .option("--agent <name>", "Select agent by name (or set MNEMOM_AGENT)");

program
  .command("status")
  .description("Show agent status and connection info")
  .action(async () => {
    try {
      const opts = program.opts();
      await statusCommand(opts.agent);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command("integrity")
  .description("Display integrity score and verification stats")
  .action(async () => {
    try {
      const opts = program.opts();
      await integrityCommand(opts.agent);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command("logs")
  .description("Show recent traces and actions")
  .option("-l, --limit <number>", "Number of traces to show", "10")
  .action(async (options) => {
    try {
      const globalOpts = program.opts();
      const limit = parseInt(options.limit, 10);
      await logsCommand({ limit: isNaN(limit) ? 10 : limit, agentName: globalOpts.agent });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

const license = program
  .command("license")
  .description("Enterprise license management");

license
  .command("activate <jwt>")
  .description("Activate an enterprise license")
  .action(async (jwt: string) => {
    try {
      await licenseActivateCommand(jwt);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

license
  .command("status")
  .description("Show license status and details")
  .action(async () => {
    try {
      await licenseStatusCommand();
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

license
  .command("deactivate")
  .description("Deactivate and remove the enterprise license")
  .action(async () => {
    try {
      await licenseDeactivateCommand();
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// Card commands (alignment card)
// ============================================================================

const cardCmd = program
  .command("card")
  .description("Manage alignment card");

cardCmd
  .command("show")
  .description("Display alignment card (YAML)")
  .action(async () => {
    try {
      const opts = program.opts();
      await cardShowCommand(opts.agent);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

cardCmd
  .command("edit")
  .description("Edit alignment card in $EDITOR")
  .option("--idempotency-key <uuid>", "Reuse a specific Idempotency-Key (for retries; default: auto)")
  .action(async (subOpts: { idempotencyKey?: string }) => {
    try {
      const opts = program.opts();
      await cardEditCommand(opts.agent, { idempotencyKey: subOpts.idempotencyKey });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

cardCmd
  .command("publish")
  .argument("<file>", "Path to alignment card file (YAML or JSON)")
  .description("Publish alignment card")
  .option("--idempotency-key <uuid>", "Reuse a specific Idempotency-Key (for retries; default: auto)")
  .action(async (file: string, subOpts: { idempotencyKey?: string }) => {
    try {
      const opts = program.opts();
      await cardPublishCommand(file, opts.agent, { idempotencyKey: subOpts.idempotencyKey });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

cardCmd
  .command("validate")
  .argument("<file>", "Path to alignment card file (YAML or JSON)")
  .description("Validate alignment card locally")
  .action(async (file: string) => {
    try {
      await cardValidateCommand(file);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

cardCmd
  .command("evaluate")
  .argument("<file>", "Path to alignment card file (YAML or JSON)")
  .option("--tools <tools>", "Comma-separated list of tool names")
  .option("--tool-manifest <file>", "Path to tool manifest JSON file")
  .option("--strict", "Exit with code 1 on warnings (not just failures)")
  .description("Evaluate card policy against tools locally (for CI/CD)")
  .action(async (file: string, options: { tools?: string; toolManifest?: string; strict?: boolean }) => {
    try {
      await cardEvaluateCommand(file, options);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// Protection card commands
// ============================================================================

const protectionCmd = program
  .command("protection")
  .description("Manage protection card");

protectionCmd
  .command("show")
  .description("Display protection card (YAML)")
  .action(async () => {
    try {
      const opts = program.opts();
      await protectionShowCommand(opts.agent);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

protectionCmd
  .command("edit")
  .description("Edit protection card in $EDITOR")
  .option("--idempotency-key <uuid>", "Reuse a specific Idempotency-Key (for retries; default: auto)")
  .action(async (subOpts: { idempotencyKey?: string }) => {
    try {
      const opts = program.opts();
      await protectionEditCommand(opts.agent, { idempotencyKey: subOpts.idempotencyKey });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

protectionCmd
  .command("publish")
  .argument("<file>", "Path to protection card file (YAML or JSON)")
  .description("Publish protection card")
  .option("--idempotency-key <uuid>", "Reuse a specific Idempotency-Key (for retries; default: auto)")
  .action(async (file: string, subOpts: { idempotencyKey?: string }) => {
    try {
      const opts = program.opts();
      await protectionPublishCommand(file, opts.agent, { idempotencyKey: subOpts.idempotencyKey });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

protectionCmd
  .command("validate")
  .argument("<file>", "Path to protection card file (YAML or JSON)")
  .description("Validate protection card locally")
  .action(async (file: string) => {
    try {
      await protectionValidateCommand(file);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// Policy commands (removed — stubs with migration guidance)
// ============================================================================

const policyCmd = program
  .command("policy")
  .description("(removed) Policy is now part of the alignment card");

policyCmd
  .command("init")
  .description("(removed) Use `mnemom card validate`")
  .action(async () => { await policyInitCommand(); });

policyCmd
  .command("validate")
  .argument("<file>", "Path to policy file")
  .description("(removed) Use `mnemom card validate`")
  .action(async (file: string) => { await policyValidateCommand(file); });

policyCmd
  .command("publish")
  .argument("<file>", "Path to policy file")
  .description("(removed) Use `mnemom card publish`")
  .action(async (file: string) => {
    const opts = program.opts();
    await policyPublishCommand(file, opts.agent);
  });

policyCmd
  .command("list")
  .description("(removed) Use `mnemom card show`")
  .action(async () => {
    const opts = program.opts();
    await policyListCommand(opts.agent);
  });

policyCmd
  .command("test")
  .argument("<file>", "Path to policy file")
  .description("(removed) Use `mnemom card evaluate`")
  .action(async (file: string) => {
    const opts = program.opts();
    await policyTestCommand(file, opts.agent);
  });

policyCmd
  .command("evaluate")
  .argument("<file>", "Path to policy file")
  .option("--card <file>", "Path to card file")
  .option("--tools <tools>", "Comma-separated list of tool names")
  .option("--tool-manifest <file>", "Path to tool manifest JSON file")
  .option("--strict", "Exit with code 1 on warnings")
  .description("(removed) Use `mnemom card evaluate`")
  .action(async (file: string, options: { card?: string; tools?: string; toolManifest?: string; strict?: boolean }) => {
    await policyEvaluateCommand(file, options);
  });

// ============================================================================
// Agent management
// ============================================================================

program
  .command("agents")
  .description("List agents in your account")
  .action(async () => {
    try {
      await agentsListCommand();
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// Organization management (ADR-044, Piece 1 of T1-3.1)
// ============================================================================

const orgCmd = program
  .command("org")
  .description("Manage your organizations (personal + multi-user)");

orgCmd
  .command("list")
  .description("List every org you are a member of, including your personal org")
  .option("--json", "Output JSON instead of a human-readable table")
  .action(async (options: { json?: boolean }) => {
    try {
      await orgListCommand({ json: options.json });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

orgCmd
  .command("show [org_id]")
  .description("Show details of an org (default: your personal org if --personal, else single membership)")
  .option("--personal", "Show your personal-org-of-one (per ADR-044)")
  .option("--json", "Output JSON instead of human-readable text")
  .action(async (orgId: string | undefined, options: { personal?: boolean; json?: boolean }) => {
    try {
      await orgShowCommand(orgId, { personal: options.personal, json: options.json });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// Team management (ADR-044 amended, Piece 2 of T1-3.1)
//
// Per ADR-044 + Charter §I11: team membership is OPTIONAL. Solo agents
// (zero teams) compose under Platform → Org → Agent. Backend RBAC for
// team-template endpoints is purely org-level (requireOrgRole on the
// team's parent org); Team Admin role lands in Piece 5.
// ============================================================================

const teamCmd = program
  .command("team")
  .description("Manage teams and their scope-cascade templates");

teamCmd
  .command("list")
  .description("List every team across all orgs you are a member of")
  .option("--json", "Output JSON instead of a human-readable table")
  .action(async (options: { json?: boolean }) => {
    try {
      await teamListCommand({ json: options.json });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

teamCmd
  .command("show <team_id>")
  .description("Show details of a single team")
  .option("--json", "Output JSON instead of human-readable text")
  .action(async (teamId: string | undefined, options: { json?: boolean }) => {
    try {
      await teamShowCommand(teamId, { json: options.json });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

teamCmd
  .command("alignment-template <team_id>")
  .description("Read or write the team's alignment template")
  .option("--set <file>", "Write the template from a YAML or JSON file")
  .option("--clear", "Clear the template")
  .option("--json", "Output JSON instead of human-readable text")
  .action(
    async (
      teamId: string | undefined,
      options: { set?: string; clear?: boolean; json?: boolean },
    ) => {
      try {
        await teamTemplateCommand("alignment", teamId, options);
      } catch (error) {
        console.error("Error:", error instanceof Error ? error.message : error);
        process.exit(1);
      }
    },
  );

teamCmd
  .command("protection-template <team_id>")
  .description("Read or write the team's protection template")
  .option("--set <file>", "Write the template from a YAML or JSON file")
  .option("--clear", "Clear the template")
  .option("--json", "Output JSON instead of human-readable text")
  .action(
    async (
      teamId: string | undefined,
      options: { set?: string; clear?: boolean; json?: boolean },
    ) => {
      try {
        await teamTemplateCommand("protection", teamId, options);
      } catch (error) {
        console.error("Error:", error instanceof Error ? error.message : error);
        process.exit(1);
      }
    },
  );

teamCmd
  .command("preview-compose <team_id>")
  .description("Dry-run the composer with a draft template (alignment by default)")
  .option("--protection", "Preview protection template (default: alignment)")
  .option("--from <file>", "Read draft template from a file (default: stdin)")
  .option("--json", "Output JSON instead of human-readable text")
  .action(
    async (
      teamId: string | undefined,
      options: { protection?: boolean; from?: string; json?: boolean },
    ) => {
      try {
        await teamPreviewComposeCommand(teamId, options);
      } catch (error) {
        console.error("Error:", error instanceof Error ? error.message : error);
        process.exit(1);
      }
    },
  );

// ============================================================================
// Auth
// ============================================================================

program
  .command("login")
  .description("Authenticate with your Mnemom account")
  .option("--no-browser", "Use email/password prompt instead of browser")
  .action(async (options) => {
    try {
      await loginCommand({ noBrowser: options.browser === false });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command("logout")
  .description("Clear stored authentication credentials")
  .action(async () => {
    try {
      await logoutCommand();
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command("whoami")
  .description("Show current authentication status")
  .action(async () => {
    try {
      await whoamiCommand();
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program.parse();
