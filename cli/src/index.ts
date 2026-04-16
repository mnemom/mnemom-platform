#!/usr/bin/env node

import { program } from "commander";
import { initCommand } from "./commands/init.js";
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
import { registerCommand } from "./commands/register.js";
import { agentsListCommand, agentsRemoveCommand, agentsAddCommand, agentsDefaultCommand, agentsRekeyCommand, agentsCheckBindingCommand } from "./commands/agents.js";
import { loginCommand, logoutCommand, whoamiCommand } from "./commands/auth.js";
import { makeMigrateConfigCommand } from "./commands/migrate-config.js";

program
  .name("mnemom")
  .description("Transparent AI agent tracing")
  .version("0.8.0")
  .option("--agent <name>", "Select agent by name (or set MNEMOM_AGENT)");

program
  .command("init")
  .description("(removed) Use `mnemom register <name>` instead")
  .option("-y, --yes", "Skip confirmation prompts")
  .option("-f, --force", "Force reconfiguration")
  .option("--openclaw", "Configure using OpenClaw")
  .option("--standalone", "Configure standalone")
  .action(async (options) => {
    try {
      await initCommand(options);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

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
  .action(async () => {
    try {
      const opts = program.opts();
      await cardEditCommand(opts.agent);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

cardCmd
  .command("publish")
  .argument("<file>", "Path to alignment card file (YAML or JSON)")
  .description("Publish alignment card")
  .action(async (file: string) => {
    try {
      const opts = program.opts();
      await cardPublishCommand(file, opts.agent);
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
  .action(async () => {
    try {
      const opts = program.opts();
      await protectionEditCommand(opts.agent);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

protectionCmd
  .command("publish")
  .argument("<file>", "Path to protection card file (YAML or JSON)")
  .description("Publish protection card")
  .action(async (file: string) => {
    try {
      const opts = program.opts();
      await protectionPublishCommand(file, opts.agent);
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
  .command("register <name>")
  .description("Register a new named agent")
  .option("--openclaw", "Configure using OpenClaw")
  .option("--standalone", "Configure standalone mode")
  .option("--set-default", "Set as default agent")
  .action(async (name: string, options) => {
    try {
      await registerCommand(name, {
        openclaw: options.openclaw,
        standalone: options.standalone,
        setDefault: options.setDefault,
      });
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

const agentsCmd = program
  .command("agents")
  .description("List and manage registered agents");

agentsCmd
  .action(async () => {
    try {
      await agentsListCommand();
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

agentsCmd
  .command("remove <name>")
  .description("Remove a registered agent")
  .action(async (name: string) => {
    try {
      await agentsRemoveCommand(name);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

agentsCmd
  .command("add <name-or-id>")
  .description("Register an existing API agent in local config")
  .option("--alias <alias>", "Local alias name (default: agent's API name)")
  .action(async (nameOrId: string, options: { alias?: string }) => {
    try {
      await agentsAddCommand(nameOrId, options.alias);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

agentsCmd
  .command("default <name>")
  .description("Set the default agent")
  .action(async (name: string) => {
    try {
      await agentsDefaultCommand(name);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

agentsCmd
  .command("rekey [name]")
  .description("Re-bind an agent to a new provider API key (key hashed locally, never transmitted)")
  .action(async (name?: string) => {
    try {
      await agentsRekeyCommand(name);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

agentsCmd
  .command("check-binding [name]")
  .description("Verify that a provider API key is bound to an agent (key hashed locally, never transmitted)")
  .action(async (name?: string) => {
    try {
      await agentsCheckBindingCommand(name);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

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

program.addCommand(makeMigrateConfigCommand());

program.parse();
