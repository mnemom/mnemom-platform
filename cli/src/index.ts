#!/usr/bin/env node

import { program } from "commander";
import { initCommand } from "./commands/init.js";
import { statusCommand } from "./commands/status.js";
import { integrityCommand } from "./commands/integrity.js";
import { logsCommand } from "./commands/logs.js";
import { licenseActivateCommand, licenseStatusCommand, licenseDeactivateCommand } from "./commands/license.js";
import { cardShowCommand, cardPublishCommand, cardValidateCommand } from "./commands/card.js";
import {
  policyInitCommand,
  policyValidateCommand,
  policyPublishCommand,
  policyListCommand,
  policyTestCommand,
  policyEvaluateCommand,
} from "./commands/policy.js";
import { registerCommand } from "./commands/register.js";
import { agentsListCommand, agentsDefaultCommand, agentsRemoveCommand } from "./commands/agents.js";
import { loginCommand, logoutCommand, whoamiCommand } from "./commands/auth.js";

program
  .name("smoltbot")
  .description("Transparent AI agent tracing - AAP compliant")
  .version("0.4.0")
  .option("--agent <name>", "Select agent by name");

program
  .command("init")
  .description("Initialize smoltbot for traced mode (interactive, --openclaw, or --standalone)")
  .option("-y, --yes", "Skip confirmation prompts (accept defaults)")
  .option("-f, --force", "Force reconfiguration even if already configured")
  .option("--openclaw", "Configure using OpenClaw (requires OpenClaw installed)")
  .option("--standalone", "Configure standalone (prompt for API keys directly)")
  .action(async (options) => {
    try {
      await initCommand({
        yes: options.yes,
        force: options.force,
        openclaw: options.openclaw,
        standalone: options.standalone,
      });
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

const cardCmd = program
  .command("card")
  .description("Manage alignment card");

cardCmd
  .command("show")
  .description("Display active alignment card")
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
  .command("publish")
  .argument("<file>", "Path to card JSON file")
  .description("Publish alignment card from JSON file")
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
  .argument("<file>", "Path to card JSON file")
  .description("Validate card JSON locally")
  .action(async (file: string) => {
    try {
      await cardValidateCommand(file);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

const policyCmd = program
  .command("policy")
  .description("Manage policy engine");

policyCmd
  .command("init")
  .description("Scaffold a policy.json template")
  .action(async () => {
    try {
      await policyInitCommand();
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

policyCmd
  .command("validate")
  .argument("<file>", "Path to policy JSON file")
  .description("Validate policy locally")
  .action(async (file: string) => {
    try {
      await policyValidateCommand(file);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

policyCmd
  .command("publish")
  .argument("<file>", "Path to policy JSON file")
  .description("Validate and publish policy to API")
  .action(async (file: string) => {
    try {
      const opts = program.opts();
      await policyPublishCommand(file, opts.agent);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

policyCmd
  .command("list")
  .description("List active policy for current agent")
  .action(async () => {
    try {
      const opts = program.opts();
      await policyListCommand(opts.agent);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

policyCmd
  .command("test")
  .argument("<file>", "Path to policy JSON file")
  .option("--against-traces", "Test against historical traces")
  .description("Dry-run policy against historical traces")
  .action(async (file: string) => {
    try {
      const opts = program.opts();
      await policyTestCommand(file, opts.agent);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

policyCmd
  .command("evaluate")
  .argument("<file>", "Path to policy JSON file")
  .option("--card <file>", "Path to alignment card JSON file")
  .option("--tools <tools>", "Comma-separated list of tool names")
  .option("--tool-manifest <file>", "Path to tool manifest JSON file")
  .option("--strict", "Exit with code 1 on warnings (not just failures)")
  .description("Evaluate policy against tools locally (for CI/CD)")
  .action(async (file: string, options: { card?: string; tools?: string; toolManifest?: string; strict?: boolean }) => {
    try {
      await policyEvaluateCommand(file, options);
    } catch (error) {
      console.error("Error:", error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

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

program
  .command("login")
  .description("Authenticate with your Mnemom account")
  .action(async () => {
    try {
      await loginCommand();
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
