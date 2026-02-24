import { loadConfig, saveConfig } from "../lib/config.js";
import { fmt } from "../lib/format.js";

export async function agentsListCommand(): Promise<void> {
  const config = loadConfig();
  if (!config) {
    console.log("\n" + fmt.error("smoltbot is not initialized") + "\n");
    console.log("Run `smoltbot init` to get started.\n");
    process.exit(1);
  }

  console.log(fmt.header("Registered Agents"));
  console.log();

  const agentNames = Object.keys(config.agents);

  if (agentNames.length === 0) {
    console.log("  No agents registered.\n");
    console.log("  Run `smoltbot init` to create the default agent.\n");
    return;
  }

  for (const name of agentNames) {
    const agent = config.agents[name];
    const isDefault = name === config.defaultAgent;
    const defaultMarker = isDefault ? " (default)" : "";
    const providerInfo = agent.providers
      ? agent.providers.join(", ")
      : agent.openclawConfigured
        ? "openclaw"
        : "unknown";

    console.log(`  ${fmt.label(name + defaultMarker, "")}`);
    console.log(`    ${fmt.label("Agent ID: ", agent.agentId)}`);
    console.log(`    ${fmt.label("Provider: ", providerInfo)}`);
    if (agent.configuredAt) {
      console.log(`    ${fmt.label("Created:  ", new Date(agent.configuredAt).toLocaleDateString())}`);
    }
    console.log();
  }

  console.log(`  Total: ${agentNames.length} agent(s)\n`);
}

export async function agentsDefaultCommand(name: string): Promise<void> {
  const config = loadConfig();
  if (!config) {
    console.log("\n" + fmt.error("smoltbot is not initialized") + "\n");
    process.exit(1);
  }

  if (!config.agents[name]) {
    console.log(fmt.error(`Agent "${name}" not found`) + "\n");
    console.log("Available agents: " + Object.keys(config.agents).join(", ") + "\n");
    process.exit(1);
  }

  config.defaultAgent = name;
  saveConfig(config);

  console.log(fmt.success(`Default agent set to "${name}"`) + "\n");
  console.log(fmt.label("Agent ID:", ` ${config.agents[name].agentId}`) + "\n");
}

export async function agentsRemoveCommand(name: string): Promise<void> {
  const config = loadConfig();
  if (!config) {
    console.log("\n" + fmt.error("smoltbot is not initialized") + "\n");
    process.exit(1);
  }

  if (!config.agents[name]) {
    console.log(fmt.error(`Agent "${name}" not found`) + "\n");
    console.log("Available agents: " + Object.keys(config.agents).join(", ") + "\n");
    process.exit(1);
  }

  if (name === "default" && Object.keys(config.agents).length === 1) {
    console.log(fmt.error("Cannot remove the only agent") + "\n");
    console.log("Register another agent first with `smoltbot register <name>`.\n");
    process.exit(1);
  }

  const removedId = config.agents[name].agentId;
  delete config.agents[name];

  // If we removed the default, switch to first remaining agent
  if (config.defaultAgent === name) {
    const remaining = Object.keys(config.agents);
    config.defaultAgent = remaining[0] || "default";
    console.log(fmt.warn(`Default agent switched to "${config.defaultAgent}"`) + "\n");
  }

  saveConfig(config);

  console.log(fmt.success(`Agent "${name}" removed (${removedId})`) + "\n");
}
