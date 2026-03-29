import { loadConfig, saveConfig } from "../lib/config.js";
import { listAgents, getAgent, getAgentByName } from "../lib/api.js";
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

  // Build reverse map: agentId → local alias name
  const localAliases = new Map<string, string>();
  for (const [name, agent] of Object.entries(config.agents)) {
    localAliases.set(agent.agentId, name);
  }

  // Fetch ALL agents from API for the authenticated user
  let apiAgents: Awaited<ReturnType<typeof listAgents>> = [];
  try {
    apiAgents = await listAgents();
  } catch {
    console.log(fmt.warn("Could not reach API — showing local agents only") + "\n");
  }

  const shown = new Set<string>();

  if (apiAgents.length > 0) {
    for (const agent of apiAgents) {
      shown.add(agent.id);
      const localName = localAliases.get(agent.id);
      const isDefault = localName === config.defaultAgent;
      const displayName = localName ?? agent.name ?? agent.email ?? agent.id;
      const defaultMarker = isDefault ? " (default)" : "";

      console.log(`  ${fmt.label(displayName + defaultMarker, "")}`);
      console.log(`    ${fmt.label("Agent ID: ", agent.id)}`);
      if (localName && localName !== displayName) {
        console.log(`    ${fmt.label("Local alias:", " " + localName)}`);
      }
      if (agent.last_seen) {
        console.log(`    ${fmt.label("Last seen:", " " + new Date(agent.last_seen).toLocaleDateString())}`);
      }
      if (agent.created_at) {
        console.log(`    ${fmt.label("Created:  ", new Date(agent.created_at).toLocaleDateString())}`);
      }
      console.log();
    }
  }

  // Show locally-registered agents not in the API response
  for (const [name, agent] of Object.entries(config.agents)) {
    if (!shown.has(agent.agentId)) {
      const isDefault = name === config.defaultAgent;
      const defaultMarker = isDefault ? " (default)" : "";
      const providerInfo = agent.providers?.join(", ") ?? (agent.openclawConfigured ? "openclaw" : "unknown");
      console.log(`  ${fmt.label(name + defaultMarker, "")} ${fmt.warn("(local only — not found in account)")}`);
      console.log(`    ${fmt.label("Agent ID: ", agent.agentId)}`);
      console.log(`    ${fmt.label("Provider: ", providerInfo)}`);
      console.log();
    }
  }

  const total = apiAgents.length > 0 ? apiAgents.length : Object.keys(config.agents).length;
  console.log(`  Total: ${total} agent(s)\n`);
}

export async function agentsDefaultCommand(name: string): Promise<void> {
  const config = loadConfig();
  if (!config) {
    console.log("\n" + fmt.error("smoltbot is not initialized") + "\n");
    process.exit(1);
  }

  if (!config.agents[name]) {
    console.log(fmt.error(`Agent "${name}" is not registered locally.`) + "\n");
    console.log(`Run \`smoltbot agents add ${name}\` to register it first.\n`);
    process.exit(1);
  }

  config.defaultAgent = name;
  saveConfig(config);

  console.log(fmt.success(`Default agent set to "${name}"`) + "\n");
  console.log(fmt.label("Agent ID:", ` ${config.agents[name].agentId}`) + "\n");
}

/**
 * smoltbot agents add <name-or-id> [--alias <alias>]
 * Register an existing API agent in the local config.
 */
export async function agentsAddCommand(nameOrId: string, alias?: string): Promise<void> {
  const config = loadConfig();
  if (!config) {
    console.log("\n" + fmt.error("smoltbot is not initialized") + "\n");
    console.log("Run `smoltbot init` to get started.\n");
    process.exit(1);
  }

  // Fetch the agent from the API
  let agentId: string;
  let apiName: string | null = null;
  let createdAt: string | undefined;

  try {
    if (/^smolt-[0-9a-f]{8}$/.test(nameOrId)) {
      const a = await getAgent(nameOrId);
      agentId = a.id;
      createdAt = a.created_at;
    } else {
      const a = await getAgentByName(nameOrId);
      if (!a) {
        console.log(fmt.error(`Agent not found: ${nameOrId}`) + "\n");
        console.log("Run `smoltbot agents` to see agents in your account.\n");
        process.exit(1);
      }
      agentId = a.id;
      apiName = a.name;
      createdAt = a.created_at;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log("\n" + fmt.error(msg) + "\n");
    process.exit(1);
  }

  const localAlias = alias ?? apiName ?? nameOrId;

  // Check for conflicts
  const existing = config.agents[localAlias];
  if (existing) {
    if (existing.agentId === agentId) {
      console.log(fmt.success(`Agent "${localAlias}" is already registered (${agentId})`) + "\n");
      return;
    }
    console.log(fmt.error(`Alias "${localAlias}" is already in use by agent ${existing.agentId}.`) + "\n");
    console.log(`Use --alias <name> to choose a different local name.\n`);
    process.exit(1);
  }

  config.agents[localAlias] = { agentId, configuredAt: createdAt };
  saveConfig(config);

  console.log(fmt.success(`Agent registered as "${localAlias}"`) + "\n");
  console.log(fmt.label("Agent ID:", ` ${agentId}`) + "\n");
  console.log(`Use --agent ${localAlias} to target this agent.\n`);
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
