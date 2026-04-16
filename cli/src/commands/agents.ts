import { listAgents } from "../lib/api.js";
import { requireAuth } from "../lib/auth.js";
import { fmt } from "../lib/format.js";

export async function agentsListCommand(): Promise<void> {
  await requireAuth();

  console.log(fmt.header("Agents"));
  console.log();

  let agents: Awaited<ReturnType<typeof listAgents>>;
  try {
    agents = await listAgents();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(fmt.error(`Failed to list agents: ${msg}`) + "\n");
    process.exit(1);
  }

  if (agents.length === 0) {
    console.log("  No agents found.\n");
    return;
  }

  // Table header
  const nameW = 24;
  const idW = 40;
  const seenW = 14;
  const statusW = 14;

  const header =
    "Name".padEnd(nameW) +
    "ID".padEnd(idW) +
    "Last Seen".padEnd(seenW) +
    "Containment";
  console.log(`  ${header}`);
  console.log(`  ${"─".repeat(nameW + idW + seenW + statusW)}`);

  for (const agent of agents) {
    const name = (agent.name ?? "-").slice(0, nameW - 2).padEnd(nameW);
    const id = agent.id.padEnd(idW);
    const lastSeen = agent.last_seen
      ? new Date(agent.last_seen).toLocaleDateString()
      : "-";
    const seen = lastSeen.padEnd(seenW);
    const containment = agent.containment_status ?? "-";

    console.log(`  ${name}${id}${seen}${containment}`);
  }

  console.log(`\n  Total: ${agents.length} agent(s)\n`);
}
