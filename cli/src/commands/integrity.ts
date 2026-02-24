import { configExists, loadConfig, getActiveAgent } from "../lib/config.js";
import { getIntegrity } from "../lib/api.js";
import { fmt } from "../lib/format.js";

export async function integrityCommand(agentName?: string): Promise<void> {
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
    console.log("\n" + fmt.error(`Agent not found${agentName ? `: ${agentName}` : ""}`) + "\n");
    process.exit(1);
  }

  console.log("\nFetching integrity score...\n");

  try {
    const integrity = await getIntegrity(agent.agentId);

    const scorePercent = (integrity.score * 100).toFixed(1);
    const scoreBar = generateScoreBar(integrity.score);

    console.log(fmt.header("Integrity Score"));
    console.log(`  ${fmt.label("Score:     ", `${scorePercent}% ${scoreBar}`)}`);
    console.log(`  ${fmt.label("Total:     ", `${integrity.total_traces} traces`)}`);
    console.log(`  ${fmt.label("Verified:  ", `${integrity.verified}`)} ${fmt.success("")}`);
    console.log(`  ${fmt.label("Violations:", ` ${integrity.violations}`)} ${fmt.error("")}`);
    console.log(`  ${fmt.label("Updated:   ", integrity.last_updated)}`);

    if (integrity.violations > 0) {
      console.log("\n" + fmt.warn("You have integrity violations. Run `smoltbot logs` to investigate.") + "\n");
    } else if (integrity.total_traces === 0) {
      console.log("\nNo traces recorded yet. Start using Claude to build your integrity score.\n");
    } else {
      console.log("\n" + fmt.success("Your agent has a clean integrity record!") + "\n");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    if (message.includes("404") || message.includes("not found")) {
      console.log(fmt.header("Integrity Score"));
      console.log(`  ${fmt.label("Score:     ", "N/A")}`);
      console.log(`  ${fmt.label("Total:     ", "0 traces")}`);
      console.log(`  ${fmt.label("Verified:  ", "0")}`);
      console.log(`  ${fmt.label("Violations:", " 0")}`);
      console.log("\nNo traces recorded yet. Start using Claude to build your integrity score.\n");
    } else {
      console.log("\n" + fmt.error(`Failed to fetch integrity score: ${message}`) + "\n");
      process.exit(1);
    }
  }
}

function generateScoreBar(score: number): string {
  const filled = Math.round(score * 10);
  const empty = 10 - filled;
  const filledChar = "█";
  const emptyChar = "░";

  return `[${filledChar.repeat(filled)}${emptyChar.repeat(empty)}]`;
}
