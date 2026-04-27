import { resolveAgentId } from "../lib/api.js";
import { getIntegrity } from "../lib/api.js";
import { fmt } from "../lib/format.js";

export async function integrityCommand(agentName?: string): Promise<void> {
  const agentId = await resolveAgentId(agentName);

  console.log("\nFetching integrity score...\n");

  try {
    const integrity = await getIntegrity(agentId);

    // Field names match the docs.mnemom.ai canonical IntegrityScore schema:
    // integrity_score (in [0,1]), total_traces, verified_traces, violation_count.
    const scorePercent = (integrity.integrity_score * 100).toFixed(1);
    const scoreBar = generateScoreBar(integrity.integrity_score);

    console.log(fmt.header("Integrity Score"));
    console.log(`  ${fmt.label("Score:     ", `${scorePercent}% ${scoreBar}`)}`);
    console.log(`  ${fmt.label("Total:     ", `${integrity.total_traces} traces`)}`);
    console.log(`  ${fmt.label("Verified:  ", `${integrity.verified_traces}`)}`);
    console.log(`  ${fmt.label("Violations:", ` ${integrity.violation_count}`)}`);

    if (integrity.violation_count > 0) {
      console.log("\n" + fmt.warn("You have integrity violations. Run `mnemom logs` to investigate.") + "\n");
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
  const filledChar = "\u2588";
  const emptyChar = "\u2591";

  return `[${filledChar.repeat(filled)}${emptyChar.repeat(empty)}]`;
}
