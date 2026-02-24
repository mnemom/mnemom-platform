import { configExists, loadConfig, getActiveAgent } from "../lib/config.js";
import { getTraces, type Trace } from "../lib/api.js";
import { fmt } from "../lib/format.js";

export interface LogsOptions {
  limit?: number;
  agentName?: string;
}

export async function logsCommand(options: LogsOptions = {}): Promise<void> {
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

  const agent = getActiveAgent(options.agentName);
  if (!agent) {
    console.log("\n" + fmt.error(`Agent not found${options.agentName ? `: ${options.agentName}` : ""}`) + "\n");
    process.exit(1);
  }

  const limit = options.limit || 10;

  console.log("\nFetching traces...\n");

  try {
    const traces = await getTraces(agent.agentId, limit);

    if (traces.length === 0) {
      console.log(fmt.header("No traces found"));
      console.log("\nStart using Claude to generate traces.\n");
      console.log("Make sure ANTHROPIC_BASE_URL is set correctly:\n");
      console.log(
        `  export ANTHROPIC_BASE_URL="${config.gateway || "https://gateway.mnemon.ai"}/v1/proxy/${agent.agentId}"\n`
      );
      return;
    }

    console.log(fmt.header(`Recent Traces (${traces.length})`));

    for (const trace of traces) {
      displayTrace(trace);
    }

    console.log(`\nView more: smoltbot logs --limit ${limit + 10}`);
    console.log(`Dashboard: https://mnemon.ai/dashboard/${agent.agentId}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    if (message.includes("404") || message.includes("not found")) {
      console.log(fmt.header("No traces found"));
      console.log("\nStart using Claude to generate traces.\n");
    } else {
      console.log("\n" + fmt.error(`Failed to fetch traces: ${message}`) + "\n");
      process.exit(1);
    }
  }
}

function displayTrace(trace: Trace): void {
  const timestamp = formatTimestamp(trace.timestamp);
  const statusMsg = trace.verified
    ? fmt.success(timestamp)
    : fmt.error(`${timestamp} [VIOLATION]`);

  console.log(`\n  ${statusMsg}`);
  console.log(`  ${fmt.label("Action:", ` ${trace.action}`)}`);

  if (trace.tool_name) {
    console.log(`  ${fmt.label("Tool:  ", ` ${trace.tool_name}`)}`);
  }

  if (trace.reasoning) {
    const preview = truncate(trace.reasoning, 60);
    console.log(`  ${fmt.label("Reason:", ` ${preview}`)}`);
  }
}

function formatTimestamp(iso: string): string {
  try {
    const date = new Date(iso);
    return date.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

function truncate(text: string, maxLength: number): string {
  const cleaned = text.replace(/\n/g, " ").trim();
  if (cleaned.length <= maxLength) {
    return cleaned;
  }
  return cleaned.slice(0, maxLength - 3) + "...";
}
