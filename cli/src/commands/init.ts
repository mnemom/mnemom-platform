/**
 * The `init` command has been removed in UC-9.
 * The `register` command is now the primary entry point.
 */

export interface InitOptions {
  yes?: boolean;
  force?: boolean;
  openclaw?: boolean;
  standalone?: boolean;
}

export async function initCommand(_options: InitOptions = {}): Promise<void> {
  console.error("\nThe `init` command has been removed.\n");
  console.error("To set up a new agent, run:\n");
  console.error("  mnemom register <agent-name>\n");
  console.error("The `register` command handles authentication, agent creation,");
  console.error("and default card setup in a single step.\n");
  process.exit(1);
}
