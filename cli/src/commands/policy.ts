/**
 * The `policy` command group has been removed in UC-9.
 * Policy capabilities are now part of the alignment card.
 *
 * Each exported function is a stub that prints a helpful migration message.
 * The exports are preserved so index.ts imports don't break.
 */

function removed(oldCmd: string, newCmd: string): never {
  console.error(`\nThe \`mnemom ${oldCmd}\` command has been removed.\n`);
  console.error(`Use \`mnemom ${newCmd}\` instead.\n`);
  process.exit(1);
}

export async function policyInitCommand(): Promise<void> {
  removed("policy init", "card validate <file.yaml>");
}

export async function policyValidateCommand(_file: string): Promise<void> {
  removed("policy validate", "card validate <file.yaml>");
}

export async function policyPublishCommand(_file: string, _agentName?: string): Promise<void> {
  removed("policy publish", "card publish <file.yaml>");
}

export async function policyListCommand(_agentName?: string): Promise<void> {
  removed("policy list", "card show");
}

export async function policyTestCommand(_file: string, _agentName?: string): Promise<void> {
  removed("policy test", "card evaluate <file.yaml> --tools <tools>");
}

export async function policyEvaluateCommand(
  _file: string,
  _options: { card?: string; tools?: string; toolManifest?: string; strict?: boolean },
): Promise<void> {
  removed("policy evaluate", "card evaluate <file.yaml> --tools <tools>");
}
