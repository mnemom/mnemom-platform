/**
 * The `migrate-config` command has been removed in UC-9.
 * Config migration from ~/.smoltbot/ to ~/.mnemom/ now happens automatically
 * on first run of any `mnemom` command.
 */

import { Command } from "commander";

export function makeMigrateConfigCommand(): Command {
  const cmd = new Command("migrate-config");
  cmd
    .description("(removed) Config migration is now automatic")
    .action(async () => {
      console.error("\nThe `migrate-config` command has been removed.\n");
      console.error("Config migration from ~/.smoltbot/ to ~/.mnemom/ now happens");
      console.error("automatically when you run any `mnemom` command.\n");
    });

  return cmd;
}
