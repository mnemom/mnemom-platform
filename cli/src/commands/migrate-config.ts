import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Command } from "commander";

const OPENCLAW_CONFIG_PATH = path.join(os.homedir(), ".openclaw", "openclaw.json");

export function makeMigrateConfigCommand(): Command {
  const cmd = new Command("migrate-config");
  cmd
    .description(
      "Migrate ~/.openclaw/openclaw.json provider keys from smoltbot* to mnemom*"
    )
    .action(async () => {
      // 1. Check if OpenClaw config exists
      if (!fs.existsSync(OPENCLAW_CONFIG_PATH)) {
        console.log(
          "OpenClaw not detected at ~/.openclaw/openclaw.json. Nothing to migrate."
        );
        return;
      }

      // 2. Read and parse the config
      let config: Record<string, unknown> | null = null;
      try {
        const raw = fs.readFileSync(OPENCLAW_CONFIG_PATH, "utf-8");
        config = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        console.error(
          "Error: ~/.openclaw/openclaw.json is malformed JSON."
        );
        process.exit(1);
        return;
      }

      if (!config) return;

      // 3. Get models.providers — must be an object
      const models = config.models as Record<string, unknown> | undefined;
      const providers = models?.providers as Record<string, unknown> | undefined;

      if (!providers || typeof providers !== "object" || Object.keys(providers).length === 0) {
        console.log("No providers found.");
        return;
      }

      // 4. Find all keys matching /^smoltbot/
      const keysToMigrate = Object.keys(providers).filter((k) =>
        /^smoltbot/.test(k)
      );

      if (keysToMigrate.length === 0) {
        console.log("No smoltbot* provider keys found. Nothing to migrate.");
        return;
      }

      // 5. Migrate each key
      const migrations: Array<{ from: string; to: string }> = [];

      for (const oldKey of keysToMigrate) {
        const newKey = oldKey.replace(/^smoltbot/, "mnemom");
        const entry = providers[oldKey] as Record<string, unknown>;

        // Deep-copy the provider entry
        const newEntry: Record<string, unknown> = { ...entry };

        // Rename x-smoltbot-agent header if present
        const defaultHeaders = newEntry.defaultHeaders as
          | Record<string, string>
          | undefined;
        if (defaultHeaders && "x-smoltbot-agent" in defaultHeaders) {
          const headersCopy = { ...defaultHeaders };
          headersCopy["x-mnemom-agent"] = headersCopy["x-smoltbot-agent"];
          delete headersCopy["x-smoltbot-agent"];
          newEntry.defaultHeaders = headersCopy;
        }

        // Remove old key, add new key
        delete providers[oldKey];
        providers[newKey] = newEntry;

        migrations.push({ from: oldKey, to: newKey });
      }

      // 6. Write back
      fs.writeFileSync(OPENCLAW_CONFIG_PATH, JSON.stringify(config, null, 2));

      // 7. Print summary
      console.log(`✓ Migrated ${migrations.length} provider${migrations.length !== 1 ? "s" : ""}:`);
      for (const { from, to } of migrations) {
        console.log(`  ${from} → ${to}`);
      }
      console.log(
        "\nYour agent config at ~/.smoltbot/ is unchanged.\n"
      );
    });

  return cmd;
}
