import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Use vi.hoisted to ensure mocks are set up before module imports
const mockHomedir = vi.hoisted(() => vi.fn(() => "/home/testuser"));
const mockExit = vi.hoisted(() => vi.fn());

// Mock node modules before importing the module under test
vi.mock("node:fs");
vi.mock("node:os", () => ({
  homedir: mockHomedir,
}));

// Import fs after mocking (for type-safe mock access)
import * as fs from "node:fs";

// Import module under test after mocking
import { makeMigrateConfigCommand } from "../commands/migrate-config.js";

const OPENCLAW_CONFIG_PATH = "/home/testuser/.openclaw/openclaw.json";

/**
 * Helper: run the migrate-config command action by parsing args.
 * Returns a promise that resolves when the action completes.
 */
async function runMigrateConfig(): Promise<void> {
  const cmd = makeMigrateConfigCommand();
  // Invoke the action directly by parsing with no extra args
  await cmd.parseAsync([], { from: "user" });
}

describe("migrate-config command", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(process, "exit").mockImplementation(
      mockExit as unknown as typeof process.exit
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("default key migration", () => {
    it("migrates smoltbot → mnemom, smoltbot-openai → mnemom-openai, smoltbot-gemini → mnemom-gemini", async () => {
      const config = {
        models: {
          mode: "merge",
          providers: {
            smoltbot: {
              baseUrl: "https://gateway.mnemom.ai/anthropic",
              apiKey: "sk-ant-test",
              api: "anthropic-messages",
              models: [],
            },
            "smoltbot-openai": {
              baseUrl: "https://gateway.mnemom.ai/openai",
              apiKey: "sk-openai-test",
              api: "openai-chat",
              models: [],
            },
            "smoltbot-gemini": {
              baseUrl: "https://gateway.mnemom.ai/gemini",
              apiKey: "AIza-test",
              api: "gemini-messages",
              models: [],
            },
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(config));
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      await runMigrateConfig();

      const writtenContent = vi.mocked(fs.writeFileSync).mock.calls[0][1];
      const written = JSON.parse(writtenContent as string);
      const providers = written.models.providers;

      expect(providers["mnemom"]).toBeDefined();
      expect(providers["mnemom-openai"]).toBeDefined();
      expect(providers["mnemom-gemini"]).toBeDefined();
      expect(providers["smoltbot"]).toBeUndefined();
      expect(providers["smoltbot-openai"]).toBeUndefined();
      expect(providers["smoltbot-gemini"]).toBeUndefined();

      expect(vi.mocked(console.log)).toHaveBeenCalledWith(expect.stringContaining("Migrated 3 providers"));
    });
  });

  describe("named-agent key migration", () => {
    it("migrates smoltbot-myagent → mnemom-myagent and smoltbot-myagent-openai → mnemom-myagent-openai", async () => {
      const config = {
        models: {
          mode: "merge",
          providers: {
            "smoltbot-myagent": {
              baseUrl: "https://gateway.mnemom.ai/anthropic",
              apiKey: "sk-ant-test",
              api: "anthropic-messages",
              defaultHeaders: { "x-smoltbot-agent": "myagent" },
              models: [],
            },
            "smoltbot-myagent-openai": {
              baseUrl: "https://gateway.mnemom.ai/openai",
              apiKey: "sk-openai-test",
              api: "openai-chat",
              defaultHeaders: { "x-smoltbot-agent": "myagent" },
              models: [],
            },
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(config));
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      await runMigrateConfig();

      const writtenContent = vi.mocked(fs.writeFileSync).mock.calls[0][1];
      const written = JSON.parse(writtenContent as string);
      const providers = written.models.providers;

      expect(providers["mnemom-myagent"]).toBeDefined();
      expect(providers["mnemom-myagent-openai"]).toBeDefined();
      expect(providers["smoltbot-myagent"]).toBeUndefined();
      expect(providers["smoltbot-myagent-openai"]).toBeUndefined();

      expect(vi.mocked(console.log)).toHaveBeenCalledWith(expect.stringContaining("Migrated 2 providers"));
    });
  });

  describe("header migration", () => {
    it("renames x-smoltbot-agent header to x-mnemom-agent in defaultHeaders", async () => {
      const config = {
        models: {
          providers: {
            "smoltbot-myagent": {
              baseUrl: "https://gateway.mnemom.ai/anthropic",
              apiKey: "sk-ant-test",
              api: "anthropic-messages",
              defaultHeaders: {
                "x-smoltbot-agent": "myagent",
                "x-other-header": "keep-me",
              },
              models: [],
            },
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(config));
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      await runMigrateConfig();

      const writtenContent = vi.mocked(fs.writeFileSync).mock.calls[0][1];
      const written = JSON.parse(writtenContent as string);
      const entry = written.models.providers["mnemom-myagent"];

      expect(entry.defaultHeaders["x-mnemom-agent"]).toBe("myagent");
      expect(entry.defaultHeaders["x-smoltbot-agent"]).toBeUndefined();
      expect(entry.defaultHeaders["x-other-header"]).toBe("keep-me");
    });
  });

  describe("idempotency", () => {
    it("is idempotent: running on already-migrated config does nothing", async () => {
      const config = {
        models: {
          providers: {
            mnemom: {
              baseUrl: "https://gateway.mnemom.ai/anthropic",
              apiKey: "sk-ant-test",
              api: "anthropic-messages",
              models: [],
            },
            "mnemom-openai": {
              baseUrl: "https://gateway.mnemom.ai/openai",
              apiKey: "sk-openai-test",
              api: "openai-chat",
              models: [],
            },
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(config));
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      await runMigrateConfig();

      // No write should happen — no smoltbot* keys to migrate
      expect(fs.writeFileSync).not.toHaveBeenCalled();
      expect(vi.mocked(console.log)).toHaveBeenCalledWith(
        expect.stringContaining("No smoltbot* provider keys found")
      );
    });
  });

  describe("missing config file", () => {
    it("prints 'OpenClaw not detected' and exits 0 when file does not exist", async () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      await runMigrateConfig();

      expect(vi.mocked(console.log)).toHaveBeenCalledWith(
        expect.stringContaining("OpenClaw not detected")
      );
      expect(fs.writeFileSync).not.toHaveBeenCalled();
      expect(mockExit).not.toHaveBeenCalled();
    });
  });

  describe("malformed JSON", () => {
    it("prints an error and exits 1 when config is malformed JSON", async () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue("not valid json {{{{");

      await runMigrateConfig();

      expect(vi.mocked(console.error)).toHaveBeenCalledWith(
        expect.stringContaining("malformed JSON")
      );
      expect(mockExit).toHaveBeenCalledWith(1);
      expect(fs.writeFileSync).not.toHaveBeenCalled();
    });
  });
});
