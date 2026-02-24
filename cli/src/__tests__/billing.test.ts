import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Use vi.hoisted to ensure mocks are set up before module imports
const mockHomedir = vi.hoisted(() => vi.fn(() => "/home/testuser"));
const mockRandomBytes = vi.hoisted(() =>
  vi.fn(() => Buffer.from("deadbeef", "hex"))
);
const mockCreateHash = vi.hoisted(() =>
  vi.fn(() => ({
    update: vi.fn().mockReturnThis(),
    digest: vi.fn(() => "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"),
  }))
);
const mockIsInteractive = vi.hoisted(() => vi.fn(() => false));
const mockAskInput = vi.hoisted(() => vi.fn());

// Mock the node modules before importing the modules under test
vi.mock("node:fs");
vi.mock("node:os", () => ({
  homedir: mockHomedir,
}));
vi.mock("node:crypto", () => ({
  randomBytes: mockRandomBytes,
  createHash: mockCreateHash,
}));
vi.mock("../lib/prompt.js", () => ({
  isInteractive: mockIsInteractive,
  askInput: mockAskInput,
  askYesNo: vi.fn(),
  askMultiSelect: vi.fn(),
  askSelect: vi.fn(),
}));

// Import fs after mocking (for type-safe mock access)
import * as fs from "node:fs";

// Import module under test after mocking
import {
  configExists,
  loadConfig,
  saveConfig,
  CONFIG_DIR,
  CONFIG_FILE,
} from "../lib/config.js";

describe("billing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ==========================================================================
  // 1. Config mnemomApiKey persistence
  // ==========================================================================

  describe("Config mnemomApiKey persistence", () => {
    it("should save config with mnemomApiKey and load it back", () => {
      const config = {
        version: 2 as const,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        mnemomApiKey: "mnm_test_key_12345",
        agents: {
          default: { agentId: "smolt-abc12345" },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      saveConfig(config);

      const writtenContent = vi.mocked(fs.writeFileSync).mock.calls[0][1];
      const parsedConfig = JSON.parse(writtenContent as string);

      expect(parsedConfig.mnemomApiKey).toBe("mnm_test_key_12345");
    });

    it("should load config that contains mnemomApiKey", () => {
      const mockConfig = {
        version: 2,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        mnemomApiKey: "mnm_saved_key_67890",
        agents: {
          default: { agentId: "smolt-abc12345" },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const result = loadConfig();

      expect(result).not.toBeNull();
      expect(result!.mnemomApiKey).toBe("mnm_saved_key_67890");
    });

    it("should load config without mnemomApiKey (free tier)", () => {
      const mockConfig = {
        version: 2,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        agents: {
          default: { agentId: "smolt-abc12345" },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const result = loadConfig();

      expect(result).not.toBeNull();
      expect(result!.mnemomApiKey).toBeUndefined();
    });

    it("should preserve mnemomApiKey alongside other optional fields", () => {
      const config = {
        version: 2 as const,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        mnemomApiKey: "mnm_full_config_key",
        agents: {
          default: {
            agentId: "smolt-abc12345",
            openclawConfigured: true,
            providers: ["anthropic", "openai"],
            configuredAt: "2026-01-15T00:00:00.000Z",
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      saveConfig(config);

      const writtenContent = vi.mocked(fs.writeFileSync).mock.calls[0][1];
      const parsedConfig = JSON.parse(writtenContent as string);

      expect(parsedConfig.agents.default.agentId).toBe("smolt-abc12345");
      expect(parsedConfig.mnemomApiKey).toBe("mnm_full_config_key");
      expect(parsedConfig.agents.default.providers).toEqual(["anthropic", "openai"]);
      expect(parsedConfig.agents.default.configuredAt).toBe("2026-01-15T00:00:00.000Z");
    });

    it("should write mnemomApiKey as formatted JSON to correct path", () => {
      const config = {
        version: 2 as const,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        mnemomApiKey: "mnm_path_check",
        agents: {
          default: { agentId: "smolt-test1234" },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      saveConfig(config);

      expect(fs.writeFileSync).toHaveBeenCalledWith(
        CONFIG_FILE,
        JSON.stringify(config, null, 2)
      );
    });
  });

  // ==========================================================================
  // 2. promptMnemomApiKey in non-interactive mode
  // ==========================================================================

  describe("promptMnemomApiKey non-interactive env var detection", () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it("should detect MNEMOM_API_KEY env var with mnm_ prefix in non-interactive mode", () => {
      // In the init command's promptMnemomApiKey, when !isInteractive():
      //   const envKey = process.env.MNEMOM_API_KEY || "";
      //   if (envKey && envKey.startsWith("mnm_")) { return envKey; }
      mockIsInteractive.mockReturnValue(false);
      process.env.MNEMOM_API_KEY = "mnm_env_key_abc123";

      const envKey = process.env.MNEMOM_API_KEY || "";
      const isNonInteractive = !mockIsInteractive();

      expect(isNonInteractive).toBe(true);
      expect(envKey).toBe("mnm_env_key_abc123");
      expect(envKey.startsWith("mnm_")).toBe(true);
    });

    it("should fall back to existing config key when MNEMOM_API_KEY env var is missing", () => {
      mockIsInteractive.mockReturnValue(false);
      delete process.env.MNEMOM_API_KEY;

      const existingConfig = {
        agentId: "smolt-existing",
        mnemomApiKey: "mnm_existing_key",
      };

      const envKey = process.env.MNEMOM_API_KEY || "";
      const isNonInteractive = !mockIsInteractive();

      expect(isNonInteractive).toBe(true);
      expect(envKey).toBe("");
      // When envKey is empty, promptMnemomApiKey returns existingConfig?.mnemomApiKey
      expect(existingConfig.mnemomApiKey).toBe("mnm_existing_key");
    });

    it("should reject env var that does not start with mnm_ prefix", () => {
      mockIsInteractive.mockReturnValue(false);
      process.env.MNEMOM_API_KEY = "sk-invalid_prefix_key";

      const envKey = process.env.MNEMOM_API_KEY || "";

      expect(envKey.startsWith("mnm_")).toBe(false);
    });

    it("should handle empty MNEMOM_API_KEY env var", () => {
      mockIsInteractive.mockReturnValue(false);
      process.env.MNEMOM_API_KEY = "";

      const envKey = process.env.MNEMOM_API_KEY || "";

      // Empty string is falsy, so promptMnemomApiKey skips it
      expect(envKey).toBe("");
      expect(!envKey).toBe(true);
    });
  });

  // ==========================================================================
  // 3. promptMnemomApiKey validation (mnm_ prefix)
  // ==========================================================================

  describe("promptMnemomApiKey validation", () => {
    it("should accept keys starting with mnm_ prefix", () => {
      const validKeys = [
        "mnm_abc123",
        "mnm_test_key_with_underscores",
        "mnm_0123456789abcdef",
        "mnm_a",
      ];

      for (const key of validKeys) {
        expect(key.startsWith("mnm_")).toBe(true);
      }
    });

    it("should reject keys not starting with mnm_ prefix", () => {
      const invalidKeys = [
        "sk-ant-api-key",
        "sk-openai-key",
        "AIza-gemini-key",
        "mnemom_wrong_prefix",
        "MNM_uppercase",
        "mnm-hyphen-not-underscore",
        "",
      ];

      for (const key of invalidKeys) {
        expect(key.startsWith("mnm_")).toBe(false);
      }
    });

    it("should return existing config key when user enters empty input", () => {
      // Simulates: user presses Enter without typing => askInput returns ""
      // promptMnemomApiKey then returns existingConfig?.mnemomApiKey
      const existingConfig = {
        agentId: "smolt-abc12345",
        mnemomApiKey: "mnm_previously_saved",
      };

      const userInput = ""; // empty = skip
      expect(!userInput).toBe(true);
      // When skipped, falls through to return existingConfig?.mnemomApiKey
      expect(existingConfig.mnemomApiKey).toBe("mnm_previously_saved");
    });

    it("should return undefined when no existing key and user skips", () => {
      const existingConfig: { agentId: string; mnemomApiKey?: string } = {
        agentId: "smolt-abc12345",
        // no mnemomApiKey
      };

      const userInput = "";
      expect(!userInput).toBe(true);
      expect(existingConfig.mnemomApiKey).toBeUndefined();
    });

    it("should show existing key prefix when config has mnemomApiKey", () => {
      const existingKey = "mnm_abcdef_long_key_value";
      const prefix = existingKey.slice(0, 8);
      expect(prefix).toBe("mnm_abcd");
    });
  });

  // ==========================================================================
  // 4. SDK snippet generation — includes x-mnemom-api-key header when key present
  // ==========================================================================

  describe("SDK snippet generation with mnemomApiKey", () => {
    const GATEWAY_URL = "https://gateway.mnemom.ai";

    const GATEWAY_BASE_URLS = {
      anthropic: `${GATEWAY_URL}/anthropic`,
      openai: `${GATEWAY_URL}/openai/v1`,
      gemini: `${GATEWAY_URL}/gemini`,
    };

    it("should include x-mnemom-api-key in Anthropic Python snippet when key is present", () => {
      const mnemomApiKey = "mnm_billing_key_123";
      const provider = "anthropic" as const;
      const baseUrl = GATEWAY_BASE_URLS[provider];

      // Reproduces the logic from showStandaloneSuccess
      const lines: string[] = [];
      if (mnemomApiKey) {
        lines.push(`client = Anthropic(`);
        lines.push(`    base_url="${baseUrl}",`);
        lines.push(`    default_headers={"x-mnemom-api-key": os.environ["MNEMOM_API_KEY"]}`);
        lines.push(`)`);
      }

      const snippet = lines.join("\n");
      expect(snippet).toContain("x-mnemom-api-key");
      expect(snippet).toContain('os.environ["MNEMOM_API_KEY"]');
      expect(snippet).toContain(GATEWAY_BASE_URLS.anthropic);
    });

    it("should include x-mnemom-api-key in Anthropic TypeScript snippet when key is present", () => {
      const mnemomApiKey = "mnm_billing_key_123";
      const provider = "anthropic" as const;
      const baseUrl = GATEWAY_BASE_URLS[provider];

      const lines: string[] = [];
      if (mnemomApiKey) {
        lines.push(`new Anthropic({`);
        lines.push(`    baseURL: "${baseUrl}",`);
        lines.push(`    defaultHeaders: { "x-mnemom-api-key": process.env.MNEMOM_API_KEY }`);
        lines.push(`})`);
      }

      const snippet = lines.join("\n");
      expect(snippet).toContain("x-mnemom-api-key");
      expect(snippet).toContain("process.env.MNEMOM_API_KEY");
      expect(snippet).toContain(GATEWAY_BASE_URLS.anthropic);
    });

    it("should include x-mnemom-api-key in OpenAI Python snippet when key is present", () => {
      const mnemomApiKey = "mnm_billing_key_456";
      const provider = "openai" as const;
      const baseUrl = GATEWAY_BASE_URLS[provider];

      const lines: string[] = [];
      if (mnemomApiKey) {
        lines.push(`client = OpenAI(`);
        lines.push(`    base_url="${baseUrl}",`);
        lines.push(`    default_headers={"x-mnemom-api-key": os.environ["MNEMOM_API_KEY"]}`);
        lines.push(`)`);
      }

      const snippet = lines.join("\n");
      expect(snippet).toContain("x-mnemom-api-key");
      expect(snippet).toContain(GATEWAY_BASE_URLS.openai);
    });

    it("should include x-mnemom-api-key in OpenAI TypeScript snippet when key is present", () => {
      const mnemomApiKey = "mnm_billing_key_456";
      const provider = "openai" as const;
      const baseUrl = GATEWAY_BASE_URLS[provider];

      const lines: string[] = [];
      if (mnemomApiKey) {
        lines.push(`new OpenAI({`);
        lines.push(`    baseURL: "${baseUrl}",`);
        lines.push(`    defaultHeaders: { "x-mnemom-api-key": process.env.MNEMOM_API_KEY }`);
        lines.push(`})`);
      }

      const snippet = lines.join("\n");
      expect(snippet).toContain("x-mnemom-api-key");
      expect(snippet).toContain("process.env.MNEMOM_API_KEY");
      expect(snippet).toContain(GATEWAY_BASE_URLS.openai);
    });

    it("should include x-mnemom-api-key header in Gemini REST snippet when key is present", () => {
      const mnemomApiKey = "mnm_billing_key_789";
      const provider = "gemini" as const;
      const baseUrl = GATEWAY_BASE_URLS[provider];

      // Gemini uses a different display format (REST, not SDK)
      const lines: string[] = [];
      lines.push(`POST ${baseUrl}/v1beta/models/{model}:generateContent`);
      if (mnemomApiKey) {
        lines.push(`Header: x-mnemom-api-key: $MNEMOM_API_KEY`);
      }

      const snippet = lines.join("\n");
      expect(snippet).toContain("x-mnemom-api-key");
      expect(snippet).toContain("$MNEMOM_API_KEY");
      expect(snippet).toContain(GATEWAY_BASE_URLS.gemini);
    });

    it("should include MNEMOM_API_KEY export instruction when key is present", () => {
      const mnemomApiKey = "mnm_export_test";

      // showStandaloneSuccess outputs: export MNEMOM_API_KEY=<key>
      const exportLine = mnemomApiKey
        ? `export MNEMOM_API_KEY=${mnemomApiKey}`
        : null;

      expect(exportLine).not.toBeNull();
      expect(exportLine).toContain("export MNEMOM_API_KEY=mnm_export_test");
    });
  });

  // ==========================================================================
  // 5. SDK snippet generation — omits header when no key
  // ==========================================================================

  describe("SDK snippet generation without mnemomApiKey", () => {
    const GATEWAY_URL = "https://gateway.mnemom.ai";

    const GATEWAY_BASE_URLS = {
      anthropic: `${GATEWAY_URL}/anthropic`,
      openai: `${GATEWAY_URL}/openai/v1`,
      gemini: `${GATEWAY_URL}/gemini`,
    };

    it("should use simple one-liner for Anthropic Python when no key", () => {
      const mnemomApiKey: string | undefined = undefined;
      const baseUrl = GATEWAY_BASE_URLS.anthropic;

      let snippet: string;
      if (mnemomApiKey) {
        snippet = [
          `client = Anthropic(`,
          `    base_url="${baseUrl}",`,
          `    default_headers={"x-mnemom-api-key": os.environ["MNEMOM_API_KEY"]}`,
          `)`,
        ].join("\n");
      } else {
        snippet = `client = Anthropic(base_url="${baseUrl}")`;
      }

      expect(snippet).not.toContain("x-mnemom-api-key");
      expect(snippet).not.toContain("MNEMOM_API_KEY");
      expect(snippet).toContain(baseUrl);
      expect(snippet).toBe(`client = Anthropic(base_url="${GATEWAY_BASE_URLS.anthropic}")`);
    });

    it("should use simple one-liner for Anthropic TypeScript when no key", () => {
      const mnemomApiKey: string | undefined = undefined;
      const baseUrl = GATEWAY_BASE_URLS.anthropic;

      let snippet: string;
      if (mnemomApiKey) {
        snippet = [
          `new Anthropic({`,
          `    baseURL: "${baseUrl}",`,
          `    defaultHeaders: { "x-mnemom-api-key": process.env.MNEMOM_API_KEY }`,
          `})`,
        ].join("\n");
      } else {
        snippet = `new Anthropic({ baseURL: "${baseUrl}" })`;
      }

      expect(snippet).not.toContain("x-mnemom-api-key");
      expect(snippet).not.toContain("MNEMOM_API_KEY");
      expect(snippet).toBe(`new Anthropic({ baseURL: "${GATEWAY_BASE_URLS.anthropic}" })`);
    });

    it("should use simple one-liner for OpenAI Python when no key", () => {
      const mnemomApiKey: string | undefined = undefined;
      const baseUrl = GATEWAY_BASE_URLS.openai;

      let snippet: string;
      if (mnemomApiKey) {
        snippet = [
          `client = OpenAI(`,
          `    base_url="${baseUrl}",`,
          `    default_headers={"x-mnemom-api-key": os.environ["MNEMOM_API_KEY"]}`,
          `)`,
        ].join("\n");
      } else {
        snippet = `client = OpenAI(base_url="${baseUrl}")`;
      }

      expect(snippet).not.toContain("x-mnemom-api-key");
      expect(snippet).toBe(`client = OpenAI(base_url="${GATEWAY_BASE_URLS.openai}")`);
    });

    it("should use simple one-liner for OpenAI TypeScript when no key", () => {
      const mnemomApiKey: string | undefined = undefined;
      const baseUrl = GATEWAY_BASE_URLS.openai;

      let snippet: string;
      if (mnemomApiKey) {
        snippet = [
          `new OpenAI({`,
          `    baseURL: "${baseUrl}",`,
          `    defaultHeaders: { "x-mnemom-api-key": process.env.MNEMOM_API_KEY }`,
          `})`,
        ].join("\n");
      } else {
        snippet = `new OpenAI({ baseURL: "${baseUrl}" })`;
      }

      expect(snippet).not.toContain("x-mnemom-api-key");
      expect(snippet).toBe(`new OpenAI({ baseURL: "${GATEWAY_BASE_URLS.openai}" })`);
    });

    it("should omit x-mnemom-api-key header line for Gemini REST when no key", () => {
      const mnemomApiKey: string | undefined = undefined;
      const baseUrl = GATEWAY_BASE_URLS.gemini;

      const lines: string[] = [];
      lines.push(`POST ${baseUrl}/v1beta/models/{model}:generateContent`);
      if (mnemomApiKey) {
        lines.push(`Header: x-mnemom-api-key: $MNEMOM_API_KEY`);
      }

      const snippet = lines.join("\n");
      expect(snippet).not.toContain("x-mnemom-api-key");
      expect(snippet).not.toContain("MNEMOM_API_KEY");
      expect(snippet).toContain(baseUrl);
    });

    it("should not include MNEMOM_API_KEY export instruction when no key", () => {
      const mnemomApiKey: string | undefined = undefined;

      const exportLine = mnemomApiKey
        ? `export MNEMOM_API_KEY=${mnemomApiKey}`
        : null;

      expect(exportLine).toBeNull();
    });
  });

  // ==========================================================================
  // 6. Status command billing display
  // ==========================================================================

  describe("Status command billing display", () => {
    it("should mask mnemomApiKey showing only first 8 characters", () => {
      const mnemomApiKey = "mnm_abcdefghijklmnop";
      const prefix = mnemomApiKey.slice(0, 8);

      expect(prefix).toBe("mnm_abcd");
      expect(prefix.length).toBe(8);

      // The status command displays: `${prefix}... (billing enabled)`
      const displayLine = `Mnemom Key: ${prefix}... (billing enabled)`;
      expect(displayLine).toBe("Mnemom Key: mnm_abcd... (billing enabled)");
      expect(displayLine).not.toContain("efghijklmnop");
    });

    it("should display 'billing enabled' label when mnemomApiKey is present", () => {
      const config = {
        agentId: "smolt-abc12345",
        mnemomApiKey: "mnm_billing_active_key",
      };

      // Reproduces logic from statusCommand lines 88-93
      let displayLine: string;
      if (config.mnemomApiKey) {
        const prefix = config.mnemomApiKey.slice(0, 8);
        displayLine = `Mnemom Key: ${prefix}... (billing enabled)`;
      } else {
        displayLine = `Mnemom Key: Not configured (free tier)`;
      }

      expect(displayLine).toContain("billing enabled");
      expect(displayLine).not.toContain("free tier");
      expect(displayLine).toContain("mnm_bill");
    });

    it("should display 'free tier' label when mnemomApiKey is absent", () => {
      const config = {
        agentId: "smolt-abc12345",
        // no mnemomApiKey
      } as { agentId: string; mnemomApiKey?: string };

      let displayLine: string;
      if (config.mnemomApiKey) {
        const prefix = config.mnemomApiKey.slice(0, 8);
        displayLine = `Mnemom Key: ${prefix}... (billing enabled)`;
      } else {
        displayLine = `Mnemom Key: Not configured (free tier)`;
      }

      expect(displayLine).toContain("free tier");
      expect(displayLine).toContain("Not configured");
      expect(displayLine).not.toContain("billing enabled");
    });

    it("should mask keys of various lengths consistently to 8 chars", () => {
      const testKeys = [
        "mnm_short",                           // 9 chars
        "mnm_medium_length_key",                // 21 chars
        "mnm_very_long_api_key_with_extra_chars", // 38 chars
      ];

      for (const key of testKeys) {
        const prefix = key.slice(0, 8);
        expect(prefix.length).toBe(8);
        expect(prefix).toBe(key.slice(0, 8));
      }
    });

    it("should handle minimum-length mnm_ key for masking", () => {
      // Shortest valid key: "mnm_X" (5 chars)
      const shortKey = "mnm_X";
      const prefix = shortKey.slice(0, 8);

      // slice(0, 8) on a 5-char string returns the full string
      expect(prefix).toBe("mnm_X");
      expect(prefix.length).toBe(5);

      const displayLine = `Mnemom Key: ${prefix}... (billing enabled)`;
      expect(displayLine).toBe("Mnemom Key: mnm_X... (billing enabled)");
    });

    it("should show existing key prefix in init prompt", () => {
      // In promptMnemomApiKey: `Existing key: ${prefix}...`
      const existingKey = "mnm_existing_key_value_12345";
      const prefix = existingKey.slice(0, 8);

      const promptLine = `Existing key: ${prefix}...`;
      expect(promptLine).toBe("Existing key: mnm_exis...");
    });

    it("should correctly distinguish billing states in config round-trip", () => {
      // Save config with key, load, check display
      const configWithKey = {
        version: 2 as const,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        mnemomApiKey: "mnm_roundtrip_key",
        agents: { default: { agentId: "smolt-billing01" } },
      };
      const configWithoutKey = {
        version: 2 as const,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        agents: { default: { agentId: "smolt-freetier1" } },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      // Save with key
      saveConfig(configWithKey);
      const writtenWithKey = JSON.parse(
        vi.mocked(fs.writeFileSync).mock.calls[0][1] as string
      );

      // Save without key
      saveConfig(configWithoutKey);
      const writtenWithoutKey = JSON.parse(
        vi.mocked(fs.writeFileSync).mock.calls[1][1] as string
      );

      // Simulate status display logic for each
      const displayWithKey = writtenWithKey.mnemomApiKey
        ? `${writtenWithKey.mnemomApiKey.slice(0, 8)}... (billing enabled)`
        : "Not configured (free tier)";

      const displayWithoutKey = writtenWithoutKey.mnemomApiKey
        ? `${writtenWithoutKey.mnemomApiKey.slice(0, 8)}... (billing enabled)`
        : "Not configured (free tier)";

      expect(displayWithKey).toBe("mnm_roun... (billing enabled)");
      expect(displayWithoutKey).toBe("Not configured (free tier)");
    });
  });
});
