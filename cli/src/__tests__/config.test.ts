import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as realCrypto from "node:crypto";

// Use vi.hoisted to ensure mocks are set up before module imports
const mockHomedir = vi.hoisted(() => vi.fn(() => "/home/testuser"));
const mockRandomBytes = vi.hoisted(() =>
  vi.fn(() => Buffer.from("deadbeef", "hex"))
);

// Mock the node modules before importing the module under test
vi.mock("node:fs");
vi.mock("node:os", () => ({
  homedir: mockHomedir,
}));
vi.mock("node:crypto", async () => {
  const actual = await vi.importActual<typeof import("node:crypto")>("node:crypto");
  return {
    ...actual,
    randomBytes: mockRandomBytes,
  };
});

// Import fs after mocking (for type-safe mock access)
import * as fs from "node:fs";

// Import module under test after mocking
import {
  configExists,
  loadConfig,
  saveConfig,
  generateAgentId,
  deriveAgentId,
  deriveAgentIdWithName,
  CONFIG_DIR,
  CONFIG_FILE,
} from "../lib/config.js";

describe("config", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("CONFIG_DIR and CONFIG_FILE", () => {
    it("should set CONFIG_DIR to ~/.smoltbot", () => {
      expect(CONFIG_DIR).toBe("/home/testuser/.smoltbot");
    });

    it("should set CONFIG_FILE to ~/.smoltbot/config.json", () => {
      expect(CONFIG_FILE).toBe("/home/testuser/.smoltbot/config.json");
    });
  });

  describe("generateAgentId", () => {
    // ADR-019 / scale/step-25b: new agents use mnm-{uuid_v4} format
    it("should generate an agent ID with mnm- prefix and UUID v4 format", () => {
      const agentId = generateAgentId();
      expect(agentId).toMatch(
        /^mnm-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      );
    });

    it("should use crypto.randomUUID() (not randomBytes)", () => {
      const agentId = generateAgentId();
      // Verify it no longer uses randomBytes mock ("deadbeef" would appear in smolt- IDs)
      expect(agentId).not.toContain("smolt-");
      expect(agentId.startsWith("mnm-")).toBe(true);
    });

    it("should generate distinct IDs on each call", () => {
      const id1 = generateAgentId();
      const id2 = generateAgentId();
      // UUID v4 is random — two calls should produce different values
      expect(id1).not.toBe(id2);
    });
  });

  describe("deriveAgentId", () => {
    it("should derive a deterministic agent ID from an API key using SHA-256", () => {
      const id = deriveAgentId("test-api-key");
      // SHA-256("test-api-key") starts with 4c806362...
      expect(id).toBe("smolt-4c806362");
    });

    it("should produce the same ID for the same input", () => {
      const id1 = deriveAgentId("test-api-key");
      const id2 = deriveAgentId("test-api-key");
      expect(id1).toBe(id2);
    });

    it("should produce different IDs for different inputs", () => {
      const id1 = deriveAgentId("key-a");
      const id2 = deriveAgentId("key-b");
      expect(id1).not.toBe(id2);
    });

    it("should match the gateway SHA-256 algorithm", () => {
      // Verify our output matches: SHA-256 hex digest, first 8 chars, prefixed with "smolt-"
      const input = "test-api-key";
      const expectedHash = realCrypto.createHash("sha256").update(input).digest("hex");
      const expectedId = `smolt-${expectedHash.slice(0, 8)}`;
      expect(deriveAgentId(input)).toBe(expectedId);
    });
  });

  describe("deriveAgentIdWithName", () => {
    it("should derive a deterministic agent ID from API key and name using SHA-256", () => {
      const id = deriveAgentIdWithName("test-api-key", "test");
      // SHA-256("test-api-key|test") starts with 9131dd88...
      expect(id).toBe("smolt-9131dd88");
    });

    it("should produce the same ID for the same inputs", () => {
      const id1 = deriveAgentIdWithName("test-api-key", "test");
      const id2 = deriveAgentIdWithName("test-api-key", "test");
      expect(id1).toBe(id2);
    });

    it("should produce different IDs for different agent names", () => {
      const idA = deriveAgentIdWithName("test-api-key", "agent-a");
      const idB = deriveAgentIdWithName("test-api-key", "agent-b");
      expect(idA).not.toBe(idB);
      // SHA-256("test-api-key|agent-a") starts with f2cfc889
      expect(idA).toBe("smolt-f2cfc889");
      // SHA-256("test-api-key|agent-b") starts with 4fc16314
      expect(idB).toBe("smolt-4fc16314");
    });

    it("should match the gateway SHA-256 algorithm (apiKey + '|' + name)", () => {
      // Gateway computes: hashApiKey(apiKey + '|' + name) where hashApiKey = SHA-256 first 16 hex
      // Then agentId = "smolt-" + hash.slice(0, 8)
      const apiKey = "sk-ant-test-key-12345";
      const name = "my-agent";
      const gatewayInput = `${apiKey}|${name}`;
      const expectedHash = realCrypto.createHash("sha256").update(gatewayInput).digest("hex");
      const expectedId = `smolt-${expectedHash.slice(0, 8)}`;
      expect(deriveAgentIdWithName(apiKey, name)).toBe(expectedId);
    });

    it("should differ from deriveAgentId for the same API key", () => {
      const idDefault = deriveAgentId("test-api-key");
      const idNamed = deriveAgentIdWithName("test-api-key", "default");
      expect(idDefault).not.toBe(idNamed);
    });
  });

  describe("configExists", () => {
    it("should return true when config file exists", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);

      const result = configExists();

      expect(result).toBe(true);
      expect(fs.existsSync).toHaveBeenCalledWith(CONFIG_FILE);
    });

    it("should return false when config file does not exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const result = configExists();

      expect(result).toBe(false);
      expect(fs.existsSync).toHaveBeenCalledWith(CONFIG_FILE);
    });
  });

  describe("loadConfig", () => {
    it("should return null when config does not exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const result = loadConfig();

      expect(result).toBeNull();
    });

    it("should return config when file exists and is valid JSON", () => {
      const mockConfig = {
        version: 2,
        defaultAgent: "default",
        gateway: "https://gateway.mnemon.ai",
        agents: {
          default: {
            agentId: "smolt-abc12345",
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const result = loadConfig();

      expect(result).toEqual(mockConfig);
      expect(fs.readFileSync).toHaveBeenCalledWith(CONFIG_FILE, "utf-8");
    });

    it("should return config with only required fields", () => {
      const mockConfig = {
        version: 2,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        agents: {
          default: {
            agentId: "smolt-minimal",
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const result = loadConfig();

      expect(result).toEqual(mockConfig);
      expect(result?.mnemomApiKey).toBeUndefined();
      expect(result?.licenseJwt).toBeUndefined();
    });

    it("should return null when file contains invalid JSON", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue("not valid json");

      const result = loadConfig();

      expect(result).toBeNull();
    });

    it("should return null when file is empty", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue("");

      const result = loadConfig();

      expect(result).toBeNull();
    });

    it("should return null when reading file throws an error", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockImplementation(() => {
        throw new Error("Permission denied");
      });

      const result = loadConfig();

      expect(result).toBeNull();
    });
  });

  describe("saveConfig", () => {
    it("should create config directory if it does not exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);
      vi.mocked(fs.mkdirSync).mockReturnValue(undefined);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      const config = {
        version: 2 as const,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        agents: { default: { agentId: "smolt-test1234" } },
      };

      saveConfig(config);

      expect(fs.mkdirSync).toHaveBeenCalledWith(CONFIG_DIR, {
        recursive: true,
      });
    });

    it("should not create directory if it already exists", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      const config = {
        version: 2 as const,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        agents: { default: { agentId: "smolt-test1234" } },
      };

      saveConfig(config);

      expect(fs.mkdirSync).not.toHaveBeenCalled();
    });

    it("should write config as formatted JSON", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      const config = {
        version: 2 as const,
        defaultAgent: "default",
        gateway: "https://gateway.mnemon.ai",
        agents: {
          default: { agentId: "smolt-test1234" },
        },
      };

      saveConfig(config);

      expect(fs.writeFileSync).toHaveBeenCalledWith(
        expect.stringContaining("config.json"),
        JSON.stringify(config, null, 2)
      );
      expect(fs.renameSync).toHaveBeenCalledWith(
        expect.stringContaining(".tmp"),
        CONFIG_FILE
      );
    });

    it("should write to the correct config file path", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      const config = {
        version: 2 as const,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        agents: { default: { agentId: "smolt-test1234" } },
      };

      saveConfig(config);

      expect(fs.renameSync).toHaveBeenCalledWith(
        expect.any(String),
        "/home/testuser/.smoltbot/config.json"
      );
    });

    it("should preserve optional fields when saving", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      const config = {
        version: 2 as const,
        defaultAgent: "default",
        gateway: "https://gateway.mnemom.ai",
        mnemomApiKey: "mnm_test_key",
        agents: {
          default: { agentId: "smolt-test1234" },
        },
      };

      saveConfig(config);

      const writtenContent = vi.mocked(fs.writeFileSync).mock.calls[0][1];
      const parsedConfig = JSON.parse(writtenContent as string);

      expect(parsedConfig.agents.default.agentId).toBe("smolt-test1234");
      expect(parsedConfig.mnemomApiKey).toBe("mnm_test_key");
      expect(parsedConfig.licenseJwt).toBeUndefined();
    });
  });
});
