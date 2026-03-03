import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

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
vi.mock("node:crypto", () => ({
  randomBytes: mockRandomBytes,
}));

// Import fs after mocking (for type-safe mock access)
import * as fs from "node:fs";

// Import module under test after mocking
import {
  configExists,
  loadConfig,
  saveConfig,
  generateAgentId,
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
    it("should generate an agent ID with smolt- prefix", () => {
      const agentId = generateAgentId();
      expect(agentId).toMatch(/^smolt-[a-f0-9]{8}$/);
    });

    it("should generate ID based on random bytes", () => {
      const agentId = generateAgentId();
      // With mocked randomBytes returning "deadbeef" as hex
      expect(agentId).toBe("smolt-deadbeef");
    });

    it("should generate different IDs when randomBytes returns different values", () => {
      mockRandomBytes.mockReturnValueOnce(Buffer.from("12345678", "hex"));

      const agentId = generateAgentId();

      expect(agentId).toBe("smolt-12345678");
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
