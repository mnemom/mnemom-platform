import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Use vi.hoisted to ensure mocks are set up before module imports
const mockHomedir = vi.hoisted(() => vi.fn(() => "/home/testuser"));

// Mock the node modules before importing the module under test
vi.mock("node:fs");
vi.mock("node:os", () => ({
  homedir: mockHomedir,
}));

// Import fs after mocking (for type-safe mock access)
import * as fs from "node:fs";

// Import module under test after mocking
import {
  OPENCLAW_DIR,
  OPENCLAW_CONFIG_FILE,
  AUTH_PROFILES_FILE,
  openclawExists,
  loadAuthProfiles,
  getAnthropicApiKey,
  loadOpenClawConfig,
  saveOpenClawConfig,
  getCurrentModel,
  isSmoltbotConfigured,
  getSmoltbotProvider,
  detectOpenClaw,
  configureSmoltbotProvider,
  setDefaultModel,
  type OpenClawConfig,
  type AuthProfilesFile,
} from "../lib/openclaw.js";

// The canonical provider key for Anthropic is now "mnemom"
const ANTHROPIC_PROVIDER_KEY = "mnemom";

describe("openclaw", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("paths", () => {
    it("should set OPENCLAW_DIR to ~/.openclaw", () => {
      expect(OPENCLAW_DIR).toBe("/home/testuser/.openclaw");
    });

    it("should set OPENCLAW_CONFIG_FILE correctly", () => {
      expect(OPENCLAW_CONFIG_FILE).toBe("/home/testuser/.openclaw/openclaw.json");
    });

    it("should set AUTH_PROFILES_FILE correctly", () => {
      expect(AUTH_PROFILES_FILE).toBe(
        "/home/testuser/.openclaw/agents/main/agent/auth-profiles.json"
      );
    });
  });

  describe("openclawExists", () => {
    it("should return true when both dir and config exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);

      const result = openclawExists();

      expect(result).toBe(true);
      expect(fs.existsSync).toHaveBeenCalledWith(OPENCLAW_DIR);
      expect(fs.existsSync).toHaveBeenCalledWith(OPENCLAW_CONFIG_FILE);
    });

    it("should return false when dir does not exist", () => {
      vi.mocked(fs.existsSync).mockReturnValueOnce(false);

      const result = openclawExists();

      expect(result).toBe(false);
    });

    it("should return false when config file does not exist", () => {
      vi.mocked(fs.existsSync)
        .mockReturnValueOnce(true) // dir exists
        .mockReturnValueOnce(false); // config doesn't

      const result = openclawExists();

      expect(result).toBe(false);
    });
  });

  describe("loadAuthProfiles", () => {
    it("should return null when file does not exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const result = loadAuthProfiles();

      expect(result).toBeNull();
    });

    it("should return parsed auth profiles when file exists", () => {
      const mockProfiles: AuthProfilesFile = {
        version: 1,
        profiles: {
          "anthropic:default": {
            type: "api_key",
            provider: "anthropic",
            key: "sk-ant-test-key",
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockProfiles));

      const result = loadAuthProfiles();

      expect(result).toEqual(mockProfiles);
    });

    it("should return null when file contains invalid JSON", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue("not valid json");

      const result = loadAuthProfiles();

      expect(result).toBeNull();
    });
  });

  describe("getAnthropicApiKey", () => {
    it("should return key when api_key profile exists", () => {
      const mockProfiles: AuthProfilesFile = {
        version: 1,
        profiles: {
          "anthropic:default": {
            type: "api_key",
            provider: "anthropic",
            key: "sk-ant-test-key",
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockProfiles));

      const result = getAnthropicApiKey();

      expect(result).toEqual({ key: "sk-ant-test-key", isOAuth: false });
    });

    it("should return isOAuth true when oauth profile exists", () => {
      const mockProfiles: AuthProfilesFile = {
        version: 1,
        profiles: {
          "anthropic:default": {
            type: "oauth",
            provider: "anthropic",
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockProfiles));

      const result = getAnthropicApiKey();

      expect(result).toEqual({ key: null, isOAuth: true });
    });

    it("should return null key when no anthropic profile exists", () => {
      const mockProfiles: AuthProfilesFile = {
        version: 1,
        profiles: {},
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockProfiles));

      const result = getAnthropicApiKey();

      expect(result).toEqual({ key: null, isOAuth: false });
    });

    it("should return null when profiles file doesn't exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const result = getAnthropicApiKey();

      expect(result).toEqual({ key: null, isOAuth: false });
    });
  });

  describe("loadOpenClawConfig", () => {
    it("should return null when file does not exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const result = loadOpenClawConfig();

      expect(result).toBeNull();
    });

    it("should return parsed config when file exists", () => {
      const mockConfig: OpenClawConfig = {
        meta: { lastTouchedAt: "2024-01-01" },
        models: {
          mode: "merge",
          providers: {},
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const result = loadOpenClawConfig();

      expect(result).toEqual(mockConfig);
    });
  });

  describe("saveOpenClawConfig", () => {
    it("should write config with updated timestamp", () => {
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      const config: OpenClawConfig = {
        models: { mode: "merge" },
      };

      saveOpenClawConfig(config);

      expect(fs.writeFileSync).toHaveBeenCalledWith(
        OPENCLAW_CONFIG_FILE,
        expect.any(String)
      );

      const writtenContent = vi.mocked(fs.writeFileSync).mock.calls[0][1];
      const parsedConfig = JSON.parse(writtenContent as string);

      expect(parsedConfig.meta).toBeDefined();
      expect(parsedConfig.meta.lastTouchedAt).toBeDefined();
    });
  });

  describe("getCurrentModel", () => {
    it("should return null values when config doesn't exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const result = getCurrentModel();

      expect(result).toEqual({
        fullPath: null,
        provider: null,
        modelId: null,
      });
    });

    it("should parse provider/model format correctly", () => {
      const mockConfig: OpenClawConfig = {
        agents: {
          defaults: {
            model: {
              primary: "smoltbot/claude-opus-4-5-20251101",
            },
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const result = getCurrentModel();

      expect(result).toEqual({
        fullPath: "smoltbot/claude-opus-4-5-20251101",
        provider: "smoltbot",
        modelId: "claude-opus-4-5-20251101",
      });
    });

    it("should handle model without provider prefix", () => {
      const mockConfig: OpenClawConfig = {
        agents: {
          defaults: {
            model: {
              primary: "claude-opus-4-5-20251101",
            },
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const result = getCurrentModel();

      expect(result).toEqual({
        fullPath: "claude-opus-4-5-20251101",
        provider: null,
        modelId: "claude-opus-4-5-20251101",
      });
    });
  });

  describe("isSmoltbotConfigured", () => {
    it("should return false when config doesn't exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const result = isSmoltbotConfigured();

      expect(result).toBe(false);
    });

    it("should return false when smoltbot provider not configured", () => {
      const mockConfig: OpenClawConfig = {
        models: {
          providers: {},
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const result = isSmoltbotConfigured();

      expect(result).toBe(false);
    });

    it("should return true when mnemom provider is configured (new key)", () => {
      const mockConfig: OpenClawConfig = {
        models: {
          providers: {
            mnemom: {
              baseUrl: "https://gateway.mnemom.ai/anthropic",
              apiKey: "test-key",
              api: "anthropic-messages",
              models: [],
            },
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const result = isSmoltbotConfigured();

      expect(result).toBe(true);
    });

    it("should return true when legacy smoltbot provider key exists (backward compat)", () => {
      const mockConfig: OpenClawConfig = {
        models: {
          providers: {
            smoltbot: {
              baseUrl: "https://gateway.mnemom.ai/anthropic",
              apiKey: "test-key",
              api: "anthropic-messages",
              models: [],
            },
          },
        },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const result = isSmoltbotConfigured();

      expect(result).toBe(true);
    });
  });

  describe("detectOpenClaw", () => {
    it("should return not installed when openclaw dir doesn't exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const result = detectOpenClaw();

      expect(result.installed).toBe(false);
      expect(result.error).toContain("not installed");
    });

    it("should detect OAuth and return error", () => {
      // Mock openclaw exists
      vi.mocked(fs.existsSync).mockImplementation((path) => {
        if (path === OPENCLAW_DIR || path === OPENCLAW_CONFIG_FILE) return true;
        if (path === AUTH_PROFILES_FILE) return true;
        return false;
      });

      const mockProfiles: AuthProfilesFile = {
        version: 1,
        profiles: {
          "anthropic:default": {
            type: "oauth",
            provider: "anthropic",
          },
        },
      };

      const mockConfig: OpenClawConfig = {};

      vi.mocked(fs.readFileSync).mockImplementation((path) => {
        if (String(path).includes("auth-profiles")) {
          return JSON.stringify(mockProfiles);
        }
        return JSON.stringify(mockConfig);
      });

      const result = detectOpenClaw();

      expect(result.installed).toBe(true);
      expect(result.isOAuth).toBe(true);
      expect(result.hasApiKey).toBe(false);
      expect(result.error).toContain("OAuth");
    });

    it("should return full detection when everything is configured", () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);

      const mockProfiles: AuthProfilesFile = {
        version: 1,
        profiles: {
          "anthropic:default": {
            type: "api_key",
            provider: "anthropic",
            key: "sk-ant-test-key",
          },
        },
      };

      const mockConfig: OpenClawConfig = {
        models: {
          providers: {
            smoltbot: {
              baseUrl: "https://gateway.mnemom.ai/anthropic",
              apiKey: "sk-ant-test-key",
              api: "anthropic-messages",
              models: [],
            },
          },
        },
        agents: {
          defaults: {
            model: {
              primary: "smoltbot/claude-opus-4-5-20251101",
            },
          },
        },
      };

      vi.mocked(fs.readFileSync).mockImplementation((path) => {
        if (String(path).includes("auth-profiles")) {
          return JSON.stringify(mockProfiles);
        }
        return JSON.stringify(mockConfig);
      });

      const result = detectOpenClaw();

      expect(result.installed).toBe(true);
      expect(result.hasApiKey).toBe(true);
      expect(result.isOAuth).toBe(false);
      expect(result.apiKey).toBe("sk-ant-test-key");
      expect(result.currentModel).toBe("smoltbot/claude-opus-4-5-20251101");
      expect(result.currentProvider).toBe("smoltbot");
      expect(result.smoltbotAlreadyConfigured).toBe(true);
    });
  });

  describe("configureSmoltbotProvider", () => {
    it("should add mnemom provider to config (canonical key)", () => {
      const existingConfig: OpenClawConfig = {
        meta: { lastTouchedAt: "old-date" },
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(existingConfig));
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      const models = [
        {
          id: "claude-opus-4-5-20251101",
          name: "Claude Opus 4.5",
        },
      ];

      configureSmoltbotProvider("test-api-key", models);

      const writtenContent = vi.mocked(fs.writeFileSync).mock.calls[0][1];
      const parsedConfig = JSON.parse(writtenContent as string);

      // configureSmoltbotProvider now writes under "mnemom" key (PROVIDER_CONFIG_KEYS.anthropic)
      expect(parsedConfig.models.providers[ANTHROPIC_PROVIDER_KEY]).toBeDefined();
      expect(parsedConfig.models.providers[ANTHROPIC_PROVIDER_KEY].apiKey).toBe("test-api-key");
      expect(parsedConfig.models.providers[ANTHROPIC_PROVIDER_KEY].baseUrl).toBe(
        "https://gateway.mnemom.ai/anthropic"
      );
      expect(parsedConfig.models.providers[ANTHROPIC_PROVIDER_KEY].models).toEqual(models);
    });

    it("should throw error when config doesn't exist", () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      expect(() => configureSmoltbotProvider("key", [])).toThrow(
        "Could not load OpenClaw config"
      );
    });
  });

  describe("setDefaultModel", () => {
    it("should set the default model in config", () => {
      const existingConfig: OpenClawConfig = {
        meta: {},
      };

      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(existingConfig));
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      setDefaultModel("smoltbot/claude-opus-4-5-20251101");

      const writtenContent = vi.mocked(fs.writeFileSync).mock.calls[0][1];
      const parsedConfig = JSON.parse(writtenContent as string);

      expect(parsedConfig.agents.defaults.model.primary).toBe(
        "smoltbot/claude-opus-4-5-20251101"
      );
      expect(
        parsedConfig.agents.defaults.models["smoltbot/claude-opus-4-5-20251101"]
      ).toEqual({});
    });
  });
});
