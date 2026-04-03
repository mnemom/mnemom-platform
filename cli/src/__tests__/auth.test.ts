import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock config module before importing auth
vi.mock("../lib/config.js", () => ({
  getApiUrl: () => "https://api.mnemom.ai",
  getWebsiteUrl: () => "https://mnemom.ai",
  getAuthInfo: vi.fn(),
  saveAuthTokens: vi.fn(),
  loadConfig: vi.fn(),
}));

import {
  getAccessToken,
  getMnemomApiKey,
  resolveAuth,
  requireAuth,
  type AuthCredential,
} from "../lib/auth.js";
import { getAuthInfo, loadConfig } from "../lib/config.js";

describe("auth", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.SMOLTBOT_TOKEN;
    delete process.env.MNEMOM_API_KEY;
    vi.mocked(getAuthInfo).mockReturnValue(null);
    vi.mocked(loadConfig).mockReturnValue(null);
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  describe("getMnemomApiKey", () => {
    it("should return MNEMOM_API_KEY env var when set", () => {
      process.env.MNEMOM_API_KEY = "mnm_env_key_123";
      expect(getMnemomApiKey()).toBe("mnm_env_key_123");
    });

    it("should return config mnemomApiKey when no env var", () => {
      vi.mocked(loadConfig).mockReturnValue({
        gateway: "https://gateway.mnemom.ai",
        agents: {},
        defaultAgent: "default",
        mnemomApiKey: "mnm_config_key_456",
      });
      expect(getMnemomApiKey()).toBe("mnm_config_key_456");
    });

    it("should prefer env var over config", () => {
      process.env.MNEMOM_API_KEY = "mnm_env_key";
      vi.mocked(loadConfig).mockReturnValue({
        gateway: "https://gateway.mnemom.ai",
        agents: {},
        defaultAgent: "default",
        mnemomApiKey: "mnm_config_key",
      });
      expect(getMnemomApiKey()).toBe("mnm_env_key");
    });

    it("should return null when nothing configured", () => {
      expect(getMnemomApiKey()).toBeNull();
    });
  });

  describe("resolveAuth", () => {
    it("should return JWT when SMOLTBOT_TOKEN is set", async () => {
      process.env.SMOLTBOT_TOKEN = "jwt_token_123";
      const cred = await resolveAuth();
      expect(cred).toEqual({ type: "jwt", token: "jwt_token_123" });
    });

    it("should return JWT from stored auth", async () => {
      vi.mocked(getAuthInfo).mockReturnValue({
        accessToken: "stored_jwt",
        refreshToken: "refresh",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        userId: "user-1",
        email: "test@test.com",
      });
      const cred = await resolveAuth();
      expect(cred).toEqual({ type: "jwt", token: "stored_jwt" });
    });

    it("should fall back to API key when no JWT", async () => {
      process.env.MNEMOM_API_KEY = "mnm_fallback_key";
      const cred = await resolveAuth();
      expect(cred).toEqual({ type: "api-key", key: "mnm_fallback_key" });
    });

    it("should fall back to config API key", async () => {
      vi.mocked(loadConfig).mockReturnValue({
        gateway: "https://gateway.mnemom.ai",
        agents: {},
        defaultAgent: "default",
        mnemomApiKey: "mnm_config_key",
      });
      const cred = await resolveAuth();
      expect(cred).toEqual({ type: "api-key", key: "mnm_config_key" });
    });

    it("should return none when nothing configured", async () => {
      const cred = await resolveAuth();
      expect(cred).toEqual({ type: "none" });
    });

    it("should prefer JWT over API key when both available", async () => {
      process.env.SMOLTBOT_TOKEN = "jwt_token";
      process.env.MNEMOM_API_KEY = "mnm_api_key";
      const cred = await resolveAuth();
      expect(cred.type).toBe("jwt");
    });
  });

  describe("requireAuth", () => {
    it("should return JWT credential when available", async () => {
      process.env.SMOLTBOT_TOKEN = "jwt_token";
      const cred = await requireAuth();
      expect(cred.type).toBe("jwt");
    });

    it("should return API key credential when no JWT", async () => {
      process.env.MNEMOM_API_KEY = "mnm_key";
      const cred = await requireAuth();
      expect(cred.type).toBe("api-key");
    });

    it("should exit when no credentials", async () => {
      const mockExit = vi.spyOn(process, "exit").mockImplementation(() => {
        throw new Error("process.exit");
      });
      const mockError = vi.spyOn(console, "error").mockImplementation(() => {});

      await expect(requireAuth()).rejects.toThrow("process.exit");
      expect(mockExit).toHaveBeenCalledWith(1);
      expect(mockError).toHaveBeenCalledWith(
        "Authentication required. Run `smoltbot login` or set MNEMOM_API_KEY."
      );

      mockExit.mockRestore();
      mockError.mockRestore();
    });
  });
});
