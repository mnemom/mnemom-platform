import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock fs so loadAuthStore inside auth.ts is controllable
vi.mock("node:fs");

// Mock config.js — only the exports that still exist
vi.mock("../lib/config.js", () => ({
  getApiUrl: () => "https://api.mnemom.ai",
  getWebsiteUrl: () => "https://mnemom.ai",
  MNEMOM_DIR: "/home/testuser/.mnemom",
}));

import * as fs from "node:fs";
import {
  getAccessToken,
  getMnemomApiKey,
  getAuthInfo,
  resolveAuth,
  requireAuth,
  type AuthCredential,
} from "../lib/auth.js";

/** Helper: make fs.existsSync/readFileSync return a stored auth file. */
function mockAuthStore(store: {
  auth?: {
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
    userId: string;
    email: string;
  };
  licenseJwt?: string;
} | null): void {
  if (store === null) {
    vi.mocked(fs.existsSync).mockReturnValue(false);
  } else {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(store));
  }
}

describe("auth", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.MNEMOM_TOKEN;
    delete process.env.SMOLTBOT_TOKEN;
    delete process.env.MNEMOM_API_KEY;
    vi.clearAllMocks();
    // Default: no auth store on disk
    mockAuthStore(null);
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

    it("should return null when nothing configured", () => {
      expect(getMnemomApiKey()).toBeNull();
    });
  });

  describe("getAuthInfo", () => {
    it("should return null when no auth store exists", () => {
      mockAuthStore(null);
      expect(getAuthInfo()).toBeNull();
    });

    it("should return stored tokens when auth store exists", () => {
      mockAuthStore({
        auth: {
          accessToken: "stored_jwt",
          refreshToken: "refresh",
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          userId: "user-1",
          email: "test@test.com",
        },
      });
      const info = getAuthInfo();
      expect(info).not.toBeNull();
      expect(info!.accessToken).toBe("stored_jwt");
      expect(info!.email).toBe("test@test.com");
    });
  });

  describe("resolveAuth", () => {
    it("should return JWT when MNEMOM_TOKEN is set", async () => {
      process.env.MNEMOM_TOKEN = "jwt_token_123";
      const cred = await resolveAuth();
      expect(cred).toEqual({ type: "jwt", token: "jwt_token_123" });
    });

    it("should return JWT from stored auth", async () => {
      mockAuthStore({
        auth: {
          accessToken: "stored_jwt",
          refreshToken: "refresh",
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          userId: "user-1",
          email: "test@test.com",
        },
      });
      const cred = await resolveAuth();
      expect(cred).toEqual({ type: "jwt", token: "stored_jwt" });
    });

    it("should fall back to API key when no JWT", async () => {
      process.env.MNEMOM_API_KEY = "mnm_fallback_key";
      const cred = await resolveAuth();
      expect(cred).toEqual({ type: "api-key", key: "mnm_fallback_key" });
    });

    it("should return none when nothing configured", async () => {
      const cred = await resolveAuth();
      expect(cred).toEqual({ type: "none" });
    });

    it("should prefer JWT over API key when both available", async () => {
      process.env.MNEMOM_TOKEN = "jwt_token";
      process.env.MNEMOM_API_KEY = "mnm_api_key";
      const cred = await resolveAuth();
      expect(cred.type).toBe("jwt");
    });
  });

  describe("requireAuth", () => {
    it("should return JWT credential when available", async () => {
      process.env.MNEMOM_TOKEN = "jwt_token";
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
        "Authentication required. Run `mnemom login` or set MNEMOM_API_KEY."
      );

      mockExit.mockRestore();
      mockError.mockRestore();
    });
  });
});
