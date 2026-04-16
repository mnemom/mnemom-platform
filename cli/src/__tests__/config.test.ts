import { describe, it, expect, beforeEach, afterEach } from "vitest";

// Import module under test
import {
  getEnvironment,
  getApiUrl,
  getGatewayUrl,
  getWebsiteUrl,
  MNEMOM_DIR,
} from "../lib/config.js";

describe("config", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.MNEMOM_ENV;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("MNEMOM_DIR", () => {
    it("should point to ~/.mnemom", () => {
      expect(MNEMOM_DIR).toMatch(/\.mnemom$/);
    });
  });

  describe("getEnvironment", () => {
    it("should default to production when MNEMOM_ENV is unset", () => {
      expect(getEnvironment()).toBe("production");
    });

    it("should return staging when MNEMOM_ENV=staging", () => {
      process.env.MNEMOM_ENV = "staging";
      expect(getEnvironment()).toBe("staging");
    });

    it("should return local when MNEMOM_ENV=local", () => {
      process.env.MNEMOM_ENV = "local";
      expect(getEnvironment()).toBe("local");
    });

    it("should default to production for unknown values", () => {
      process.env.MNEMOM_ENV = "bogus";
      expect(getEnvironment()).toBe("production");
    });
  });

  describe("getApiUrl / getGatewayUrl / getWebsiteUrl", () => {
    it("should return production URLs by default", () => {
      expect(getApiUrl()).toBe("https://api.mnemom.ai");
      expect(getGatewayUrl()).toBe("https://gateway.mnemom.ai");
      expect(getWebsiteUrl()).toBe("https://www.mnemom.ai");
    });

    it("should return staging URLs when MNEMOM_ENV=staging", () => {
      process.env.MNEMOM_ENV = "staging";
      expect(getApiUrl()).toBe("https://api-staging.mnemom.ai");
      expect(getGatewayUrl()).toBe("https://gateway-staging.mnemom.ai");
      expect(getWebsiteUrl()).toBe("https://staging.mnemom.ai");
    });

    it("should return local URLs when MNEMOM_ENV=local", () => {
      process.env.MNEMOM_ENV = "local";
      expect(getApiUrl()).toBe("http://localhost:8787");
      expect(getGatewayUrl()).toBe("http://localhost:8787");
      expect(getWebsiteUrl()).toBe("http://localhost:5173");
    });
  });
});
