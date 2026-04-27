import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  getAgent,
  getIntegrity,
  getTraces,
  newIdempotencyKey,
  putAlignmentCard,
  putProtectionCard,
  API_BASE,
  type Agent,
  type IntegrityScore,
  type Trace,
} from "../lib/api.js";

// Store the original fetch
const originalFetch = globalThis.fetch;

describe("api", () => {
  beforeEach(() => {
    // Mock global fetch
    globalThis.fetch = vi.fn();
  });

  afterEach(() => {
    // Restore original fetch
    globalThis.fetch = originalFetch;
  });

  function mockFetchResponse<T>(data: T, ok = true, status = 200) {
    vi.mocked(globalThis.fetch).mockResolvedValue({
      ok,
      status,
      statusText: ok ? "OK" : "Error",
      json: vi.fn().mockResolvedValue(data),
    } as unknown as Response);
  }

  function mockFetchError(errorData: { error: string; message: string }) {
    vi.mocked(globalThis.fetch).mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: vi.fn().mockResolvedValue(errorData),
    } as unknown as Response);
  }

  describe("API_BASE", () => {
    it("should be set to the correct API URL", () => {
      expect(API_BASE).toBe("https://api.mnemom.ai");
    });
  });

  describe("getAgent", () => {
    it("should fetch agent by ID", async () => {
      const mockAgent: Agent = {
        id: "smolt-abc12345",
        gateway: "https://gateway.mnemom.ai",
        last_seen: "2024-01-15T10:30:00Z",
        claimed: true,
        email: "test@example.com",
        created_at: "2024-01-01T00:00:00Z",
      };

      mockFetchResponse(mockAgent);

      const result = await getAgent("smolt-abc12345");

      expect(result).toEqual(mockAgent);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        `${API_BASE}/v1/agents/smolt-abc12345`
      );
    });

    it("should handle unclaimed agent", async () => {
      const mockAgent: Agent = {
        id: "smolt-newagent",
        gateway: "https://gateway.mnemom.ai",
        last_seen: null,
        claimed: false,
        created_at: "2024-01-15T00:00:00Z",
      };

      mockFetchResponse(mockAgent);

      const result = await getAgent("smolt-newagent");

      expect(result).toEqual(mockAgent);
      expect(result.claimed).toBe(false);
      expect(result.last_seen).toBeNull();
    });

    it("should throw error when agent not found", async () => {
      mockFetchError({ error: "not_found", message: "Agent not found" });

      await expect(getAgent("smolt-nonexistent")).rejects.toThrow(
        "Agent not found"
      );
    });

    it("should handle API error with fallback message", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: vi.fn().mockRejectedValue(new Error("Parse error")),
      } as unknown as Response);

      await expect(getAgent("smolt-abc12345")).rejects.toThrow(
        "Internal Server Error"
      );
    });
  });

  describe("getIntegrity", () => {
    it("should fetch integrity score by agent ID", async () => {
      const mockIntegrity: IntegrityScore = {
        agent_id: "smolt-abc12345",
        score: 95.5,
        total_traces: 100,
        verified: 95,
        violations: 5,
        last_updated: "2024-01-15T12:00:00Z",
      };

      mockFetchResponse(mockIntegrity);

      const result = await getIntegrity("smolt-abc12345");

      expect(result).toEqual(mockIntegrity);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        `${API_BASE}/v1/integrity/smolt-abc12345`
      );
    });

    it("should handle zero score", async () => {
      const mockIntegrity: IntegrityScore = {
        agent_id: "smolt-newagent",
        score: 0,
        total_traces: 0,
        verified: 0,
        violations: 0,
        last_updated: "2024-01-15T00:00:00Z",
      };

      mockFetchResponse(mockIntegrity);

      const result = await getIntegrity("smolt-newagent");

      expect(result.score).toBe(0);
      expect(result.total_traces).toBe(0);
    });

    it("should throw error when integrity not found", async () => {
      mockFetchError({
        error: "not_found",
        message: "Integrity score not found",
      });

      await expect(getIntegrity("smolt-nonexistent")).rejects.toThrow(
        "Integrity score not found"
      );
    });
  });

  describe("getTraces", () => {
    it("should fetch traces with default limit", async () => {
      const mockTraces: Trace[] = [
        {
          id: "trace-1",
          agent_id: "smolt-abc12345",
          timestamp: "2024-01-15T10:00:00Z",
          action: "file_read",
          verified: true,
          tool_name: "Read",
          tool_input: { file_path: "/test/file.ts" },
        },
        {
          id: "trace-2",
          agent_id: "smolt-abc12345",
          timestamp: "2024-01-15T10:01:00Z",
          action: "file_write",
          verified: true,
          reasoning: "User requested file update",
          tool_name: "Write",
          tool_input: { file_path: "/test/output.ts", content: "test" },
        },
      ];

      mockFetchResponse(mockTraces);

      const result = await getTraces("smolt-abc12345");

      expect(result).toEqual(mockTraces);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        `${API_BASE}/v1/traces?agent_id=smolt-abc12345&limit=10`
      );
    });

    it("should fetch traces with custom limit", async () => {
      const mockTraces: Trace[] = [];

      mockFetchResponse(mockTraces);

      const result = await getTraces("smolt-abc12345", 50);

      expect(result).toEqual([]);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        `${API_BASE}/v1/traces?agent_id=smolt-abc12345&limit=50`
      );
    });

    it("should handle traces with optional fields", async () => {
      const mockTraces: Trace[] = [
        {
          id: "trace-1",
          agent_id: "smolt-abc12345",
          timestamp: "2024-01-15T10:00:00Z",
          action: "unknown_action",
          verified: false,
        },
      ];

      mockFetchResponse(mockTraces);

      const result = await getTraces("smolt-abc12345");

      expect(result[0].reasoning).toBeUndefined();
      expect(result[0].tool_name).toBeUndefined();
      expect(result[0].tool_input).toBeUndefined();
    });

    it("should throw error when fetch fails", async () => {
      mockFetchError({
        error: "unauthorized",
        message: "Invalid agent ID",
      });

      await expect(getTraces("invalid-id")).rejects.toThrow("Invalid agent ID");
    });

    it("should handle empty error message with status fallback", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValue({
        ok: false,
        status: 503,
        statusText: "Service Unavailable",
        json: vi.fn().mockResolvedValue({ error: "unavailable", message: "" }),
      } as unknown as Response);

      await expect(getTraces("smolt-abc12345")).rejects.toThrow(
        "API request failed: 503"
      );
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Idempotency-Key on mutations (ADR-039 / mnemom-api/src/idempotency.ts)
  // The API short-circuits with 400 if PUT/POST/DELETE arrives without the
  // header — every CLI mutation must mint or accept one.
  // ──────────────────────────────────────────────────────────────────────────

  describe("newIdempotencyKey", () => {
    it("returns a UUIDv4 string", () => {
      const key = newIdempotencyKey();
      expect(key).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });

    it("returns a different key on every call", () => {
      const a = newIdempotencyKey();
      const b = newIdempotencyKey();
      expect(a).not.toEqual(b);
    });
  });

  describe("putAlignmentCard", () => {
    it("sends an Idempotency-Key header on every PUT", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({ card_id: "ac-1", composed: true }),
      } as unknown as Response);

      await putAlignmentCard("mnm-test", "card_version: x", "text/yaml");

      const init = vi.mocked(globalThis.fetch).mock.calls[0][1] as RequestInit;
      const headers = init.headers as Record<string, string>;
      expect(headers["Idempotency-Key"]).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });

    it("uses the explicit idempotencyKey when provided (retry case)", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({ card_id: "ac-1", composed: true }),
      } as unknown as Response);

      const explicitKey = "11111111-1111-4111-8111-111111111111";
      await putAlignmentCard("mnm-test", "card_version: x", "text/yaml", {
        idempotencyKey: explicitKey,
      });

      const init = vi.mocked(globalThis.fetch).mock.calls[0][1] as RequestInit;
      const headers = init.headers as Record<string, string>;
      expect(headers["Idempotency-Key"]).toBe(explicitKey);
    });

    it("mints a fresh key on every call when none is provided", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({ card_id: "ac-1", composed: true }),
      } as unknown as Response);

      await putAlignmentCard("mnm-test", "card_version: x", "text/yaml");
      await putAlignmentCard("mnm-test", "card_version: x", "text/yaml");

      const calls = vi.mocked(globalThis.fetch).mock.calls;
      const k1 = (calls[0][1]!.headers as Record<string, string>)["Idempotency-Key"];
      const k2 = (calls[1][1]!.headers as Record<string, string>)["Idempotency-Key"];
      expect(k1).not.toEqual(k2);
    });
  });

  describe("putProtectionCard", () => {
    it("sends an Idempotency-Key header on every PUT", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({ card_id: "pc-1", composed: true }),
      } as unknown as Response);

      await putProtectionCard("mnm-test", "card_version: x", "text/yaml");

      const init = vi.mocked(globalThis.fetch).mock.calls[0][1] as RequestInit;
      const headers = init.headers as Record<string, string>;
      expect(headers["Idempotency-Key"]).toBeTruthy();
    });

    it("uses the explicit idempotencyKey when provided", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({ card_id: "pc-1", composed: true }),
      } as unknown as Response);

      const explicitKey = "22222222-2222-4222-8222-222222222222";
      await putProtectionCard("mnm-test", "card_version: x", "text/yaml", {
        idempotencyKey: explicitKey,
      });

      const init = vi.mocked(globalThis.fetch).mock.calls[0][1] as RequestInit;
      const headers = init.headers as Record<string, string>;
      expect(headers["Idempotency-Key"]).toBe(explicitKey);
    });
  });
});
