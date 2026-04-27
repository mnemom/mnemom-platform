import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock auth.js so the 401-retry path can simulate a successful forced refresh
// without touching the real auth file on disk. The other tests don't depend
// on this — they exercise unauthenticated GET/POST paths.
vi.mock("../lib/auth.js", async () => {
  const actual = await vi.importActual<typeof import("../lib/auth.js")>("../lib/auth.js");
  return {
    ...actual,
    resolveAuth: vi.fn(async () => ({ type: "none" as const })),
    forceRefreshAccessToken: vi.fn(async () => "refreshed-jwt"),
  };
});

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
      // PR-B: getIntegrity now sends auth headers via fetchWithAuthRetry, so
      // the call signature is fetch(url, { headers }) — second arg present
      // (was previously just `fetch(url)`).
      expect(globalThis.fetch).toHaveBeenCalledWith(
        `${API_BASE}/v1/integrity/smolt-abc12345`,
        expect.objectContaining({ headers: expect.any(Object) }),
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
      // PR-B: getTraces now sends auth headers via fetchWithAuthRetry.
      expect(globalThis.fetch).toHaveBeenCalledWith(
        `${API_BASE}/v1/traces?agent_id=smolt-abc12345&limit=10`,
        expect.objectContaining({ headers: expect.any(Object) }),
      );
    });

    it("should fetch traces with custom limit", async () => {
      const mockTraces: Trace[] = [];

      mockFetchResponse(mockTraces);

      const result = await getTraces("smolt-abc12345", 50);

      expect(result).toEqual([]);
      expect(globalThis.fetch).toHaveBeenCalledWith(
        `${API_BASE}/v1/traces?agent_id=smolt-abc12345&limit=50`,
        expect.objectContaining({ headers: expect.any(Object) }),
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

  // ──────────────────────────────────────────────────────────────────────────
  // Accept: application/json on PUT cards
  //
  // The API content-negotiates the response by Accept (see
  // mnemom-api/src/composition/response.ts:respondYamlJson). With Node's
  // default Accept: */* the API returns a YAML body, which crashes
  // response.json() on the client with "Unexpected token 'a' is not valid
  // JSON". This pins the explicit Accept so the bug never returns.
  // ──────────────────────────────────────────────────────────────────────────

  describe("PUT response content negotiation", () => {
    function jsonOk() {
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({ card_id: "x", composed: true }),
      } as unknown as Response;
    }

    it("putAlignmentCard asks for JSON in the response", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValue(jsonOk());
      await putAlignmentCard("mnm-test", "card_version: x", "text/yaml");
      const init = vi.mocked(globalThis.fetch).mock.calls[0][1] as RequestInit;
      const headers = init.headers as Record<string, string>;
      expect(headers["Accept"]).toBe("application/json");
    });

    it("putProtectionCard asks for JSON in the response", async () => {
      vi.mocked(globalThis.fetch).mockResolvedValue(jsonOk());
      await putProtectionCard("mnm-test", "card_version: x", "text/yaml");
      const init = vi.mocked(globalThis.fetch).mock.calls[0][1] as RequestInit;
      const headers = init.headers as Record<string, string>;
      expect(headers["Accept"]).toBe("application/json");
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // 401 retry with forced refresh
  //
  // When local expiresAt diverges from the JWT's actual exp, authenticated
  // calls 401 even though the local cache claims the token is valid. The
  // CLI now refreshes once on 401 and retries — and the second attempt must
  // reuse the same Idempotency-Key so the server's reservation table sees
  // a single mutation.
  // ──────────────────────────────────────────────────────────────────────────

  describe("401 retry on PUT", () => {
    it("putAlignmentCard retries with the same Idempotency-Key after 401", async () => {
      // First PUT returns 401; auth.js mock unconditionally returns a fresh
      // token from forceRefreshAccessToken; second PUT returns 200.
      vi.mocked(globalThis.fetch)
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          statusText: "Unauthorized",
          json: vi.fn().mockResolvedValue({ error: "unauthorized", message: "expired" }),
        } as unknown as Response)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({ card_id: "ac-1", composed: true }),
        } as unknown as Response);

      const explicitKey = "33333333-3333-4333-8333-333333333333";
      const result = await putAlignmentCard("mnm-test", "card_version: x", "text/yaml", {
        idempotencyKey: explicitKey,
      });
      expect(result.card_id).toBe("ac-1");

      const calls = vi.mocked(globalThis.fetch).mock.calls;
      expect(calls.length).toBe(2);
      const firstHeaders = calls[0][1]!.headers as Record<string, string>;
      const retryHeaders = calls[1][1]!.headers as Record<string, string>;
      expect(firstHeaders["Idempotency-Key"]).toBe(explicitKey);
      expect(retryHeaders["Idempotency-Key"]).toBe(explicitKey);
    });

    it("putAlignmentCard does not retry when refresh fails", async () => {
      const auth = await import("../lib/auth.js");
      vi.mocked(auth.forceRefreshAccessToken).mockResolvedValueOnce(null);

      vi.mocked(globalThis.fetch).mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        json: vi.fn().mockResolvedValue({ error: "unauthorized", message: "expired" }),
      } as unknown as Response);

      await expect(
        putAlignmentCard("mnm-test", "card_version: x", "text/yaml"),
      ).rejects.toThrow();
      expect(vi.mocked(globalThis.fetch).mock.calls.length).toBe(1);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // getIntegrity sends auth headers
  //
  // Pre-PR-B getIntegrity used the unauth fetchApi helper. The API's
  // /v1/integrity/:id route requires owner auth for private claimed agents
  // (which is the common case), so unauth calls returned 403. CLI now
  // sends authHeaders + uses fetchWithAuthRetry so 401s heal transparently.
  // ──────────────────────────────────────────────────────────────────────────

  describe("getIntegrity (auth)", () => {
    it("sends an Authorization header on the request", async () => {
      const auth = await import("../lib/auth.js");
      vi.mocked(auth.resolveAuth).mockResolvedValueOnce({
        type: "jwt",
        token: "test-jwt-token",
      });

      mockFetchResponse({
        agent_id: "mnm-x",
        score: 1,
        total_traces: 0,
        verified: 0,
        violations: 0,
        last_updated: "2026-04-27T00:00:00Z",
      });

      await getIntegrity("mnm-x");

      const init = vi.mocked(globalThis.fetch).mock.calls[0][1] as RequestInit;
      const headers = init.headers as Record<string, string>;
      expect(headers["Authorization"]).toBe("Bearer test-jwt-token");
    });

    it("retries with a refreshed token on 401", async () => {
      vi.mocked(globalThis.fetch)
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          statusText: "Unauthorized",
          json: vi.fn().mockResolvedValue({ error: "unauthorized" }),
        } as unknown as Response)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          statusText: "OK",
          json: vi.fn().mockResolvedValue({
            agent_id: "mnm-x",
            score: 0.9,
            total_traces: 10,
            verified: 9,
            violations: 1,
            last_updated: "2026-04-27T00:00:00Z",
          }),
        } as unknown as Response);

      const result = await getIntegrity("mnm-x");
      expect(result.score).toBe(0.9);
      expect(vi.mocked(globalThis.fetch).mock.calls.length).toBe(2);
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // getTraces handles the API envelope
  //
  // The API returns `{ traces, limit, offset }` (mnemom-api/src/index.ts:
  // handleGetTraces). Pre-PR-B the CLI typed the response as Trace[] and
  // crashed downstream with "traces is not iterable" against the envelope.
  // CLI now unwraps; defensive against a bare-array shape too (older API).
  // ──────────────────────────────────────────────────────────────────────────

  describe("getTraces (envelope)", () => {
    it("unwraps the API envelope { traces, limit, offset }", async () => {
      const traces: Trace[] = [
        {
          id: "trace-1",
          agent_id: "mnm-x",
          timestamp: "2026-04-27T00:00:00Z",
          action: "respond",
          verified: true,
        },
      ];
      mockFetchResponse({ traces, limit: 10, offset: 0 });

      const result = await getTraces("mnm-x");
      expect(Array.isArray(result)).toBe(true);
      expect(result).toEqual(traces);
    });

    it("returns [] when the envelope has no traces field", async () => {
      mockFetchResponse({ limit: 10, offset: 0 });
      const result = await getTraces("mnm-x");
      expect(result).toEqual([]);
    });

    it("accepts a bare array (defensive — older API shape)", async () => {
      const traces: Trace[] = [
        {
          id: "trace-1",
          agent_id: "mnm-x",
          timestamp: "2026-04-27T00:00:00Z",
          action: "respond",
          verified: true,
        },
      ];
      mockFetchResponse(traces);
      const result = await getTraces("mnm-x");
      expect(result).toEqual(traces);
    });

    it("sends an Authorization header", async () => {
      const auth = await import("../lib/auth.js");
      vi.mocked(auth.resolveAuth).mockResolvedValueOnce({
        type: "jwt",
        token: "trace-jwt",
      });
      mockFetchResponse({ traces: [], limit: 10, offset: 0 });

      await getTraces("mnm-x");

      const init = vi.mocked(globalThis.fetch).mock.calls[0][1] as RequestInit;
      const headers = init.headers as Record<string, string>;
      expect(headers["Authorization"]).toBe("Bearer trace-jwt");
    });
  });

  // ──────────────────────────────────────────────────────────────────────────
  // PublishedCardResponse — typed return matches API contract
  //
  // The API returns the canonical card directly (Unified*Card with
  // _composition stripped). Pre-PR-B the CLI typed the return as
  // `{ card_id, composed: boolean }` — a fictional wrapper. The composed
  // field never existed on the wire. After PR-A both alignment and
  // protection canonical reliably carry card_id; we surface it
  // defensively (only print when present) since canonical can still be
  // sparse on edge paths.
  // ──────────────────────────────────────────────────────────────────────────

  describe("PublishedCardResponse shape", () => {
    it("putAlignmentCard returns the canonical card with card_id", async () => {
      mockFetchResponse({
        card_id: "ac-realfromserver",
        agent_id: "mnm-x",
        card_version: "unified/2026-04-27",
        autonomy_mode: "observe",
      });

      const result = await putAlignmentCard("mnm-x", "card_version: x", "text/yaml");
      expect(result.card_id).toBe("ac-realfromserver");
      expect(result.agent_id).toBe("mnm-x");
      // `composed` is no longer in the typed shape.
      expect((result as Record<string, unknown>).composed).toBeUndefined();
    });

    it("putProtectionCard returns the canonical card with card_id (after PR-A composer parity)", async () => {
      mockFetchResponse({
        card_id: "pc-realfromserver",
        agent_id: "mnm-x",
        card_version: "protection/2026-04-27",
        mode: "observe",
      });

      const result = await putProtectionCard("mnm-x", "card_version: x", "text/yaml");
      expect(result.card_id).toBe("pc-realfromserver");
      expect(result.agent_id).toBe("mnm-x");
    });

    it("putProtectionCard tolerates a missing card_id (graceful, no crash)", async () => {
      // Defensive: pre-PR-A the protection canonical didn't include card_id.
      // The CLI no longer prints "Card ID: undefined" — but the return value
      // shape is still valid (card_id is optional on PublishedCardResponse).
      mockFetchResponse({
        agent_id: "mnm-x",
        card_version: "protection/2026-04-27",
        mode: "observe",
      });

      const result = await putProtectionCard("mnm-x", "card_version: x", "text/yaml");
      expect(result.card_id).toBeUndefined();
      expect(result.agent_id).toBe("mnm-x");
    });
  });
});
