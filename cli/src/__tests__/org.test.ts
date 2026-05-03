/**
 * Tests for `mnemom org list` + `mnemom org show` commands (ADR-044, Piece 1).
 *
 * The commands call API helpers in lib/api.ts; tests mock the helpers
 * directly so each command's orchestration logic is exercised in isolation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../lib/auth.js", () => ({
  requireAuth: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../lib/api.js", () => ({
  listMyOrgs: vi.fn(),
  getMyPersonalOrg: vi.fn(),
}));

vi.mock("../lib/format.js", () => ({
  fmt: {
    header: (s: string) => s,
    error: (s: string) => `ERR: ${s}`,
    warn: (s: string) => `WARN: ${s}`,
  },
}));

import { orgListCommand, orgShowCommand } from "../commands/org.js";
import * as api from "../lib/api.js";

const personalOrg: api.OrgListItem = {
  org_id: "pers-abcd1234",
  name: "Personal",
  slug: "personal-x",
  is_personal: true,
  is_owner: true,
  role: "owner",
  billing_email: null,
  company_name: null,
  accepted_at: "2026-05-02T00:00:00Z",
  created_at: "2026-05-02T00:00:00Z",
};

const acmeOrg: api.OrgListItem = {
  org_id: "org-acme",
  name: "Acme Corp",
  slug: "acme",
  is_personal: false,
  is_owner: false,
  role: "member",
  billing_email: "billing@acme.com",
  company_name: "Acme Corp",
  accepted_at: "2026-04-15T00:00:00Z",
  created_at: "2026-04-01T00:00:00Z",
};

describe("orgListCommand", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it("renders both personal and multi-user org with (personal) tag on the personal row", async () => {
    vi.mocked(api.listMyOrgs).mockResolvedValueOnce([personalOrg, acmeOrg]);

    await orgListCommand({});

    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toMatch(/Personal\s+\(personal\)/);
    expect(out).toContain("Acme Corp");
    expect(out).toMatch(/Total: 2 organization\(s\)/);
  });

  it("emits JSON with --json", async () => {
    vi.mocked(api.listMyOrgs).mockResolvedValueOnce([personalOrg]);

    await orgListCommand({ json: true });

    const last = logSpy.mock.calls[0][0] as string;
    const parsed = JSON.parse(last);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].is_personal).toBe(true);
  });
});

describe("orgShowCommand", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
  });

  afterEach(() => {
    logSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it("--personal resolves via getMyPersonalOrg and prints the personal org", async () => {
    vi.mocked(api.getMyPersonalOrg).mockResolvedValueOnce({
      org_id: "pers-abcd1234",
      is_personal: true,
      just_provisioned: false,
    });
    vi.mocked(api.listMyOrgs).mockResolvedValueOnce([personalOrg, acmeOrg]);

    await orgShowCommand(undefined, { personal: true });

    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("pers-abcd1234");
    expect(out).toMatch(/Personal:\s+yes/);
  });

  it("explicit org_id selects the matching membership", async () => {
    vi.mocked(api.listMyOrgs).mockResolvedValueOnce([personalOrg, acmeOrg]);

    await orgShowCommand("org-acme", {});

    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("Acme Corp");
    expect(out).toMatch(/Personal:\s+no/);
  });

  it("warns and exits when multiple memberships exist with no selector", async () => {
    vi.mocked(api.listMyOrgs).mockResolvedValueOnce([personalOrg, acmeOrg]);

    await orgShowCommand(undefined, {});

    expect(exitSpy).toHaveBeenCalledWith(1);
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toMatch(/2 memberships/);
  });

  it("auto-selects when the user has exactly one membership", async () => {
    vi.mocked(api.listMyOrgs).mockResolvedValueOnce([personalOrg]);

    await orgShowCommand(undefined, {});

    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("pers-abcd1234");
  });
});
