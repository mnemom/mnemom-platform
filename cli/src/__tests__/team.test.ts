/**
 * Tests for `mnemom team` commands (Piece 2 of T1-3.1, ADR-044 amended).
 *
 * The commands call API helpers in lib/api.ts; tests mock the helpers
 * directly so each command's orchestration logic is exercised in
 * isolation. Mirrors the shape of org.test.ts.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../lib/auth.js", () => ({
  requireAuth: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../lib/api.js", () => ({
  listMyTeams: vi.fn(),
  getTeam: vi.fn(),
  getTeamTemplate: vi.fn(),
  putTeamTemplate: vi.fn(),
  deleteTeamTemplate: vi.fn(),
  previewComposeTeamTemplate: vi.fn(),
}));

vi.mock("../lib/format.js", () => ({
  fmt: {
    header: (s: string) => s,
    error: (s: string) => `ERR: ${s}`,
    warn: (s: string) => `WARN: ${s}`,
  },
}));

import {
  teamListCommand,
  teamShowCommand,
  teamTemplateCommand,
  teamPreviewComposeCommand,
} from "../commands/team.js";
import * as api from "../lib/api.js";

const teamA: api.TeamListItem = {
  team_id: "11111111-1111-1111-1111-111111111111",
  name: "platform",
  org_id: "org-acme",
  org_name: "Acme Corp",
  member_count: 4,
};

const teamB: api.TeamListItem = {
  team_id: "22222222-2222-2222-2222-222222222222",
  name: "sre",
  org_id: "org-acme",
  org_name: "Acme Corp",
  member_count: 7,
};

const teamADetail: api.TeamDetail = {
  team_id: teamA.team_id,
  org_id: teamA.org_id,
  name: teamA.name,
  description: "platform engineering",
  status: "active",
  member_count: 4,
  visibility: "public",
  created_at: "2026-04-12T00:00:00Z",
};

// Type captures for vitest 1.x spy types — same idiom as org.test.ts.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const spySampleLog = () => vi.spyOn(console, "log").mockImplementation(() => {});
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const spySampleExit = () =>
  vi.spyOn(process, "exit").mockImplementation(() => undefined as never);

describe("teamListCommand", () => {
  type LogSpy = ReturnType<typeof spySampleLog>;
  let logSpy: LogSpy;

  beforeEach(() => {
    vi.clearAllMocks();
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it("prints both teams in a human-readable table", async () => {
    vi.mocked(api.listMyTeams).mockResolvedValueOnce([teamA, teamB]);
    await teamListCommand({});
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("platform");
    expect(out).toContain("sre");
    expect(out).toContain("Acme Corp");
    expect(out).toMatch(/Total: 2 team\(s\)/);
  });

  it("emits JSON with --json", async () => {
    vi.mocked(api.listMyTeams).mockResolvedValueOnce([teamA]);
    await teamListCommand({ json: true });
    const last = logSpy.mock.calls[0][0] as string;
    const parsed = JSON.parse(last) as Array<Record<string, unknown>>;
    expect(parsed).toHaveLength(1);
    expect(parsed[0].team_id).toBe(teamA.team_id);
  });

  it("renders the empty-state message when no teams", async () => {
    vi.mocked(api.listMyTeams).mockResolvedValueOnce([]);
    await teamListCommand({});
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toMatch(/No teams found/);
    // The empty-state copy reminds the user team membership is optional.
    expect(out).toMatch(/optional|Solo agents/);
  });
});

describe("teamShowCommand", () => {
  type LogSpy = ReturnType<typeof spySampleLog>;
  type ExitSpy = ReturnType<typeof spySampleExit>;
  let logSpy: LogSpy;
  let exitSpy: ExitSpy;

  beforeEach(() => {
    vi.clearAllMocks();
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
  });

  afterEach(() => {
    logSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it("prints team detail including org_id", async () => {
    vi.mocked(api.getTeam).mockResolvedValueOnce(teamADetail);
    await teamShowCommand(teamA.team_id, {});
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain(teamA.team_id);
    expect(out).toContain(teamA.org_id);
    expect(out).toContain("platform engineering");
    expect(out).toContain("active");
  });

  it("exits 1 when no team_id supplied", async () => {
    await teamShowCommand(undefined, {});
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

describe("teamTemplateCommand", () => {
  type LogSpy = ReturnType<typeof spySampleLog>;
  type ExitSpy = ReturnType<typeof spySampleExit>;
  let logSpy: LogSpy;
  let exitSpy: ExitSpy;

  beforeEach(() => {
    vi.clearAllMocks();
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
  });

  afterEach(() => {
    logSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it("GET path: prints the template + enabled flag for alignment", async () => {
    vi.mocked(api.getTeamTemplate).mockResolvedValueOnce({
      team_id: teamA.team_id,
      org_id: teamA.org_id,
      template: { values: { declared: ["safety"] } },
      enabled: true,
    });
    await teamTemplateCommand("alignment", teamA.team_id, {});
    expect(api.getTeamTemplate).toHaveBeenCalledWith(teamA.team_id, "alignment");
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("Enabled");
    expect(out).toContain("yes");
    expect(out).toContain("safety");
  });

  it("GET path: prints empty-template hint when nothing set", async () => {
    vi.mocked(api.getTeamTemplate).mockResolvedValueOnce({
      team_id: teamA.team_id,
      org_id: teamA.org_id,
      template: null,
      enabled: false,
    });
    await teamTemplateCommand("protection", teamA.team_id, {});
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toMatch(/No template set/);
  });

  it("rejects --set + --clear together", async () => {
    await teamTemplateCommand("alignment", teamA.team_id, {
      set: "/tmp/x.yaml",
      clear: true,
    });
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("DELETE path: prints recompose count + cleared confirmation", async () => {
    vi.mocked(api.deleteTeamTemplate).mockResolvedValueOnce({
      team_id: teamA.team_id,
      org_id: teamA.org_id,
      template: null,
      enabled: false,
      deleted: true,
      agents_flagged_for_recompose: 4,
    });
    await teamTemplateCommand("alignment", teamA.team_id, { clear: true });
    expect(api.deleteTeamTemplate).toHaveBeenCalledWith(teamA.team_id, "alignment");
    const out = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(out).toContain("Deleted");
    expect(out).toContain("yes");
    expect(out).toContain("4");
  });

  it("exits 1 when no team_id supplied", async () => {
    await teamTemplateCommand("alignment", undefined, {});
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

describe("teamPreviewComposeCommand", () => {
  type LogSpy = ReturnType<typeof spySampleLog>;
  type ExitSpy = ReturnType<typeof spySampleExit>;
  let logSpy: LogSpy;
  let exitSpy: ExitSpy;

  beforeEach(() => {
    vi.clearAllMocks();
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
  });

  afterEach(() => {
    logSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it("exits 1 when no team_id supplied", async () => {
    await teamPreviewComposeCommand(undefined, {});
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("forwards --protection to alignment kind switch", async () => {
    vi.mocked(api.previewComposeTeamTemplate).mockResolvedValueOnce({
      composed: { mode: "observe" },
      conflicts: [],
    });
    await teamPreviewComposeCommand(teamA.team_id, {
      protection: true,
      from: "/dev/null", // empty body — the mocked API doesn't validate
    });
    expect(api.previewComposeTeamTemplate).toHaveBeenCalledWith(
      teamA.team_id,
      "protection",
      expect.any(String),
    );
  });
});
