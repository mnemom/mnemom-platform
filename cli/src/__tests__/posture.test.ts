/**
 * Tests for `mnemom posture` commands (Piece 3 of T1-3.1, ADR-045).
 *
 * Mocks lib/api.ts at the helper level so each command's orchestration
 * is exercised in isolation. Mirrors the shape of team.test.ts.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("../lib/auth.js", () => ({
  requireAuth: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../lib/api.js", () => ({
  listPostures: vi.fn(),
  getPosture: vi.fn(),
  listPostureRevisions: vi.fn(),
  diffPostureRevisions: vi.fn(),
  createPosture: vi.fn(),
  updatePosture: vi.fn(),
  clonePosture: vi.fn(),
  deletePosture: vi.fn(),
  assignPosture: vi.fn(),
  unassignPosture: vi.fn(),
  previewComposePosture: vi.fn(),
}));

vi.mock("../lib/format.js", () => ({
  fmt: {
    header: (s: string) => s,
    success: (s: string) => `OK: ${s}`,
    error: (s: string) => `ERR: ${s}`,
    warn: (s: string) => `WARN: ${s}`,
  },
}));

import {
  postureListCommand,
  postureShowCommand,
  postureCreateCommand,
  postureUpdateCommand,
  postureCloneCommand,
  postureRevisionsCommand,
  postureDiffCommand,
  postureAssignCommand,
  postureUnassignCommand,
  posturePreviewComposeCommand,
  postureDeleteCommand,
} from "../commands/posture.js";
import * as api from "../lib/api.js";

const VALID_BODY: api.PostureBody = {
  posture_schema_version: "v1.0",
  sideband: {
    coherence: {
      enabled: true,
      cadence_seconds: 600,
      fire_on: {
        pairwise_governance_floor_below: 0.5,
        conflict_edge_count_exceeds: 3,
        outlier_agents_count_exceeds: 0,
      },
      severity_on_fire: "medium",
    },
    fault_line: {
      enabled: true,
      cadence_seconds: 600,
      severity_floor: "high",
      use_reputation_scores: true,
      severity_on_fire: "high",
    },
    fleet: {
      enabled: true,
      cadence_seconds: 600,
      patterns: { outliers: true, min_pair_score_below: 0.5, cluster_partition: true },
      severity_on_fire: "medium",
    },
  },
  fleet_identification: { by: "team_membership" },
  fan_out: { rule: "per_named_affected_agent" },
};

const POSTURE_ROW: api.PostureSummary = {
  posture_id: "tp-test1234",
  slug: "test-posture",
  name: "Test Posture",
  description: "An org-cloned posture.",
  scope: "org",
  org_id: "org-acme",
  is_default: false,
  current_revision_id: "tpr-test12345678",
  body: VALID_BODY,
  created_at: "2026-05-04T00:00:00Z",
  updated_at: "2026-05-04T00:00:00Z",
  deleted_at: null,
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const spySampleLog = () => vi.spyOn(console, "log").mockImplementation(() => {});
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const spySampleErr = () => vi.spyOn(console, "error").mockImplementation(() => {});
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const spySampleExit = () => vi.spyOn(process, "exit").mockImplementation(() => undefined as never);

type LogSpy = ReturnType<typeof spySampleLog>;
type ErrSpy = ReturnType<typeof spySampleErr>;
type ExitSpy = ReturnType<typeof spySampleExit>;

let logSpy: LogSpy;
let errSpy: ErrSpy;
let exitSpy: ExitSpy;

beforeEach(() => {
  vi.clearAllMocks();
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  exitSpy = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
});

afterEach(() => {
  logSpy.mockRestore();
  errSpy.mockRestore();
  exitSpy.mockRestore();
});

function out(): string {
  return logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
}
function err(): string {
  return errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
}

// ─── list ────────────────────────────────────────────────────────────────

describe("postureListCommand", () => {
  it("prints a table of postures", async () => {
    vi.mocked(api.listPostures).mockResolvedValueOnce([
      POSTURE_ROW,
      {
        ...POSTURE_ROW,
        posture_id: "tp-platform-standard",
        slug: "standard",
        scope: "platform",
        org_id: null,
        is_default: true,
      },
    ]);
    await postureListCommand({});
    expect(out()).toContain("standard");
    expect(out()).toContain("test-posture");
    expect(out()).toContain("Total: 2 posture(s)");
  });

  it("emits JSON when --json", async () => {
    vi.mocked(api.listPostures).mockResolvedValueOnce([POSTURE_ROW]);
    await postureListCommand({ json: true });
    const parsed = JSON.parse(out());
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0].posture_id).toBe("tp-test1234");
  });

  it("shows empty-state message + tip when no postures", async () => {
    vi.mocked(api.listPostures).mockResolvedValueOnce([]);
    await postureListCommand({});
    expect(out()).toContain("No postures found");
    expect(out()).toContain("Tip:");
  });
});

// ─── show ────────────────────────────────────────────────────────────────

describe("postureShowCommand", () => {
  it("prints the posture metadata + body summary", async () => {
    vi.mocked(api.getPosture).mockResolvedValueOnce(POSTURE_ROW);
    await postureShowCommand("tp-test1234", {});
    expect(out()).toContain("tp-test1234");
    expect(out()).toContain("coherence");
    expect(out()).toContain("fault_line");
    expect(out()).toContain("fleet");
  });

  it("prints JSON when --json", async () => {
    vi.mocked(api.getPosture).mockResolvedValueOnce(POSTURE_ROW);
    await postureShowCommand("tp-test1234", { json: true });
    expect(JSON.parse(out()).posture_id).toBe("tp-test1234");
  });

  it("usage when no posture_id", async () => {
    await postureShowCommand(undefined, {});
    expect(err()).toContain("Usage:");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

// ─── create / update / clone ─────────────────────────────────────────────

describe("postureCreateCommand", () => {
  it("reads body from --from and POSTs", async () => {
    const dir = mkdtempSync(join(tmpdir(), "posture-test-"));
    const file = join(dir, "body.json");
    writeFileSync(file, JSON.stringify(VALID_BODY));

    vi.mocked(api.createPosture).mockResolvedValueOnce(POSTURE_ROW);
    await postureCreateCommand({
      org: "org-acme",
      slug: "my-posture",
      name: "My Posture",
      from: file,
    });
    expect(api.createPosture).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "org",
        org_id: "org-acme",
        slug: "my-posture",
      }),
    );
    expect(out()).toContain("Created posture tp-test1234");
  });

  it("usage when required flags missing", async () => {
    await postureCreateCommand({});
    expect(err()).toContain("Usage:");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

describe("postureUpdateCommand", () => {
  it("reads body and PUTs a new revision", async () => {
    const dir = mkdtempSync(join(tmpdir(), "posture-test-"));
    const file = join(dir, "v2.json");
    writeFileSync(file, JSON.stringify(VALID_BODY));

    vi.mocked(api.updatePosture).mockResolvedValueOnce({
      ...POSTURE_ROW,
      current_revision_id: "tpr-newrevision",
    });
    await postureUpdateCommand("tp-test1234", { from: file, summary: "tighten coherence" });
    expect(api.updatePosture).toHaveBeenCalledWith(
      "tp-test1234",
      expect.objectContaining({ change_summary: "tighten coherence" }),
    );
    expect(out()).toContain("New revision written");
  });
});

describe("postureCloneCommand", () => {
  it("clones to target org", async () => {
    vi.mocked(api.clonePosture).mockResolvedValueOnce({
      ...POSTURE_ROW,
      posture_id: "tp-clone7777",
      slug: "standard-clone",
    });
    await postureCloneCommand("tp-platform-standard", { org: "org-acme" });
    expect(api.clonePosture).toHaveBeenCalledWith(
      "tp-platform-standard",
      expect.objectContaining({ org_id: "org-acme" }),
    );
    expect(out()).toContain("Cloned tp-platform-standard");
    expect(out()).toContain("tp-clone7777");
  });
});

// ─── revisions / diff ────────────────────────────────────────────────────

describe("postureRevisionsCommand", () => {
  it("prints revisions newest-first", async () => {
    vi.mocked(api.listPostureRevisions).mockResolvedValueOnce([
      {
        revision_id: "tpr-r2",
        posture_id: "tp-test1234",
        revision_no: 2,
        body: VALID_BODY,
        change_summary: "tighten",
        authored_by: "user-test",
        authored_at: "2026-05-05T00:00:00Z",
      },
      {
        revision_id: "tpr-r1",
        posture_id: "tp-test1234",
        revision_no: 1,
        body: VALID_BODY,
        change_summary: "Initial",
        authored_by: "user-test",
        authored_at: "2026-05-04T00:00:00Z",
      },
    ]);
    await postureRevisionsCommand("tp-test1234", {});
    expect(out()).toContain("v002");
    expect(out()).toContain("v001");
  });
});

describe("postureDiffCommand", () => {
  it("prints structural diff entries", async () => {
    vi.mocked(api.diffPostureRevisions).mockResolvedValueOnce({
      from: { revision_no: 1 },
      to: { revision_no: 2 },
      changes: [
        {
          path: "sideband.coherence.cadence_seconds",
          op: "changed",
          before: 600,
          after: 300,
        },
      ],
    });
    await postureDiffCommand("tp-test1234", { from: "1", to: "2" });
    expect(out()).toContain("changed");
    expect(out()).toContain("sideband.coherence.cadence_seconds");
    expect(out()).toContain("before");
  });

  it("rejects non-integer --from / --to", async () => {
    await postureDiffCommand("tp-test1234", { from: "abc", to: "2" });
    expect(err()).toContain("must be integers");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

// ─── assign / unassign / preview-compose / delete ────────────────────────

describe("postureAssignCommand", () => {
  it("assigns and reports replaced_prior=false", async () => {
    vi.mocked(api.assignPosture).mockResolvedValueOnce({
      posture_id: "tp-test1234",
      team_id: "11111111-1111-1111-1111-111111111111",
      replaced_prior: false,
    });
    await postureAssignCommand("tp-test1234", {
      team: "11111111-1111-1111-1111-111111111111",
    });
    expect(out()).toContain("Assigned tp-test1234");
  });

  it("notes replaced_prior when true", async () => {
    vi.mocked(api.assignPosture).mockResolvedValueOnce({
      posture_id: "tp-test1234",
      team_id: "11111111-1111-1111-1111-111111111111",
      replaced_prior: true,
    });
    await postureAssignCommand("tp-test1234", {
      team: "11111111-1111-1111-1111-111111111111",
    });
    expect(out()).toContain("Replaced a prior assignment");
  });

  it("validates --pin-revision is integer", async () => {
    await postureAssignCommand("tp-test1234", {
      team: "11111111-1111-1111-1111-111111111111",
      pinRevision: "not-a-number",
    });
    expect(err()).toContain("must be an integer");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});

describe("postureUnassignCommand", () => {
  it("calls unassign and prints success", async () => {
    vi.mocked(api.unassignPosture).mockResolvedValueOnce(undefined);
    await postureUnassignCommand("tp-test1234", {
      team: "11111111-1111-1111-1111-111111111111",
    });
    expect(api.unassignPosture).toHaveBeenCalledWith(
      "tp-test1234",
      "11111111-1111-1111-1111-111111111111",
    );
    expect(out()).toContain("Unassigned tp-test1234");
  });
});

describe("posturePreviewComposeCommand", () => {
  it("prints cascade trail + effective summary", async () => {
    vi.mocked(api.previewComposePosture).mockResolvedValueOnce({
      team_id: "11111111-1111-1111-1111-111111111111",
      org_id: "org-acme",
      composed: {
        body: VALID_BODY,
        scopes_applied: [
          { scope: "platform", posture_id: "tp-platform-standard", revision_no: 1 },
          { scope: "team", posture_id: "tp-test1234", revision_no: 1 },
        ],
      },
    });
    await posturePreviewComposeCommand("tp-test1234", {
      team: "11111111-1111-1111-1111-111111111111",
    });
    expect(out()).toContain("Cascade applied");
    expect(out()).toContain("platform");
    expect(out()).toContain("team");
    expect(out()).toContain("coherence");
  });
});

describe("postureDeleteCommand", () => {
  it("calls delete and prints success", async () => {
    vi.mocked(api.deletePosture).mockResolvedValueOnce(undefined);
    await postureDeleteCommand("tp-test1234");
    expect(api.deletePosture).toHaveBeenCalledWith("tp-test1234");
    expect(out()).toContain("Soft-deleted posture tp-test1234");
  });
});

// Mark imports as used to silence ts noUnusedLocals.
void readFileSync;
