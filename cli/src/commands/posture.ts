/**
 * `mnemom posture ...` commands — Piece 3 of T1-3.1 (ADR-045).
 *
 *   mnemom posture list [--org <id>] [--include-platform=false] [--json]
 *   mnemom posture show <posture_id> [--json]
 *   mnemom posture create --org <id> --slug <slug> --name <name>
 *                         --from <file> [--description <text>]
 *   mnemom posture update <posture_id> --from <file> [--summary <text>]
 *   mnemom posture clone <posture_id> --org <id> [--slug <slug>] [--name <name>]
 *   mnemom posture revisions <posture_id> [--json]
 *   mnemom posture diff <posture_id> --from <N> --to <M> [--json]
 *   mnemom posture assign <posture_id> --team <team_id> [--pin-revision <N>]
 *   mnemom posture unassign <posture_id> --team <team_id>
 *   mnemom posture preview-compose <posture_id> --team <team_id> [--json]
 *   mnemom posture delete <posture_id>
 *
 * Per ADR-045: postures are team-scoped policy input; cards remain
 * agent-scoped runtime output. The CLI authenticates the user the same
 * way `mnemom team` and `mnemom org` do — login token or MNEMOM_API_KEY.
 */

import { readFileSync } from "node:fs";
import {
  listPostures,
  getPosture,
  listPostureRevisions,
  diffPostureRevisions,
  createPosture,
  updatePosture,
  clonePosture,
  deletePosture,
  assignPosture,
  unassignPosture,
  previewComposePosture,
  type PostureSummary,
  type PostureBody,
} from "../lib/api.js";
import { requireAuth } from "../lib/auth.js";
import { fmt } from "../lib/format.js";

// ─── Helpers ─────────────────────────────────────────────────────────────

function readBodyFile(path: string): PostureBody {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(fmt.error(`Failed to read '${path}': ${msg}`) + "\n");
    process.exit(1);
    // process.exit is `never` in prod; tests mock it to undefined. Rethrow
    // so this function still satisfies its return type and the test is
    // decisive (caller should not get back a sentinel "undefined as PostureBody").
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(fmt.error(`Invalid JSON in '${path}': ${msg}`) + "\n");
    process.exit(1);
    throw err;
  }
  // Server validates strictly; CLI just forwards.
  return parsed as PostureBody;
}

function severityBadge(s: string): string {
  return s.toUpperCase();
}

// ─── mnemom posture list ─────────────────────────────────────────────────

export async function postureListCommand(opts: {
  org?: string;
  includePlatform?: boolean;
  json?: boolean;
}): Promise<void> {
  await requireAuth();

  let postures: PostureSummary[];
  try {
    postures = await listPostures({
      orgId: opts.org,
      includePlatform: opts.includePlatform,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(fmt.error(`Failed to list postures: ${msg}`) + "\n");
    process.exit(1);
    return;
  }

  if (opts.json) {
    console.log(JSON.stringify(postures, null, 2));
    return;
  }

  console.log(fmt.header("Trust Postures"));
  console.log();
  if (postures.length === 0) {
    console.log("  No postures found.\n");
    if (!opts.org) {
      console.log("  Tip: specify --org <id> to see your org-owned postures.\n");
    }
    return;
  }

  const slugW = 22;
  const nameW = 24;
  const idW = 16;
  const scopeW = 10;
  const revW = 6;

  const header =
    "Slug".padEnd(slugW) +
    "Name".padEnd(nameW) +
    "Posture ID".padEnd(idW) +
    "Scope".padEnd(scopeW) +
    "Rev".padEnd(revW);
  console.log(`  ${header}`);
  console.log(`  ${"─".repeat(slugW + nameW + idW + scopeW + revW)}`);

  for (const p of postures) {
    const slug = p.slug.slice(0, slugW - 2).padEnd(slugW);
    const name = p.name.slice(0, nameW - 2).padEnd(nameW);
    const id = p.posture_id.slice(0, idW - 2).padEnd(idW);
    const scope = (p.is_default ? "platform*" : p.scope).padEnd(scopeW);
    const revNo = p.body
      ? // current_revision body has an N-counter implied by revision history
        // — but we don't refetch; use posture summary's signal.
        "current"
      : "—";
    const rev = revNo.padEnd(revW);
    console.log(`  ${slug}${name}${id}${scope}${rev}`);
  }
  console.log(`\n  Total: ${postures.length} posture(s)`);
  console.log(`  (* = Mnemom-shipped default; immutable)\n`);
}

// ─── mnemom posture show ─────────────────────────────────────────────────

export async function postureShowCommand(
  postureId: string | undefined,
  opts: { json?: boolean },
): Promise<void> {
  await requireAuth();
  if (!postureId) {
    console.error(fmt.error("Usage: mnemom posture show <posture_id> [--json]") + "\n");
    process.exit(1);
    return;
  }

  let p: PostureSummary;
  try {
    p = await getPosture(postureId);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(fmt.error(`Failed to fetch posture: ${msg}`) + "\n");
    process.exit(1);
    return;
  }

  if (opts.json) {
    console.log(JSON.stringify(p, null, 2));
    return;
  }

  console.log(fmt.header(p.name + (p.is_default ? "  (Mnemom-shipped default)" : "")));
  console.log();
  console.log(`  Posture ID:  ${p.posture_id}`);
  console.log(`  Slug:        ${p.slug}`);
  console.log(`  Scope:       ${p.scope}${p.org_id ? `  (org: ${p.org_id})` : ""}`);
  if (p.description) console.log(`  Description: ${p.description}`);
  console.log(`  Revision:    ${p.current_revision_id ?? "—"}`);
  console.log(`  Created:     ${new Date(p.created_at).toLocaleDateString()}`);
  if (p.deleted_at) console.log(`  ${fmt.warn("Deleted:")}     ${p.deleted_at}`);
  console.log();
  if (p.body) {
    console.log(`  Body summary:`);
    console.log(
      `    coherence:  enabled=${p.body.sideband.coherence.enabled}  ` +
        `cadence=${p.body.sideband.coherence.cadence_seconds}s  ` +
        `severity=${severityBadge(p.body.sideband.coherence.severity_on_fire)}`,
    );
    console.log(
      `    fault_line: enabled=${p.body.sideband.fault_line.enabled}  ` +
        `floor=${severityBadge(p.body.sideband.fault_line.severity_floor)}  ` +
        `severity=${severityBadge(p.body.sideband.fault_line.severity_on_fire)}`,
    );
    console.log(
      `    fleet:      enabled=${p.body.sideband.fleet.enabled}  ` +
        `cadence=${p.body.sideband.fleet.cadence_seconds}s  ` +
        `severity=${severityBadge(p.body.sideband.fleet.severity_on_fire)}`,
    );
    console.log(`\n  Use --json to see the full body.`);
  } else {
    console.log(`  No body (no current revision).`);
  }
  console.log();
}

// ─── mnemom posture create ───────────────────────────────────────────────

export async function postureCreateCommand(opts: {
  org?: string;
  slug?: string;
  name?: string;
  from?: string;
  description?: string;
  summary?: string;
  json?: boolean;
}): Promise<void> {
  await requireAuth();
  if (!opts.org || !opts.slug || !opts.name || !opts.from) {
    console.error(
      fmt.error(
        "Usage: mnemom posture create --org <id> --slug <slug> --name <name> --from <file> [--description <text>]",
      ) + "\n",
    );
    process.exit(1);
    return;
  }
  const body = readBodyFile(opts.from);

  let result: PostureSummary;
  try {
    result = await createPosture({
      scope: "org",
      org_id: opts.org,
      slug: opts.slug,
      name: opts.name,
      description: opts.description ?? null,
      body,
      change_summary: opts.summary ?? "Initial revision.",
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(fmt.error(`Failed to create posture: ${msg}`) + "\n");
    process.exit(1);
    return;
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  console.log(fmt.success(`Created posture ${result.posture_id} (slug: ${result.slug})`));
  console.log(`  Org:      ${result.org_id}`);
  console.log(`  Revision: ${result.current_revision_id} (revision_no=1)\n`);
}

// ─── mnemom posture update ───────────────────────────────────────────────

export async function postureUpdateCommand(
  postureId: string | undefined,
  opts: { from?: string; summary?: string; name?: string; description?: string; json?: boolean },
): Promise<void> {
  await requireAuth();
  if (!postureId || !opts.from) {
    console.error(
      fmt.error(
        "Usage: mnemom posture update <posture_id> --from <file> [--summary <text>] [--name <text>] [--description <text>]",
      ) + "\n",
    );
    process.exit(1);
    return;
  }
  const body = readBodyFile(opts.from);

  let result: PostureSummary;
  try {
    result = await updatePosture(postureId, {
      body,
      change_summary: opts.summary ?? null,
      name: opts.name,
      description: opts.description,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(fmt.error(`Failed to update posture: ${msg}`) + "\n");
    process.exit(1);
    return;
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  console.log(fmt.success(`New revision written for ${result.posture_id}`));
  console.log(`  Current revision: ${result.current_revision_id}`);
  console.log(`  (Old revisions remain queryable; this is forward-only.)\n`);
}

// ─── mnemom posture clone ────────────────────────────────────────────────

export async function postureCloneCommand(
  postureId: string | undefined,
  opts: { org?: string; slug?: string; name?: string; description?: string; json?: boolean },
): Promise<void> {
  await requireAuth();
  if (!postureId || !opts.org) {
    console.error(
      fmt.error(
        "Usage: mnemom posture clone <posture_id> --org <id> [--slug <slug>] [--name <name>]",
      ) + "\n",
    );
    process.exit(1);
    return;
  }

  let result: PostureSummary;
  try {
    result = await clonePosture(postureId, {
      org_id: opts.org,
      slug: opts.slug,
      name: opts.name,
      description: opts.description,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(fmt.error(`Failed to clone posture: ${msg}`) + "\n");
    process.exit(1);
    return;
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  console.log(fmt.success(`Cloned ${postureId} → ${result.posture_id}`));
  console.log(`  Slug:     ${result.slug}`);
  console.log(`  Org:      ${result.org_id}`);
  console.log(`  Revision: ${result.current_revision_id} (revision_no=1)\n`);
}

// ─── mnemom posture revisions ────────────────────────────────────────────

export async function postureRevisionsCommand(
  postureId: string | undefined,
  opts: { json?: boolean },
): Promise<void> {
  await requireAuth();
  if (!postureId) {
    console.error(fmt.error("Usage: mnemom posture revisions <posture_id> [--json]") + "\n");
    process.exit(1);
    return;
  }
  const revisions = await listPostureRevisions(postureId).catch((err) => {
    console.error(
      fmt.error(`Failed to list revisions: ${err instanceof Error ? err.message : err}`) + "\n",
    );
    process.exit(1);
    throw err;
  });
  if (opts.json) {
    console.log(JSON.stringify(revisions, null, 2));
    return;
  }
  console.log(fmt.header(`Revisions of ${postureId}`));
  console.log();
  if (revisions.length === 0) {
    console.log("  No revisions found.\n");
    return;
  }
  for (const rev of revisions) {
    const date = new Date(rev.authored_at).toLocaleString();
    console.log(`  v${rev.revision_no.toString().padStart(3, "0")}  ${date}`);
    console.log(`        ${rev.revision_id}`);
    if (rev.change_summary) console.log(`        ${rev.change_summary}`);
    console.log();
  }
}

// ─── mnemom posture diff ─────────────────────────────────────────────────

export async function postureDiffCommand(
  postureId: string | undefined,
  opts: { from?: string; to?: string; json?: boolean },
): Promise<void> {
  await requireAuth();
  if (!postureId || !opts.from || !opts.to) {
    console.error(
      fmt.error("Usage: mnemom posture diff <posture_id> --from <N> --to <M> [--json]") + "\n",
    );
    process.exit(1);
    return;
  }
  const fromNo = parseInt(opts.from, 10);
  const toNo = parseInt(opts.to, 10);
  if (Number.isNaN(fromNo) || Number.isNaN(toNo)) {
    console.error(fmt.error("--from and --to must be integers (revision numbers).") + "\n");
    process.exit(1);
    return;
  }
  const result = await diffPostureRevisions(postureId, fromNo, toNo).catch((err) => {
    console.error(fmt.error(`Diff failed: ${err instanceof Error ? err.message : err}`) + "\n");
    process.exit(1);
    throw err;
  });
  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  console.log(fmt.header(`Diff: ${postureId}  v${fromNo} → v${toNo}`));
  console.log();
  if (result.changes.length === 0) {
    console.log("  No structural differences.\n");
    return;
  }
  for (const c of result.changes) {
    const op =
      c.op === "added"
        ? fmt.success("  + added  ")
        : c.op === "removed"
          ? fmt.error("  - removed")
          : fmt.warn("  ~ changed");
    console.log(`${op}  ${c.path}`);
    if (c.op === "changed") {
      console.log(`              before: ${JSON.stringify(c.before)}`);
      console.log(`              after:  ${JSON.stringify(c.after)}`);
    } else if (c.op === "added") {
      console.log(`              value:  ${JSON.stringify(c.after)}`);
    } else {
      console.log(`              value:  ${JSON.stringify(c.before)}`);
    }
  }
  console.log();
}

// ─── mnemom posture assign / unassign ────────────────────────────────────

export async function postureAssignCommand(
  postureId: string | undefined,
  opts: { team?: string; pinRevision?: string },
): Promise<void> {
  await requireAuth();
  if (!postureId || !opts.team) {
    console.error(
      fmt.error("Usage: mnemom posture assign <posture_id> --team <team_id> [--pin-revision <N>]") +
        "\n",
    );
    process.exit(1);
    return;
  }
  const pin = opts.pinRevision ? parseInt(opts.pinRevision, 10) : null;
  if (opts.pinRevision && Number.isNaN(pin)) {
    console.error(fmt.error("--pin-revision must be an integer.") + "\n");
    process.exit(1);
    return;
  }
  const result = await assignPosture(postureId, opts.team, pin).catch((err) => {
    console.error(fmt.error(`Assign failed: ${err instanceof Error ? err.message : err}`) + "\n");
    process.exit(1);
    throw err;
  });
  console.log(fmt.success(`Assigned ${postureId} → team ${opts.team}`));
  if (result.replaced_prior) {
    console.log(`  (Replaced a prior assignment — one active posture per team.)`);
  }
  if (pin !== null) console.log(`  Pinned to revision_no=${pin}.`);
  console.log();
}

export async function postureUnassignCommand(
  postureId: string | undefined,
  opts: { team?: string },
): Promise<void> {
  await requireAuth();
  if (!postureId || !opts.team) {
    console.error(fmt.error("Usage: mnemom posture unassign <posture_id> --team <team_id>") + "\n");
    process.exit(1);
    return;
  }
  await unassignPosture(postureId, opts.team).catch((err) => {
    console.error(fmt.error(`Unassign failed: ${err instanceof Error ? err.message : err}`) + "\n");
    process.exit(1);
    throw err;
  });
  console.log(fmt.success(`Unassigned ${postureId} from team ${opts.team}\n`));
}

// ─── mnemom posture preview-compose ──────────────────────────────────────

export async function posturePreviewComposeCommand(
  postureId: string | undefined,
  opts: { team?: string; json?: boolean },
): Promise<void> {
  await requireAuth();
  if (!postureId || !opts.team) {
    console.error(
      fmt.error("Usage: mnemom posture preview-compose <posture_id> --team <team_id> [--json]") +
        "\n",
    );
    process.exit(1);
    return;
  }
  const result = await previewComposePosture(postureId, opts.team).catch((err) => {
    console.error(
      fmt.error(`Preview-compose failed: ${err instanceof Error ? err.message : err}`) + "\n",
    );
    process.exit(1);
    throw err;
  });
  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  console.log(fmt.header(`Preview-compose: ${postureId}  →  team ${opts.team}`));
  console.log();
  console.log(`  Cascade applied:`);
  for (const s of result.composed.scopes_applied) {
    console.log(`    ${s.scope.padEnd(8)} ${s.posture_id}  (rev ${s.revision_no})`);
  }
  console.log();
  const body = result.composed.body;
  console.log(`  Effective:`);
  console.log(
    `    coherence:  enabled=${body.sideband.coherence.enabled}  ` +
      `cadence=${body.sideband.coherence.cadence_seconds}s  ` +
      `severity=${severityBadge(body.sideband.coherence.severity_on_fire)}`,
  );
  console.log(
    `    fault_line: enabled=${body.sideband.fault_line.enabled}  ` +
      `floor=${severityBadge(body.sideband.fault_line.severity_floor)}  ` +
      `severity=${severityBadge(body.sideband.fault_line.severity_on_fire)}`,
  );
  console.log(
    `    fleet:      enabled=${body.sideband.fleet.enabled}  ` +
      `cadence=${body.sideband.fleet.cadence_seconds}s  ` +
      `severity=${severityBadge(body.sideband.fleet.severity_on_fire)}`,
  );
  console.log(`\n  Use --json to see the full body.\n`);
}

// ─── mnemom posture delete ───────────────────────────────────────────────

export async function postureDeleteCommand(postureId: string | undefined): Promise<void> {
  await requireAuth();
  if (!postureId) {
    console.error(fmt.error("Usage: mnemom posture delete <posture_id>") + "\n");
    process.exit(1);
    return;
  }
  await deletePosture(postureId).catch((err) => {
    console.error(fmt.error(`Delete failed: ${err instanceof Error ? err.message : err}`) + "\n");
    process.exit(1);
    throw err;
  });
  console.log(fmt.success(`Soft-deleted posture ${postureId}\n`));
}
