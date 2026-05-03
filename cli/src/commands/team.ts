/**
 * `mnemom team ...` commands — Piece 2 of T1-3.1 (ADR-044 amended).
 *
 *   mnemom team list                                     — list all teams across orgs
 *   mnemom team show <team_id> [--json]                  — show one team's detail
 *   mnemom team alignment-template <team_id>             — read alignment template
 *   mnemom team alignment-template <team_id> --set <f>   — write from YAML/JSON file
 *   mnemom team alignment-template <team_id> --clear     — clear template
 *   mnemom team protection-template <team_id> [...]      — same shape (protection)
 *   mnemom team preview-compose <team_id> [--protection] — dry-run from stdin/file
 *
 * Per ADR-044 amended + Charter §I11: team membership is OPTIONAL. Teams
 * are an agent grouping primitive within an org; users have no team
 * concept. Backend RBAC for these endpoints is purely org-level
 * (requireOrgRole on team.org_id). The CLI authenticates the user the
 * same way `mnemom org` does — login token or MNEMOM_API_KEY.
 */

import { readFileSync } from "node:fs";
import {
  listMyTeams,
  getTeam,
  getTeamTemplate,
  putTeamTemplate,
  deleteTeamTemplate,
  previewComposeTeamTemplate,
  type TeamListItem,
  type TeamDetail,
  type TeamTemplateBody,
  type TeamTemplateKind,
} from "../lib/api.js";
import { requireAuth } from "../lib/auth.js";
import { fmt } from "../lib/format.js";

// ─── mnemom team list ────────────────────────────────────────────────────

export async function teamListCommand(opts: { json?: boolean }): Promise<void> {
  await requireAuth();

  let teams: TeamListItem[];
  try {
    teams = await listMyTeams();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(fmt.error(`Failed to list teams: ${msg}`) + "\n");
    process.exit(1);
  }

  if (opts.json) {
    console.log(JSON.stringify(teams, null, 2));
    return;
  }

  console.log(fmt.header("Teams"));
  console.log();

  if (teams.length === 0) {
    console.log(
      "  No teams found.\n" +
        "  Teams are an optional agent grouping primitive within an org.\n" +
        "  Solo agents (zero teams) compose under Platform → Org → Agent.\n",
    );
    return;
  }

  const nameW = 28;
  const idW = 38;
  const orgW = 22;
  const memberW = 8;

  const header =
    "Name".padEnd(nameW) +
    "Team ID".padEnd(idW) +
    "Org".padEnd(orgW) +
    "Members".padEnd(memberW);
  console.log(`  ${header}`);
  console.log(`  ${"─".repeat(nameW + idW + orgW + memberW)}`);

  for (const team of teams) {
    const name = team.name.slice(0, nameW - 2).padEnd(nameW);
    const id = team.team_id.slice(0, idW - 2).padEnd(idW);
    const org = (team.org_name ?? team.org_id).slice(0, orgW - 2).padEnd(orgW);
    const members = String(team.member_count ?? 0).padEnd(memberW);
    console.log(`  ${name}${id}${org}${members}`);
  }

  console.log(`\n  Total: ${teams.length} team(s)\n`);
}

// ─── mnemom team show <team_id> ──────────────────────────────────────────

export async function teamShowCommand(
  teamId: string | undefined,
  opts: { json?: boolean },
): Promise<void> {
  await requireAuth();

  if (!teamId) {
    console.log(fmt.error("Usage: mnemom team show <team_id>") + "\n");
    process.exit(1);
    return;
  }

  let team: TeamDetail;
  try {
    team = await getTeam(teamId);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(fmt.error(`Failed to fetch team: ${msg}`) + "\n");
    process.exit(1);
    return;
  }

  if (opts.json) {
    console.log(JSON.stringify(team, null, 2));
    return;
  }

  console.log(fmt.header(team.name));
  console.log();
  console.log(`  Team ID:     ${team.team_id}`);
  console.log(`  Org ID:      ${team.org_id}`);
  if (team.description) {
    console.log(`  Description: ${team.description}`);
  }
  console.log(`  Status:      ${team.status ?? "active"}`);
  if (typeof team.member_count === "number") {
    console.log(`  Members:     ${team.member_count}`);
  }
  if (team.visibility) {
    console.log(`  Visibility:  ${team.visibility}`);
  }
  if (team.created_at) {
    console.log(`  Created:     ${new Date(team.created_at).toLocaleDateString()}`);
  }
  console.log();
}

// ─── mnemom team alignment-template / protection-template ───────────────
//
// Shared dispatcher. The two commands differ only in the `kind` argument
// passed through to the API client. A get/set/clear flag determines the
// operation; without a flag the command reads the template (GET).

interface TemplateOpts {
  set?: string; // path to YAML/JSON file
  clear?: boolean;
  json?: boolean;
}

export async function teamTemplateCommand(
  kind: TeamTemplateKind,
  teamId: string | undefined,
  opts: TemplateOpts,
): Promise<void> {
  await requireAuth();

  if (!teamId) {
    console.log(
      fmt.error(`Usage: mnemom team ${kind}-template <team_id> [--set <file> | --clear] [--json]`) +
        "\n",
    );
    process.exit(1);
    return;
  }

  if (opts.set && opts.clear) {
    console.log(fmt.error("Specify --set OR --clear, not both.") + "\n");
    process.exit(1);
    return;
  }

  // ── PUT (--set <file>) ─────────────────────────────────────────────
  if (opts.set) {
    let body: string;
    try {
      body = readFileSync(opts.set, "utf8");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(fmt.error(`Failed to read '${opts.set}': ${msg}`) + "\n");
      process.exit(1);
      return;
    }
    let result: TeamTemplateBody;
    try {
      result = await putTeamTemplate(teamId, kind, body);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(fmt.error(`Failed to write team ${kind} template: ${msg}`) + "\n");
      process.exit(1);
      return;
    }
    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }
    console.log(fmt.header(`Team ${kind} template — saved`));
    console.log();
    console.log(`  Team ID:           ${result.team_id}`);
    console.log(`  Org ID:            ${result.org_id}`);
    console.log(`  Enabled:           ${result.enabled ? "yes" : "no"}`);
    if (typeof result.agents_flagged_for_recompose === "number") {
      console.log(
        `  Agents recompose:  ${result.agents_flagged_for_recompose} ` +
          `(active members of this team only — not blanket fan-out)`,
      );
    }
    console.log();
    return;
  }

  // ── DELETE (--clear) ────────────────────────────────────────────────
  if (opts.clear) {
    let result: TeamTemplateBody;
    try {
      result = await deleteTeamTemplate(teamId, kind);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(fmt.error(`Failed to clear team ${kind} template: ${msg}`) + "\n");
      process.exit(1);
      return;
    }
    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }
    console.log(fmt.header(`Team ${kind} template — cleared`));
    console.log();
    console.log(`  Team ID:           ${result.team_id}`);
    console.log(`  Org ID:            ${result.org_id}`);
    console.log(`  Deleted:           yes`);
    if (typeof result.agents_flagged_for_recompose === "number") {
      console.log(
        `  Agents recompose:  ${result.agents_flagged_for_recompose}`,
      );
    }
    console.log();
    return;
  }

  // ── GET (default) ──────────────────────────────────────────────────
  let result: TeamTemplateBody;
  try {
    result = await getTeamTemplate(teamId, kind);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(fmt.error(`Failed to read team ${kind} template: ${msg}`) + "\n");
    process.exit(1);
    return;
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  console.log(fmt.header(`Team ${kind} template`));
  console.log();
  console.log(`  Team ID:  ${result.team_id}`);
  console.log(`  Org ID:   ${result.org_id}`);
  console.log(`  Enabled:  ${result.enabled ? "yes" : "no"}`);
  console.log();
  if (result.template) {
    console.log(`  Template:`);
    console.log(JSON.stringify(result.template, null, 2));
  } else {
    console.log(
      `  No template set. Use --set <file> to write a YAML or JSON template.`,
    );
  }
  console.log();
}

// ─── mnemom team preview-compose <team_id> ───────────────────────────────

export async function teamPreviewComposeCommand(
  teamId: string | undefined,
  opts: { protection?: boolean; from?: string; json?: boolean },
): Promise<void> {
  await requireAuth();

  if (!teamId) {
    console.log(
      fmt.error(
        "Usage: mnemom team preview-compose <team_id> [--protection] [--from <file>] [--json]",
      ) + "\n",
    );
    process.exit(1);
    return;
  }

  const kind: TeamTemplateKind = opts.protection ? "protection" : "alignment";

  let body: string;
  if (opts.from) {
    try {
      body = readFileSync(opts.from, "utf8");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(fmt.error(`Failed to read '${opts.from}': ${msg}`) + "\n");
      process.exit(1);
      return;
    }
  } else {
    // Read from stdin if no file specified.
    body = await readAllStdin();
    if (!body.trim()) {
      console.log(
        fmt.error(
          "No template body supplied. Pass --from <file> or pipe YAML/JSON via stdin.",
        ) + "\n",
      );
      process.exit(1);
      return;
    }
  }

  let result: { composed: Record<string, unknown>; conflicts: unknown };
  try {
    result = await previewComposeTeamTemplate(teamId, kind, body);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(fmt.error(`Preview failed: ${msg}`) + "\n");
    process.exit(1);
    return;
  }

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  console.log(fmt.header(`Preview compose — team ${kind}`));
  console.log();
  console.log(`  Team ID:    ${teamId}`);
  console.log();
  console.log(`  Composed (org floor + draft team + platform ceiling):`);
  console.log(JSON.stringify(result.composed, null, 2));
  console.log();
  if (Array.isArray(result.conflicts) && result.conflicts.length > 0) {
    console.log(fmt.warn(`  Conflicts (${result.conflicts.length}):`));
    console.log(JSON.stringify(result.conflicts, null, 2));
  } else {
    console.log(`  No conflicts — draft does not weaken any floor.`);
  }
  console.log();
}

async function readAllStdin(): Promise<string> {
  return new Promise<string>((resolve) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (chunk) => {
      chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    });
    process.stdin.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    process.stdin.on("error", () => {
      resolve("");
    });
  });
}
