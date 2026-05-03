import { listMyOrgs, getMyPersonalOrg, type OrgListItem } from "../lib/api.js";
import { requireAuth } from "../lib/auth.js";
import { fmt } from "../lib/format.js";

/**
 * `mnemom org list`
 *
 * Lists every org the user is a member of, including their personal-org-of-one
 * (per ADR-044 Option A — GitHub model). Personal orgs are tagged `(personal)`
 * in the Name column. Output is a human-readable table; pass `--json` for
 * machine-readable output.
 */
export async function orgListCommand(opts: { json?: boolean }): Promise<void> {
  await requireAuth();

  let orgs: OrgListItem[];
  try {
    orgs = await listMyOrgs();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(fmt.error(`Failed to list orgs: ${msg}`) + "\n");
    process.exit(1);
  }

  if (opts.json) {
    console.log(JSON.stringify(orgs, null, 2));
    return;
  }

  console.log(fmt.header("Organizations"));
  console.log();

  if (orgs.length === 0) {
    console.log("  No organizations found.\n");
    return;
  }

  const nameW = 32;
  const idW = 24;
  const roleW = 10;
  const ownerW = 8;

  const header =
    "Name".padEnd(nameW) +
    "ID".padEnd(idW) +
    "Role".padEnd(roleW) +
    "Owner".padEnd(ownerW);
  console.log(`  ${header}`);
  console.log(`  ${"─".repeat(nameW + idW + roleW + ownerW)}`);

  for (const org of orgs) {
    const tag = org.is_personal ? " (personal)" : "";
    const name = `${org.name}${tag}`.slice(0, nameW - 2).padEnd(nameW);
    const id = org.org_id.slice(0, idW - 2).padEnd(idW);
    const role = (org.role ?? "-").padEnd(roleW);
    const owner = (org.is_owner ? "yes" : "no").padEnd(ownerW);
    console.log(`  ${name}${id}${role}${owner}`);
  }

  console.log(`\n  Total: ${orgs.length} organization(s)\n`);
}

/**
 * `mnemom org show [<org_id>]` or `mnemom org show --personal`
 *
 * Print details for one organization. With `--personal`, fetches the user's
 * personal org via `/v1/auth/me/personal-org`. Otherwise, the membership
 * matching `<org_id>` is printed (or, if no id is given and the user has
 * exactly one membership, that one).
 */
export async function orgShowCommand(
  orgIdArg: string | undefined,
  opts: { personal?: boolean; json?: boolean },
): Promise<void> {
  await requireAuth();

  let target: OrgListItem | null = null;

  try {
    if (opts.personal) {
      const ref = await getMyPersonalOrg();
      // Re-resolve to the full org row so we can print every field.
      const orgs = await listMyOrgs();
      target = orgs.find((o) => o.org_id === ref.org_id) ?? null;
    } else {
      const orgs = await listMyOrgs();
      if (orgIdArg) {
        target = orgs.find((o) => o.org_id === orgIdArg) ?? null;
        if (!target) {
          console.log(fmt.error(`Org '${orgIdArg}' not found in your memberships.`) + "\n");
          process.exit(1);
        }
      } else if (orgs.length === 1) {
        target = orgs[0];
      } else {
        console.log(
          fmt.warn(
            `You have ${orgs.length} memberships. Specify an org_id or pass --personal.`,
          ) + "\n",
        );
        process.exit(1);
        return;
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(fmt.error(`Failed to fetch org: ${msg}`) + "\n");
    process.exit(1);
    return;
  }

  if (!target) {
    console.log(fmt.error("Org not found.") + "\n");
    process.exit(1);
    return;
  }

  if (opts.json) {
    console.log(JSON.stringify(target, null, 2));
    return;
  }

  console.log(fmt.header(target.name));
  console.log();
  console.log(`  ID:          ${target.org_id}`);
  console.log(`  Slug:        ${target.slug}`);
  console.log(`  Personal:    ${target.is_personal ? "yes" : "no"}`);
  console.log(`  Role:        ${target.role ?? "-"}`);
  console.log(`  Owner:       ${target.is_owner ? "yes (you)" : "no"}`);
  if (target.billing_email) {
    console.log(`  Billing:     ${target.billing_email}`);
  }
  if (target.company_name) {
    console.log(`  Company:     ${target.company_name}`);
  }
  if (target.accepted_at) {
    console.log(`  Accepted at: ${new Date(target.accepted_at).toLocaleDateString()}`);
  }
  console.log();
}
