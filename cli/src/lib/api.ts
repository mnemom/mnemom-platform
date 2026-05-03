import { randomUUID } from "node:crypto";
import { getApiUrl } from "./config.js";
import { forceRefreshAccessToken, resolveAuth } from "./auth.js";

export const API_BASE = getApiUrl();

/** Sanitize file-sourced data before use in outbound HTTP requests. */
function sanitizeForHttp(data: string): string {
  return String(data).trim();
}

/** Validate a URL before use in HTTP requests to prevent injection. */
function validateUrl(url: string): string {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`Invalid URL protocol: ${parsed.protocol}`);
  }
  return parsed.href;
}

/**
 * Generate a fresh Idempotency-Key for a mutation request.
 *
 * The server's beginIdempotentMutation contract (mnemom-api/src/idempotency.ts)
 * requires this header on every PUT/POST/DELETE to a mutation endpoint;
 * without it the server short-circuits with a 400 "Idempotency-Key header is
 * required". Callers may pass an explicit key (for retries that must hit the
 * cached reservation) — when omitted, we mint a UUIDv4.
 */
export function newIdempotencyKey(): string {
  return randomUUID();
}

export interface Agent {
  id: string;
  gateway: string;
  last_seen: string | null;
  claimed: boolean;
  email?: string;
  created_at: string;
}

/**
 * Per docs.mnemom.ai/api-reference/openapi.json#components/schemas/IntegrityScore:
 *
 *   { agent_id, total_traces, verified_traces, violation_count, integrity_score }
 *
 * `integrity_score` is a value in [0, 1].
 *
 * Pre-this-fix the CLI's interface declared `score` / `verified` /
 * `violations` / `last_updated` — none of which exist on the wire. The
 * `mnemom integrity` command rendered every field as `undefined` (and the
 * score as `NaN%`) against any agent. Field names now match the docs
 * verbatim.
 *
 * NOTE — API shape divergence (flagged for a follow-up mnemom-api PR):
 * the RPC path in handleGetIntegrity returns an *array* of one object
 * (Supabase wraps TABLE-returning RPCs as arrays) without `agent_id`;
 * the manual fallback returns the *object* with `agent_id`. The docs
 * canonical is the object shape. We accept both shapes defensively in
 * getIntegrity below so this CLI works against today's prod API and
 * keeps working when the API normalizes to a single shape.
 */
export interface IntegrityScore {
  agent_id?: string;
  total_traces: number;
  verified_traces: number;
  violation_count: number;
  integrity_score: number;
}

export interface Trace {
  id: string;
  agent_id: string;
  timestamp: string;
  action: string;
  verified: boolean;
  reasoning?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
}

export interface ApiError {
  error: string;
  message: string;
}

async function fetchApi<T>(endpoint: string): Promise<T> {
  const url = validateUrl(`${API_BASE}${endpoint}`);
  const response = await fetch(url);

  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `API request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export async function postApi<T>(
  endpoint: string,
  body: unknown,
  opts: { idempotencyKey?: string } = {},
): Promise<T> {
  const url = validateUrl(`${API_BASE}${endpoint}`);
  const cred = await resolveAuth();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Idempotency-Key": opts.idempotencyKey ?? newIdempotencyKey(),
  };
  if (cred.type === "jwt") {
    headers["Authorization"] = `Bearer ${cred.token}`;
  } else if (cred.type === "api-key") {
    headers["X-Mnemom-Api-Key"] = cred.key;
  }

  const response = await fetch(url, { // lgtm[js/file-data-url]
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: `HTTP ${response.status}`,
    }))) as ApiError | { error: string; message: string; conflict_agent_id?: string };
    const msg = "message" in error ? error.message : JSON.stringify(error);
    // Preserve conflict_agent_id in the error message for 409 handling upstream
    if (response.status === 409 && "conflict_agent_id" in error) {
      throw new Error(`409: ${msg} (conflict: ${(error as any).conflict_agent_id})`);
    }
    throw new Error(`${response.status}: ${msg}`);
  }

  return response.json() as Promise<T>;
}

export async function verifyBinding(
  agentId: string,
  keyHash: string,
): Promise<{ bound: boolean; key_prefix: string | null }> {
  return postApi(`/v1/agents/${agentId}/verify-binding`, { key_hash: keyHash });
}

/**
 * Build auth headers from the best available credential.
 * Returns empty object when unauthenticated (read-only calls).
 */
async function authHeaders(): Promise<Record<string, string>> {
  const cred = await resolveAuth();
  switch (cred.type) {
    case "jwt":
      return { Authorization: `Bearer ${sanitizeForHttp(cred.token)}` };
    case "api-key":
      return { "X-Mnemom-Api-Key": sanitizeForHttp(cred.key) };
    case "none":
      return {};
  }
}

/**
 * Issue an authenticated fetch, and on a 401 response transparently force a
 * token refresh and retry once.
 *
 * We hit this in the wild when the locally-stored expiresAt diverges from
 * the JWT's actual exp claim (e.g. Supabase has been observed reporting
 * expires_in values longer than the JWT's exp). Without this retry,
 * `whoami` cheerfully reports a "valid" token while every authenticated
 * call gets 401 — and the user has no path forward besides
 * `mnemom logout && mnemom login`. The retry heals stale auth files
 * transparently for users who haven't re-logged-in since the
 * computeExpiresAt fix landed.
 *
 * `buildInit` is invoked fresh for each attempt so the retry picks up the
 * new Authorization header from the refreshed token. We do NOT mint a new
 * Idempotency-Key on the retry — the same key keys back into the same
 * server-side reservation by design.
 */
async function fetchWithAuthRetry(
  url: string,
  buildInit: () => Promise<RequestInit>,
): Promise<Response> {
  const first = await fetch(url, await buildInit());
  if (first.status !== 401) return first;
  const refreshed = await forceRefreshAccessToken();
  if (!refreshed) return first;
  return fetch(url, await buildInit());
}

export async function getAgent(id: string): Promise<Agent> {
  return fetchApi<Agent>(`/v1/agents/${id}`);
}

export interface AgentListItem {
  id: string;
  name: string | null;
  email: string | null;
  created_at: string;
  last_seen: string | null;
  containment_status: string | null;
  key_prefix?: string | null;
}

export async function listAgents(): Promise<AgentListItem[]> {
  const url = validateUrl(`${API_BASE}/v1/agents?limit=100`);
  const response = await fetchWithAuthRetry(url, async () => ({
    headers: await authHeaders(),
  }));
  if (!response.ok) {
    if (response.status === 401) {
      throw new Error("Not authenticated. Run `mnemom login` or set MNEMOM_API_KEY.");
    }
    const err = await response.json().catch(() => ({ error: "unknown" })) as ApiError;
    throw new Error(err.message || `Failed to list agents: ${response.status}`);
  }
  const data = await response.json() as { agents: AgentListItem[] };
  return data.agents ?? [];
}

// ─── orgs ───────────────────────────────────────────────────────────────

export interface OrgListItem {
  org_id: string;
  name: string;
  slug: string;
  is_personal: boolean;
  is_owner: boolean;
  role: string | null;
  billing_email?: string | null;
  company_name?: string | null;
  accepted_at?: string | null;
  created_at?: string | null;
}

export interface PersonalOrgRef {
  org_id: string;
  is_personal: true;
  just_provisioned?: boolean;
}

/**
 * GET /v1/orgs — list every org the user is a member of, including the
 * personal-org-of-one (per ADR-044 Option A, GitHub model). Personal sorts
 * first; multi-user orgs follow.
 */
export async function listMyOrgs(): Promise<OrgListItem[]> {
  const url = validateUrl(`${API_BASE}/v1/orgs`);
  const response = await fetchWithAuthRetry(url, async () => ({
    headers: await authHeaders(),
  }));
  if (!response.ok) {
    if (response.status === 401) {
      throw new Error("Not authenticated. Run `mnemom login` or set MNEMOM_API_KEY.");
    }
    const err = await response.json().catch(() => ({ error: "unknown" })) as ApiError;
    throw new Error(err.message || `API request failed: ${response.status}`);
  }
  const data = await response.json() as { orgs: OrgListItem[] };
  return data.orgs ?? [];
}

/**
 * GET /v1/auth/me/personal-org — accessor for the user's personal org.
 * Idempotent: lazily provisions for legacy accounts that pre-date the
 * mnemom-api migration 161 backfill.
 */
export async function getMyPersonalOrg(): Promise<PersonalOrgRef> {
  const url = validateUrl(`${API_BASE}/v1/auth/me/personal-org`);
  const response = await fetchWithAuthRetry(url, async () => ({
    headers: await authHeaders(),
  }));
  if (!response.ok) {
    if (response.status === 401) {
      throw new Error("Not authenticated. Run `mnemom login` or set MNEMOM_API_KEY.");
    }
    const err = await response.json().catch(() => ({ error: "unknown" })) as ApiError;
    throw new Error(err.message || `API request failed: ${response.status}`);
  }
  return await response.json() as PersonalOrgRef;
}

// ─── teams (Piece 2 of T1-3.1, ADR-044 amended) ─────────────────────────
//
// Per ADR-044 amended + Charter §I11: team membership is OPTIONAL. Teams
// are an agent grouping primitive within an org; users have no team
// concept. Backend RBAC for team-scope endpoints is purely org-level
// (requireOrgRole(team.org_id, ...)) — the CLI sends the user's auth
// header and the API enforces the role check.

export interface TeamListItem {
  team_id: string;
  name: string;
  org_id: string;
  org_name?: string | null;
  description?: string | null;
  status?: string;
  member_count?: number;
  visibility?: string;
}

export interface TeamDetail {
  team_id: string;
  name: string;
  org_id: string;
  description?: string | null;
  status?: string;
  member_count?: number;
  visibility?: string;
  avatar_url?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface TeamTemplateBody {
  team_id: string;
  org_id: string;
  name?: string;
  template: Record<string, unknown> | null;
  enabled: boolean;
  agents_flagged_for_recompose?: number;
  deleted?: boolean;
}

export type TeamTemplateKind = "alignment" | "protection";

/**
 * GET /v1/orgs/:org_id/teams for every org the user is a member of,
 * concatenated. The CLI consumer that just wants "every team I can see"
 * doesn't need to know about org boundaries; team_id is unique anyway.
 * Returns the flat list with org_name attached for display.
 */
export async function listMyTeams(): Promise<TeamListItem[]> {
  const orgs = await listMyOrgs();
  const teams: TeamListItem[] = [];
  for (const org of orgs) {
    const url = validateUrl(`${API_BASE}/v1/orgs/${org.org_id}/teams`);
    const response = await fetchWithAuthRetry(url, async () => ({
      headers: await authHeaders(),
    }));
    if (!response.ok) {
      // Skip orgs the user can't read teams from (e.g., role doesn't permit).
      // The list call should succeed at the member level, but tolerate edge cases.
      continue;
    }
    const data = (await response.json()) as { teams?: TeamListItem[] };
    for (const t of data.teams ?? []) {
      teams.push({ ...t, org_id: t.org_id ?? org.org_id, org_name: org.name });
    }
  }
  return teams;
}

/**
 * GET /v1/teams/:team_id — fetch a single team's row. Returns the team
 * detail including org_id (which the CLI uses to disambiguate team_id
 * collisions across orgs in error messages).
 */
export async function getTeam(teamId: string): Promise<TeamDetail> {
  const url = validateUrl(`${API_BASE}/v1/teams/${teamId}`);
  const response = await fetchWithAuthRetry(url, async () => ({
    headers: await authHeaders(),
  }));
  if (!response.ok) {
    if (response.status === 401) {
      throw new Error("Not authenticated. Run `mnemom login` or set MNEMOM_API_KEY.");
    }
    if (response.status === 404) {
      throw new Error(`Team '${teamId}' not found or not accessible.`);
    }
    const err = (await response.json().catch(() => ({ error: "unknown" }))) as ApiError;
    throw new Error(err.message || `API request failed: ${response.status}`);
  }
  return (await response.json()) as TeamDetail;
}

/**
 * GET /v1/teams/:team_id/(alignment|protection)-template — read the
 * current team-scope template + its enabled flag. Returns the wire body
 * verbatim. Empty for teams that have no template set yet (template:
 * null, enabled: false).
 */
export async function getTeamTemplate(
  teamId: string,
  kind: TeamTemplateKind,
): Promise<TeamTemplateBody> {
  const url = validateUrl(`${API_BASE}/v1/teams/${teamId}/${kind}-template`);
  const response = await fetchWithAuthRetry(url, async () => ({
    headers: { ...(await authHeaders()), Accept: "application/json" },
  }));
  if (!response.ok) {
    if (response.status === 401) {
      throw new Error("Not authenticated. Run `mnemom login` or set MNEMOM_API_KEY.");
    }
    if (response.status === 403) {
      throw new Error(`Forbidden: not a member of team '${teamId}'s org.`);
    }
    if (response.status === 404) {
      throw new Error(`Team '${teamId}' not found.`);
    }
    const err = (await response.json().catch(() => ({ error: "unknown" }))) as ApiError;
    throw new Error(err.message || `API request failed: ${response.status}`);
  }
  return (await response.json()) as TeamTemplateBody;
}

/**
 * PUT /v1/teams/:team_id/(alignment|protection)-template — write the
 * team-scope template. Body is YAML or JSON template content; the API
 * accepts either via Content-Type. Idempotency-Key is required (per the
 * idempotency-with-body-hash discipline in the API).
 *
 * On success returns the post-write team template body, including
 * agents_flagged_for_recompose so the caller can surface the fan-out
 * count to the user.
 */
export async function putTeamTemplate(
  teamId: string,
  kind: TeamTemplateKind,
  yamlBody: string,
): Promise<TeamTemplateBody> {
  const url = validateUrl(`${API_BASE}/v1/teams/${teamId}/${kind}-template`);
  const response = await fetchWithAuthRetry(url, async () => ({
    method: "PUT",
    headers: {
      ...(await authHeaders()),
      "Content-Type": "text/yaml",
      Accept: "application/json",
      "Idempotency-Key": newIdempotencyKey(),
    },
    body: yamlBody,
  }));
  if (!response.ok) {
    if (response.status === 401) {
      throw new Error("Not authenticated. Run `mnemom login` or set MNEMOM_API_KEY.");
    }
    if (response.status === 403) {
      throw new Error(`Forbidden: org admin or owner role required to write a team template.`);
    }
    if (response.status === 404) {
      throw new Error(`Team '${teamId}' not found.`);
    }
    if (response.status === 413) {
      throw new Error(`Template too large (server limit: 128 KiB alignment / 64 KiB protection).`);
    }
    const err = (await response.json().catch(() => ({ error: "unknown" }))) as ApiError;
    throw new Error(err.message || `API request failed: ${response.status}`);
  }
  return (await response.json()) as TeamTemplateBody;
}

/**
 * DELETE /v1/teams/:team_id/(alignment|protection)-template — clear the
 * template. Idempotent (deleting an already-cleared template is a 200).
 * Returns the post-delete team template body with deleted=true and the
 * recompose fan-out count.
 */
export async function deleteTeamTemplate(
  teamId: string,
  kind: TeamTemplateKind,
): Promise<TeamTemplateBody> {
  const url = validateUrl(`${API_BASE}/v1/teams/${teamId}/${kind}-template`);
  const response = await fetchWithAuthRetry(url, async () => ({
    method: "DELETE",
    headers: {
      ...(await authHeaders()),
      Accept: "application/json",
      "Idempotency-Key": newIdempotencyKey(),
    },
  }));
  if (!response.ok) {
    if (response.status === 401) {
      throw new Error("Not authenticated. Run `mnemom login` or set MNEMOM_API_KEY.");
    }
    if (response.status === 403) {
      throw new Error(`Forbidden: org admin or owner role required to clear a team template.`);
    }
    if (response.status === 404) {
      throw new Error(`Team '${teamId}' not found.`);
    }
    const err = (await response.json().catch(() => ({ error: "unknown" }))) as ApiError;
    throw new Error(err.message || `API request failed: ${response.status}`);
  }
  return (await response.json()) as TeamTemplateBody;
}

/**
 * POST /v1/teams/:team_id/(alignment|protection)-template/preview-compose
 * — dry-run the composer with the supplied draft against the team's
 * current org+platform context. Returns the composed canonical output
 * plus per-field conflicts where the draft was tightened by the
 * org/platform floor. No DB writes.
 */
export async function previewComposeTeamTemplate(
  teamId: string,
  kind: TeamTemplateKind,
  yamlBody: string,
): Promise<{ composed: Record<string, unknown>; conflicts: unknown }> {
  const url = validateUrl(
    `${API_BASE}/v1/teams/${teamId}/${kind}-template/preview-compose`,
  );
  const response = await fetchWithAuthRetry(url, async () => ({
    method: "POST",
    headers: {
      ...(await authHeaders()),
      "Content-Type": "text/yaml",
      Accept: "application/json",
    },
    body: yamlBody,
  }));
  if (!response.ok) {
    const err = (await response.json().catch(() => ({ error: "unknown" }))) as ApiError;
    throw new Error(err.message || `Preview failed: ${response.status}`);
  }
  const body = (await response.json()) as {
    composed: Record<string, unknown>;
    conflicts: unknown;
  };
  return { composed: body.composed, conflicts: body.conflicts };
}

/**
 * Look up an agent in the authenticated user's account by name.
 * Tries exact match first, then single partial match.
 * Throws if multiple agents partially match (ambiguous).
 * Returns null if no match found.
 * Note: capped at 100 agents by listAgents().
 */
export async function getAgentByName(name: string): Promise<AgentListItem | null> {
  const agents = await listAgents();
  const lower = name.toLowerCase();

  const exact = agents.find(a => a.name?.toLowerCase() === lower);
  if (exact) return exact;

  const partials = agents.filter(a => a.name?.toLowerCase().includes(lower));
  if (partials.length === 1) return partials[0];
  if (partials.length > 1) {
    const names = partials.map(a => a.name ?? a.id).join(", ");
    throw new Error(`Multiple agents match '${name}': ${names}. Use a more specific name.`);
  }

  return null;
}

/**
 * Fetch the integrity score for an agent.
 *
 * `/v1/integrity/:id` is the public-when-agent-is-public, owner-otherwise
 * data route. The CLI must send the owner's auth header so private claimed
 * agents (the common case for customers and internal users) return 200
 * instead of 401. fetchWithAuthRetry inherits the 401-retry-with-refresh
 * path from PR #200 so a stale local expiresAt heals transparently.
 */
export async function getIntegrity(id: string): Promise<IntegrityScore> {
  const url = validateUrl(`${API_BASE}/v1/integrity/${id}`);
  const response = await fetchWithAuthRetry(url, async () => ({
    headers: await authHeaders(),
  }));
  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `API request failed: ${response.status}`);
  }
  // Accept both the canonical docs shape (object) and the RPC-wrapped shape
  // (array of one row). The latter is what prod actually returns today on
  // the RPC path; flagged for a follow-up API normalization.
  const body = (await response.json()) as IntegrityScore | IntegrityScore[];
  const row: IntegrityScore = Array.isArray(body) ? (body[0] ?? emptyIntegrityRow(id)) : body;
  // Fill in agent_id when the API didn't (RPC path) so the field is always
  // populated for consumers regardless of which API path served the request.
  if (!row.agent_id) row.agent_id = id;
  return row;
}

function emptyIntegrityRow(agentId: string): IntegrityScore {
  return {
    agent_id: agentId,
    total_traces: 0,
    verified_traces: 0,
    violation_count: 0,
    integrity_score: 1,
  };
}

/**
 * Fetch recent traces for an agent.
 *
 * The API returns an envelope `{ traces, limit, offset }` (see
 * mnemom-api/src/index.ts:handleGetTraces). Pre-this-fix the CLI typed
 * the response as `Trace[]` and downstream code crashed with "traces is
 * not iterable" because the envelope is not iterable. We unwrap the
 * envelope here and return the bare array so callers (logs.ts) can keep
 * the simpler shape.
 *
 * Sends auth headers — same reasoning as getIntegrity. The pre-PR-A
 * `{ traces: [], private: true }` leaky envelope branch is gone, so we
 * don't need a special case for it.
 */
export async function getTraces(
  id: string,
  limit: number = 10
): Promise<Trace[]> {
  const url = validateUrl(`${API_BASE}/v1/traces?agent_id=${id}&limit=${limit}`);
  const response = await fetchWithAuthRetry(url, async () => ({
    headers: await authHeaders(),
  }));
  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `API request failed: ${response.status}`);
  }
  const data = (await response.json()) as { traces?: Trace[] } | Trace[];
  // Accept both the envelope shape (current API) and a bare array (defensive
  // — staging is mid-deploy when a CLI smoke runs against an older API).
  if (Array.isArray(data)) return data;
  return data.traces ?? [];
}

// ============================================================================
// Alignment Card API
// ============================================================================

export interface AlignmentCard {
  card_id?: string;
  version?: string;
  issued_at?: string;
  expires_at?: string;
  principal?: {
    name?: string;
    type?: string;
    organization?: string;
  };
  values?: {
    declared?: string[];
    definitions?: Record<string, string>;
  };
  autonomy_envelope?: {
    bounded_actions?: string[];
    forbidden_actions?: string[];
    escalation_triggers?: Array<{
      condition: string;
      action?: string;
    }>;
  };
  audit_commitment?: {
    log_level?: string;
    retention_days?: number;
    access_policy?: string;
  };
  extensions?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface CardResponse {
  card_id: string;
  agent_id: string;
  card_json: AlignmentCard;
  created_at: string;
  updated_at: string;
}

export async function getCard(agentId: string): Promise<CardResponse | null> {
  try {
    return await fetchApi<CardResponse>(`/v1/agents/${agentId}/card`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("404") || message.includes("not found")) {
      return null;
    }
    throw error;
  }
}

export async function updateCard(
  agentId: string,
  cardJson: AlignmentCard,
  opts: { idempotencyKey?: string } = {},
): Promise<{ updated: boolean; card_id: string }> {
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/card`);
  const response = await fetch(url, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": opts.idempotencyKey ?? newIdempotencyKey(),
      ...(await authHeaders()),
    },
    body: sanitizeForHttp(JSON.stringify({ card_json: cardJson })),
  });

  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `Card update failed: ${response.status}`);
  }

  return response.json() as Promise<{ updated: boolean; card_id: string }>;
}

export async function reverifyAgent(
  agentId: string,
  opts: { idempotencyKey?: string } = {},
): Promise<{ reverified: number }> {
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/reverify`);
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": opts.idempotencyKey ?? newIdempotencyKey(),
      ...(await authHeaders()),
    },
  });

  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `Reverify failed: ${response.status}`);
  }

  return response.json() as Promise<{ reverified: number }>;
}

// ============================================================================
// Policy API
// ============================================================================

export interface PolicyResponse {
  id: string;
  name: string;
  description: string | null;
  policy_json: Record<string, unknown>;
  version: number;
  created_by: string;
  created_at: string;
}

export interface PolicyListResponse {
  agent_id: string;
  policy: PolicyResponse | null;
}

export async function getPolicy(agentId: string): Promise<PolicyListResponse | null> {
  try {
    return await fetchApi<PolicyListResponse>(`/v1/agents/${agentId}/policy`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("404") || message.includes("not found")) {
      return null;
    }
    throw error;
  }
}

export async function publishPolicy(
  agentId: string,
  policyJson: Record<string, unknown>,
  opts: { idempotencyKey?: string } = {},
): Promise<{ id: string; version: number; created: boolean }> {
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/policy`);
  const response = await fetch(url, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": opts.idempotencyKey ?? newIdempotencyKey(),
      ...(await authHeaders()),
    },
    body: sanitizeForHttp(JSON.stringify({ policy_json: policyJson })),
  });

  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `Policy publish failed: ${response.status}`);
  }

  return response.json() as Promise<{ id: string; version: number; created: boolean }>;
}

export async function testPolicyHistorical(
  agentId: string,
  policyJson: Record<string, unknown>,
  limit: number = 50
): Promise<{
  agent_id: string;
  policy_name: string;
  total_traces: number;
  results: any[];
  summary: { pass: number; warn: number; fail: number; skipped: number };
}> {
  const url = validateUrl(`${API_BASE}/v1/policies/evaluate/historical`);
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await authHeaders()) },
    body: sanitizeForHttp(JSON.stringify({ agent_id: agentId, policy_json: policyJson, limit })),
  });

  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `Historical evaluation failed: ${response.status}`);
  }

  return response.json() as Promise<any>;
}

// ============================================================================
// Unified Card API (UC-4+)
// ============================================================================

/**
 * Fetch the canonical alignment card as YAML (or JSON fallback).
 * Returns the raw response body as a string.
 */
export async function getAlignmentCard(
  agentId: string,
  format: "yaml" | "json" = "yaml",
): Promise<{ body: string; contentType: string }> {
  const accept = format === "yaml" ? "text/yaml" : "application/json";
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/alignment-card`);
  const response = await fetch(url, {
    headers: { Accept: accept, ...(await authHeaders()) },
  });

  if (!response.ok) {
    if (response.status === 404) {
      return { body: "", contentType: "" };
    }
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `Failed to fetch alignment card: ${response.status}`);
  }

  const ct = response.headers.get("content-type") ?? "";
  const body = await response.text();
  return { body, contentType: ct };
}

/** Hard cap enforced by the API on inbound alignment-card bodies (413 otherwise). */
export const ALIGNMENT_CARD_MAX_BYTES = 128 * 1024;

/**
 * Shape of a successful PUT response — the canonical card the composer
 * just wrote, serialized as JSON via mnemom-api/src/composition/response.ts:
 * respondCard with `_composition` stripped. We type the fields we display;
 * the rest of the canonical card is allowed (and ignored at this layer).
 *
 * Pre-this-fix the typed return was `{ card_id, composed: boolean }` —
 * a fictional wrapper. The API never returned a `composed` field; the CLI
 * was rendering "Canonical card recomposed" gated on a value that, on the
 * real wire, is always undefined. Drop the lie; reflect the actual shape.
 */
export interface PublishedCardResponse {
  card_id?: string;
  agent_id?: string;
  card_version?: string;
  issued_at?: string;
  [key: string]: unknown;
}

/**
 * Publish (create or update) an alignment card.
 * Accepts YAML or JSON body; set contentType accordingly.
 */
export async function putAlignmentCard(
  agentId: string,
  body: string,
  contentType: "text/yaml" | "application/json" = "text/yaml",
  opts: { idempotencyKey?: string } = {},
): Promise<PublishedCardResponse> {
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/alignment-card`);
  // Lock in a single Idempotency-Key for this logical mutation. If the auth
  // token is stale and the first attempt returns 401, fetchWithAuthRetry
  // refreshes the token and retries — but the Idempotency-Key must be the
  // same key on both attempts so the server's reservation table sees them as
  // a single mutation, not two competing PUTs.
  const idempotencyKey = opts.idempotencyKey ?? newIdempotencyKey();
  const sanitizedBody = sanitizeForHttp(body);
  const response = await fetchWithAuthRetry(url, async () => ({
    method: "PUT",
    headers: {
      "Content-Type": contentType,
      // The API content-negotiates the response body via Accept (see
      // mnemom-api/src/composition/response.ts:respondYamlJson). We parse the
      // response as JSON below, so we have to ask for JSON explicitly —
      // Node's default Accept: */* would otherwise yield a YAML body and
      // response.json() would crash with "Unexpected token 'a' is not valid
      // JSON" against the canonical card we just wrote.
      Accept: "application/json",
      "Idempotency-Key": idempotencyKey,
      ...(await authHeaders()),
    },
    body: sanitizedBody,
  }));

  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `Failed to publish alignment card: ${response.status}`);
  }

  return response.json() as Promise<PublishedCardResponse>;
}

/**
 * Fetch the canonical protection card as YAML (or JSON fallback).
 */
export async function getProtectionCard(
  agentId: string,
  format: "yaml" | "json" = "yaml",
): Promise<{ body: string; contentType: string }> {
  const accept = format === "yaml" ? "text/yaml" : "application/json";
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/protection-card`);
  const response = await fetch(url, {
    headers: { Accept: accept, ...(await authHeaders()) },
  });

  if (!response.ok) {
    if (response.status === 404) {
      return { body: "", contentType: "" };
    }
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `Failed to fetch protection card: ${response.status}`);
  }

  const ct = response.headers.get("content-type") ?? "";
  const body = await response.text();
  return { body, contentType: ct };
}

/** Hard cap enforced by the API on inbound protection-card bodies (413 otherwise). */
export const PROTECTION_CARD_MAX_BYTES = 64 * 1024;

/**
 * Publish (create or update) a protection card.
 */
export async function putProtectionCard(
  agentId: string,
  body: string,
  contentType: "text/yaml" | "application/json" = "text/yaml",
  opts: { idempotencyKey?: string } = {},
): Promise<PublishedCardResponse> {
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/protection-card`);
  // See putAlignmentCard for why the Idempotency-Key is computed once outside
  // the retry closure.
  const idempotencyKey = opts.idempotencyKey ?? newIdempotencyKey();
  const sanitizedBody = sanitizeForHttp(body);
  const response = await fetchWithAuthRetry(url, async () => ({
    method: "PUT",
    headers: {
      "Content-Type": contentType,
      // See putAlignmentCard for the rationale — the API negotiates response
      // body format via Accept and we parse the response as JSON below.
      Accept: "application/json",
      "Idempotency-Key": idempotencyKey,
      ...(await authHeaders()),
    },
    body: sanitizedBody,
  }));

  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `Failed to publish protection card: ${response.status}`);
  }

  return response.json() as Promise<PublishedCardResponse>;
}

// ============================================================================
// Agent Resolution (server-side, no local config)
// ============================================================================

/**
 * Resolve an agent name or ID to a server agent ID.
 *
 * Resolution order:
 *  1. Explicit agentName parameter (--agent flag)
 *  2. MNEMOM_AGENT environment variable
 *
 * If the value looks like an agent ID (smolt-* or mnm-*), uses it directly.
 * Otherwise resolves the name from the authenticated user's agent list.
 */
export async function resolveAgentId(agentName?: string): Promise<string> {
  const name = agentName ?? process.env.MNEMOM_AGENT;

  if (!name) {
    console.error("\nAgent required. Use --agent <name> or set MNEMOM_AGENT.\n");
    console.error("List your agents with: mnemom agents\n");
    process.exit(1);
  }

  // If it looks like an agent ID, use directly (no server call needed)
  if (/^(smolt-[0-9a-f]{8}|mnm-[0-9a-f-]{36})$/.test(name)) {
    return name;
  }

  // Resolve name from server (requires auth)
  try {
    const agent = await getAgentByName(name);
    if (agent) return agent.id;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("Not authenticated")) {
      console.error(`\nNot authenticated. Run \`mnemom login\` first.\n`);
      process.exit(1);
    }
  }

  console.error(`\nAgent not found: ${name}`);
  console.error("List your agents with: mnemom agents\n");
  process.exit(1);
}
