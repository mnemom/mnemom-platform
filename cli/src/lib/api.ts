import { getApiUrl } from "./config.js";
import { resolveAuth } from "./auth.js";

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

export interface Agent {
  id: string;
  gateway: string;
  last_seen: string | null;
  claimed: boolean;
  email?: string;
  created_at: string;
}

export interface IntegrityScore {
  agent_id: string;
  score: number;
  total_traces: number;
  verified: number;
  violations: number;
  last_updated: string;
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

export async function postApi<T>(endpoint: string, body: unknown): Promise<T> {
  const url = validateUrl(`${API_BASE}${endpoint}`);
  const cred = await resolveAuth();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
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
  const response = await fetch(url, { headers: await authHeaders() });
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

export async function getIntegrity(id: string): Promise<IntegrityScore> {
  return fetchApi<IntegrityScore>(`/v1/integrity/${id}`);
}

export async function getTraces(
  id: string,
  limit: number = 10
): Promise<Trace[]> {
  return fetchApi<Trace[]>(`/v1/traces?agent_id=${id}&limit=${limit}`);
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
  cardJson: AlignmentCard
): Promise<{ updated: boolean; card_id: string }> {
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/card`);
  const response = await fetch(url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", ...(await authHeaders()) },
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
  agentId: string
): Promise<{ reverified: number }> {
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/reverify`);
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await authHeaders()) },
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
  policyJson: Record<string, unknown>
): Promise<{ id: string; version: number; created: boolean }> {
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/policy`);
  const response = await fetch(url, {
    method: "PUT",
    headers: { "Content-Type": "application/json", ...(await authHeaders()) },
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

/**
 * Publish (create or update) an alignment card.
 * Accepts YAML or JSON body; set contentType accordingly.
 */
export async function putAlignmentCard(
  agentId: string,
  body: string,
  contentType: "text/yaml" | "application/json" = "text/yaml",
): Promise<{ card_id: string; composed: boolean }> {
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/alignment-card`);
  const response = await fetch(url, {
    method: "PUT",
    headers: { "Content-Type": contentType, ...(await authHeaders()) },
    body: sanitizeForHttp(body),
  });

  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `Failed to publish alignment card: ${response.status}`);
  }

  return response.json() as Promise<{ card_id: string; composed: boolean }>;
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

/**
 * Publish (create or update) a protection card.
 */
export async function putProtectionCard(
  agentId: string,
  body: string,
  contentType: "text/yaml" | "application/json" = "text/yaml",
): Promise<{ card_id: string; composed: boolean }> {
  const url = validateUrl(`${API_BASE}/v1/agents/${agentId}/protection-card`);
  const response = await fetch(url, {
    method: "PUT",
    headers: { "Content-Type": contentType, ...(await authHeaders()) },
    body: sanitizeForHttp(body),
  });

  if (!response.ok) {
    const error = (await response.json().catch(() => ({
      error: "unknown",
      message: response.statusText,
    }))) as ApiError;
    throw new Error(error.message || `Failed to publish protection card: ${response.status}`);
  }

  return response.json() as Promise<{ card_id: string; composed: boolean }>;
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
