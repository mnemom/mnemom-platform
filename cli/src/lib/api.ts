import { getApiUrl } from "./config.js";
import { getAccessToken } from "./auth.js";

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

/**
 * Build auth headers if a token is available.
 * Returns empty object when unauthenticated (read-only calls).
 */
async function authHeaders(): Promise<Record<string, string>> {
  const token = await getAccessToken();
  if (!token) return {};
  return { Authorization: `Bearer ${sanitizeForHttp(token)}` };
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
}

export async function listAgents(): Promise<AgentListItem[]> {
  const url = validateUrl(`${API_BASE}/v1/agents?limit=100`);
  const response = await fetch(url, { headers: await authHeaders() });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: "unknown" })) as ApiError;
    throw new Error(err.message || `Failed to list agents: ${response.status}`);
  }
  const data = await response.json() as { agents: AgentListItem[] };
  return data.agents ?? [];
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
