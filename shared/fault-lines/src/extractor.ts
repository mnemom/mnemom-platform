import type {
  FleetCoherenceResult,
  ValueDivergence,
  FaultLine,
  FaultLineClassification,
  FaultLineAnalysis,
  FaultLineSummary,
  FaultLineAlignment,
} from './types.js';

// Minimal agent card shape needed for extraction
type AgentCardInput = {
  agent_id: string;
  values?: {
    declared?: string[];
    definitions?: Record<string, { conflicts_with?: string[] }>;
  };
  autonomy_envelope?: { bounded_actions?: string[] };
  extensions?: {
    clpi?: { role?: string };
    [key: string]: unknown;
  };
};

type Severity = 'critical' | 'high' | 'medium' | 'low';

// Role-specific keywords used for complementary classification heuristic
const ROLE_KEYWORDS = [
  'analyst', 'reviewer', 'auditor', 'monitor', 'validator',
  'coordinator', 'planner', 'scheduler', 'orchestrator',
  'executor', 'worker', 'processor', 'handler',
  'reporter', 'summarizer', 'aggregator',
];

/**
 * Extract classified fault lines from fleet coherence results and agent cards.
 * Pure, synchronous, deterministic — no I/O, no LLM calls.
 *
 * This is a temporary local implementation. Once @mnemom/agent-alignment-protocol@0.6.0
 * is published, this file will be deleted and we'll call analyzeFaultLines from the SDK.
 */
export function extractFaultLines(
  coherenceResult: FleetCoherenceResult,
  agentCards: AgentCardInput[],
): FaultLineAnalysis {
  const cardMap = new Map<string, AgentCardInput>();
  for (const card of agentCards) {
    cardMap.set(card.agent_id, card);
  }

  const allAgentIds = agentCards.map((c) => c.agent_id);

  // Process each divergence from the SDK group-centric format directly
  const faultLines: FaultLine[] = [];

  for (const div of coherenceResult.divergence_report) {
    const { value, agents_declaring, agents_missing, agents_conflicting, impact_on_fleet_score } = div;

    // For agents in the cards but not listed by SDK, classify based on card data
    const sdkKnownAgents = new Set([
      ...agents_declaring,
      ...agents_missing,
      ...agents_conflicting,
    ]);

    // Re-classify agents not known to the SDK based on card data
    const finalDeclaring = [...agents_declaring];
    const finalMissing = [...agents_missing];
    const finalConflicting = [...agents_conflicting];

    for (const agentId of allAgentIds) {
      if (sdkKnownAgents.has(agentId)) continue;
      const card = cardMap.get(agentId);
      if (!card) continue;

      const declaredValues = card.values?.declared ?? [];
      const definitions = card.values?.definitions ?? {};

      if (hasConflict(value, definitions)) {
        finalConflicting.push(agentId);
      } else if (declaredValues.includes(value)) {
        finalDeclaring.push(agentId);
      } else {
        finalMissing.push(agentId);
      }
    }

    const totalAgents = allAgentIds.length || (finalDeclaring.length + finalMissing.length + finalConflicting.length);

    // Determine classification
    const classification = classifyFaultLine(
      finalDeclaring,
      finalMissing,
      finalConflicting,
      agentCards,
    );

    // Compute agent_fraction
    const affectedCount = finalMissing.length + finalConflicting.length;
    const agentFraction = totalAgents > 0 ? affectedCount / totalAgents : 0;

    // Compute capability_overlap among affected agents
    const affectedAgentIds = [...finalMissing, ...finalConflicting];
    const capabilityOverlap = computeCapabilityOverlap(affectedAgentIds, finalDeclaring, cardMap);

    // Impact score — use impact_on_fleet_score as the divergence signal
    const impactScore = clamp(impact_on_fleet_score * agentFraction * Math.max(capabilityOverlap, 0.5), 0, 1);

    // Severity
    const severity = impactToSeverity(impactScore);

    // Affected capabilities: intersection of bounded_actions from all involved agents
    const allInvolved = [...finalDeclaring, ...finalMissing, ...finalConflicting];
    const affectsCapabilities = intersectBoundedActions(allInvolved, cardMap);

    // Resolution hint
    const resolutionHint = buildResolutionHint(classification, value, finalMissing, finalConflicting);

    // Deterministic ID
    const idInput = value + ':' + allInvolved.slice().sort().join(',');
    const id = `fl-${deterministicHex(idInput, 8)}`;

    faultLines.push({
      id,
      value,
      classification,
      severity,
      agents_declaring: finalDeclaring,
      agents_missing: finalMissing,
      agents_conflicting: finalConflicting,
      impact_score: round4(impactScore),
      resolution_hint: resolutionHint,
      affects_capabilities: affectsCapabilities,
    });
  }

  // Sort: critical first, then by impact_score descending
  faultLines.sort((a, b) => {
    const severityOrder = severityRank(a.severity) - severityRank(b.severity);
    if (severityOrder !== 0) return severityOrder;
    return b.impact_score - a.impact_score;
  });

  // Build summary
  const summary = buildSummary(faultLines);

  // Build fault line alignments
  const alignments = detectAlignments(faultLines);

  // Analysis ID: deterministic from sorted agent IDs
  const teamIdInput = allAgentIds.slice().sort().join(':');
  const analysisId = `fla-${deterministicHex('analysis:' + teamIdInput, 12)}`;

  return {
    analysis_id: analysisId,
    fleet_score: coherenceResult.fleet_score,
    fault_lines: faultLines,
    alignments,
    summary,
  };
}

// ============================================================================
// Fault line alignment detection
// ============================================================================

/**
 * Detect cross-cutting alignment patterns: groups of fault lines that share
 * the same minority vs. majority agent split.
 */
function detectAlignments(faultLines: FaultLine[]): FaultLineAlignment[] {
  if (faultLines.length < 2) return [];

  // Group fault lines by their minority agent set (agents_conflicting + agents_missing)
  const groupMap = new Map<string, FaultLine[]>();

  for (const fl of faultLines) {
    const minority = [...fl.agents_conflicting, ...fl.agents_missing].sort().join(',');
    if (!minority) continue;
    const existing = groupMap.get(minority) ?? [];
    existing.push(fl);
    groupMap.set(minority, existing);
  }

  const alignments: FaultLineAlignment[] = [];

  for (const [minorityKey, group] of groupMap) {
    if (group.length < 2) continue;

    const minorityAgents = minorityKey.split(',').filter(Boolean);
    const majorityAgents = group[0].agents_declaring;

    // Alignment score: fraction of fault lines in this group out of total
    const alignmentScore = round4(group.length / faultLines.length);

    // Severity based on worst fault line in the group
    const worstSeverity = group.reduce<Severity>((worst, fl) => {
      return severityRank(fl.severity) < severityRank(worst) ? fl.severity : worst;
    }, 'low');

    const faultLineIds = group.map((fl) => fl.id);
    const idInput = faultLineIds.slice().sort().join(':');
    const id = `fla-align-${deterministicHex(idInput, 8)}`;

    alignments.push({
      id,
      fault_line_ids: faultLineIds,
      minority_agents: minorityAgents,
      majority_agents: majorityAgents,
      alignment_score: alignmentScore,
      severity: worstSeverity,
      description: `${minorityAgents.length} agent(s) consistently diverge from the majority across ${group.length} fault lines.`,
    });
  }

  // Sort by alignment_score descending
  alignments.sort((a, b) => b.alignment_score - a.alignment_score);

  return alignments;
}

// ============================================================================
// Internal helpers
// ============================================================================

function deterministicHex(input: string, length: number): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  const hex = Math.abs(hash).toString(16).padStart(length, '0');
  return hex.slice(0, length);
}

/**
 * Check whether any value definition in this agent's card lists the target value
 * in its conflicts_with array.
 */
function hasConflict(
  targetValue: string,
  definitions: Record<string, { conflicts_with?: string[] }>,
): boolean {
  for (const def of Object.values(definitions)) {
    if (def.conflicts_with?.includes(targetValue)) {
      return true;
    }
  }
  return false;
}

/**
 * Classify a fault line based on which agents declare, miss, or conflict with the value.
 * Includes complementary detection: if declaring agents share a CLPI role that missing
 * agents do NOT share, this is intentional role specialization — not a gap.
 */
function classifyFaultLine(
  declaring: string[],
  missing: string[],
  conflicting: string[],
  agentCards: AgentCardInput[],
): FaultLineClassification {
  // Hard blocker: at least one agent explicitly conflicts
  if (conflicting.length > 0) {
    return 'incompatible';
  }

  // Complementary: declaring agents share a CLPI role that missing agents do not have.
  // Primary check: extensions.clpi.role (authoritative — mirrors SDK v0.6.1 logic)
  if (declaring.length >= 1 && missing.length >= 1) {
    const cardMap = new Map(agentCards.map(c => [c.agent_id, c]));
    const declaringRoles = new Set(
      declaring.map(id => cardMap.get(id)?.extensions?.clpi?.role ?? null).filter(Boolean)
    );
    const missingRoles = new Set(
      missing.map(id => cardMap.get(id)?.extensions?.clpi?.role ?? null).filter(Boolean)
    );
    if (declaringRoles.size > 0) {
      const isRoleExclusive = [...declaringRoles].every(role => !missingRoles.has(role));
      if (isRoleExclusive) return 'complementary';
    }
    // Fallback: agent ID contains a role keyword
    if ([...declaring, ...missing].some(id => ROLE_KEYWORDS.some(kw => id.toLowerCase().includes(kw)))) {
      return 'complementary';
    }
  }

  // Priority mismatch: multiple agents declare the same value but all agents are declaring
  if (declaring.length >= 2 && missing.length === 0) {
    return 'priority_mismatch';
  }

  // Default: agents are missing the value but none conflict — resolvable
  return 'resolvable';
}

/**
 * Compute capability overlap between affected agents (missing + conflicting) and declaring agents.
 * Returns 0-1 representing the fraction of overlapping bounded_actions.
 */
function computeCapabilityOverlap(
  affectedIds: string[],
  declaringIds: string[],
  cardMap: Map<string, AgentCardInput>,
): number {
  if (affectedIds.length === 0 || declaringIds.length === 0) {
    return affectedIds.length === 0 ? 0 : 1;
  }

  const affectedActions = collectBoundedActions(affectedIds, cardMap);
  const declaringActions = collectBoundedActions(declaringIds, cardMap);

  if (affectedActions.size === 0 || declaringActions.size === 0) {
    return 0;
  }

  const union = new Set([...affectedActions, ...declaringActions]);
  let intersectionCount = 0;
  for (const action of affectedActions) {
    if (declaringActions.has(action)) {
      intersectionCount++;
    }
  }

  return union.size > 0 ? intersectionCount / union.size : 0;
}

function collectBoundedActions(agentIds: string[], cardMap: Map<string, AgentCardInput>): Set<string> {
  const actions = new Set<string>();
  for (const id of agentIds) {
    const card = cardMap.get(id);
    if (card?.autonomy_envelope?.bounded_actions) {
      for (const action of card.autonomy_envelope.bounded_actions) {
        actions.add(action);
      }
    }
  }
  return actions;
}

/**
 * Intersection of bounded_actions across all involved agents.
 */
function intersectBoundedActions(agentIds: string[], cardMap: Map<string, AgentCardInput>): string[] {
  const agentsWithActions = agentIds
    .map((id) => cardMap.get(id))
    .filter((card): card is AgentCardInput => card != null)
    .map((card) => new Set(card.autonomy_envelope?.bounded_actions ?? []));

  if (agentsWithActions.length === 0) return [];

  const first = agentsWithActions[0];
  const result: string[] = [];
  for (const action of first) {
    if (agentsWithActions.every((s) => s.has(action))) {
      result.push(action);
    }
  }
  return result.sort();
}

function impactToSeverity(score: number): Severity {
  if (score >= 0.7) return 'critical';
  if (score >= 0.4) return 'high';
  if (score >= 0.2) return 'medium';
  return 'low';
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case 'critical': return 0;
    case 'high': return 1;
    case 'medium': return 2;
    case 'low': return 3;
  }
}

function buildResolutionHint(
  classification: FaultLineClassification,
  value: string,
  agentsMissing: string[],
  agentsConflicting: string[],
): string {
  switch (classification) {
    case 'resolvable':
      return `Add value "${value}" to agent cards: ${agentsMissing.join(', ')}. No conflicts detected — this is a straightforward card update.`;
    case 'priority_mismatch':
      return `Agents declare "${value}" with different priorities or definitions. Align on a shared definition and priority ranking across the fleet.`;
    case 'incompatible':
      return `Value "${value}" is in the conflicts_with list for agents: ${agentsConflicting.join(', ')}. This requires human review to resolve the fundamental value conflict.`;
    case 'complementary':
      return `Value "${value}" is intentionally absent for role-scoped agents: ${agentsMissing.join(', ')}. This is by design — no action required.`;
  }
}

function buildSummary(faultLines: FaultLine[]): FaultLineSummary {
  let resolvable = 0;
  let priorityMismatch = 0;
  let incompatible = 0;
  let complementary = 0;
  let criticalCount = 0;

  for (const fl of faultLines) {
    switch (fl.classification) {
      case 'resolvable': resolvable++; break;
      case 'priority_mismatch': priorityMismatch++; break;
      case 'incompatible': incompatible++; break;
      case 'complementary': complementary++; break;
    }
    if (fl.severity === 'critical') {
      criticalCount++;
    }
  }

  return {
    total: faultLines.length,
    resolvable,
    priority_mismatch: priorityMismatch,
    incompatible,
    complementary,
    critical_count: criticalCount,
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function round4(value: number): number {
  return Math.round(value * 10000) / 10000;
}
