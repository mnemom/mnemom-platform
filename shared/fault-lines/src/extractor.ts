import type {
  FleetCoherenceResult,
  ValueDivergence,
  AgentCard,
  FaultLine,
  FaultLineClassification,
  FaultLineAnalysis,
  FaultLineSummary,
  Severity,
} from './types.js';

/**
 * Extract classified fault lines from fleet coherence results and agent cards.
 * Pure, synchronous, deterministic — no I/O, no LLM calls.
 */
export function extractFaultLines(
  coherenceResult: FleetCoherenceResult,
  agentCards: AgentCard[],
): FaultLineAnalysis {
  const cardMap = new Map<string, AgentCard>();
  for (const card of agentCards) {
    cardMap.set(card.agent_id, card);
  }

  const allAgentIds = agentCards.map((c) => c.agent_id);
  const totalAgents = allAgentIds.length;

  // Generate deterministic team_id from sorted agent IDs
  const teamId = deterministicHex(allAgentIds.slice().sort().join(':'), 16);

  // Group value_divergences by value
  const grouped = new Map<string, ValueDivergence[]>();
  for (const div of coherenceResult.value_divergences) {
    const existing = grouped.get(div.value) ?? [];
    existing.push(div);
    grouped.set(div.value, existing);
  }

  // Process each value group into a FaultLine
  const faultLines: FaultLine[] = [];

  for (const [value, divergences] of grouped) {
    // Collect all agents involved in divergences for this value
    const involvedAgentIds = new Set<string>();
    for (const div of divergences) {
      involvedAgentIds.add(div.agent_a);
      involvedAgentIds.add(div.agent_b);
    }

    // Classify each agent's relationship to this value
    const agentsDeclaring: string[] = [];
    const agentsMissing: string[] = [];
    const agentsConflicting: string[] = [];

    for (const agentId of allAgentIds) {
      const card = cardMap.get(agentId);
      if (!card) continue;

      const declaredValues = card.values?.declared ?? [];
      const definitions = card.values?.definitions ?? {};

      const declaresValue = declaredValues.includes(value);
      const conflictsWithValue = hasConflict(value, definitions);

      if (conflictsWithValue) {
        agentsConflicting.push(agentId);
      } else if (declaresValue) {
        agentsDeclaring.push(agentId);
      } else {
        agentsMissing.push(agentId);
      }
    }

    // Determine classification
    const classification = classifyFaultLine(
      agentsDeclaring,
      agentsMissing,
      agentsConflicting,
      divergences,
    );

    // Compute max divergence_score across the group
    const maxDivergenceScore = Math.max(...divergences.map((d) => d.divergence_score));

    // Compute agent_fraction
    const affectedCount = agentsMissing.length + agentsConflicting.length;
    const agentFraction = totalAgents > 0 ? affectedCount / totalAgents : 0;

    // Compute capability_overlap among affected agents
    const affectedAgentIds = [...agentsMissing, ...agentsConflicting];
    const capabilityOverlap = computeCapabilityOverlap(affectedAgentIds, agentsDeclaring, cardMap);

    // Impact score
    const impactScore = clamp(maxDivergenceScore * agentFraction * capabilityOverlap, 0, 1);

    // Severity
    const severity = impactToSeverity(impactScore);

    // Affected capabilities: intersection of bounded_actions from all involved agents
    const allInvolved = [...agentsDeclaring, ...agentsMissing, ...agentsConflicting];
    const affectsCapabilities = intersectBoundedActions(allInvolved, cardMap);

    // Resolution hint
    const resolutionHint = buildResolutionHint(classification, value, agentsMissing, agentsConflicting);

    // Deterministic ID
    const idInput = value + ':' + allInvolved.slice().sort().join(',');
    const id = `fl-${deterministicHex(idInput, 8)}`;

    faultLines.push({
      id,
      value,
      classification,
      severity,
      agents_declaring: agentsDeclaring,
      agents_missing: agentsMissing,
      agents_conflicting: agentsConflicting,
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

  // Analysis ID: deterministic from team_id
  const analysisId = `fla-${deterministicHex('analysis:' + teamId, 12)}`;

  return {
    team_id: teamId,
    analysis_id: analysisId,
    fleet_score: coherenceResult.fleet_score,
    fault_lines: faultLines,
    summary,
  };
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
 */
function classifyFaultLine(
  declaring: string[],
  missing: string[],
  conflicting: string[],
  divergences: ValueDivergence[],
): FaultLineClassification {
  // Hard blocker: at least one agent explicitly conflicts
  if (conflicting.length > 0) {
    return 'incompatible';
  }

  // Priority mismatch: multiple agents declare the same value but with significant divergence
  if (declaring.length >= 2 && missing.length === 0) {
    // All agents declare it — divergence must come from priority/definition differences
    return 'priority_mismatch';
  }

  // If some declare and some are missing, check whether the divergence among declarers
  // suggests a priority mismatch (divergence_score > 0.3 between two declaring agents)
  if (declaring.length >= 2) {
    const hasPriorityDivergence = divergences.some(
      (d) =>
        d.divergence_score > 0.3 &&
        declaring.includes(d.agent_a) &&
        declaring.includes(d.agent_b),
    );
    if (hasPriorityDivergence) {
      return 'priority_mismatch';
    }
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
  cardMap: Map<string, AgentCard>,
): number {
  if (affectedIds.length === 0 || declaringIds.length === 0) {
    // If no affected or no declaring agents, overlap is 0 — but treat as 1.0
    // for the degenerate case where everyone is affected (e.g., all conflicting)
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

function collectBoundedActions(agentIds: string[], cardMap: Map<string, AgentCard>): Set<string> {
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
function intersectBoundedActions(agentIds: string[], cardMap: Map<string, AgentCard>): string[] {
  const agentsWithActions = agentIds
    .map((id) => cardMap.get(id))
    .filter((card): card is AgentCard => card != null)
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
  }
}

function buildSummary(faultLines: FaultLine[]): FaultLineSummary {
  let resolvable = 0;
  let priorityMismatch = 0;
  let incompatible = 0;
  let criticalCount = 0;

  for (const fl of faultLines) {
    switch (fl.classification) {
      case 'resolvable': resolvable++; break;
      case 'priority_mismatch': priorityMismatch++; break;
      case 'incompatible': incompatible++; break;
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
    critical_count: criticalCount,
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function round4(value: number): number {
  return Math.round(value * 10000) / 10000;
}
