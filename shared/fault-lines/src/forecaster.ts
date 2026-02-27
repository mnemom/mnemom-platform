import type {
  FaultLine,
  FaultLineClassification,
  TaskContext,
  RiskTolerance,
  RiskForecast,
  FailureMode,
  FailureModeType,
  Severity,
  LLMCaller,
} from './types.js';
import { buildForecastPrompt } from './prompts.js';

// ============================================================================
// Constants
// ============================================================================

const VALID_FAILURE_MODES: Set<FailureModeType> = new Set([
  'escalation_conflict',
  'capability_gap',
  'value_override',
  'coordination_deadlock',
  'trust_erosion',
]);

const SEVERITY_SCALE: Record<Severity, number> = {
  critical: 1.0,
  high: 0.7,
  medium: 0.4,
  low: 0.2,
};

const RISK_TOLERANCE_OFFSET: Record<RiskTolerance, number> = {
  conservative: 0.1,
  moderate: 0.0,
  aggressive: -0.1,
};

const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/**
 * Mapping from fault line classification to the failure modes it can trigger,
 * with base probability weights.
 */
const CLASSIFICATION_MODE_MAP: Record<
  FaultLineClassification,
  Array<{ mode: FailureModeType; weight: number }>
> = {
  incompatible: [
    { mode: 'escalation_conflict', weight: 0.7 },
    { mode: 'coordination_deadlock', weight: 0.5 },
  ],
  priority_mismatch: [
    { mode: 'value_override', weight: 0.6 },
    { mode: 'trust_erosion', weight: 0.4 },
  ],
  resolvable: [
    { mode: 'capability_gap', weight: 0.3 },
  ],
};

const LLM_TIMEOUT_MS = 10_000;
const LLM_MAX_ADJUSTMENT = 0.2;
const DETERMINISTIC_CONFIDENCE = 0.7;
const LLM_ENRICHED_CONFIDENCE = 0.85;

// ============================================================================
// Deterministic descriptions for fallback
// ============================================================================

const DETERMINISTIC_DESCRIPTIONS: Record<FailureModeType, string> = {
  escalation_conflict:
    'Incompatible agent values may cause conflicting escalation decisions, leading to deadlocked or contradictory responses to critical events.',
  capability_gap:
    'Resolvable fault lines indicate missing capabilities that could be filled through configuration changes or additional tool mappings.',
  value_override:
    'Priority mismatches between agents may result in one agent\'s values being silently overridden by another, undermining intended behavior.',
  coordination_deadlock:
    'Incompatible agent configurations may prevent consensus on shared operations, causing coordination failures and task stalls.',
  trust_erosion:
    'Ongoing priority mismatches may gradually erode trust relationships between agents, reducing collaboration effectiveness over time.',
};

// ============================================================================
// Public API
// ============================================================================

/**
 * Forecast risks from fault lines, optionally enriched by an LLM.
 *
 * 1. Computes deterministic base probabilities from fault line data.
 * 2. Optionally calls LLM for enrichment (descriptions, probability adjustments).
 * 3. Returns a deduplicated, scored RiskForecast.
 */
export async function forecastRisks(
  faultLines: FaultLine[],
  taskContext: TaskContext,
  riskTolerance: RiskTolerance,
  llm?: LLMCaller
): Promise<RiskForecast> {
  // Step 1: Compute deterministic failure modes
  const deterministicModes = computeDeterministicModes(
    faultLines,
    taskContext,
    riskTolerance
  );

  // Step 2: Optionally enrich with LLM
  let finalModes: FailureMode[];
  let confidence: number;

  if (llm) {
    const enriched = await enrichWithLLM(
      deterministicModes,
      faultLines,
      taskContext,
      llm
    );
    finalModes = enriched.modes;
    confidence = enriched.succeeded ? LLM_ENRICHED_CONFIDENCE : DETERMINISTIC_CONFIDENCE;
  } else {
    finalModes = deterministicModes;
    confidence = DETERMINISTIC_CONFIDENCE;
  }

  // Step 3: Deduplicate by mode type (keep highest probability)
  const deduped = deduplicateByMode(finalModes);

  // Step 4: Determine overall risk level
  const overallRiskLevel = computeOverallRiskLevel(deduped);

  // Step 5: Generate forecast ID
  const forecastId = generateForecastId(faultLines, taskContext);

  // Derive analysis ID from fault lines (use first fault line's id prefix or 'unknown')
  const analysisId = faultLines.length > 0
    ? faultLines[0].id.split('-').slice(0, 2).join('-')
    : 'unknown';

  return {
    forecast_id: forecastId,
    fault_line_analysis_id: analysisId,
    failure_modes: deduped,
    overall_risk_level: overallRiskLevel,
    confidence,
  };
}

// ============================================================================
// Deterministic computation
// ============================================================================

function computeDeterministicModes(
  faultLines: FaultLine[],
  taskContext: TaskContext,
  riskTolerance: RiskTolerance
): FailureMode[] {
  // Accumulate per-mode: max probability, all triggered_by, all affected_agents
  const modeAccumulator = new Map<
    FailureModeType,
    {
      maxProbability: number;
      triggeredBy: Set<string>;
      affectedAgents: Set<string>;
      maxSeverity: Severity;
      mitigationAvailable: boolean;
    }
  >();

  const toleranceOffset = RISK_TOLERANCE_OFFSET[riskTolerance];
  const taskTools = new Set(taskContext.tools ?? []);

  for (const fl of faultLines) {
    const mappedModes = CLASSIFICATION_MODE_MAP[fl.classification] ?? [];
    const severityScale = SEVERITY_SCALE[fl.severity];

    // Compute tool overlap relevance multiplier
    const hasToolOverlap =
      taskTools.size > 0 &&
      fl.affects_capabilities.some((cap) => taskTools.has(cap));
    const relevanceMultiplier = hasToolOverlap ? 1.5 : 1.0;

    // Collect all affected agents from this fault line
    const agents = new Set([
      ...fl.agents_declaring,
      ...fl.agents_missing,
      ...fl.agents_conflicting,
    ]);

    for (const { mode, weight } of mappedModes) {
      // base * severity * relevance + tolerance, clamped to [0, 1]
      const rawProbability =
        weight * severityScale * relevanceMultiplier + toleranceOffset;
      const probability = clamp(rawProbability, 0, 1);

      const existing = modeAccumulator.get(mode);
      if (existing) {
        existing.maxProbability = Math.max(existing.maxProbability, probability);
        existing.triggeredBy.add(fl.id);
        for (const a of agents) existing.affectedAgents.add(a);
        // Keep highest severity
        if (SEVERITY_ORDER[fl.severity] > SEVERITY_ORDER[existing.maxSeverity]) {
          existing.maxSeverity = fl.severity;
        }
        // Mitigation available only if ALL contributing fault lines are resolvable
        if (fl.classification !== 'resolvable') {
          existing.mitigationAvailable = false;
        }
      } else {
        modeAccumulator.set(mode, {
          maxProbability: probability,
          triggeredBy: new Set([fl.id]),
          affectedAgents: new Set(agents),
          maxSeverity: fl.severity,
          mitigationAvailable: fl.classification === 'resolvable',
        });
      }
    }
  }

  // Convert accumulator to FailureMode array
  const modes: FailureMode[] = [];
  for (const [mode, data] of modeAccumulator) {
    modes.push({
      mode,
      description: DETERMINISTIC_DESCRIPTIONS[mode],
      probability: roundTo(data.maxProbability, 4),
      severity: data.maxSeverity,
      triggered_by: Array.from(data.triggeredBy),
      affected_agents: Array.from(data.affectedAgents),
      mitigation_available: data.mitigationAvailable,
    });
  }

  return modes;
}

// ============================================================================
// LLM enrichment
// ============================================================================

interface EnrichmentResult {
  modes: FailureMode[];
  succeeded: boolean;
}

async function enrichWithLLM(
  deterministicModes: FailureMode[],
  faultLines: FaultLine[],
  taskContext: TaskContext,
  llm: LLMCaller
): Promise<EnrichmentResult> {
  try {
    const { system, user } = buildForecastPrompt(faultLines, taskContext);

    const response = await withTimeout(llm.call(system, user), LLM_TIMEOUT_MS);
    const parsed = parseLLMResponse(response);

    if (!parsed || !Array.isArray(parsed)) {
      return { modes: deterministicModes, succeeded: false };
    }

    // Build a map of deterministic modes for merging
    const deterministicMap = new Map<FailureModeType, FailureMode>();
    for (const mode of deterministicModes) {
      deterministicMap.set(mode.mode, mode);
    }

    // Cast parsed entries to record type for property access
    const parsedModes = parsed as Array<Record<string, unknown>>;

    // Apply LLM adjustments
    const enriched: FailureMode[] = [];
    for (const detMode of deterministicModes) {
      const llmMode = parsedModes.find(
        (m) => m.mode === detMode.mode
      );

      if (llmMode && isValidLLMMode(llmMode)) {
        // LLM can adjust probability by +/-0.2 max
        const llmProb = Number(llmMode.probability);
        const adjustedProb = clamp(
          detMode.probability + clamp(llmProb - detMode.probability, -LLM_MAX_ADJUSTMENT, LLM_MAX_ADJUSTMENT),
          0,
          1
        );

        enriched.push({
          ...detMode,
          probability: roundTo(adjustedProb, 4),
          description:
            typeof llmMode.description === 'string' && llmMode.description.length > 0
              ? llmMode.description
              : detMode.description,
        });
      } else {
        enriched.push(detMode);
      }
    }

    // Check if LLM suggested any new valid modes not in deterministic set
    for (const llmMode of parsedModes) {
      if (
        isValidLLMMode(llmMode) &&
        !deterministicMap.has(llmMode.mode as FailureModeType)
      ) {
        enriched.push({
          mode: llmMode.mode as FailureModeType,
          description: (llmMode.description as string) ?? '',
          probability: roundTo(clamp(Number(llmMode.probability), 0, 1), 4),
          severity: (llmMode.severity as Severity) ?? 'medium',
          triggered_by: Array.isArray(llmMode.triggered_by)
            ? (llmMode.triggered_by as string[])
            : [],
          affected_agents: Array.isArray(llmMode.affected_agents)
            ? (llmMode.affected_agents as string[])
            : [],
          mitigation_available: Boolean(llmMode.mitigation_available),
        });
      }
    }

    return { modes: enriched, succeeded: true };
  } catch {
    // Timeout or any other error — fall back to deterministic
    return { modes: deterministicModes, succeeded: false };
  }
}

// ============================================================================
// Validation & parsing helpers
// ============================================================================

function isValidLLMMode(mode: unknown): boolean {
  if (!mode || typeof mode !== 'object') return false;
  const m = mode as Record<string, unknown>;

  if (typeof m.mode !== 'string' || !VALID_FAILURE_MODES.has(m.mode as FailureModeType)) {
    return false;
  }

  const prob = Number(m.probability);
  if (isNaN(prob) || prob < 0 || prob > 1) {
    return false;
  }

  return true;
}

function parseLLMResponse(response: string): unknown[] | null {
  try {
    // Try direct parse first
    const parsed = JSON.parse(response.trim());
    if (Array.isArray(parsed)) return parsed;
    return null;
  } catch {
    // Try extracting JSON array from response (in case of markdown wrapping)
    const match = response.match(/\[[\s\S]*\]/);
    if (match) {
      try {
        const parsed = JSON.parse(match[0]);
        if (Array.isArray(parsed)) return parsed;
      } catch {
        return null;
      }
    }
    return null;
  }
}

// ============================================================================
// Deduplication & aggregation
// ============================================================================

function deduplicateByMode(modes: FailureMode[]): FailureMode[] {
  const byMode = new Map<FailureModeType, FailureMode>();

  for (const mode of modes) {
    const existing = byMode.get(mode.mode);
    if (!existing || mode.probability > existing.probability) {
      byMode.set(mode.mode, mode);
    }
  }

  return Array.from(byMode.values());
}

function computeOverallRiskLevel(modes: FailureMode[]): Severity {
  if (modes.length === 0) return 'low';

  let maxSeverity: Severity = 'low';
  for (const mode of modes) {
    if (SEVERITY_ORDER[mode.severity] > SEVERITY_ORDER[maxSeverity]) {
      maxSeverity = mode.severity;
    }
  }

  return maxSeverity;
}

// ============================================================================
// Utility helpers
// ============================================================================

function generateForecastId(
  faultLines: FaultLine[],
  taskContext: TaskContext
): string {
  const input = faultLines.map((f) => f.id).sort().join(',') + '|' + taskContext.description + taskContext.action_type;
  return `rf-${deterministicHex(input, 12)}`;
}

function deterministicHex(input: string, length: number): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(length, '0').slice(0, length);
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function roundTo(value: number, decimals: number): number {
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('LLM call timed out')), ms);
    promise.then(
      (val) => {
        clearTimeout(timer);
        resolve(val);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}
