import { describe, it, expect } from 'vitest';
import { forecastRisks } from '../forecaster';
import type {
  FaultLine,
  TaskContext,
  LLMCaller,
  FailureModeType,
} from '../types';

// ============================================================================
// Helper factories
// ============================================================================

function makeFaultLine(overrides?: Partial<FaultLine>): FaultLine {
  return {
    id: 'fl-001',
    value: 'transparency',
    classification: 'incompatible',
    severity: 'high',
    agents_declaring: ['agent-a'],
    agents_missing: ['agent-b'],
    agents_conflicting: [],
    impact_score: 0.8,
    resolution_hint: 'Align transparency definitions',
    affects_capabilities: ['tool-x'],
    ...overrides,
  };
}

function makeTaskContext(overrides?: Partial<TaskContext>): TaskContext {
  return {
    description: 'Run scheduled compliance audit',
    action_type: 'audit',
    tools: [],
    duration_hours: 2,
    ...overrides,
  };
}

function makeLLMCaller(response: string): LLMCaller {
  return { call: async () => response };
}

function makeFailingLLMCaller(): LLMCaller {
  return {
    call: async () => {
      throw new Error('LLM failed');
    },
  };
}

// ============================================================================
// Deterministic base probability tests
// ============================================================================

describe('forecastRisks', () => {
  describe('deterministic base probabilities', () => {
    it('incompatible fault line maps to escalation_conflict and coordination_deadlock', async () => {
      const fl = makeFaultLine({ classification: 'incompatible' });
      const ctx = makeTaskContext();

      const forecast = await forecastRisks([fl], ctx, 'moderate');

      const modeTypes = forecast.failure_modes.map((m) => m.mode).sort();
      expect(modeTypes).toEqual(['coordination_deadlock', 'escalation_conflict']);
    });

    it('priority_mismatch maps to value_override and trust_erosion', async () => {
      const fl = makeFaultLine({ classification: 'priority_mismatch' });
      const ctx = makeTaskContext();

      const forecast = await forecastRisks([fl], ctx, 'moderate');

      const modeTypes = forecast.failure_modes.map((m) => m.mode).sort();
      expect(modeTypes).toEqual(['trust_erosion', 'value_override']);
    });

    it('resolvable maps to capability_gap', async () => {
      const fl = makeFaultLine({ classification: 'resolvable' });
      const ctx = makeTaskContext();

      const forecast = await forecastRisks([fl], ctx, 'moderate');

      const modeTypes = forecast.failure_modes.map((m) => m.mode);
      expect(modeTypes).toEqual(['capability_gap']);
    });

    it('critical severity produces higher probability than low', async () => {
      const criticalFl = makeFaultLine({
        id: 'fl-crit',
        classification: 'incompatible',
        severity: 'critical',
      });
      const lowFl = makeFaultLine({
        id: 'fl-low',
        classification: 'incompatible',
        severity: 'low',
      });
      const ctx = makeTaskContext();

      const critForecast = await forecastRisks([criticalFl], ctx, 'moderate');
      const lowForecast = await forecastRisks([lowFl], ctx, 'moderate');

      // Compare escalation_conflict probabilities
      const critProb = critForecast.failure_modes.find(
        (m) => m.mode === 'escalation_conflict'
      )!.probability;
      const lowProb = lowForecast.failure_modes.find(
        (m) => m.mode === 'escalation_conflict'
      )!.probability;

      expect(critProb).toBeGreaterThan(lowProb);
    });

    it('task tool overlap increases probability (1.5x multiplier)', async () => {
      const fl = makeFaultLine({
        classification: 'incompatible',
        severity: 'high',
        affects_capabilities: ['deploy-tool'],
      });
      const ctxNoOverlap = makeTaskContext({ tools: ['other-tool'] });
      const ctxWithOverlap = makeTaskContext({ tools: ['deploy-tool'] });

      const noOverlapForecast = await forecastRisks([fl], ctxNoOverlap, 'moderate');
      const overlapForecast = await forecastRisks([fl], ctxWithOverlap, 'moderate');

      const noOverlapProb = noOverlapForecast.failure_modes.find(
        (m) => m.mode === 'escalation_conflict'
      )!.probability;
      const overlapProb = overlapForecast.failure_modes.find(
        (m) => m.mode === 'escalation_conflict'
      )!.probability;

      expect(overlapProb).toBeGreaterThan(noOverlapProb);
    });

    it('conservative risk tolerance adds 0.1, aggressive subtracts 0.1', async () => {
      const fl = makeFaultLine({
        classification: 'incompatible',
        severity: 'medium',
      });
      const ctx = makeTaskContext();

      const conservativeForecast = await forecastRisks([fl], ctx, 'conservative');
      const aggressiveForecast = await forecastRisks([fl], ctx, 'aggressive');

      const conservativeProb = conservativeForecast.failure_modes.find(
        (m) => m.mode === 'escalation_conflict'
      )!.probability;
      const aggressiveProb = aggressiveForecast.failure_modes.find(
        (m) => m.mode === 'escalation_conflict'
      )!.probability;

      // Conservative should be 0.2 higher than aggressive (0.1 - (-0.1))
      expect(conservativeProb - aggressiveProb).toBeCloseTo(0.2, 4);
    });

    it('probabilities are clamped to [0, 1]', async () => {
      // Use critical severity + conservative + tool overlap to push probability very high
      const fl = makeFaultLine({
        classification: 'incompatible',
        severity: 'critical',
        affects_capabilities: ['overlap-tool'],
      });
      const ctx = makeTaskContext({ tools: ['overlap-tool'] });

      const forecast = await forecastRisks([fl], ctx, 'conservative');

      for (const mode of forecast.failure_modes) {
        expect(mode.probability).toBeGreaterThanOrEqual(0);
        expect(mode.probability).toBeLessThanOrEqual(1);
      }

      // Also test aggressive + low severity to ensure no negative values
      const lowFl = makeFaultLine({
        classification: 'resolvable',
        severity: 'low',
      });
      const lowForecast = await forecastRisks([lowFl], ctx, 'aggressive');

      for (const mode of lowForecast.failure_modes) {
        expect(mode.probability).toBeGreaterThanOrEqual(0);
        expect(mode.probability).toBeLessThanOrEqual(1);
      }
    });
  });

  // ============================================================================
  // LLM enrichment tests
  // ============================================================================

  describe('LLM enrichment', () => {
    it('LLM can adjust description (replaces deterministic)', async () => {
      const fl = makeFaultLine({ classification: 'incompatible', severity: 'high' });
      const ctx = makeTaskContext();

      const llmResponse = JSON.stringify([
        {
          mode: 'escalation_conflict',
          description: 'Custom LLM description for escalation conflict',
          probability: 0.5,
          severity: 'high',
          triggered_by: ['fl-001'],
          affected_agents: ['agent-a'],
          mitigation_available: false,
        },
      ]);

      const forecast = await forecastRisks([fl], ctx, 'moderate', makeLLMCaller(llmResponse));

      const escalation = forecast.failure_modes.find(
        (m) => m.mode === 'escalation_conflict'
      )!;
      expect(escalation.description).toBe('Custom LLM description for escalation conflict');
    });

    it('LLM probability adjustment is capped at +/-0.2 from base', async () => {
      const fl = makeFaultLine({
        classification: 'incompatible',
        severity: 'high',
      });
      const ctx = makeTaskContext();

      // First, get the deterministic base probability
      const baseForecast = await forecastRisks([fl], ctx, 'moderate');
      const baseProb = baseForecast.failure_modes.find(
        (m) => m.mode === 'escalation_conflict'
      )!.probability;

      // LLM tries to push probability to 1.0 (far from base)
      const llmResponse = JSON.stringify([
        {
          mode: 'escalation_conflict',
          description: 'Extreme risk',
          probability: 1.0,
          severity: 'high',
          triggered_by: ['fl-001'],
          affected_agents: ['agent-a'],
          mitigation_available: false,
        },
      ]);

      const enrichedForecast = await forecastRisks(
        [fl],
        ctx,
        'moderate',
        makeLLMCaller(llmResponse)
      );
      const enrichedProb = enrichedForecast.failure_modes.find(
        (m) => m.mode === 'escalation_conflict'
      )!.probability;

      // Adjusted probability should be at most base + 0.2
      expect(enrichedProb).toBeLessThanOrEqual(baseProb + 0.2 + 0.0001);
      expect(enrichedProb).toBeGreaterThanOrEqual(baseProb - 0.2 - 0.0001);
    });

    it('LLM failure falls back to deterministic with confidence 0.7', async () => {
      const fl = makeFaultLine({ classification: 'incompatible' });
      const ctx = makeTaskContext();

      const forecast = await forecastRisks(
        [fl],
        ctx,
        'moderate',
        makeFailingLLMCaller()
      );

      expect(forecast.confidence).toBe(0.7);
      // Should still have deterministic modes
      expect(forecast.failure_modes.length).toBeGreaterThan(0);
    });

    it('LLM success produces confidence 0.85', async () => {
      const fl = makeFaultLine({ classification: 'incompatible', severity: 'high' });
      const ctx = makeTaskContext();

      const llmResponse = JSON.stringify([
        {
          mode: 'escalation_conflict',
          description: 'LLM enriched description',
          probability: 0.5,
          severity: 'high',
          triggered_by: ['fl-001'],
          affected_agents: ['agent-a'],
          mitigation_available: false,
        },
      ]);

      const forecast = await forecastRisks(
        [fl],
        ctx,
        'moderate',
        makeLLMCaller(llmResponse)
      );

      expect(forecast.confidence).toBe(0.85);
    });
  });

  // ============================================================================
  // Deduplication tests
  // ============================================================================

  describe('deduplication', () => {
    it('duplicate failure mode types keep highest probability', async () => {
      // Two incompatible fault lines with different severities will produce
      // the same mode types. The accumulator keeps the max probability.
      const flHigh = makeFaultLine({
        id: 'fl-high',
        classification: 'incompatible',
        severity: 'critical',
      });
      const flLow = makeFaultLine({
        id: 'fl-low',
        classification: 'incompatible',
        severity: 'low',
      });
      const ctx = makeTaskContext();

      const forecast = await forecastRisks([flHigh, flLow], ctx, 'moderate');

      // Should have exactly 2 modes (escalation_conflict, coordination_deadlock), not 4
      const escalationModes = forecast.failure_modes.filter(
        (m) => m.mode === 'escalation_conflict'
      );
      expect(escalationModes).toHaveLength(1);

      // The surviving mode should have the higher (critical-based) probability
      const criticalOnly = await forecastRisks([flHigh], ctx, 'moderate');
      const critProb = criticalOnly.failure_modes.find(
        (m) => m.mode === 'escalation_conflict'
      )!.probability;

      expect(escalationModes[0].probability).toBe(critProb);
    });
  });

  // ============================================================================
  // Overall risk level tests
  // ============================================================================

  describe('overall risk level', () => {
    it('overall risk equals max severity across failure modes', async () => {
      const flCritical = makeFaultLine({
        id: 'fl-crit',
        classification: 'incompatible',
        severity: 'critical',
      });
      const flLow = makeFaultLine({
        id: 'fl-low',
        classification: 'resolvable',
        severity: 'low',
      });
      const ctx = makeTaskContext();

      const forecast = await forecastRisks([flCritical, flLow], ctx, 'moderate');

      expect(forecast.overall_risk_level).toBe('critical');
    });

    it('empty fault lines produce empty failure_modes and low risk', async () => {
      const ctx = makeTaskContext();

      const forecast = await forecastRisks([], ctx, 'moderate');

      expect(forecast.failure_modes).toEqual([]);
      expect(forecast.overall_risk_level).toBe('low');
    });
  });

  // ============================================================================
  // Forecast ID tests
  // ============================================================================

  describe('forecast ID', () => {
    it('same inputs produce same forecast_id (deterministic)', async () => {
      const fl = makeFaultLine();
      const ctx = makeTaskContext();

      const forecast1 = await forecastRisks([fl], ctx, 'moderate');
      const forecast2 = await forecastRisks([fl], ctx, 'moderate');

      expect(forecast1.forecast_id).toBe(forecast2.forecast_id);
      expect(forecast1.forecast_id).toMatch(/^rf-/);
    });
  });
});
