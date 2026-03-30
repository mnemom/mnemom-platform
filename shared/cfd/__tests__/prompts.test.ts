import { describe, it, expect } from 'vitest';
import {
  parseL2Response,
  mergeL1AndL2,
  buildThreatContextForAIP,
  buildPreemptiveNudgeContent,
  buildCFDUserPrompt,
} from '../src/prompts.js';
import type { ThreatDetection, CFDDecision, L2Result } from '../src/types.js';

// Helpers
function makeDecision(overrides: Partial<CFDDecision> = {}): CFDDecision {
  return {
    verdict: 'pass',
    overall_risk: 0.5,
    threats: [],
    l1_score: 0.5,
    session_multiplier: 1,
    detection_layer: 'l1',
    duration_ms: 10,
    ...overrides,
  };
}

function makeThreat(type: ThreatDetection['type'], confidence: number): ThreatDetection {
  return { type, confidence, reasoning: 'test reasoning' };
}

// ─── parseL2Response ─────────────────────────────────────────────────────────

describe('parseL2Response', () => {
  it('1. valid JSON with threats → returns L2Result with parsed threats', () => {
    const raw = JSON.stringify({
      threats: [{ type: 'prompt_injection', confidence: 0.9, reasoning: 'override attempt' }],
      overall_risk: 0.9,
      recommendation: 'block',
    });
    const result = parseL2Response(raw);
    expect(result).not.toBeNull();
    expect(result!.threats).toHaveLength(1);
    expect(result!.threats[0].type).toBe('prompt_injection');
    expect(result!.threats[0].confidence).toBe(0.9);
    expect(result!.overall_risk).toBe(0.9);
    expect(result!.recommendation).toBe('block');
  });

  it('2. JSON wrapped in ```json...``` fences → strips fences and parses correctly', () => {
    const raw = '```json\n' + JSON.stringify({
      threats: [{ type: 'bec_fraud', confidence: 0.75, reasoning: 'authority impersonation' }],
      overall_risk: 0.75,
      recommendation: 'warn',
    }) + '\n```';
    const result = parseL2Response(raw);
    expect(result).not.toBeNull();
    expect(result!.threats[0].type).toBe('bec_fraud');
    expect(result!.recommendation).toBe('warn');
  });

  it('3. invalid JSON → returns null', () => {
    const result = parseL2Response('not json at all { broken');
    expect(result).toBeNull();
  });

  it('4. empty threats array → returns L2Result with empty threats', () => {
    const raw = JSON.stringify({
      threats: [],
      overall_risk: 0.1,
      recommendation: 'pass',
    });
    const result = parseL2Response(raw);
    expect(result).not.toBeNull();
    expect(result!.threats).toHaveLength(0);
    expect(result!.overall_risk).toBe(0.1);
  });

  it('5. confidence clamped to 0-1 range (above 1)', () => {
    const raw = JSON.stringify({
      threats: [{ type: 'social_engineering', confidence: 1.5, reasoning: 'test' }],
      overall_risk: 1.5,
      recommendation: 'block',
    });
    const result = parseL2Response(raw);
    expect(result).not.toBeNull();
    expect(result!.threats[0].confidence).toBe(1.0);
    expect(result!.overall_risk).toBe(1.0);
  });

  it('5b. confidence clamped to 0-1 range (below 0)', () => {
    const raw = JSON.stringify({
      threats: [{ type: 'social_engineering', confidence: -0.5, reasoning: 'test' }],
      overall_risk: -0.5,
      recommendation: 'pass',
    });
    const result = parseL2Response(raw);
    expect(result).not.toBeNull();
    expect(result!.threats[0].confidence).toBe(0.0);
    expect(result!.overall_risk).toBe(0.0);
  });

  it('6. recommendation="block" → preserved', () => {
    const raw = JSON.stringify({
      threats: [],
      overall_risk: 0.96,
      recommendation: 'block',
    });
    const result = parseL2Response(raw);
    expect(result!.recommendation).toBe('block');
  });

  it('7. unknown recommendation → falls back to "pass"', () => {
    const raw = JSON.stringify({
      threats: [],
      overall_risk: 0.5,
      recommendation: 'reject_unknown',
    });
    const result = parseL2Response(raw);
    expect(result).not.toBeNull();
    expect(result!.recommendation).toBe('pass');
  });

  it('8. malformed response text (no JSON object) → returns null', () => {
    const result = parseL2Response('The message seems benign. No threats detected.');
    expect(result).toBeNull();
  });

  it('8b. raw_response is truncated to 1000 chars', () => {
    const longReasoning = 'x'.repeat(2000);
    const raw = JSON.stringify({
      threats: [],
      overall_risk: 0,
      recommendation: 'pass',
      extra: longReasoning,
    });
    const result = parseL2Response(raw);
    expect(result).not.toBeNull();
    expect(result!.raw_response.length).toBeLessThanOrEqual(1000);
  });
});

// ─── mergeL1AndL2 ─────────────────────────────────────────────────────────────

describe('mergeL1AndL2', () => {
  it('9. no L2 result → returns L1 threats and score unchanged', () => {
    const l1Threats = [makeThreat('prompt_injection', 0.8)];
    const { threats, score } = mergeL1AndL2(l1Threats, 0.8, null);
    expect(threats).toEqual(l1Threats);
    expect(score).toBe(0.8);
  });

  it('10. L2 has higher confidence for same type → L2 wins', () => {
    const l1Threats = [makeThreat('prompt_injection', 0.5)];
    const l2Result: L2Result = {
      threats: [{ type: 'prompt_injection', confidence: 0.9, reasoning: 'L2 analysis' }],
      overall_risk: 0.9,
      recommendation: 'block',
      raw_response: '',
    };
    const { threats } = mergeL1AndL2(l1Threats, 0.5, l2Result);
    const t = threats.find(t => t.type === 'prompt_injection');
    expect(t).toBeDefined();
    expect(t!.confidence).toBe(0.9);
    expect(t!.reasoning).toBe('L2 analysis');
  });

  it('11. L2 has lower confidence for same type → L1 wins', () => {
    const l1Threats = [makeThreat('bec_fraud', 0.85)];
    const l2Result: L2Result = {
      threats: [{ type: 'bec_fraud', confidence: 0.4, reasoning: 'L2 lower' }],
      overall_risk: 0.4,
      recommendation: 'warn',
      raw_response: '',
    };
    const { threats } = mergeL1AndL2(l1Threats, 0.85, l2Result);
    const t = threats.find(t => t.type === 'bec_fraud');
    expect(t).toBeDefined();
    expect(t!.confidence).toBe(0.85);
  });

  it('12. L2 adds new threat type not in L1 → included in merged', () => {
    const l1Threats = [makeThreat('prompt_injection', 0.7)];
    const l2Result: L2Result = {
      threats: [{ type: 'data_exfiltration', confidence: 0.6, reasoning: 'new from L2' }],
      overall_risk: 0.7,
      recommendation: 'warn',
      raw_response: '',
    };
    const { threats } = mergeL1AndL2(l1Threats, 0.7, l2Result);
    expect(threats.some(t => t.type === 'prompt_injection')).toBe(true);
    expect(threats.some(t => t.type === 'data_exfiltration')).toBe(true);
  });

  it('13. merged score is weighted: 0.4*l1 + 0.6*l2', () => {
    const l2Result: L2Result = {
      threats: [],
      overall_risk: 0.5,
      recommendation: 'pass',
      raw_response: '',
    };
    const { score } = mergeL1AndL2([], 1.0, l2Result);
    expect(score).toBeCloseTo(0.4 * 1.0 + 0.6 * 0.5, 5);
  });

  it('14. low-confidence threats (< 0.3) filtered out from merged result', () => {
    const l1Threats = [makeThreat('agent_spoofing', 0.2)]; // below 0.3
    const l2Result: L2Result = {
      threats: [{ type: 'hijack_attempt', confidence: 0.25, reasoning: 'low conf' }],
      overall_risk: 0.2,
      recommendation: 'pass',
      raw_response: '',
    };
    const { threats } = mergeL1AndL2(l1Threats, 0.2, l2Result);
    expect(threats).toHaveLength(0);
  });
});

// ─── buildThreatContextForAIP ─────────────────────────────────────────────────

describe('buildThreatContextForAIP', () => {
  it('15. score < 0.6 → returns undefined', () => {
    const decision = makeDecision({
      overall_risk: 0.5,
      threats: [makeThreat('prompt_injection', 0.5)],
    });
    expect(buildThreatContextForAIP(decision)).toBeUndefined();
  });

  it('16. score >= 0.6 with threats → returns non-empty string containing "INBOUND THREAT CONTEXT"', () => {
    const decision = makeDecision({
      overall_risk: 0.7,
      threats: [makeThreat('bec_fraud', 0.7)],
    });
    const result = buildThreatContextForAIP(decision);
    expect(result).toBeDefined();
    expect(result).toContain('INBOUND THREAT CONTEXT');
  });

  it('17. score >= 0.8 → contains "Heighten scrutiny"', () => {
    const decision = makeDecision({
      overall_risk: 0.85,
      threats: [makeThreat('prompt_injection', 0.85)],
    });
    const result = buildThreatContextForAIP(decision);
    expect(result).toContain('Heighten scrutiny');
  });

  it('18. score 0.65 → contains "manipulated" but not "Heighten scrutiny"', () => {
    const decision = makeDecision({
      overall_risk: 0.65,
      threats: [makeThreat('social_engineering', 0.65)],
    });
    const result = buildThreatContextForAIP(decision);
    expect(result).toContain('manipulated');
    expect(result).not.toContain('Heighten scrutiny');
  });

  it('18b. score >= 0.6 but no threats → returns undefined', () => {
    const decision = makeDecision({ overall_risk: 0.7, threats: [] });
    expect(buildThreatContextForAIP(decision)).toBeUndefined();
  });
});

// ─── buildPreemptiveNudgeContent ──────────────────────────────────────────────

describe('buildPreemptiveNudgeContent', () => {
  it('19. score < 0.6 → returns null', () => {
    const decision = makeDecision({
      overall_risk: 0.4,
      threats: [makeThreat('bec_fraud', 0.4)],
    });
    expect(buildPreemptiveNudgeContent(decision)).toBeNull();
  });

  it('20. score >= 0.6 → returns PreemptiveNudge with non-empty nudge_content', () => {
    const decision = makeDecision({
      overall_risk: 0.75,
      threats: [makeThreat('social_engineering', 0.75)],
    });
    const result = buildPreemptiveNudgeContent(decision);
    expect(result).not.toBeNull();
    expect(result!.nudge_content.length).toBeGreaterThan(0);
  });

  it('21. bec_fraud threat → content mentions "fraud"', () => {
    const decision = makeDecision({
      overall_risk: 0.75,
      threats: [makeThreat('bec_fraud', 0.75)],
    });
    const result = buildPreemptiveNudgeContent(decision);
    expect(result!.nudge_content).toContain('fraud');
  });

  it('22. pre_emptive field is true', () => {
    const decision = makeDecision({
      overall_risk: 0.75,
      threats: [makeThreat('prompt_injection', 0.75)],
    });
    const result = buildPreemptiveNudgeContent(decision);
    expect(result!.pre_emptive).toBe(true);
  });

  it('22b. no threats → returns null even with high score', () => {
    const decision = makeDecision({ overall_risk: 0.9, threats: [] });
    expect(buildPreemptiveNudgeContent(decision)).toBeNull();
  });

  it('22c. nudge includes the risk percentage', () => {
    const decision = makeDecision({
      overall_risk: 0.72,
      threats: [makeThreat('agent_spoofing', 0.72)],
    });
    const result = buildPreemptiveNudgeContent(decision);
    // 72% risk
    expect(result!.nudge_content).toContain('72%');
  });
});

// ─── buildCFDUserPrompt ───────────────────────────────────────────────────────

describe('buildCFDUserPrompt', () => {
  it('23. content > 2000 chars → truncated at 2000 with "[... truncated ...]"', () => {
    const long = 'a'.repeat(3000);
    const result = buildCFDUserPrompt(long);
    expect(result).toContain('[... truncated ...]');
    // The truncated content portion is 2000 chars
    expect(result.indexOf('[... truncated ...]')).toBeGreaterThan(1999);
  });

  it('24. sourceType provided → appears in output', () => {
    const result = buildCFDUserPrompt('hello', 'email');
    expect(result).toContain('email');
    expect(result).toContain('Source type:');
  });

  it('25. short content → not truncated', () => {
    const short = 'short message';
    const result = buildCFDUserPrompt(short);
    expect(result).toContain(short);
    expect(result).not.toContain('[... truncated ...]');
  });

  it('25b. sourceType="unknown" → no source note in output', () => {
    const result = buildCFDUserPrompt('hello', 'unknown');
    expect(result).not.toContain('Source type:');
  });

  it('25c. no sourceType → no source note in output', () => {
    const result = buildCFDUserPrompt('hello');
    expect(result).not.toContain('Source type:');
  });

  it('25d. content exactly 2000 chars → not truncated', () => {
    const exact = 'b'.repeat(2000);
    const result = buildCFDUserPrompt(exact);
    expect(result).not.toContain('[... truncated ...]');
  });
});
