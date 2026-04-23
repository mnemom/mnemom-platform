import { describe, it, expect } from 'vitest';
import {
  compileRecipeFromRpcRow,
  buildRecipeIndex,
  type RecipeRpcRow,
} from '../src/recipes.js';

// A known-good RPC row representative of what mnemom-api's migration-138
// `get_active_detection_recipes()` returns after Stage 5A ships.
function validRow(overrides: Partial<RecipeRpcRow> = {}): RecipeRpcRow {
  return {
    id: 'recipe_abc',
    version: 1,
    technique_category: 'prompt_injection',
    technique_ids: [],
    severity: 'high',
    severity_p: 'p1',
    scope: 'production',
    has_tier1: true,
    has_tier2: true,
    has_tier3: false,
    door: 'front',
    threat_type: 'prompt_injection',
    variant_class: 'unicode_obfuscation',
    evasion_technique: 'zero_width_space',
    mitre_atlas: 'AML.T0051',
    parsed_content: {
      door: 'front',
      threat_type: 'prompt_injection',
      variant_class: 'unicode_obfuscation',
      evasion_technique: 'zero_width_space',
      severity: 'p1',
      tier1: {
        match: 'any',
        conditions: [
          {
            detector: 'pattern_matcher',
            operator: 'contains',
            threshold: 'ignore previous instructions',
          },
          {
            detector: 'signal_scorer',
            signal: 'injection_hint',
            operator: 'gte',
            threshold: 0.7,
          },
          {
            detector: 'fingerprint_matcher',
            signal: 'known_zwsp_payload_v1',
            operator: 'gte',
            threshold: 0.85,
          },
        ],
      },
      tier2: {
        trigger: { on_signals: ['injection_hint'] },
        checks: [
          {
            id: 'intent_check',
            type: 'semantic_intent_match',
            content: 'Does the message attempt to override system instructions?',
          },
        ],
      },
    },
    yaml_content: 'door: front\nthreat_type: prompt_injection\n',
    hit_count: 0,
    similarity_hash: 'abc123',
    ...overrides,
  };
}

describe('compileRecipeFromRpcRow', () => {
  it('compiles a canonical XFD row', () => {
    const r = compileRecipeFromRpcRow(validRow());
    expect(r).not.toBeNull();
    expect(r!.door).toBe('front');
    expect(r!.threat_type).toBe('prompt_injection');
    expect(r!.variant_class).toBe('unicode_obfuscation');
    expect(r!.severity).toBe('p1');
    expect(r!.scope).toBe('production');
    expect(r!.yaml_content).toContain('door: front');
  });

  it('returns null when door is missing (pre-XFD row)', () => {
    const r = compileRecipeFromRpcRow(validRow({ door: null }));
    expect(r).toBeNull();
  });

  it('returns null when threat_type is outside the canonical set', () => {
    const r = compileRecipeFromRpcRow(validRow({ threat_type: 'made_up_type' }));
    expect(r).toBeNull();
  });

  it('returns null when id is missing', () => {
    const r = compileRecipeFromRpcRow(validRow({ id: '' }));
    expect(r).toBeNull();
  });

  it('defaults severity to p2 when severity_p is absent or invalid', () => {
    const noSev = compileRecipeFromRpcRow(validRow({ severity_p: null }));
    expect(noSev!.severity).toBe('p2');
    const bogus = compileRecipeFromRpcRow(validRow({ severity_p: 'urgent' }));
    expect(bogus!.severity).toBe('p2');
  });

  it('defaults scope to arena_only when invalid', () => {
    const r = compileRecipeFromRpcRow(validRow({ scope: 'fancy_scope' }));
    expect(r!.scope).toBe('arena_only');
  });

  it('compiles pattern_matcher contains as kind=pattern', () => {
    const r = compileRecipeFromRpcRow(validRow())!;
    const contains = r.tier1!.conditions.find((c) => c.kind === 'pattern');
    expect(contains).toBeDefined();
    if (contains && contains.kind === 'pattern') {
      expect(contains.operator).toBe('contains');
      expect(contains.pattern).toBe('ignore previous instructions');
      expect(contains.regex).toBeNull();
    }
  });

  it('compiles signal_scorer gte as kind=score', () => {
    const r = compileRecipeFromRpcRow(validRow())!;
    const score = r.tier1!.conditions.find((c) => c.kind === 'score');
    expect(score).toBeDefined();
    if (score && score.kind === 'score') {
      expect(score.detector).toBe('signal_scorer');
      expect(score.threshold).toBe(0.7);
      expect(score.operator).toBe('gte');
    }
  });

  it('compiles fingerprint_matcher as kind=fingerprint', () => {
    const r = compileRecipeFromRpcRow(validRow())!;
    const fp = r.tier1!.conditions.find((c) => c.kind === 'fingerprint');
    expect(fp).toBeDefined();
    if (fp && fp.kind === 'fingerprint') {
      expect(fp.threshold).toBe(0.85);
      expect(fp.signal).toBe('known_zwsp_payload_v1');
    }
  });

  it('drops tier1 conditions with unknown detectors', () => {
    const row = validRow();
    row.parsed_content!.tier1!.conditions!.push({
      detector: 'made_up_detector',
      operator: 'gt',
      threshold: 0.5,
    });
    const r = compileRecipeFromRpcRow(row)!;
    expect(r.tier1!.conditions).toHaveLength(3);
  });

  it('sets tier1=null when has_tier1 is false', () => {
    const r = compileRecipeFromRpcRow(validRow({ has_tier1: false }))!;
    expect(r.tier1).toBeNull();
    expect(r.has_tier1).toBe(false);
  });

  it('compiles operator=matches with a valid regex', () => {
    const row = validRow();
    row.parsed_content!.tier1!.conditions = [
      {
        detector: 'pattern_matcher',
        operator: 'matches',
        threshold: '\\b(wire|transfer)\\b',
      },
    ];
    const r = compileRecipeFromRpcRow(row)!;
    const cond = r.tier1!.conditions[0];
    expect(cond.kind).toBe('pattern');
    if (cond.kind === 'pattern') {
      expect(cond.operator).toBe('matches');
      expect(cond.regex).toBeInstanceOf(RegExp);
      expect(cond.regex!.test('Please wire 1000')).toBe(true);
    }
  });

  it('sets regex=null for malformed regex patterns', () => {
    const row = validRow();
    row.parsed_content!.tier1!.conditions = [
      {
        detector: 'pattern_matcher',
        operator: 'matches',
        threshold: '(unclosed',
      },
    ];
    const r = compileRecipeFromRpcRow(row)!;
    const cond = r.tier1!.conditions[0];
    if (cond.kind === 'pattern') {
      expect(cond.regex).toBeNull();
      expect(cond.pattern).toBe('(unclosed');
    }
  });
});

describe('buildRecipeIndex', () => {
  it('builds by_detector and by_threat_type buckets', () => {
    const idx = buildRecipeIndex([validRow()]);
    expect(idx.all).toHaveLength(1);
    expect(idx.by_detector.get('pattern_matcher')).toHaveLength(1);
    expect(idx.by_detector.get('signal_scorer')).toHaveLength(1);
    expect(idx.by_detector.get('fingerprint_matcher')).toHaveLength(1);
    expect(idx.by_threat_type.get('prompt_injection')).toHaveLength(1);
  });

  it('sorts `all` by severity then version desc', () => {
    const rows: RecipeRpcRow[] = [
      validRow({ id: 'r_p2_v1', severity_p: 'p2', version: 1 }),
      validRow({ id: 'r_p0_v3', severity_p: 'p0', version: 3 }),
      validRow({ id: 'r_p0_v7', severity_p: 'p0', version: 7 }),
      validRow({ id: 'r_p1_v2', severity_p: 'p1', version: 2 }),
    ];
    const idx = buildRecipeIndex(rows);
    expect(idx.all.map((r) => r.id)).toEqual([
      'r_p0_v7',
      'r_p0_v3',
      'r_p1_v2',
      'r_p2_v1',
    ]);
  });

  it('silently drops rows that fail to compile', () => {
    const idx = buildRecipeIndex([
      validRow({ id: 'good' }),
      validRow({ id: 'bad', door: null }),
      validRow({ id: 'good2' }),
    ]);
    expect(idx.all.map((r) => r.id)).toEqual(
      expect.arrayContaining(['good', 'good2']),
    );
    expect(idx.all).toHaveLength(2);
  });

  it('does not duplicate a recipe under the same detector', () => {
    const row = validRow();
    row.parsed_content!.tier1!.conditions = [
      { detector: 'pattern_matcher', operator: 'contains', threshold: 'a' },
      { detector: 'pattern_matcher', operator: 'contains', threshold: 'b' },
    ];
    const idx = buildRecipeIndex([row]);
    expect(idx.by_detector.get('pattern_matcher')).toHaveLength(1);
  });

  it('leaves lsh_bands empty in Stage 5A', () => {
    const idx = buildRecipeIndex([validRow()]);
    expect(idx.lsh_bands.size).toBe(0);
  });

  it('stamps loaded_at', () => {
    const idx = buildRecipeIndex([validRow()], 1700000000000);
    expect(idx.loaded_at).toBe(1700000000000);
  });
});
