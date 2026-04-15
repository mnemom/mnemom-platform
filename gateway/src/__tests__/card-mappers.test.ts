/**
 * UC-6 card-mappers tests (gateway).
 *
 * Covers the pure functions in src/card-mappers.ts:
 *   - mapUnifiedCardToAAP: canonical unified card → AAP 1.0.x shape
 *   - mapCanonicalToSafeHouseConfig: canonical protection card → SafeHouseConfig
 *
 * The canonical-fetch helpers in the same file are covered in a separate
 * suite (canonical-fetch.test.ts) because they are async + KV-driven.
 */

import { describe, it, expect } from 'vitest';
import { mapUnifiedCardToAAP, mapCanonicalToSafeHouseConfig } from '../card-mappers';

describe('mapUnifiedCardToAAP', () => {
  it('maps a full unified card to the AAP shape', () => {
    const unified = {
      card_version: '2026-04-15',
      card_id: 'ac-abc',
      agent_id: 'mnm-1',
      issued_at: '2026-04-15T00:00:00Z',
      expires_at: '2027-04-15T00:00:00Z',
      principal: { type: 'human', relationship: 'delegated_authority' },
      values: { declared: ['safety', 'transparency'] },
      autonomy: {
        bounded_actions: ['inference', 'web_fetch'],
        forbidden_actions: ['delete_data'],
        escalation_triggers: [
          { condition: 'amount > 1000', action: 'escalate', reason: 'high value' },
        ],
        max_autonomous_value: { amount: 100, currency: 'USD' },
      },
      audit: {
        trace_format: 'aap/otel-1.0',
        retention_days: 90,
        queryable: true,
        query_endpoint: 'https://api.mnemom.ai/v1/traces',
        tamper_evidence: 'merkle',
        storage: { type: 'distributed', location: 'cf-r2' },
      },
      extensions: { mnemom: { role: 'support bot' } },
    };

    const aap = mapUnifiedCardToAAP(unified);
    expect(aap.card_id).toBe('ac-abc');
    expect(aap.agent_id).toBe('mnm-1');
    expect(aap.aap_version).toBe('2026-04-15');
    expect(aap.issued_at).toBe('2026-04-15T00:00:00Z');
    expect(aap.expires_at).toBe('2027-04-15T00:00:00Z');
    expect(aap.principal).toEqual({ type: 'human', relationship: 'delegated_authority' });
    expect(aap.values).toEqual({ declared: ['safety', 'transparency'] });
    expect(aap.autonomy_envelope.bounded_actions).toEqual(['inference', 'web_fetch']);
    expect(aap.autonomy_envelope.forbidden_actions).toEqual(['delete_data']);
    expect(aap.autonomy_envelope.escalation_triggers).toHaveLength(1);
    expect(aap.autonomy_envelope.max_autonomous_value).toEqual({ amount: 100, currency: 'USD' });
    expect(aap.audit_commitment?.retention_days).toBe(90);
    expect(aap.audit_commitment?.queryable).toBe(true);
    expect(aap.audit_commitment?.tamper_evidence).toBe('merkle');
    expect(aap.extensions).toEqual({ mnemom: { role: 'support bot' } });
  });

  it('maps autonomy.bounded_actions → autonomy_envelope.bounded_actions (field rename)', () => {
    const aap = mapUnifiedCardToAAP({
      agent_id: 'mnm-2',
      autonomy: { bounded_actions: ['a', 'b'], escalation_triggers: [] },
      audit: { retention_days: 30, queryable: false },
    });
    expect(aap.autonomy_envelope.bounded_actions).toEqual(['a', 'b']);
  });

  it('falls back to _composition.source_card_id / canonical_id when top-level card_id is absent', () => {
    const aap1 = mapUnifiedCardToAAP({
      agent_id: 'mnm-3',
      autonomy: { bounded_actions: ['inference'] },
      audit: { retention_days: 30 },
      _composition: { source_card_id: 'src-1' },
    });
    expect(aap1.card_id).toBe('src-1');

    const aap2 = mapUnifiedCardToAAP({
      agent_id: 'mnm-4',
      autonomy: { bounded_actions: ['inference'] },
      audit: { retention_days: 30 },
      _composition: { canonical_id: 'canon-1' },
    });
    expect(aap2.card_id).toBe('canon-1');
  });

  it('preserves missing fields as undefined or [] rather than synthesising', () => {
    const aap = mapUnifiedCardToAAP({
      agent_id: 'mnm-5',
      // no autonomy/audit/principal/values
    });
    expect(aap.autonomy_envelope.bounded_actions).toEqual([]);
    expect(aap.autonomy_envelope.forbidden_actions).toBeUndefined();
    expect(aap.autonomy_envelope.escalation_triggers).toBeUndefined();
    expect(aap.autonomy_envelope.max_autonomous_value).toBeUndefined();
    expect(aap.audit_commitment?.retention_days).toBeUndefined();
    expect(aap.audit_commitment?.queryable).toBeUndefined();
    expect(aap.principal).toBeUndefined();
    expect(aap.values).toBeUndefined();
    expect(aap.aap_version).toBeUndefined();
    expect(aap.expires_at).toBeNull(); // explicit nulled expires_at per the mapper
  });

  it('coerces non-array autonomy fields to safe defaults', () => {
    const aap = mapUnifiedCardToAAP({
      agent_id: 'mnm-6',
      autonomy: {
        bounded_actions: 'not-an-array' as any,
        forbidden_actions: null as any,
        escalation_triggers: 'junk' as any,
      },
    });
    expect(aap.autonomy_envelope.bounded_actions).toEqual([]);
    expect(aap.autonomy_envelope.forbidden_actions).toBeUndefined();
    expect(aap.autonomy_envelope.escalation_triggers).toBeUndefined();
  });
});

describe('mapCanonicalToSafeHouseConfig', () => {
  it('maps a full protection card to SafeHouseConfig', () => {
    const cfg = mapCanonicalToSafeHouseConfig({
      card_version: '2026-04-15',
      agent_id: 'mnm-1',
      mode: 'enforce',
      thresholds: { warn: 0.5, quarantine: 0.7, block: 0.9 },
      screen_surfaces: ['user_message', 'tool_output'],
      trusted_sources: [{ pattern: '*.mnemom.ai', trust_tier: 'high', risk_multiplier: 0.1 }],
    });
    expect(cfg.mode).toBe('enforce');
    expect(cfg.thresholds).toEqual({ warn: 0.5, quarantine: 0.7, block: 0.9 });
    expect(cfg.screen_surfaces).toEqual(['user_message', 'tool_output']);
    expect(cfg.trusted_sources).toHaveLength(1);
  });

  it('supplies default thresholds when thresholds object is missing', () => {
    const cfg = mapCanonicalToSafeHouseConfig({ agent_id: 'mnm-1' });
    expect(cfg.mode).toBe('observe');
    expect(cfg.thresholds).toEqual({ warn: 0.6, quarantine: 0.8, block: 0.95 });
  });

  it('fills per-threshold defaults for missing entries, keeps provided ones', () => {
    const cfg = mapCanonicalToSafeHouseConfig({
      agent_id: 'mnm-1',
      thresholds: { block: 0.5 } as any,
    });
    // warn/quarantine fall back to defaults, block honoured
    expect(cfg.thresholds.warn).toBe(0.6);
    expect(cfg.thresholds.quarantine).toBe(0.8);
    expect(cfg.thresholds.block).toBe(0.5);
  });

  it('defaults screen_surfaces to ["user_message"] when absent or not an array', () => {
    const cfg1 = mapCanonicalToSafeHouseConfig({ agent_id: 'mnm-1' });
    expect(cfg1.screen_surfaces).toEqual(['user_message']);

    const cfg2 = mapCanonicalToSafeHouseConfig({ agent_id: 'mnm-1', screen_surfaces: 'junk' as any });
    expect(cfg2.screen_surfaces).toEqual(['user_message']);
  });

  it('defaults trusted_sources to [] when absent', () => {
    const cfg = mapCanonicalToSafeHouseConfig({ agent_id: 'mnm-1' });
    expect(cfg.trusted_sources).toEqual([]);
  });

  it('defaults mode to observe when absent', () => {
    const cfg = mapCanonicalToSafeHouseConfig({ agent_id: 'mnm-1' });
    expect(cfg.mode).toBe('observe');
  });
});
