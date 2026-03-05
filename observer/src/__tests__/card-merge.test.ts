import { describe, it, expect } from 'vitest';
import { mergeOrgAndAgentCard } from '../card-merge';

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function makeAgentCard(overrides?: Record<string, any>): Record<string, any> {
  return {
    card_id: 'card-agent-001',
    agent_id: 'agent-001',
    aap_version: '0.5.0',
    issued_at: '2025-01-01T00:00:00Z',
    expires_at: '2026-01-01T00:00:00Z',
    principal: { name: 'Agent Owner', contact: 'owner@example.com' },
    audit_commitment: { frequency: 'monthly', method: 'internal' },
    values: {
      declared: ['honesty', 'transparency'],
      definitions: {
        honesty: { name: 'honesty', description: 'Always tell the truth', priority: 1 },
        transparency: { name: 'transparency', description: 'Be open about processes', priority: 2 },
      },
    },
    autonomy_envelope: {
      bounded_actions: ['code_review', 'answer_questions'],
      forbidden_actions: ['delete_production_data'],
      escalation_triggers: [
        { condition: 'uncertainty > 0.8', action: 'escalate_to_human', reason: 'High uncertainty' },
      ],
    },
    extensions: { mnemom: { description: 'Test agent', role: 'assistant' } },
    ...overrides,
  };
}

function makeOrgTemplate(overrides?: Record<string, any>): Record<string, any> {
  return {
    values: {
      declared: ['safety', 'honesty'],
      definitions: {
        safety: { name: 'safety', description: 'Org safety policy', priority: 1 },
        honesty: { name: 'honesty', description: 'Org honesty policy', priority: 2 },
      },
    },
    autonomy_envelope: {
      bounded_actions: ['read_files', 'write_files'],
      forbidden_actions: ['access_secrets', 'modify_billing'],
      escalation_triggers: [
        { condition: 'pii_detected', action: 'escalate_to_compliance', reason: 'PII found' },
      ],
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('mergeOrgAndAgentCard', () => {
  it('returns null when agent card is null', () => {
    expect(mergeOrgAndAgentCard(makeOrgTemplate(), null, false)).toBeNull();
  });

  it('returns agent card unchanged when no org template', () => {
    const agentCard = makeAgentCard();
    expect(mergeOrgAndAgentCard(null, agentCard, false)).toEqual(agentCard);
  });

  it('returns agent card unchanged when agent is exempt', () => {
    const agentCard = makeAgentCard();
    expect(mergeOrgAndAgentCard(makeOrgTemplate(), agentCard, true)).toEqual(agentCard);
  });

  it('org values are always present in merged result', () => {
    const result = mergeOrgAndAgentCard(makeOrgTemplate(), makeAgentCard(), false)!;
    expect(result.values.declared).toContain('safety');
    expect(result.values.declared).toContain('honesty');
  });

  it('agent values are added to org values (union)', () => {
    const result = mergeOrgAndAgentCard(makeOrgTemplate(), makeAgentCard(), false)!;
    expect(result.values.declared).toContain('transparency');
    expect(result.values.declared).toHaveLength(3);
  });

  it('agent cannot remove org values', () => {
    const agentCard = makeAgentCard({
      values: { declared: ['transparency'], definitions: {} },
    });
    const result = mergeOrgAndAgentCard(makeOrgTemplate(), agentCard, false)!;
    expect(result.values.declared).toContain('safety');
    expect(result.values.declared).toContain('honesty');
  });

  it('org forbidden actions are always enforced', () => {
    const result = mergeOrgAndAgentCard(makeOrgTemplate(), makeAgentCard(), false)!;
    expect(result.autonomy_envelope.forbidden_actions).toContain('access_secrets');
    expect(result.autonomy_envelope.forbidden_actions).toContain('modify_billing');
    expect(result.autonomy_envelope.forbidden_actions).toContain('delete_production_data');
  });

  it('escalation triggers are concatenated (org first, then agent)', () => {
    const result = mergeOrgAndAgentCard(makeOrgTemplate(), makeAgentCard(), false)!;
    const triggers = result.autonomy_envelope.escalation_triggers;
    expect(triggers).toHaveLength(2);
    expect(triggers[0].condition).toBe('pii_detected');
    expect(triggers[1].condition).toBe('uncertainty > 0.8');
  });

  it('principal comes from agent card', () => {
    const result = mergeOrgAndAgentCard(makeOrgTemplate(), makeAgentCard(), false)!;
    expect(result.principal).toEqual({ name: 'Agent Owner', contact: 'owner@example.com' });
  });

  it('audit commitment comes from agent card', () => {
    const result = mergeOrgAndAgentCard(makeOrgTemplate(), makeAgentCard(), false)!;
    expect(result.audit_commitment).toEqual({ frequency: 'monthly', method: 'internal' });
  });
});
