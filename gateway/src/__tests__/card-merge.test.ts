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
  describe('no-op cases', () => {
    it('returns null when agent card is null', () => {
      const result = mergeOrgAndAgentCard(makeOrgTemplate(), null, false);
      expect(result).toBeNull();
    });

    it('returns agent card unchanged when no org template', () => {
      const agentCard = makeAgentCard();
      const result = mergeOrgAndAgentCard(null, agentCard, false);
      expect(result).toEqual(agentCard);
    });

    it('returns agent card unchanged when agent is exempt', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, true);
      expect(result).toEqual(agentCard);
    });

    it('returns agent card unchanged when org template is null and agent is exempt', () => {
      const agentCard = makeAgentCard();
      const result = mergeOrgAndAgentCard(null, agentCard, true);
      expect(result).toEqual(agentCard);
    });
  });

  describe('values.declared merge', () => {
    it('org values are always present in merged result', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.values.declared).toContain('safety');
      expect(result.values.declared).toContain('honesty');
    });

    it('agent values are added to org values (union)', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      // org has: safety, honesty
      // agent has: honesty, transparency
      // union: safety, honesty, transparency
      expect(result.values.declared).toContain('safety');
      expect(result.values.declared).toContain('honesty');
      expect(result.values.declared).toContain('transparency');
      expect(result.values.declared).toHaveLength(3);
    });

    it('agent cannot remove org values', () => {
      // Agent card only has "transparency", org has "safety" and "honesty"
      const agentCard = makeAgentCard({
        values: {
          declared: ['transparency'],
          definitions: {
            transparency: { name: 'transparency', description: 'Agent transparency', priority: 1 },
          },
        },
      });
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      // Org values must still be present
      expect(result.values.declared).toContain('safety');
      expect(result.values.declared).toContain('honesty');
      expect(result.values.declared).toContain('transparency');
    });
  });

  describe('values.definitions merge', () => {
    it('org definitions take precedence for conflicts', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      // Both have "honesty" definition — org should win
      expect(result.values.definitions.honesty.description).toBe('Org honesty policy');
    });

    it('agent-only definitions are preserved', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      // "transparency" only exists on agent card
      expect(result.values.definitions.transparency.description).toBe('Be open about processes');
    });

    it('org-only definitions are included', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      // "safety" only exists on org template
      expect(result.values.definitions.safety.description).toBe('Org safety policy');
    });
  });

  describe('autonomy_envelope.bounded_actions merge', () => {
    it('produces union of org and agent bounded actions', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      // org: read_files, write_files
      // agent: code_review, answer_questions
      expect(result.autonomy_envelope.bounded_actions).toContain('read_files');
      expect(result.autonomy_envelope.bounded_actions).toContain('write_files');
      expect(result.autonomy_envelope.bounded_actions).toContain('code_review');
      expect(result.autonomy_envelope.bounded_actions).toContain('answer_questions');
      expect(result.autonomy_envelope.bounded_actions).toHaveLength(4);
    });
  });

  describe('autonomy_envelope.forbidden_actions merge', () => {
    it('org forbidden actions are always enforced', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.autonomy_envelope.forbidden_actions).toContain('access_secrets');
      expect(result.autonomy_envelope.forbidden_actions).toContain('modify_billing');
    });

    it('agent forbidden actions are also included', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.autonomy_envelope.forbidden_actions).toContain('delete_production_data');
    });

    it('produces union (no duplicates)', () => {
      const agentCard = makeAgentCard({
        autonomy_envelope: {
          bounded_actions: ['code_review'],
          forbidden_actions: ['access_secrets', 'delete_production_data'], // "access_secrets" overlaps with org
          escalation_triggers: [],
        },
      });
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      // Should have no duplicates
      const forbidden = result.autonomy_envelope.forbidden_actions;
      expect(forbidden).toContain('access_secrets');
      expect(forbidden).toContain('modify_billing');
      expect(forbidden).toContain('delete_production_data');
      expect(new Set(forbidden).size).toBe(forbidden.length);
    });
  });

  describe('autonomy_envelope.escalation_triggers merge', () => {
    it('escalation triggers are concatenated (org first, then agent)', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      const triggers = result.autonomy_envelope.escalation_triggers;
      expect(triggers).toHaveLength(2);

      // Org trigger comes first
      expect(triggers[0].condition).toBe('pii_detected');
      expect(triggers[0].action).toBe('escalate_to_compliance');

      // Agent trigger comes second
      expect(triggers[1].condition).toBe('uncertainty > 0.8');
      expect(triggers[1].action).toBe('escalate_to_human');
    });
  });

  describe('agent-specific fields', () => {
    it('principal comes from agent card', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.principal).toEqual({ name: 'Agent Owner', contact: 'owner@example.com' });
    });

    it('audit_commitment comes from agent card', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.audit_commitment).toEqual({ frequency: 'monthly', method: 'internal' });
    });

    it('card_id comes from agent card', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.card_id).toBe('card-agent-001');
    });

    it('agent_id comes from agent card', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.agent_id).toBe('agent-001');
    });

    it('extensions come from agent card', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.extensions).toEqual({ mnemom: { description: 'Test agent', role: 'assistant' } });
    });

    it('aap_version comes from agent card', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.aap_version).toBe('0.5.0');
    });

    it('issued_at comes from agent card', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.issued_at).toBe('2025-01-01T00:00:00Z');
    });

    it('expires_at comes from agent card', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.expires_at).toBe('2026-01-01T00:00:00Z');
    });
  });

  describe('edge cases', () => {
    it('handles org template with empty values', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate({
        values: { declared: [], definitions: {} },
      });
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      // Agent values should remain
      expect(result.values.declared).toContain('honesty');
      expect(result.values.declared).toContain('transparency');
    });

    it('handles agent card with empty autonomy envelope', () => {
      const agentCard = makeAgentCard({
        autonomy_envelope: {},
      });
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      // Org values should be present
      expect(result.autonomy_envelope.bounded_actions).toContain('read_files');
      expect(result.autonomy_envelope.forbidden_actions).toContain('access_secrets');
      expect(result.autonomy_envelope.escalation_triggers[0].condition).toBe('pii_detected');
    });

    it('handles agent card with no autonomy envelope', () => {
      const agentCard = makeAgentCard();
      delete agentCard.autonomy_envelope;
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.autonomy_envelope.bounded_actions).toContain('read_files');
      expect(result.autonomy_envelope.forbidden_actions).toContain('access_secrets');
    });

    it('handles agent card with no values', () => {
      const agentCard = makeAgentCard();
      delete agentCard.values;
      const orgTemplate = makeOrgTemplate();
      const result = mergeOrgAndAgentCard(orgTemplate, agentCard, false)!;

      expect(result.values.declared).toContain('safety');
      expect(result.values.declared).toContain('honesty');
    });

    it('does not mutate the original agent card', () => {
      const agentCard = makeAgentCard();
      const original = JSON.parse(JSON.stringify(agentCard));
      const orgTemplate = makeOrgTemplate();
      mergeOrgAndAgentCard(orgTemplate, agentCard, false);

      expect(agentCard).toEqual(original);
    });

    it('does not mutate the original org template', () => {
      const agentCard = makeAgentCard();
      const orgTemplate = makeOrgTemplate();
      const original = JSON.parse(JSON.stringify(orgTemplate));
      mergeOrgAndAgentCard(orgTemplate, agentCard, false);

      expect(orgTemplate).toEqual(original);
    });
  });
});
