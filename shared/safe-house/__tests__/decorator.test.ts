import { describe, it, expect } from 'vitest';
import { decorateMessage, buildQuarantineNotification } from '../src/decorator.js';
import type { SafeHouseDecision } from '../src/types.js';

function makeBECDecision(overrides: Partial<SafeHouseDecision> = {}): SafeHouseDecision {
  return {
    verdict: 'warn',
    overall_risk: 0.75,
    threats: [
      {
        type: 'bec_fraud',
        confidence: 0.75,
        reasoning: 'Financial action + urgency signals',
      },
    ],
    l1_score: 0.75,
    session_multiplier: 1.0,
    detection_layer: 'l1',
    duration_ms: 2,
    ...overrides,
  };
}

function makeBlockDecision(overrides: Partial<SafeHouseDecision> = {}): SafeHouseDecision {
  return {
    verdict: 'block',
    overall_risk: 0.96,
    threats: [
      {
        type: 'prompt_injection',
        confidence: 0.9,
        reasoning: 'Direct injection pattern matched',
      },
      {
        type: 'agent_spoofing',
        confidence: 0.8,
        reasoning: 'Spoofing pattern matched',
      },
    ],
    l1_score: 0.96,
    session_multiplier: 1.0,
    quarantine_id: 'qid-test-001',
    detection_layer: 'l1',
    duration_ms: 3,
    ...overrides,
  };
}

describe('decorateMessage', () => {
  it('output contains <context_security_assessment sh_version="1">', () => {
    const result = decorateMessage('Hello, wire me money.', makeBECDecision());
    expect(result.content).toContain('<context_security_assessment sh_version="1">');
  });

  it('output contains <verdict>WARN</verdict>', () => {
    const result = decorateMessage('Hello, wire me money.', makeBECDecision());
    expect(result.content).toContain('<verdict>WARN</verdict>');
  });

  it('output contains <untrusted_content', () => {
    const result = decorateMessage('Hello, wire me money.', makeBECDecision());
    expect(result.content).toContain('<untrusted_content');
  });

  it('original message appears after the assessment block', () => {
    const original = 'Hello, wire me money.';
    const result = decorateMessage(original, makeBECDecision());
    const assessmentEnd = result.content.indexOf('</context_security_assessment>');
    const messagePos = result.content.indexOf(original);
    expect(assessmentEnd).toBeGreaterThan(-1);
    expect(messagePos).toBeGreaterThan(assessmentEnd);
  });

  it('XML-special chars in original message are not double-escaped in untrusted_content', () => {
    const original = 'Message with <special> & "chars"';
    const result = decorateMessage(original, makeBECDecision());
    // The original unmodified content should appear as-is inside untrusted_content
    expect(result.content).toContain(original);
    expect(result.original).toBe(original);
  });

  it('instructionForThreats produces BEC-specific instruction for bec_fraud threat', () => {
    const result = decorateMessage('Pay invoice now.', makeBECDecision());
    expect(result.content).toContain('financial transfer');
    expect(result.content).toContain('out-of-band channel');
  });

  it('verdict field on AnnotatedMessage is "warn"', () => {
    const result = decorateMessage('test', makeBECDecision());
    expect(result.verdict).toBe('warn');
  });

  it('original field preserves original message exactly', () => {
    const original = 'Test message content';
    const result = decorateMessage(original, makeBECDecision());
    expect(result.original).toBe(original);
  });

  it('quarantine_ref is set when decision has quarantine_id', () => {
    const decision = makeBECDecision({ quarantine_id: 'qid-abc-123' });
    const result = decorateMessage('test', decision);
    expect(result.quarantine_ref).toBe('qid-abc-123');
    expect(result.content).toContain('qid-abc-123');
  });

  it('source_type option is reflected in untrusted_content source attribute', () => {
    const result = decorateMessage('test', makeBECDecision(), { source_type: 'email' });
    expect(result.content).toContain('source="email"');
  });

  it('apparent_sender with XML special chars is escaped in quarantine notification', () => {
    const notif = buildQuarantineNotification('qid-001', makeBlockDecision(), {
      apparent_sender: 'Boss <ceo@evil.com>',
    });
    expect(notif.xml).toContain('&lt;ceo@evil.com&gt;');
    expect(notif.xml).not.toContain('<ceo@evil.com>');
  });
});

describe('buildQuarantineNotification', () => {
  it('output contains <quarantine_notification sh_version="1">', () => {
    const notif = buildQuarantineNotification('qid-001', makeBlockDecision());
    expect(notif.xml).toContain('<quarantine_notification sh_version="1">');
  });

  it('output contains <status>BLOCKED</status>', () => {
    const notif = buildQuarantineNotification('qid-001', makeBlockDecision());
    expect(notif.xml).toContain('<status>BLOCKED</status>');
  });

  it('output contains the quarantine_id', () => {
    const notif = buildQuarantineNotification('qid-xyz-789', makeBlockDecision());
    expect(notif.xml).toContain('qid-xyz-789');
    expect(notif.quarantine_id).toBe('qid-xyz-789');
  });

  it('throws if decision has no threats', () => {
    const emptyDecision: SafeHouseDecision = {
      verdict: 'block',
      overall_risk: 0.96,
      threats: [],
      l1_score: 0.96,
      session_multiplier: 1.0,
      detection_layer: 'l1',
      duration_ms: 1,
    };
    expect(() => buildQuarantineNotification('qid-empty', emptyDecision)).toThrow(
      'Cannot build notification for decision with no threats',
    );
  });

  it('returns correct threat_type matching top threat', () => {
    const notif = buildQuarantineNotification('qid-001', makeBlockDecision());
    // Top threat by confidence is prompt_injection (0.9 > 0.8)
    expect(notif.threat_type).toBe('prompt_injection');
  });

  it('apparent_sender is passed through to return value', () => {
    const notif = buildQuarantineNotification('qid-001', makeBlockDecision(), {
      apparent_sender: 'attacker@evil.com',
    });
    expect(notif.apparent_sender).toBe('attacker@evil.com');
  });

  it('uses default review URL when no review_base_url provided', () => {
    const notif = buildQuarantineNotification('qid-001', makeBlockDecision());
    expect(notif.xml).toContain('https://app.mnemom.com/safe-house/quarantine/qid-001');
  });

  it('uses custom review_base_url when provided', () => {
    const notif = buildQuarantineNotification('qid-001', makeBlockDecision(), {
      review_base_url: 'https://staging.mnemom.com',
    });
    expect(notif.xml).toContain('https://staging.mnemom.com/safe-house/quarantine/qid-001');
  });
});
