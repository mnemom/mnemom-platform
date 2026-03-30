import { scanDLP } from './dlp.js';
import { computeMinHash, isSimilarToPattern } from './fingerprint.js';
import type { ThreatDetection, ThreatType, CFDThreatPattern, SessionRiskState } from './types.js';

// Urgency / authority pressure word patterns
const URGENCY_WORDS = [
  'immediately', 'urgent', 'asap', 'right now', 'emergency', 'critical',
  'time sensitive', 'time-sensitive', 'do not delay', 'act now', 'deadline',
  'last chance', 'expires today', 'expires soon',
];
const AUTHORITY_WORDS = [
  'ceo', 'cfo', 'president', 'executive', 'boss', 'manager', 'compliance',
  'legal', 'audit', 'regulator', 'irs', 'fbi', 'police', 'government',
  'official notice', 'court order', 'subpoena',
];
const SECRECY_WORDS = [
  "don't tell", "don't mention", 'keep this between us', 'confidential',
  'no one else should know', "don't share", 'secret', 'off the record',
  'bypass', 'skip the usual', 'without approval', 'unauthorized',
];
const FINANCIAL_ACTION_WORDS = [
  'wire transfer', 'bank transfer', 'ach transfer', 'send money', 'send funds',
  'transfer funds', 'pay invoice', 'account number', 'routing number',
  'cryptocurrency', 'bitcoin', 'gift card', 'itunes card',
  'wire $', 'wire funds', 'wire money', 'wired to', 'wire to',
];

// Direct injection patterns
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions?/i,
  /disregard\s+(all\s+)?(prior|previous|earlier)\s+instructions?/i,
  /forget\s+(all\s+)?(your\s+)?(previous\s+)?instructions?/i,
  /you\s+are\s+now\s+(a\s+)?(?!an?\s+agent|a\s+sovereign)/i,
  /new\s+(system\s+)?instructions?:/i,
  /\[system\]/i,
  /\[admin\]/i,
  /\[override\]/i,
  /<\s*system\s*>/i,
  /assistant:\s*i\s+will\s+now/i,
  /print\s+(your\s+)?(system\s+prompt|instructions|rules)/i,
  /reveal\s+(your\s+)?(system\s+prompt|instructions|rules)/i,
  /what\s+are\s+your\s+(exact\s+)?(instructions|rules|system prompt)/i,
  /pretend\s+you\s+(are|have no)/i,
  /act\s+as\s+if\s+you\s+(have\s+no|are\s+not)/i,
  /jailbreak/i,
  /dan\s+mode/i,
  /developer\s+mode/i,
  /sudo\s+mode/i,
];

// Agent spoofing patterns
const SPOOFING_PATTERNS = [
  /i\s+am\s+(a\s+)?(?:mnemom|trusted|authorized|system|admin|root)(\s+\w+)?\s+agent/i,
  /this\s+is\s+(a\s+)?system\s+message/i,
  /\[trusted\s+agent\]/i,
  /\[mnemom\s+system\]/i,
  /message\s+from\s+(the\s+)?(?:admin|system|orchestrator|coordinator)/i,
  /authorized\s+override/i,
];

// Data exfiltration patterns
const EXFIL_PATTERNS = [
  /send\s+(all\s+)?(your\s+)?(data|files|documents|emails|messages)\s+to/i,
  /export\s+(all\s+)?(your\s+)?(data|files)/i,
  /forward\s+(all\s+)?(emails?|messages?|files?)/i,
  /upload\s+(all\s+)?(your\s+)?(data|files)/i,
  /exfiltrate/i,
];

function countWords(text: string, words: string[]): number {
  const lower = text.toLowerCase();
  return words.filter(w => lower.includes(w)).length;
}

function matchesAny(text: string, patterns: RegExp[]): { matched: boolean; pattern?: string } {
  for (const re of patterns) {
    if (re.test(text)) return { matched: true, pattern: re.source };
  }
  return { matched: false };
}

export interface L1Result {
  threats: ThreatDetection[];
  score: number;
}

export function runL1Detection(
  content: string,
  patterns: CFDThreatPattern[] = [],
): L1Result {
  const threats: ThreatDetection[] = [];

  // 1. Direct prompt injection
  const injMatch = matchesAny(content, INJECTION_PATTERNS);
  if (injMatch.matched) {
    threats.push({
      type: 'prompt_injection',
      confidence: 0.85,
      reasoning: 'Matched direct prompt injection pattern',
      matched_pattern: injMatch.pattern,
    });
  }

  // 2. Agent spoofing
  const spoofMatch = matchesAny(content, SPOOFING_PATTERNS);
  if (spoofMatch.matched) {
    threats.push({
      type: 'agent_spoofing',
      confidence: 0.80,
      reasoning: 'Matched agent identity spoofing pattern',
      matched_pattern: spoofMatch.pattern,
    });
  }

  // 3. BEC / social engineering scoring
  const urgencyCount = countWords(content, URGENCY_WORDS);
  const authorityCount = countWords(content, AUTHORITY_WORDS);
  const secrecyCount = countWords(content, SECRECY_WORDS);
  const financialCount = countWords(content, FINANCIAL_ACTION_WORDS);

  // BEC fraud: financial action + urgency/authority + secrecy
  if (financialCount > 0 && (urgencyCount > 0 || authorityCount > 0)) {
    const confidence = Math.min(
      0.5 + financialCount * 0.15 + urgencyCount * 0.1 + secrecyCount * 0.15 + authorityCount * 0.1,
      0.92,
    );
    threats.push({
      type: 'bec_fraud',
      confidence,
      reasoning: `Financial action (${financialCount}) + urgency (${urgencyCount}) + authority (${authorityCount}) + secrecy (${secrecyCount}) signals`,
    });
  }

  // Social engineering: urgency/authority without financial component
  if ((urgencyCount >= 2 || authorityCount >= 2) && financialCount === 0) {
    const confidence = Math.min(0.4 + urgencyCount * 0.1 + authorityCount * 0.1 + secrecyCount * 0.15, 0.75);
    if (confidence >= 0.4) {
      threats.push({
        type: 'social_engineering',
        confidence,
        reasoning: `Urgency (${urgencyCount}) + authority (${authorityCount}) + secrecy (${secrecyCount}) signals without financial action`,
      });
    }
  }

  // 4. Data exfiltration
  const exfilMatch = matchesAny(content, EXFIL_PATTERNS);
  if (exfilMatch.matched) {
    threats.push({
      type: 'data_exfiltration',
      confidence: 0.75,
      reasoning: 'Matched data exfiltration pattern',
      matched_pattern: exfilMatch.pattern,
    });
  }

  // 5. DLP — PII / credentials in inbound
  const dlpMatches = scanDLP(content);
  if (dlpMatches.length > 0) {
    threats.push({
      type: 'pii_in_inbound',
      confidence: Math.min(0.7 + dlpMatches.length * 0.05, 0.95),
      reasoning: `DLP: detected ${dlpMatches.length} sensitive data pattern(s): ${[...new Set(dlpMatches.map(m => m.type))].join(', ')}`,
    });
  }

  // 6. Known threat pattern matching (from cfd_threat_patterns table)
  // Uses MinHash similarity when minhash is stored; falls back to substring match
  const contentSig = computeMinHash(content);
  for (const pattern of patterns) {
    if (pattern.label !== 'malicious') continue;

    let isMatch = false;
    let matchConfidence = 0.70;

    if (pattern.minhash) {
      // MinHash similarity — catches near-duplicate variants of known attacks
      const { similar, similarity } = isSimilarToPattern(contentSig, pattern.minhash);
      if (similar) {
        isMatch = true;
        matchConfidence = 0.60 + similarity * 0.35; // 0.60 at threshold → 0.95 at perfect match
      }
    } else {
      // Fallback: substring match
      isMatch = content.toLowerCase().includes(pattern.content.toLowerCase());
    }

    if (isMatch) {
      const existing = threats.find(t => t.type === pattern.threat_type);
      if (existing) {
        existing.confidence = Math.min(existing.confidence + 0.1, 0.98);
        existing.matched_pattern = `known_pattern:${pattern.id}`;
      } else {
        threats.push({
          type: pattern.threat_type,
          confidence: matchConfidence,
          reasoning: pattern.minhash
            ? `MinHash similarity match against known threat pattern (library match)`
            : `Substring match against known threat pattern`,
          matched_pattern: `known_pattern:${pattern.id}`,
        });
      }
    }
  }

  // Aggregate score: max individual confidence, with bonus for multiple threats
  const maxConfidence = threats.length > 0 ? Math.max(...threats.map(t => t.confidence)) : 0;
  const multiThreatBonus = threats.length > 1 ? Math.min((threats.length - 1) * 0.05, 0.15) : 0;
  const score = Math.min(maxConfidence + multiThreatBonus, 1.0);

  return { threats, score };
}

export function applySessionMultiplier(
  l1Score: number,
  session: SessionRiskState | null,
): { multiplied_score: number; session_multiplier: number } {
  if (!session || l1Score === 0) return { multiplied_score: l1Score, session_multiplier: 1.0 };

  // Count recent elevated scores in this session (last 10 min)
  const tenMinAgo = Date.now() - 10 * 60 * 1000;
  const recentElevated = session.window_scores.filter(
    s => s.score >= 0.6 && s.timestamp >= tenMinAgo,
  ).length;

  let multiplier = 1.0;
  if (recentElevated >= 3) multiplier = 1.3;
  else if (recentElevated >= 2) multiplier = 1.15;

  return {
    multiplied_score: Math.min(l1Score * multiplier, 1.0),
    session_multiplier: multiplier,
  };
}
