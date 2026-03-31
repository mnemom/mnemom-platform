import { scanDLP } from './dlp.js';
import { computeMinHash, isSimilarToPattern } from './fingerprint.js';
import type { ThreatDetection, ThreatType, CFDThreatPattern, SessionRiskState } from './types.js';
import { detectLanguage, hasNativeL1Support } from './lang-detect.js';
import { MULTILINGUAL_SIGNALS } from './i18n-signals.js';

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
  // "I am a/an trusted/admin/... [optional words] agent" — handle 'an' article and multi-word gaps
  /i\s+am\s+(an?\s+)?(?:mnemom|trusted|authorized|system|admin|root)(?:\s+\w+){0,2}\s+agent/i,
  /this\s+is\s+(a\s+)?system\s+message/i,
  /\[trusted\s+agent\]/i,
  /\[mnemom\s+system\]/i,
  /message\s+from\s+(the\s+)?(?:admin|system|orchestrator|coordinator)/i,
  /authorized\s+override/i,
  // Additional: claiming agent identity with authority
  /i\s+am\s+(?:an?\s+)?(?:authorized|privileged|elevated|override)\s+(?:agent|system|process)/i,
  // Alignment card / constraint bypass
  /(?:ignore|bypass|disable|remove)\s+(?:your\s+)?(?:alignment\s+card|constraints?|restrictions?|guidelines?)/i,
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
  return words.filter(w => lower.includes(w.toLowerCase())).length;
}

function matchedWords(text: string, words: string[]): string[] {
  const lower = text.toLowerCase();
  return words.filter(w => lower.includes(w.toLowerCase()));
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
  detected_lang?: string;
}

// Maximum content length to process in L1 detection.
// Protects against DoS via unbounded regex/MinHash on large payloads.
// 8,000 chars covers 99.9%+ of legitimate messages.
const MAX_L1_CONTENT_LENGTH = 8_000;

export function runL1Detection(
  content: string,
  patterns: CFDThreatPattern[] = [],
): L1Result {
  // Cap content length before any processing
  const text = content.length > MAX_L1_CONTENT_LENGTH
    ? content.slice(0, MAX_L1_CONTENT_LENGTH)
    : content;

  // Detect language for multilingual signal selection (~0.1ms)
  const lang = detectLanguage(text);
  const nativeSupport = hasNativeL1Support(lang);

  // Select language-appropriate signal lists (fall back to English for unsupported languages)
  const URGENCY = MULTILINGUAL_SIGNALS.urgency[lang] ?? MULTILINGUAL_SIGNALS.urgency.en;
  const AUTHORITY = MULTILINGUAL_SIGNALS.authority[lang] ?? MULTILINGUAL_SIGNALS.authority.en;
  const FINANCIAL = MULTILINGUAL_SIGNALS.financial[lang] ?? MULTILINGUAL_SIGNALS.financial.en;
  const SECRECY = MULTILINGUAL_SIGNALS.secrecy[lang] ?? MULTILINGUAL_SIGNALS.secrecy.en;
  const FINANCIAL_TARGET = MULTILINGUAL_SIGNALS.financial_target[lang] ?? MULTILINGUAL_SIGNALS.financial_target.en;

  // Confidence penalty for unsupported languages (English fallback is less precise)
  const langPenalty = nativeSupport ? 0 : 0.08;

  const threats: ThreatDetection[] = [];

  // 1. Direct prompt injection
  const injMatch = matchesAny(text, INJECTION_PATTERNS);
  if (injMatch.matched) {
    threats.push({
      type: 'prompt_injection',
      confidence: 0.85,
      reasoning: 'Matched direct prompt injection pattern',
      matched_pattern: injMatch.pattern,
    });
  }

  // 2. Agent spoofing
  const spoofMatch = matchesAny(text, SPOOFING_PATTERNS);
  if (spoofMatch.matched) {
    threats.push({
      type: 'agent_spoofing',
      confidence: 0.80,
      reasoning: 'Matched agent identity spoofing pattern',
      matched_pattern: spoofMatch.pattern,
    });
  }

  // 3. BEC / social engineering scoring
  const urgencyMatched = matchedWords(text, URGENCY);
  const authorityMatched = matchedWords(text, AUTHORITY);
  const secrecyMatched = matchedWords(text, SECRECY);
  const financialMatched = matchedWords(text, FINANCIAL);
  const urgencyCount = urgencyMatched.length;
  const authorityCount = authorityMatched.length;
  const secrecyCount = secrecyMatched.length;
  const financialCount = financialMatched.length + countWords(text, FINANCIAL_TARGET);

  // BEC fraud: financial action + urgency/authority + secrecy
  if (financialCount > 0 && (urgencyCount > 0 || authorityCount > 0)) {
    const confidence = Math.min(
      0.5 + financialCount * 0.15 + urgencyCount * 0.1 + secrecyCount * 0.15 + authorityCount * 0.1 - langPenalty,
      0.92,
    );
    threats.push({
      type: 'bec_fraud',
      confidence,
      reasoning: [
        financialMatched.length > 0 ? `Financial action (${financialMatched.slice(0,3).map(w=>`'${w}'`).join(', ')})` : '',
        urgencyMatched.length > 0  ? `Urgency (${urgencyMatched.slice(0,3).map(w=>`'${w}'`).join(', ')})` : '',
        authorityMatched.length > 0 ? `Authority (${authorityMatched.slice(0,2).map(w=>`'${w}'`).join(', ')})` : '',
        secrecyMatched.length > 0  ? `Secrecy (${secrecyMatched.slice(0,2).map(w=>`'${w}'`).join(', ')})` : '',
      ].filter(Boolean).join(' · '),
    });
  }

  // Social engineering: urgency/authority without financial component
  if ((urgencyCount >= 2 || authorityCount >= 2) && financialCount === 0) {
    const confidence = Math.min(0.4 + urgencyCount * 0.1 + authorityCount * 0.1 + secrecyCount * 0.15 - langPenalty, 0.75);
    if (confidence >= 0.4) {
      threats.push({
        type: 'social_engineering',
        confidence,
        reasoning: [
          urgencyMatched.length > 0  ? `Urgency (${urgencyMatched.slice(0,3).map(w=>`'${w}'`).join(', ')})` : '',
          authorityMatched.length > 0 ? `Authority (${authorityMatched.slice(0,2).map(w=>`'${w}'`).join(', ')})` : '',
          secrecyMatched.length > 0  ? `Secrecy (${secrecyMatched.slice(0,2).map(w=>`'${w}'`).join(', ')})` : '',
        ].filter(Boolean).join(' · '),
      });
    }
  }

  // 4. Data exfiltration
  const exfilMatch = matchesAny(text, EXFIL_PATTERNS);
  if (exfilMatch.matched) {
    threats.push({
      type: 'data_exfiltration',
      confidence: 0.75,
      reasoning: 'Matched data exfiltration pattern',
      matched_pattern: exfilMatch.pattern,
    });
  }

  // 5. DLP — PII / credentials in inbound
  const dlpMatches = scanDLP(text);
  if (dlpMatches.length > 0) {
    threats.push({
      type: 'pii_in_inbound',
      confidence: Math.min(0.7 + dlpMatches.length * 0.05, 0.95),
      reasoning: `DLP: detected ${dlpMatches.length} sensitive data pattern(s): ${[...new Set(dlpMatches.map(m => m.type))].join(', ')}`,
    });
  }

  // 6. Known threat pattern matching (from cfd_threat_patterns table)
  // Uses MinHash similarity when minhash is stored; falls back to substring match
  const contentSig = computeMinHash(text);
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
      isMatch = text.toLowerCase().includes(pattern.content.toLowerCase());
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

  // Aggregate score: max individual confidence + bonus for independent threat types only.
  // bec_fraud and social_engineering share urgency/authority signals — they are correlated,
  // not independent evidence. Only award bonus for genuinely distinct threat categories.
  const maxConfidence = threats.length > 0 ? Math.max(...threats.map(t => t.confidence)) : 0;
  const detectedTypes = new Set(threats.map(t => t.type));
  // Collapse correlated pair: bec_fraud + social_engineering share signal sources
  if (detectedTypes.has('bec_fraud') && detectedTypes.has('social_engineering')) {
    detectedTypes.delete('social_engineering');
  }
  const independentCount = detectedTypes.size;
  const multiThreatBonus = independentCount > 1 ? Math.min((independentCount - 1) * 0.05, 0.15) : 0;
  const score = Math.min(maxConfidence + multiThreatBonus, 1.0);

  return { threats, score, detected_lang: lang };
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
