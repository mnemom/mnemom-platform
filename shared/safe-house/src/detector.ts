import { scanDLP } from './dlp.js';
import { computeMinHash, isSimilarToPattern } from './fingerprint.js';
import type {
  ThreatDetection, ThreatType, SafeHouseThreatPattern, SessionRiskState,
  SourceType, L1Options,
} from './types.js';
import { detectLanguage, hasNativeL1Support } from './lang-detect.js';
import { MULTILINGUAL_SIGNALS } from './i18n-signals.js';
import { preprocessForDetection } from './preprocessor.js';

// ── Direct injection patterns ──────────────────────────────────────────────
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

// ── Structural injection patterns (language-agnostic) ──────────────────────
// These work in any script because they use ASCII structural markers that
// attackers embed even in non-English messages.
const STRUCTURAL_INJECTION_PATTERNS = [
  /\[(?:system|admin|override|root|sudo|superuser)\]/i,
  /<\s*(?:instructions?|prompt|override)\s*>/i,
  /\{(?:system_prompt|instructions?|override)\}\s*:/i,
  /#{1,3}\s*(?:system|admin|override)\s*$/im,
  /\/\*\s*(?:system|admin|override)/i,
];

// ── Multilingual injection patterns (Latin-script languages) ──────────────
// Translated equivalents of core injection phrases. Tight patterns require
// AI-role completion to prevent false positives ("vous êtes maintenant inscrit").
const MULTILINGUAL_INJECTION_PATTERNS: Record<string, RegExp[]> = {
  fr: [
    /ignore(?:r|z|s)?\s+(?:toutes?\s+les\s+)?instructions?\s+précédentes?/i,
    /vous\s+êtes\s+maintenant\s+(?:une?\s+)?(?:assistant|agent\s+(?:ia|artificiel)|bot|système\s+ia|intelligence artificielle)/i,
    /nouvelles?\s+instructions?\s+(?:du\s+)?système\s*:/i,
    /je\s+suis\s+(?:un?\s+)?(?:agent\s+(?:de\s+confiance|autorisé|système)|orchestrateur)/i,
  ],
  de: [
    /ignorier(?:en|e)\s+(?:Sie\s+)?(?:alle\s+)?vorherigen?\s+(?:Anweisungen|Befehle)/i,
    /Sie\s+sind\s+jetzt\s+(?:ein?\s+)?(?:assistent|KI[-\s]?agent|bot|KI[-\s]?system)/i,
    /neue\s+(?:System)?anweisungen\s*:/i,
    /ich\s+bin\s+(?:ein?\s+)?(?:autorisierter|vertrauensw[üu]rdiger)\s+(?:agent|assistent)/i,
  ],
  it: [
    /ignora\s+(?:tutte\s+le\s+)?istruzioni\s+(?:precedenti|precedentemente)/i,
    /sei\s+ora\s+(?:un?\s+)?(?:assistente|agente\s+(?:ia|artificiale)|bot|sistema\s+ia)/i,
    /nuove\s+istruzioni\s+(?:di\s+)?sistema\s*:/i,
    /sono\s+(?:un?\s+)?(?:agente\s+(?:fidato|autorizzato)|orchestratore)/i,
  ],
  es: [
    /ignora\s+(?:todas?\s+las?\s+)?instrucciones?\s+anteriores?/i,
    /ahora\s+eres?\s+(?:un?\s+)?(?:asistente|agente\s+(?:ia|artificial)|bot|sistema\s+(?:de\s+)?ia)/i,
    /nuevas?\s+instrucciones?\s+(?:del?\s+)?sistema\s*:/i,
    /soy\s+(?:un?\s+)?(?:agente\s+(?:de\s+confianza|autorizado)|orquestador)/i,
  ],
  pt: [
    /ignore\s+(?:todas?\s+as\s+)?instruções\s+anteriores?/i,
    /você\s+é\s+agora\s+(?:um?\s+)?(?:assistente|agente\s+(?:de\s+)?ia|bot|sistema\s+(?:de\s+)?ia)/i,
    /novas?\s+instruções?\s+(?:do\s+)?sistema\s*:/i,
    /sou\s+(?:um?\s+)?(?:agente\s+(?:de\s+confiança|autorizado)|orquestrador)/i,
  ],
};

// ── Multilingual spoofing patterns (Latin-script languages) ────────────────
const MULTILINGUAL_SPOOFING_PATTERNS: Record<string, RegExp[]> = {
  fr: [
    /je\s+suis\s+(?:un?\s+)?(?:agent|système|orchestrateur)\s+(?:autorisé|de\s+confiance|système)/i,
    /message\s+(?:du|de\s+l[ae]?)\s+(?:système|administrateur|orchestrateur)/i,
  ],
  de: [
    /ich\s+bin\s+(?:ein?\s+)?(?:autorisierter|vertrauensw[üu]rdiger|privilegierter)\s+(?:agent|assistent)/i,
    /nachricht\s+(?:vom?|von\s+der?)\s+(?:system|administrator|orchestrator)/i,
  ],
  it: [
    /sono\s+(?:un?\s+)?(?:agente|sistema)\s+(?:autorizzato|fidato|privilegiato)/i,
    /messaggio\s+(?:dal?|della?)\s+(?:sistema|amministratore|orchestratore)/i,
  ],
  es: [
    /soy\s+(?:un?\s+)?(?:agente|sistema)\s+(?:autorizado|de\s+confianza|privilegiado)/i,
    /mensaje\s+(?:del?|desde\s+el)\s+(?:sistema|administrador|orquestador)/i,
  ],
  pt: [
    /sou\s+(?:um?\s+)?(?:agente|sistema)\s+(?:autorizado|de\s+confiança|privilegiado)/i,
    /mensagem\s+(?:do|da)\s+(?:sistema|administrador|orquestrador)/i,
  ],
};

// ── Indirect injection patterns (all surfaces, surface-aware confidence) ───
// These patterns detect instruction-like language in content that should be data.
// Confidence is LOWER for user_message (users can legitimately talk about AI)
// and HIGHER for tool_result / agent_message (data should not instruct the AI).
const INDIRECT_INJECTION_PATTERNS = [
  /\bif\s+you(?:\s+are|'re)\s+(?:an?\s+)?(?:ai|language model|llm|assistant|bot)\b/i,
  /\bnote\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|model|llm|bot)\b/i,
  /\battention\s*:?\s+(?:ai|assistant|model|llm)\b/i,
  /\bwhen\s+you\s+(?:receive|read|process|see|parse)\s+this\b/i,
  /\bignore\s+(?:the\s+)?(?:above|previous|prior)\s+(?:context|request|instruction|task)\b/i,
  /\bdisregard\s+(?:the\s+)?(?:above|previous|prior)\s+(?:context|request|instruction)\b/i,
  /\[\[?(?:human|assistant|system|ai|llm)[\s:]\]\]?/i,
  /p\.s\.?\s+(?:if\s+you|when\s+you|note\s+to)/i,
];

// Tool result / agent message only — too noisy in user_message context
const TOOL_RESULT_INJECTION_PATTERNS = [
  /(?:^|\n)\s*(?:system|assistant)\s*:\s+/im,
  /\n\s*ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\s*\.?\s*\n/i,
  /<\s*(?:injection|payload|cmd|exec)\s*>/i,
];

// ── Agent spoofing patterns ────────────────────────────────────────────────
const SPOOFING_PATTERNS = [
  /i\s+am\s+(an?\s+)?(?:mnemom|trusted|authorized|system|admin|root)(?:\s+\w+){0,2}\s+agent/i,
  /this\s+is\s+(a\s+)?system\s+message/i,
  /\[trusted\s+agent\]/i,
  /\[mnemom\s+system\]/i,
  /message\s+from\s+(the\s+)?(?:admin|system|orchestrator|coordinator)/i,
  /authorized\s+override/i,
  /i\s+am\s+(?:an?\s+)?(?:authorized|privileged|elevated|override)\s+(?:agent|system|process)/i,
  /(?:ignore|bypass|disable|remove)\s+(?:your\s+)?(?:alignment\s+card|constraints?|restrictions?|guidelines?)/i,
];

// ── Data exfiltration patterns ─────────────────────────────────────────────
const EXFIL_PATTERNS = [
  /send\s+(all\s+)?(your\s+)?(data|files|documents|emails|messages)\s+to/i,
  /export\s+(all\s+)?(your\s+)?(data|files)/i,
  /forward\s+(all\s+)?(emails?|messages?|files?)/i,
  /upload\s+(all\s+)?(your\s+)?(data|files)/i,
  /exfiltrate/i,
];

// ── Helpers ────────────────────────────────────────────────────────────────

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

function getIndirectInjectionConfidence(surface: SourceType | undefined): number {
  if (surface === 'tool_result' || surface === 'agent_message') return 0.70;
  if (surface === 'user_message') return 0.45;
  return 0.55;
}

// ── L1Result ───────────────────────────────────────────────────────────────

export interface L1Result {
  threats: ThreatDetection[];
  score: number;
  detected_lang?: string;
  /** True when a decode instruction + base64-like string were found near each other.
   *  Advisory only — the gateway uses this to force SemanticAnalyzer regardless of score. */
  encoding_detected?: boolean;
}

const MAX_L1_CONTENT_LENGTH = 8_000;

// ── runL1Detection ─────────────────────────────────────────────────────────

export function runL1Detection(
  content: string,
  patterns: SafeHouseThreatPattern[] = [],
  options: L1Options = {},
): L1Result {
  const surface = options.surface;

  // 1. Cap content length (DoS protection)
  const raw = content.length > MAX_L1_CONTENT_LENGTH
    ? content.slice(0, MAX_L1_CONTENT_LENGTH)
    : content;

  // 2. Normalize for detection (zero-width strip, fullwidth→ASCII, homoglyph map, emoji strip)
  //    All pattern matching runs on `text` (normalized). Storage/decoration uses `raw` (original).
  const { normalized: text, encoding_detected } = preprocessForDetection(raw);

  // 3. Language detection (on normalized text — Cyrillic-disguised injection now looks Latin)
  const lang = detectLanguage(text);
  const nativeSupport = hasNativeL1Support(lang);

  // 4. Select language-appropriate signal lists
  const URGENCY         = MULTILINGUAL_SIGNALS.urgency[lang]          ?? MULTILINGUAL_SIGNALS.urgency.en;
  const AUTHORITY       = MULTILINGUAL_SIGNALS.authority[lang]        ?? MULTILINGUAL_SIGNALS.authority.en;
  const FINANCIAL       = MULTILINGUAL_SIGNALS.financial[lang]        ?? MULTILINGUAL_SIGNALS.financial.en;
  const SECRECY         = MULTILINGUAL_SIGNALS.secrecy[lang]          ?? MULTILINGUAL_SIGNALS.secrecy.en;
  const FINANCIAL_TARGET = MULTILINGUAL_SIGNALS.financial_target[lang] ?? MULTILINGUAL_SIGNALS.financial_target.en;

  const langPenalty = nativeSupport ? 0 : 0.08;
  const threats: ThreatDetection[] = [];

  // ── Detection module 1: Direct prompt injection ──────────────────────────
  const injMatch = matchesAny(text, INJECTION_PATTERNS);
  if (injMatch.matched) {
    threats.push({
      type: 'prompt_injection',
      confidence: 0.85,
      reasoning: 'Matched direct prompt injection pattern',
      matched_pattern: injMatch.pattern,
    });
  }

  // ── Detection module 2: Structural injection (language-agnostic) ─────────
  if (!injMatch.matched) {
    const structMatch = matchesAny(text, STRUCTURAL_INJECTION_PATTERNS);
    if (structMatch.matched) {
      threats.push({
        type: 'prompt_injection',
        confidence: 0.78,
        reasoning: 'Matched structural injection pattern (bracket/tag override syntax)',
        matched_pattern: structMatch.pattern,
      });
    }
  }

  // ── Detection module 3: Multilingual injection (Latin-script) ────────────
  if (!threats.some(t => t.type === 'prompt_injection')) {
    const langPatterns = MULTILINGUAL_INJECTION_PATTERNS[lang];
    if (langPatterns) {
      const mlMatch = matchesAny(text, langPatterns);
      if (mlMatch.matched) {
        threats.push({
          type: 'prompt_injection',
          confidence: 0.80,
          reasoning: `Matched multilingual injection pattern (${lang})`,
          matched_pattern: mlMatch.pattern,
        });
      }
    }
  }

  // ── Detection module 4: Agent spoofing ───────────────────────────────────
  const spoofMatch = matchesAny(text, SPOOFING_PATTERNS);
  if (spoofMatch.matched) {
    threats.push({
      type: 'agent_spoofing',
      confidence: 0.80,
      reasoning: 'Matched agent identity spoofing pattern',
      matched_pattern: spoofMatch.pattern,
    });
  }

  // Multilingual spoofing (Latin-script languages)
  if (!spoofMatch.matched) {
    const mlSpoofPatterns = MULTILINGUAL_SPOOFING_PATTERNS[lang];
    if (mlSpoofPatterns) {
      const mlSpoofMatch = matchesAny(text, mlSpoofPatterns);
      if (mlSpoofMatch.matched) {
        threats.push({
          type: 'agent_spoofing',
          confidence: 0.75,
          reasoning: `Matched multilingual spoofing pattern (${lang})`,
          matched_pattern: mlSpoofMatch.pattern,
        });
      }
    }
  }

  // ── Detection module 5: BEC / social engineering scoring ─────────────────
  const urgencyMatched  = matchedWords(text, URGENCY);
  const authorityMatched = matchedWords(text, AUTHORITY);
  const secrecyMatched  = matchedWords(text, SECRECY);
  const financialMatched = matchedWords(text, FINANCIAL);
  const urgencyCount   = urgencyMatched.length;
  const authorityCount = authorityMatched.length;
  const secrecyCount   = secrecyMatched.length;
  const financialCount = financialMatched.length + countWords(text, FINANCIAL_TARGET);

  if (financialCount > 0 && (urgencyCount > 0 || authorityCount > 0)) {
    const confidence = Math.min(
      0.5 + financialCount * 0.15 + urgencyCount * 0.1 + secrecyCount * 0.15 + authorityCount * 0.1 - langPenalty,
      0.92,
    );
    threats.push({
      type: 'bec_fraud',
      confidence,
      reasoning: [
        financialMatched.length > 0  ? `Financial action (${financialMatched.slice(0,3).map(w=>`'${w}'`).join(', ')})` : '',
        urgencyMatched.length > 0    ? `Urgency (${urgencyMatched.slice(0,3).map(w=>`'${w}'`).join(', ')})` : '',
        authorityMatched.length > 0  ? `Authority (${authorityMatched.slice(0,2).map(w=>`'${w}'`).join(', ')})` : '',
        secrecyMatched.length > 0    ? `Secrecy (${secrecyMatched.slice(0,2).map(w=>`'${w}'`).join(', ')})` : '',
      ].filter(Boolean).join(' · '),
    });
  }

  if ((urgencyCount >= 2 || authorityCount >= 2) && financialCount === 0) {
    const confidence = Math.min(0.4 + urgencyCount * 0.1 + authorityCount * 0.1 + secrecyCount * 0.15 - langPenalty, 0.75);
    if (confidence >= 0.4) {
      threats.push({
        type: 'social_engineering',
        confidence,
        reasoning: [
          urgencyMatched.length > 0    ? `Urgency (${urgencyMatched.slice(0,3).map(w=>`'${w}'`).join(', ')})` : '',
          authorityMatched.length > 0  ? `Authority (${authorityMatched.slice(0,2).map(w=>`'${w}'`).join(', ')})` : '',
          secrecyMatched.length > 0    ? `Secrecy (${secrecyMatched.slice(0,2).map(w=>`'${w}'`).join(', ')})` : '',
        ].filter(Boolean).join(' · '),
      });
    }
  }

  // ── Detection module 6: Data exfiltration ────────────────────────────────
  const exfilMatch = matchesAny(text, EXFIL_PATTERNS);
  if (exfilMatch.matched) {
    threats.push({
      type: 'data_exfiltration',
      confidence: 0.75,
      reasoning: 'Matched data exfiltration pattern',
      matched_pattern: exfilMatch.pattern,
    });
  }

  // ── Detection module 7: Indirect injection (surface-aware) ───────────────
  const indirectConf = getIndirectInjectionConfidence(surface);
  const indirectMatch = matchesAny(text, INDIRECT_INJECTION_PATTERNS);
  if (indirectMatch.matched) {
    threats.push({
      type: 'indirect_injection',
      confidence: indirectConf,
      reasoning: 'Instruction-like language detected — possible embedded injection',
      matched_pattern: indirectMatch.pattern,
    });
  }

  // Tool-result-specific patterns (too noisy for user_message surface)
  if (surface && surface !== 'user_message' && !indirectMatch.matched) {
    const toolMatch = matchesAny(text, TOOL_RESULT_INJECTION_PATTERNS);
    if (toolMatch.matched) {
      threats.push({
        type: 'indirect_injection',
        confidence: 0.70,
        reasoning: 'Instruction-syntax detected in tool/agent response content',
        matched_pattern: toolMatch.pattern,
      });
    }
  }

  // ── Detection module 8: DLP — PII / credentials in inbound ───────────────
  const dlpMatches = scanDLP(text);
  if (dlpMatches.length > 0) {
    threats.push({
      type: 'pii_in_inbound',
      confidence: Math.min(0.7 + dlpMatches.length * 0.05, 0.95),
      reasoning: `DLP: detected ${dlpMatches.length} sensitive data pattern(s): ${[...new Set(dlpMatches.map(m => m.type))].join(', ')}`,
    });
  }

  // ── Detection module 9: Known threat pattern matching (MinHash + substring) ──
  const contentSig = computeMinHash(text);
  for (const pattern of patterns) {
    if (pattern.label !== 'malicious') continue;

    let isMatch = false;
    let matchConfidence = 0.70;

    if (pattern.minhash) {
      const { similar, similarity } = isSimilarToPattern(contentSig, pattern.minhash);
      if (similar) {
        isMatch = true;
        matchConfidence = 0.60 + similarity * 0.35;
      }
    } else {
      isMatch = text.toLowerCase().includes(pattern.content.toLowerCase());
    }

    if (isMatch) {
      const existing = threats.find(t => t.type === pattern.threat_type);
      if (existing) {
        existing.confidence = Math.min(existing.confidence + 0.1, 0.98);
        existing.matched_pattern = `known_pattern:${pattern.id}`;
      } else {
        threats.push({
          type: pattern.threat_type as ThreatType,
          confidence: matchConfidence,
          reasoning: pattern.minhash
            ? 'MinHash similarity match against known threat pattern (library match)'
            : 'Substring match against known threat pattern',
          matched_pattern: `known_pattern:${pattern.id}`,
        });
      }
    }
  }

  // ── Score aggregation ─────────────────────────────────────────────────────
  const maxConfidence = threats.length > 0 ? Math.max(...threats.map(t => t.confidence)) : 0;
  const detectedTypes = new Set(threats.map(t => t.type));
  // Collapse correlated pair: bec_fraud + social_engineering share signal sources
  if (detectedTypes.has('bec_fraud') && detectedTypes.has('social_engineering')) {
    detectedTypes.delete('social_engineering');
  }
  const independentCount = detectedTypes.size;
  const multiThreatBonus = independentCount > 1 ? Math.min((independentCount - 1) * 0.05, 0.15) : 0;
  const score = Math.min(maxConfidence + multiThreatBonus, 1.0);

  return { threats, score, detected_lang: lang, encoding_detected };
}

// ── applySessionMultiplier ─────────────────────────────────────────────────

export function applySessionMultiplier(
  l1Score: number,
  session: SessionRiskState | null,
): { multiplied_score: number; session_multiplier: number } {
  if (!session || l1Score === 0) return { multiplied_score: l1Score, session_multiplier: 1.0 };

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
