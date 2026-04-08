/**
 * Lightweight language detector for CFD L1 signal selection.
 * Zero dependencies, ~0.1ms, works in Cloudflare Workers.
 * Uses high-frequency function words as language markers.
 * Falls back to 'en' if fewer than 2 markers match.
 */

const LANGUAGE_MARKERS: Record<string, string[]> = {
  fr: ['le','la','les','de','du','une','est','pas','que','je','nous','vous','cette','mais','avec'],
  de: ['der','die','das','ist','ich','sie','nicht','und','ein','eine','wir','für','auf','dem','den'],
  it: ['il','la','che','non','una','per','del','della','sono','questo','anche','come','tutto','mio'],
  es: ['el','la','que','los','del','una','por','con','más','este','para','también','como','todo'],
  pt: ['que','não','com','uma','por','mais','para','como','dos','você','isso','tem','são','mas'],
  ja: ['の','に','は','を','が','で','と','し','て','す','ます','です','から','まで','など'],
  zh: ['的','了','是','在','我','有','和','人','这','来','他','们','也','都','就'],
  // Arabic: high-frequency particles and pronouns; uses substring check (distinct script)
  ar: ['ال','في','من','إلى','على','هذا','هذه','أن','كان','مع','لا','هو','هي','نحن','ما'],
  // Korean: grammatical particles (postpositions); uses substring check (distinct script)
  ko: ['은','는','이','가','을','를','의','에','에서','로','으로','과','와','한','있'],
};

/**
 * Detect the language of a text sample.
 * Returns ISO 639-1 language code, or 'en' as default.
 * Requires 2+ marker matches for confidence.
 */
export function detectLanguage(text: string): string {
  const sample = text.slice(0, 300).toLowerCase();
  let best = 'en';
  let bestScore = 0;

  for (const [lang, markers] of Object.entries(LANGUAGE_MARKERS)) {
    const score = markers.filter(m => {
      // Use word-boundary-aware check for Latin scripts only
      if (/^[a-zà-öø-ÿ]+$/i.test(m)) {
        return new RegExp(`(?:^|\\s)${m}(?:\\s|$|[.,!?;:])`, 'i').test(sample);
      }
      // CJK, Arabic, Korean: simple substring check (script is visually distinct)
      return sample.includes(m);
    }).length;

    if (score > bestScore) {
      bestScore = score;
      best = lang;
    }
  }

  return bestScore >= 2 ? best : 'en';
}

/** Languages with full L1 word list support */
export const SUPPORTED_L1_LANGUAGES = new Set(['en','fr','de','it','es','pt','ja','zh','ar','ko']);

/**
 * Whether L1 has native word lists for this language.
 * When false, L1 uses English fallback with reduced confidence.
 */
export function hasNativeL1Support(lang: string): boolean {
  return SUPPORTED_L1_LANGUAGES.has(lang);
}
