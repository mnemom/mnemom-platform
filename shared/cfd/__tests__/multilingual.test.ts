import { describe, it, expect } from 'vitest';
import { runL1Detection } from '../src/detector';
import { detectLanguage } from '../src/lang-detect';

describe('Language detection', () => {
  it('detects French from function words', () => {
    expect(detectLanguage('Le directeur général vous demande de faire ceci')).toBe('fr');
  });
  it('detects German from function words', () => {
    expect(detectLanguage('Der Geschäftsführer braucht das sofort')).toBe('de');
  });
  it('detects Italian from function words', () => {
    expect(detectLanguage('Il direttore ha bisogno di questo subito')).toBe('it');
  });
  it('detects Spanish from function words', () => {
    expect(detectLanguage('El director general necesita esto para los fondos del proyecto con urgencia')).toBe('es');
  });
  it('detects Portuguese from function words', () => {
    expect(detectLanguage('O diretor precisa que você faça isso mais rápido para nós')).toBe('pt');
  });
  it('detects Japanese from CJK characters', () => {
    expect(detectLanguage('社長からの緊急のお知らせです')).toBe('ja');
  });
  it('detects Chinese from CJK characters', () => {
    expect(detectLanguage('总裁要求立刻处理这件事，我们都需要在今天完成。')).toBe('zh');
  });
  it('falls back to en for unknown language', () => {
    expect(detectLanguage('Hola amigo, cómo')).toBe('en'); // too short / ambiguous
  });
  it('falls back to en for very short text', () => {
    expect(detectLanguage('ok')).toBe('en');
  });
});

describe('Multilingual BEC detection', () => {
  it('detects French BEC: virement urgent + PDG', () => {
    const result = runL1Detection('Le PDG demande que vous fassiez un virement urgent avec les fonds de la société. Ne dites pas à la comptabilité.');
    expect(result.threats.some(t => t.type === 'bec_fraud')).toBe(true);
    expect(result.score).toBeGreaterThan(0.6);
  });

  it('detects German BEC: Überweisung + Geschäftsführer', () => {
    const result = runL1Detection('Der Geschäftsführer benötigt sofort eine Überweisung. Bitte sagen Sie niemandem davon.');
    expect(result.threats.some(t => t.type === 'bec_fraud')).toBe(true);
    expect(result.score).toBeGreaterThan(0.6);
  });

  it('detects Italian BEC: bonifico + direttore', () => {
    const result = runL1Detection('Il direttore richiede un bonifico urgente. Non dirlo a nessuno per ora.');
    expect(result.threats.some(t => t.type === 'bec_fraud')).toBe(true);
  });

  it('detects Spanish BEC: transferencia + director', () => {
    const result = runL1Detection('El director general necesita una transferencia urgente ahora mismo. No lo menciones.');
    expect(result.threats.some(t => t.type === 'bec_fraud')).toBe(true);
  });

  it('detects Portuguese BEC: transferência + diretor', () => {
    const result = runL1Detection('O diretor precisa de uma transferência urgente imediatamente. Não diga a ninguém.');
    expect(result.threats.some(t => t.type === 'bec_fraud')).toBe(true);
  });

  it('detects Japanese BEC: 振込 + 社長', () => {
    const result = runL1Detection('社長から至急振込をするよう指示がありました。誰にも言わないでください。');
    expect(result.threats.some(t => t.type === 'bec_fraud')).toBe(true);
  });

  it('detects Chinese BEC: 转账 + 总裁', () => {
    const result = runL1Detection('总裁要求立刻转账50000元，这是我们都需要保密的事，不要告诉别人。');
    expect(result.threats.some(t => t.type === 'bec_fraud')).toBe(true);
  });

  it('clean message in French scores low', () => {
    const result = runL1Detection('Bonjour, pouvez-vous me confirmer la date de la réunion de demain?');
    expect(result.score).toBeLessThan(0.4);
  });

  it('detected_lang reflects the detected language', () => {
    const result = runL1Detection('Le PDG demande que vous fassiez un virement urgent avec les fonds de la société immédiatement');
    expect(result.detected_lang).toBe('fr');
  });

  it('English BEC still works after refactor', () => {
    const result = runL1Detection('This is the CEO. Wire $50,000 immediately. Do not tell finance.');
    expect(result.threats.some(t => t.type === 'bec_fraud')).toBe(true);
    expect(result.score).toBeGreaterThan(0.7);
  });
});
