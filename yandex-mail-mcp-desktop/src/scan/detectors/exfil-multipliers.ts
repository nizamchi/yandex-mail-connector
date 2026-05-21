// detectors/exfil-multipliers.ts -- category 2.9 (exfiltration-suggesting phrases).
//
// CRITICAL CONTRACT (L-EXF-1 + CONTEXT D12):
//   Category 2.9 exfil phrases are MULTIPLIERS ONLY. This detector emits
//   hits with subCategory='multiplier' and weight=0; actual scoring
//   contribution comes from composite-scoring.ts multiplying COMPANION hits
//   within a 200-byte window per Patch 10 PER-COMPANION IDEMPOTENT
//   semantics. A standalone "send me the report" must yield ZERO totalScore
//   contribution (T-EXF-NEG-001 invariant).
//
// L-LOGGING-1 carve-out: this detector deliberately does NOT call
// emitRedactedMatch. Multiplier markers are bookkeeping -- they exist to
// inform the composite scoring pass that exfiltration intent is present
// nearby a real hit. Emitting an audit line per multiplier would spam logs
// for benign messages ("send me a coffee", "send me the report") that
// produce zero score. T-LOGGING-01 (Patch 13) asserts only the absence of
// auditLogAction in this file, NOT the presence of emitRedactedMatch.
//
// CONTEXT decisions enforced:
//   D5: keyword-pass detector.
//   D8: byte offsets via ctx.pp.normalizedToOriginalByte.
//   D9-D11: weight=0; per-marker has no policy weight.
//   D12: multiplier semantics, never standalone, +25 absolute cap (enforced
//       in composite-scoring.ts).
//   D27: ScanHit.category === 'exfil_phrase' (singular).
//
// Pure function over DetectorContext.

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { registerDetector } from '../../outbound-scan.js';
// Note: does NOT import emitRedactedMatch -- multiplier markers are bookkeeping.

// Each token matched against ctx.pp.normalized (case-folded).
const PHRASES: ReadonlyArray<string> = Object.freeze([
  // RU
  'пришли мне',
  'отправь мне',
  'перешли',
  'вышли мне',
  'скинь мне',
  'по моему запросу',
  'как просил',
  'как просила',
  'переведи на счёт',
  'переведи на счет',
  'переведи на карту',
  'переведи на кошелёк',
  'переведи на кошелек',
  'вот пароль',
  'вот мой пароль',
  'сохрани этот пароль',
  'отправь на адрес',
  'передай дальше',
  'перешли всем',
  'forward всем',
  // EN
  'send me',
  'send it to me',
  'forward me',
  'forward to',
  'ship me',
  'as requested',
  'per your request',
  'wire transfer to',
  'transfer to account',
  'transfer to wallet',
  'send to wallet',
  'here is the password',
  'here\'s the password',
  'save this password',
  'email this to',
  'forward this email to',
  'please forward to',
]);

function isWordCp(cp: number): boolean {
  if (cp >= 48 && cp <= 57) return true;
  if (cp >= 65 && cp <= 90) return true;
  if (cp >= 97 && cp <= 122) return true;
  if (cp === 95) return true;
  if (cp >= 0x0400 && cp <= 0x04FF) return true;
  return false;
}

function bounded(text: string, start: number, end: number, tok: string): boolean {
  const tokStartIsWord = isWordCp(tok.charCodeAt(0));
  const tokEndIsWord = isWordCp(tok.charCodeAt(tok.length - 1));
  const beforeOk = !tokStartIsWord || start === 0 || !isWordCp(text.charCodeAt(start - 1));
  const afterOk = !tokEndIsWord || end === text.length || !isWordCp(text.charCodeAt(end));
  return beforeOk && afterOk;
}

export const exfilMultipliersDetector: DetectorFn = (ctx: DetectorContext): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.exfil_phrases) return [];

  const text = ctx.pp.normalized;
  const map = ctx.pp.normalizedToOriginalByte;
  const originalByteLen = ctx.pp.originalByteLength;

  const hits: ScanHit[] = [];

  for (const tok of PHRASES) {
    let from = 0;
    while (from <= text.length - tok.length) {
      const idx = text.indexOf(tok, from);
      if (idx === -1) break;
      const end = idx + tok.length;
      from = end;
      if (!bounded(text, idx, end, tok)) continue;

      const byteStart = map[idx] ?? 0;
      const byteEnd = end < map.length ? map[end] : (map[map.length - 1] ?? originalByteLen);
      const prefix4 = tok.slice(0, 4);
      // weight=0 -- multiplier marker only; composite-scoring.ts is the SOLE
      // consumer of subCategory==='multiplier'.
      hits.push({
        category: 'exfil_phrase',
        subCategory: 'multiplier',
        weight: 0,
        evidence: { byteStart, byteEnd, prefix4 },
        matchedIn: ctx.matchedIn,
      });
    }
  }

  return hits;
};

registerDetector('exfil_phrase', exfilMultipliersDetector, false);
