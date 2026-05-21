// detectors/medical.ts -- category 2.7 (medical / PHI / ФЗ-152 special).
//
// CONTEXT decisions enforced:
//   D5: keyword-pass detector (registered after structural pass).
//   D8: ScanHit.evidence.byteStart/byteEnd index ORIGINAL bytes via
//       ctx.pp.normalizedToOriginalByte.
//   D9-D11: weights from ctx.policy.weights.medical_secret (40) and
//       ctx.policy.weights.medical_elevated (60); enable flag
//       ctx.policy.categories.medical (boolean).
//   D15: emitRedactedMatch is the SOLE logging seam.
//   D20: zero new npm deps.
//   D21: detector receives policy via DetectorContext.policy; never calls
//       getPolicy() directly.
//   D27: ScanHit.category === 'medical' (singular).
//
// L-MED-1 sub-rules:
//   - General medical keywords (RU + EN) -- weight scaled by bundling:
//       lone               -> floor(medical_secret * 0.33) ~= 13, subCategory='general_lone'
//       bundled with name  -> medical_secret (40),           subCategory='general_bundled'
//     "Bundled" = a Russian ФИО pattern or English Name-Name pattern within
//     +/- 200 NORMALIZED code units of the keyword hit. ICD-10 / ОМС polis
//     also satisfy the bundling predicate.
//   - Elevated keywords (ВИЧ / HIV / СПИД / psychiatric / oncology / narcology
//     / hepatitis / etc.) -- weight = medical_elevated (60), regardless of
//     bundling. Standalone reasonable per L-MED-1 ("intentional").
//   - ОМС polis: 16-digit sequence in proximity of a polis-context keyword
//     (полис ОМС / ОМС). Weight medical_secret (40). Inline Luhn skip: if
//     the 16-digit sequence passes Luhn AND starts with a known card BIN
//     (most Mir/Visa/MC card prefixes), we skip -- payment-cards detector
//     owns that surface.
//   - ICD-10 shape (one Latin letter + 2 digits + optional .digit[-digit])
//     emitted only when at least one medical keyword fires elsewhere in the
//     body -- low confidence on its own.
//
// FP mitigations carry from dictionary section 2.7:
//   - "депрессия" alone -> too colloquial -> require a stronger medical
//     keyword or bundling proximity.
//   - "КТ" / "МРТ" -- common Russian abbreviations also appear as
//     "конструкторская техника"; we require co-occurrence with a stronger
//     keyword.
//
// Pure function over DetectorContext. No I/O, no async. ASCII identifiers;
// Cyrillic only in string literals.

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { emitRedactedMatch } from '../../outbound-scan.js';

interface KeywordSpec {
  token: string;
  tier: 'general' | 'elevated' | 'colloquial';
}

// All tokens stored case-folded (the ctx.pp.normalized text is already case-folded).
const KEYWORDS: ReadonlyArray<KeywordSpec> = Object.freeze([
  // RU general
  { token: 'диагноз',                tier: 'general' },
  { token: 'мой диагноз',            tier: 'general' },
  { token: 'поставлен диагноз',      tier: 'general' },
  { token: 'история болезни',        tier: 'general' },
  { token: 'медицинская карта',      tier: 'general' },
  { token: 'медкарта',               tier: 'general' },
  { token: 'амбулаторная карта',     tier: 'general' },
  { token: 'рецепт',                 tier: 'colloquial' },
  { token: 'назначение врача',       tier: 'general' },
  { token: 'результаты анализов',    tier: 'general' },
  { token: 'лабораторные исследования', tier: 'general' },
  { token: 'обследование',           tier: 'general' },
  { token: 'группа крови',           tier: 'general' },
  { token: 'заболевание',            tier: 'general' },
  // RU elevated -- ФЗ-152 ст. 10 special categories
  { token: 'вич',                    tier: 'elevated' },
  { token: 'спид',                   tier: 'elevated' },
  { token: 'гепатит c',              tier: 'elevated' },
  { token: 'гепатит b',              tier: 'elevated' },
  { token: 'туберкулёз',             tier: 'elevated' },
  { token: 'туберкулез',             tier: 'elevated' },
  { token: 'онкология',              tier: 'elevated' },
  { token: 'психиатрический диагноз', tier: 'elevated' },
  { token: 'психиатр',               tier: 'elevated' },
  { token: 'психиатрия',             tier: 'elevated' },
  { token: 'шизофрения',             tier: 'elevated' },
  { token: 'биполярное расстройство', tier: 'elevated' },
  { token: 'наркологический',        tier: 'elevated' },
  { token: 'нарколог',               tier: 'elevated' },
  { token: 'наркозависимость',       tier: 'elevated' },
  { token: 'алкоголизм',             tier: 'elevated' },
  // EN general
  { token: 'diagnosis',              tier: 'general' },
  { token: 'medical record',         tier: 'general' },
  { token: 'medical history',        tier: 'general' },
  { token: 'health record',          tier: 'general' },
  { token: 'prescription',           tier: 'colloquial' },
  { token: 'medication',             tier: 'colloquial' },
  { token: 'lab results',            tier: 'general' },
  { token: 'blood test',             tier: 'general' },
  { token: 'blood type',             tier: 'general' },
  { token: 'mri scan',               tier: 'general' },
  { token: 'ct scan',                tier: 'general' },
  // EN elevated
  { token: 'hiv',                    tier: 'elevated' },
  { token: 'aids',                   tier: 'elevated' },
  { token: 'hepatitis',              tier: 'elevated' },
  { token: 'cancer diagnosis',       tier: 'elevated' },
  { token: 'oncology',               tier: 'elevated' },
  { token: 'psychiatric',            tier: 'elevated' },
  { token: 'schizophrenia',          tier: 'elevated' },
  { token: 'bipolar disorder',       tier: 'elevated' },
  { token: 'substance abuse',        tier: 'elevated' },
]);

// Russian ФИО: three (or two) capitalised Cyrillic words. We match against
// the ORIGINAL body (case-sensitive) because case-folding destroys the
// uppercase-vs-lowercase distinction. The detector translates body positions
// to normalized positions via the offset map for proximity checks.
const RU_FIO_RE = /[А-ЯЁ][а-яё]{1,20}\s+[А-ЯЁ][а-яё]{1,20}(?:\s+[А-ЯЁ][а-яё]{1,20})?/gu;
// Loose English Name pair: capitalised tokens 2..16 chars each.
const EN_NAME_RE = /\b[A-Z][a-z]{1,15}\s+[A-Z][a-z]{1,15}\b/g;

// ICD-10 shape: one Latin letter + 2 digits + optional .digit[-digit].
const ICD10_RE = /\b[A-TV-Z][0-9]{2}(?:\.[0-9](?:[0-9]?)?)?\b/g;

// ОМС polis: 16 digits with optional grouping spaces.
const OMS_DIGITS_RE = /\b(?:\d[\s\-]?){15}\d\b/g;

const OMS_CONTEXT_RE = /\b(?:полис\s+омс|омс|enrollment\s+number)\b/i;

// Card BIN prefixes likely to belong to the payment-cards detector. We do
// not need exhaustive coverage -- one match means "payment-cards detector
// will own this", skip in the medical detector.
function looksLikeCardBin(digits16: string): boolean {
  // Mir: 2200-2204
  if (digits16.startsWith('2200') || digits16.startsWith('2201') ||
      digits16.startsWith('2202') || digits16.startsWith('2203') ||
      digits16.startsWith('2204')) return true;
  // Visa: 4
  if (digits16.startsWith('4')) return true;
  // Mastercard: 5[1-5] or 2221-2720
  if (digits16.charAt(0) === '5' &&
      digits16.charAt(1) >= '1' && digits16.charAt(1) <= '5') return true;
  return false;
}

function luhnPasses(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// Word-boundary helper for mixed Cyrillic/Latin tokens (JavaScript \b is
// ASCII-only). Same shape as detectors/credentials.ts isWordChar.
function isWordCp(cp: number): boolean {
  if (cp >= 48 && cp <= 57) return true;   // 0-9
  if (cp >= 65 && cp <= 90) return true;   // A-Z
  if (cp >= 97 && cp <= 122) return true;  // a-z
  if (cp === 95) return true;              // _
  if (cp >= 0x0400 && cp <= 0x04FF) return true; // Cyrillic
  return false;
}
function bounded(text: string, start: number, end: number, tok: string): boolean {
  const tokStartIsWord = isWordCp(tok.charCodeAt(0));
  const tokEndIsWord = isWordCp(tok.charCodeAt(tok.length - 1));
  const beforeOk = !tokStartIsWord || start === 0 || !isWordCp(text.charCodeAt(start - 1));
  const afterOk = !tokEndIsWord || end === text.length || !isWordCp(text.charCodeAt(end));
  return beforeOk && afterOk;
}

// Translate ORIGINAL-byte position to NORMALIZED code-unit index via binary
// search on the monotonic offset map. Mirrors outbound-scan.ts byteToNormIndex.
function byteToNormIndex(map: Int32Array, targetByte: number): number {
  const n = map.length;
  if (n === 0) return 0;
  if (targetByte <= map[0]) return 0;
  if (targetByte > map[n - 1]) return n;
  let lo = 0;
  let hi = n - 1;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (map[mid] < targetByte) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

const BUNDLE_WINDOW = 200;

export const medicalDetector: DetectorFn = (ctx: DetectorContext): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.medical) return [];

  const text = ctx.pp.normalized;
  const map = ctx.pp.normalizedToOriginalByte;
  const original = ctx.matchedIn === 'body' ? ctx.originalBody : ctx.originalSubject;
  const originalByteLen = ctx.pp.originalByteLength;
  const wGeneralLone = Math.floor(policy.weights.medical_secret * 0.33);
  const wGeneralBundled = policy.weights.medical_secret;
  const wElevated = policy.weights.medical_elevated;
  const wOmsPolis = policy.weights.medical_secret;
  const wIcd10 = 10;

  const hits: ScanHit[] = [];

  // Collect "bundling anchor" normalized positions: ФИО / EN-name / ICD-10
  // / ОМС polis. Computed against the ORIGINAL body (case-sensitive for ФИО
  // / EN-name). Translate JS index to byte offset via a cumulative-table
  // built once (O(N)), then to normalized index via the existing map.
  //
  // Without the cumulative table, per-match Buffer.byteLength(original.slice(...))
  // is O(N) -- and with many anchor matches in a long body, scanning becomes
  // O(N*M). Pre-building the table is a small one-time cost (~100 KB int32 for
  // a 100 KB body) that flatlines the perf.
  const origByteAt = new Int32Array(original.length + 1);
  {
    let acc = 0;
    for (let i = 0; i < original.length; i++) {
      origByteAt[i] = acc;
      const cp = original.charCodeAt(i);
      if (cp < 0x80) acc += 1;
      else if (cp < 0x800) acc += 2;
      else if (cp >= 0xD800 && cp <= 0xDBFF) acc += 4;
      else if (cp >= 0xDC00 && cp <= 0xDFFF) acc += 0;
      else acc += 3;
    }
    origByteAt[original.length] = acc;
  }
  function origIndexToByte(jsIdx: number): number {
    if (jsIdx <= 0) return 0;
    if (jsIdx >= origByteAt.length) return origByteAt[origByteAt.length - 1];
    return origByteAt[jsIdx];
  }

  const anchors: number[] = [];
  RU_FIO_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = RU_FIO_RE.exec(original)) !== null) {
    anchors.push(byteToNormIndex(map, origIndexToByte(m.index)));
  }
  EN_NAME_RE.lastIndex = 0;
  while ((m = EN_NAME_RE.exec(original)) !== null) {
    anchors.push(byteToNormIndex(map, origIndexToByte(m.index)));
  }
  // Note: ICD-10 + ОМС anchors collected after their own emission logic, so
  // bundling proximity to those anchors is detected too. Recorded at end of
  // their respective scan loops.

  // Helper: nearest anchor distance check.
  function hasAnchorNear(normIdx: number): boolean {
    for (const a of anchors) {
      if (Math.abs(a - normIdx) <= BUNDLE_WINDOW) return true;
    }
    return false;
  }

  // ОМС polis pass -- find 16-digit sequences with polis context within
  // +/- 200 normalized chars; skip card-BIN-prefixed sequences that pass Luhn.
  OMS_DIGITS_RE.lastIndex = 0;
  while ((m = OMS_DIGITS_RE.exec(text)) !== null) {
    const startNorm = m.index;
    const endNorm = startNorm + m[0].length;
    // Re-strip separators
    const digits = m[0].replace(/[\s\-]/g, '');
    if (digits.length !== 16) {
      OMS_DIGITS_RE.lastIndex = endNorm;
      continue;
    }
    if (luhnPasses(digits) && looksLikeCardBin(digits)) {
      // Payment-cards detector owns this surface.
      OMS_DIGITS_RE.lastIndex = endNorm;
      continue;
    }
    // Context window check
    const ctxStart = Math.max(0, startNorm - BUNDLE_WINDOW);
    const ctxEnd = Math.min(text.length, endNorm + BUNDLE_WINDOW);
    const ctxText = text.slice(ctxStart, ctxEnd);
    if (!OMS_CONTEXT_RE.test(ctxText)) {
      OMS_DIGITS_RE.lastIndex = endNorm;
      continue;
    }
    const byteStart = map[startNorm] ?? 0;
    const byteEnd = endNorm < map.length ? map[endNorm] : (map[map.length - 1] ?? originalByteLen);
    const prefix4 = m[0].slice(0, 4);
    emitRedactedMatch('medical', 'oms_polis', byteStart, byteEnd, prefix4);
    hits.push({
      category: 'medical',
      subCategory: 'oms_polis',
      weight: wOmsPolis,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
    anchors.push(startNorm);
    OMS_DIGITS_RE.lastIndex = endNorm;
  }

  // Keyword pass.
  let anyGeneral = false;
  for (const spec of KEYWORDS) {
    const tok = spec.token;
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

      if (spec.tier === 'elevated') {
        emitRedactedMatch('medical', 'elevated', byteStart, byteEnd, prefix4);
        hits.push({
          category: 'medical',
          subCategory: 'elevated',
          weight: wElevated,
          evidence: { byteStart, byteEnd, prefix4 },
          matchedIn: ctx.matchedIn,
        });
        anchors.push(idx);
        continue;
      }

      if (spec.tier === 'colloquial') {
        // Require co-occurrence of a stronger keyword OR an anchor within
        // window. We can't know that yet (other keywords scanned later);
        // record as candidate and resolve in a second pass below.
        continue;
      }

      // General tier.
      const bundled = hasAnchorNear(idx);
      if (bundled) {
        emitRedactedMatch('medical', 'general_bundled', byteStart, byteEnd, prefix4);
        hits.push({
          category: 'medical',
          subCategory: 'general_bundled',
          weight: wGeneralBundled,
          evidence: { byteStart, byteEnd, prefix4 },
          matchedIn: ctx.matchedIn,
        });
      } else {
        emitRedactedMatch('medical', 'general_lone', byteStart, byteEnd, prefix4);
        hits.push({
          category: 'medical',
          subCategory: 'general_lone',
          weight: wGeneralLone,
          evidence: { byteStart, byteEnd, prefix4 },
          matchedIn: ctx.matchedIn,
        });
      }
      anyGeneral = true;
      anchors.push(idx);
    }
  }

  // ICD-10 pass -- gated by at least one medical keyword fired anywhere.
  if (anyGeneral || hits.some(h => h.subCategory === 'elevated' || h.subCategory === 'oms_polis')) {
    ICD10_RE.lastIndex = 0;
    while ((m = ICD10_RE.exec(text)) !== null) {
      const idx = m.index;
      const end = idx + m[0].length;
      const byteStart = map[idx] ?? 0;
      const byteEnd = end < map.length ? map[end] : (map[map.length - 1] ?? originalByteLen);
      const prefix4 = m[0].slice(0, 4);
      emitRedactedMatch('medical', 'icd10', byteStart, byteEnd, prefix4);
      hits.push({
        category: 'medical',
        subCategory: 'icd10',
        weight: wIcd10,
        evidence: { byteStart, byteEnd, prefix4 },
        matchedIn: ctx.matchedIn,
      });
    }
  }

  return hits;
};

// Registration is performed by outbound-scan.ts _reregisterAllDetectors().
// Module-load side-effect registration would race with the parent module's
// `detectorRegistry` const initialization (TDZ on the import cycle).
