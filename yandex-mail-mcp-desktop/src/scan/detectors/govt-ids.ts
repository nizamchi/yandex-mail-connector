// detectors/govt-ids.ts -- category 2.3 (government IDs: RU passport, СНИЛС, US SSN, ВУ).
//
// CONTEXT decisions enforced:
//   D5: structural-pass detector.
//   D8: ScanHit.evidence.byteStart/byteEnd index into ORIGINAL bytes via map.
//   D9-D11: weight from ctx.policy.weights.govt_id (default 60).
//   D21: detector receives policy via DetectorContext.
//   D27: ScanHit.category === 'govt_id' singular.
//
// Plan 02-02 L6: all regex anchored at \b. No nested unbounded quantifiers.
//
// US SSN OWASP carve-outs (dictionary section 2.3):
//   AAA: reject 000, 666, 9xx (900-999)
//   GG (group): reject 00
//   SSSS (serial): reject 0000
//
// СНИЛС mod-101 checksum (dictionary section 2.3 formula):
//   sum = sum_i(d[i] * (9 - i)) for i in 0..8
//   if sum < 100: cs = sum
//   else if sum == 100 || sum == 101: cs = 0
//   else cs = sum % 101; if cs == 100: cs = 0

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { emitRedactedMatch } from '../../outbound-scan.js';

// Russian internal passport: 4-digit series + 6-digit number with optional space/hyphen.
// (?:[ -]?) avoids backtracking; total digits = 10 with optional separators.
const RU_PASSPORT_RE = /\b\d{4}[ -]?\d{6}\b/g;

// СНИЛС: 11 digits with optional XXX-XXX-XXX YY formatting.
const SNILS_RE = /\b\d{3}-?\d{3}-?\d{3}[ -]?\d{2}\b/g;

// US SSN: NNN-NN-NNNN strict format (carve-outs applied post-match for clarity).
const US_SSN_RE = /\b(\d{3})-(\d{2})-(\d{4})\b/g;

// Russian driver's licence (ВУ): 2 digits + 2 letters (Latin OR Cyrillic) + 6 digits
// OR 2+2+6 all digits; tolerant of one space/hyphen between groups.
const RU_DL_RE = /\b\d{2}[ -]?(?:[A-ZА-Я]{2}|\d{2})[ -]?\d{6}\b/gu;

// СНИЛС checksum -- canonical mod-101 formula (dictionary section 2.3).
function snilsChecksumValid(d: string): boolean {
  // d is exactly 11 digits with separators removed.
  if (d.length !== 11) return false;
  let s = 0;
  for (let i = 0; i < 9; i++) s += (d.charCodeAt(i) - 48) * (9 - i);
  let cs: number;
  if (s < 100) cs = s;
  else if (s === 100 || s === 101) cs = 0;
  else cs = s % 101;
  if (cs === 100) cs = 0;
  const last2 = parseInt(d.slice(9, 11), 10);
  return cs === last2;
}

// US SSN OWASP carve-outs.
function ssnValid(aaa: string, gg: string, ssss: string): boolean {
  if (aaa === '000' || aaa === '666') return false;
  if (aaa.charCodeAt(0) === 57) return false;  // 9xx prefix
  if (gg === '00') return false;
  if (ssss === '0000') return false;
  return true;
}

interface MatchedSpan {
  normStart: number;
  normEnd: number;
}

function overlapsAny(spans: MatchedSpan[], start: number, end: number): boolean {
  for (const s of spans) {
    if (s.normStart < end && start < s.normEnd) return true;
  }
  return false;
}

export const detectGovtIds: DetectorFn = (ctx: DetectorContext): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.govt_ids) return [];

  const baseWeight = policy.weights.govt_id;
  const lowerWeight = Math.floor(baseWeight * 2 / 3);  // ~40 by default

  const text = ctx.pp.normalizedCaseSensitive;
  const map = ctx.pp.normalizedToOriginalByte;
  const originalByteLen = ctx.pp.originalByteLength;
  const hits: ScanHit[] = [];
  const emittedSpans: MatchedSpan[] = [];

  function emit(
    subCategory: string,
    weight: number,
    normStart: number,
    normEnd: number,
    prefix4: string,
  ): void {
    const byteStart = map[normStart] ?? 0;
    const byteEnd = normEnd < map.length
      ? map[normEnd]
      : (map[map.length - 1] ?? originalByteLen);
    emitRedactedMatch('govt_id', subCategory, byteStart, byteEnd, prefix4);
    hits.push({
      category: 'govt_id',
      subCategory,
      weight,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
    emittedSpans.push({ normStart, normEnd });
  }

  // Pass A: СНИЛС first (checksum-validated; most-specific shape).
  SNILS_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SNILS_RE.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    const digits = matchStr.replace(/[\s\-]/g, '');
    if (!snilsChecksumValid(digits)) continue;
    emit('snils', baseWeight, start, end, matchStr.slice(0, 4));
  }

  // Pass B: US SSN with OWASP carve-outs.
  US_SSN_RE.lastIndex = 0;
  while ((m = US_SSN_RE.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    if (overlapsAny(emittedSpans, start, end)) continue;
    if (!ssnValid(m[1], m[2], m[3])) continue;
    emit('us_ssn', baseWeight, start, end, matchStr.slice(0, 4));
  }

  // Pass C: RU passport (shape only).
  RU_PASSPORT_RE.lastIndex = 0;
  while ((m = RU_PASSPORT_RE.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    if (overlapsAny(emittedSpans, start, end)) continue;
    // Avoid collision with СНИЛС (already emitted) -- overlap check handles it.
    emit('ru_passport', baseWeight, start, end, matchStr.slice(0, 4));
  }

  // Pass D: ВУ (Russian driver's licence; shape only -- lower weight per plan).
  RU_DL_RE.lastIndex = 0;
  while ((m = RU_DL_RE.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    if (overlapsAny(emittedSpans, start, end)) continue;
    emit('ru_drivers_licence', lowerWeight, start, end, matchStr.slice(0, 4));
  }

  return hits;
};
