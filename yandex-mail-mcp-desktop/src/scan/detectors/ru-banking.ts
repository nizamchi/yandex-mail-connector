// detectors/ru-banking.ts -- category 2.2 (RU banking identifiers / банковская тайна).
//
// CONTEXT decisions enforced:
//   D5: structural-pass detector.
//   D8: ScanHit.evidence.byteStart/byteEnd index into ORIGINAL bytes via map.
//   D9-D11: weight from ctx.policy.weights.govt_id (default 60). Half-weight
//           for shape-only matches.
//   D21: detector receives policy via DetectorContext.
//   D27: ScanHit.category === 'ru_banking' singular.
//
// Plan 02-02 L6: all regex anchored at \b. No nested unbounded quantifiers.
// Plan 02-02 L9 (Patch 14 / W-2.2): ИНН-12 vs расчётный счёт 20-digit collision
//   handled by scanning ИНН-12 FIRST and tracking emitted spans; remaining
//   unmatched 20-digit spans get scanned as settlement accounts. No overlap.
//
// Pure function over DetectorContext.

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { emitRedactedMatch } from '../../outbound-scan.js';

// ИНН: 10 or 12 digits at \b boundary.
const INN_CANDIDATE = /\b(\d{10}|\d{12})\b/g;
// БИК: 9 digits starting with 04 (RU Central Bank prefix).
const BIK_RE = /\b04\d{7}\b/g;
// ОГРН: 13 digits; ОГРНИП: 15 digits.
const OGRN_CANDIDATE = /\b(\d{13}|\d{15})\b/g;
// КПП: 9 chars NNNN(NN|AA)NNN -- enforced via Latin OR Cyrillic uppercase.
// W-2.4 grep concern: anchored, no nested quantifiers.
const KPP_RE = /\b\d{4}[A-ZА-Я0-9]{2}\d{3}\b/gu;
// IBAN: country code + 2 check digits + BBAN, up to 30 alnum.
const IBAN_RE = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g;
// BIC/SWIFT: 4 letters bank + 2 letters country + 2 alnum + optional 3 alnum.
const BIC_RE = /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g;
// Settlement account: exactly 20 digits.
const ACCT20_RE = /\b\d{20}\b/g;

// ИНН-10 mod-11 checksum.
// Weights: [2,4,10,3,5,9,4,6,8]. Check digit = (sum % 11) % 10.
export function innChecksumValid(d: string): boolean {
  if (d.length === 10) {
    const w = [2, 4, 10, 3, 5, 9, 4, 6, 8];
    let s = 0;
    for (let i = 0; i < 9; i++) s += (d.charCodeAt(i) - 48) * w[i];
    return (s % 11) % 10 === d.charCodeAt(9) - 48;
  }
  if (d.length === 12) {
    // Pass 1 -> digit 11 (index 10): weights [7,2,4,10,3,5,9,4,6,8] over first 10 digits.
    const w1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
    // Pass 2 -> digit 12 (index 11): weights [3,7,2,4,10,3,5,9,4,6,8] over first 11 digits.
    const w2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
    let s1 = 0;
    for (let i = 0; i < 10; i++) s1 += (d.charCodeAt(i) - 48) * w1[i];
    if ((s1 % 11) % 10 !== d.charCodeAt(10) - 48) return false;
    let s2 = 0;
    for (let i = 0; i < 11; i++) s2 += (d.charCodeAt(i) - 48) * w2[i];
    return (s2 % 11) % 10 === d.charCodeAt(11) - 48;
  }
  return false;
}

// ОГРН / ОГРНИП mod-11-mod-10 checksum: leading n-1 digits' numeric value mod 11 then mod 10.
// For 13-digit ОГРН: first 12 digits' numeric value % 11, then % 10, = digit 13.
// For 15-digit ОГРНИП: first 14 digits' numeric value % 13, then % 10, = digit 15.
function ogrnChecksumValid(d: string): boolean {
  if (d.length === 13) {
    const body = d.slice(0, 12);
    // 12-digit decimal -> bigint safe; do mod arithmetic incrementally.
    let m = 0n;
    for (let i = 0; i < 12; i++) m = (m * 10n + BigInt(d.charCodeAt(i) - 48)) % 11n;
    const cs = Number(m) % 10;
    return cs === d.charCodeAt(12) - 48;
  }
  if (d.length === 15) {
    let m = 0n;
    for (let i = 0; i < 14; i++) m = (m * 10n + BigInt(d.charCodeAt(i) - 48)) % 13n;
    const cs = Number(m) % 10;
    return cs === d.charCodeAt(14) - 48;
  }
  return false;
}

// IBAN mod-97 (ISO 13616). Move first 4 chars to end, replace letters with
// numeric A=10..Z=35, parse digit-by-digit modulo 97; valid iff remainder = 1.
export function ibanMod97Valid(iban: string): boolean {
  const s = iban.toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$/.test(s)) return false;
  if (s.length < 4) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let m = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const c = rearranged.charCodeAt(i);
    let val: number;
    if (c >= 48 && c <= 57) val = c - 48;
    else if (c >= 65 && c <= 90) val = c - 55;  // A=10
    else return false;
    if (val >= 10) {
      m = (m * 100 + val) % 97;
    } else {
      m = (m * 10 + val) % 97;
    }
  }
  return m === 1;
}

// СНИЛС has its own detector (govt-ids.ts). We do not duplicate it here.
// snilsChecksumValid is exported from govt-ids.ts.
// Stub re-export to satisfy plan artifact contract: re-imported from govt-ids
// at module-load time would create a circular dep. We instead duplicate the
// formula here (it is a 5-line function) to keep this module self-contained.
export function snilsChecksumValid(d: string): boolean {
  if (d.length !== 11) return false;
  let s = 0;
  for (let i = 0; i < 9; i++) s += (d.charCodeAt(i) - 48) * (9 - i);
  let cs: number;
  if (s < 100) cs = s;
  else if (s === 100 || s === 101) cs = 0;
  else cs = s % 101;
  if (cs === 100) cs = 0;
  return cs === parseInt(d.slice(9, 11), 10);
}

// Helper: translate normalized [start, end) to ORIGINAL byte offsets.
function toOriginalBytes(
  start: number,
  end: number,
  map: Int32Array,
  originalByteLen: number,
): { byteStart: number; byteEnd: number } {
  const byteStart = map[start] ?? 0;
  const byteEnd = end < map.length ? map[end] : (map[map.length - 1] ?? originalByteLen);
  return { byteStart, byteEnd };
}

interface MatchedSpan {
  normStart: number;
  normEnd: number;
}

function spansOverlap(a: MatchedSpan, b: { normStart: number; normEnd: number }): boolean {
  return a.normStart < b.normEnd && b.normStart < a.normEnd;
}

export const detectRuBanking: DetectorFn = (ctx: DetectorContext): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.ru_banking) return [];

  const baseWeight = policy.weights.govt_id;
  const shapeOnlyWeight = Math.floor(baseWeight / 2);

  const text = ctx.pp.normalizedCaseSensitive;  // need uppercase for IBAN/BIC
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
    const { byteStart, byteEnd } = toOriginalBytes(normStart, normEnd, map, originalByteLen);
    emitRedactedMatch('ru_banking', subCategory, byteStart, byteEnd, prefix4);
    hits.push({
      category: 'ru_banking',
      subCategory,
      weight,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
    emittedSpans.push({ normStart, normEnd });
  }

  // Pass A: ИНН (10 or 12 digits with mod-11 checksum). ИНН-12 wins first per L9.
  // Iterate twice: first 12-digit candidates, then 10-digit candidates that
  // do not overlap with ИНН-12 hits.
  // We do this with a single regex pass on INN_CANDIDATE since it matches both
  // lengths, but route 12-digit results to the higher-priority bucket.
  INN_CANDIDATE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = INN_CANDIDATE.exec(text)) !== null) {
    const digits = m[0];
    const start = m.index;
    const end = start + digits.length;
    if (!innChecksumValid(digits)) continue;
    const subCategory = digits.length === 12 ? 'inn12' : 'inn10';
    emit(subCategory, baseWeight, start, end, digits.slice(0, 4));
  }

  // Pass B: БИК (9 digits starting 04).
  BIK_RE.lastIndex = 0;
  while ((m = BIK_RE.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    if (emittedSpans.some(s => spansOverlap(s, { normStart: start, normEnd: end }))) continue;
    // No checksum on БИК; shape-only weight per plan.
    emit('bik', shapeOnlyWeight, start, end, matchStr.slice(0, 4));
  }

  // Pass C: ОГРН / ОГРНИП (13 or 15 digits with mod-11/13 checksum).
  OGRN_CANDIDATE.lastIndex = 0;
  while ((m = OGRN_CANDIDATE.exec(text)) !== null) {
    const digits = m[0];
    const start = m.index;
    const end = start + digits.length;
    if (emittedSpans.some(s => spansOverlap(s, { normStart: start, normEnd: end }))) continue;
    if (!ogrnChecksumValid(digits)) continue;
    const subCategory = digits.length === 13 ? 'ogrn' : 'ogrnip';
    emit(subCategory, baseWeight, start, end, digits.slice(0, 4));
  }

  // Pass D: КПП (9 chars, shape only).
  KPP_RE.lastIndex = 0;
  while ((m = KPP_RE.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    if (emittedSpans.some(s => spansOverlap(s, { normStart: start, normEnd: end }))) continue;
    emit('kpp', shapeOnlyWeight, start, end, matchStr.slice(0, 4));
  }

  // Pass E: IBAN (mod-97 validated).
  IBAN_RE.lastIndex = 0;
  while ((m = IBAN_RE.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    if (emittedSpans.some(s => spansOverlap(s, { normStart: start, normEnd: end }))) continue;
    if (!ibanMod97Valid(matchStr)) continue;
    emit('iban', baseWeight, start, end, matchStr.slice(0, 4));
  }

  // Pass F: BIC/SWIFT shape only (4+2+2[+3] letters/digits).
  BIC_RE.lastIndex = 0;
  while ((m = BIC_RE.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    if (emittedSpans.some(s => spansOverlap(s, { normStart: start, normEnd: end }))) continue;
    emit('bic', shapeOnlyWeight, start, end, matchStr.slice(0, 4));
  }

  // Pass G: расчётный счёт (20-digit settlement account). Per L9, this runs
  // LAST; any 20-digit span already overlapping an emitted INN/OGRN hit is
  // skipped to honour the no-overlap rule. (In practice ИНН-12 is only 12
  // digits so a 20-digit span cannot fully contain an ИНН-12 match -- they
  // are distinct lengths -- but partial overlaps could occur near boundaries
  // of digit clusters. The check is defensive and aligns with plan L9.)
  ACCT20_RE.lastIndex = 0;
  while ((m = ACCT20_RE.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    if (emittedSpans.some(s => spansOverlap(s, { normStart: start, normEnd: end }))) continue;
    emit('settlement_account', shapeOnlyWeight, start, end, matchStr.slice(0, 4));
  }

  return hits;
};
