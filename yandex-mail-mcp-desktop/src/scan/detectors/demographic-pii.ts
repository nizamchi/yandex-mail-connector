// detectors/demographic-pii.ts -- category 2.11 (personal demographic PII;
// ФЗ-152 базовые персональные данные).
//
// Category 2.11 demographic PII signals (RU phone, DOB, personal email) --
// emitted per-signal at weight 10 each. Per Patch 9 (revision 2), CONTEXT
// D14 is satisfied BY CONSTRUCTION: weight 10 + 1.5x per-category
// diminishing-returns cap = 15 < 25. The synthetic Math.min(..., 25) floor
// previously in composite-scoring is dead code; removed in revision 2.
// Per L-WIRING-2, per-signal weight 10 is HARDCODED -- no new policy key.
// Backlog: v2.1.x may expose `policy.weights.demographic_pii_per_signal`
// for operator tuning (Patch 14 / W-3.5).
//
// CONTEXT decisions enforced:
//   D5: keyword/regex-pass detector.
//   D8: byte offsets via Buffer.byteLength on ORIGINAL slices (regexes are
//       run on ORIGINAL because phone/DOB/email shapes are case-insensitive
//       digit/punct patterns that the normalizer preserves -- we use the
//       original to keep offsets exact).
//   D9-D11: weight HARDCODED at 10 per signal (L-PII-1, L-WIRING-2). Enable
//       flag ctx.policy.categories.demographic_pii (boolean).
//   D14: PII floor satisfied by construction (Patch 9). The 1.5x per-category
//       cap (= 15 for weight-10 signals) binds at 15 -- never reaches 25.
//   D15: emitRedactedMatch only.
//   D27: ScanHit.category === 'demographic_pii' (singular).
//
// FP mitigation: emails and phones are inherently part of email business;
// the composite-scoring cap is the discipline that keeps casual signatures
// from blowing up the score.
//
// Pure function over DetectorContext. No I/O. ASCII identifiers.

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { emitRedactedMatch } from '../../outbound-scan.js';

// Russian mobile phone: +7 / 8 prefix + 10 digits with various separators.
const RU_PHONE_RE = /(?:\+7|\b8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b/g;

// DOB-shaped: DD.MM.YYYY or DD/MM/YYYY or DD-MM-YYYY, OR YYYY-MM-DD,
// year clamped 1900..2026 (per L-PII-1; "plausibility" gate).
const DOB_RE = /\b(?:(?:0[1-9]|[12]\d|3[01])[.\-/](?:0[1-9]|1[0-2])[.\-/](?:19\d{2}|20[0-2]\d)|(?:19\d{2}|20[0-2]\d)[.\-/](?:0[1-9]|1[0-2])[.\-/](?:0[1-9]|[12]\d|3[01]))\b/g;

// Personal email (RFC 5322-lite). Loose -- we want signatures and
// "write to me at <addr>" lines.
const PERSONAL_EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;

// Weight hardcoded per L-PII-1 / L-WIRING-2. NO new policy key.
const PII_WEIGHT = 10;

// Plausibility check for DOB: year must be 1900..2026. The regex already
// constrains to these decades, but we also defend against e.g. 2099.
function isPlausibleDobYear(yearStr: string): boolean {
  const y = Number(yearStr);
  return Number.isFinite(y) && y >= 1900 && y <= 2026;
}

function extractDobYear(matched: string): string | null {
  // Match captured as either DD-MM-YYYY or YYYY-MM-DD form.
  const parts = matched.split(/[.\-/]/);
  if (parts.length !== 3) return null;
  // YYYY-MM-DD vs DD-MM-YYYY: the longest 4-digit chunk is the year.
  if (parts[0].length === 4) return parts[0];
  if (parts[2].length === 4) return parts[2];
  return null;
}

export const demographicPiiDetector: DetectorFn = (ctx: DetectorContext): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.demographic_pii) return [];

  const original = ctx.matchedIn === 'body' ? ctx.originalBody : ctx.originalSubject;

  // Cumulative byte-prefix table for the original; avoids O(N) Buffer.byteLength
  // calls per match (would otherwise blow the 50 ms perf budget on hit-heavy
  // 100 KB bodies).
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

  const hits: ScanHit[] = [];
  const emittedSpans: Array<[number, number]> = [];

  function overlaps(start: number, end: number): boolean {
    for (const [s, e] of emittedSpans) {
      if (start < e && end > s) return true;
    }
    return false;
  }

  function emit(subCategory: 'ru_phone' | 'dob' | 'personal_email',
                jsIdx: number, matched: string): void {
    const byteStart = origByteAt[jsIdx];
    const byteEnd = origByteAt[jsIdx + matched.length];
    if (overlaps(byteStart, byteEnd)) return;
    emittedSpans.push([byteStart, byteEnd]);
    const prefix4 = matched.slice(0, 4);
    emitRedactedMatch('demographic_pii', subCategory, byteStart, byteEnd, prefix4);
    hits.push({
      category: 'demographic_pii',
      subCategory,
      weight: PII_WEIGHT,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
  }

  // RU phone.
  RU_PHONE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = RU_PHONE_RE.exec(original)) !== null) {
    emit('ru_phone', m.index, m[0]);
  }

  // DOB with plausibility check.
  DOB_RE.lastIndex = 0;
  while ((m = DOB_RE.exec(original)) !== null) {
    const year = extractDobYear(m[0]);
    if (year === null || !isPlausibleDobYear(year)) continue;
    emit('dob', m.index, m[0]);
  }

  // Personal email.
  PERSONAL_EMAIL_RE.lastIndex = 0;
  while ((m = PERSONAL_EMAIL_RE.exec(original)) !== null) {
    emit('personal_email', m.index, m[0]);
  }

  return hits;
};

// Registration is performed by outbound-scan.ts _reregisterAllDetectors().
