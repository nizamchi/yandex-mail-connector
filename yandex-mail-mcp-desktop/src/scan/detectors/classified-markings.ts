// detectors/classified-markings.ts -- category 2.8 (classified / restricted-
// distribution markings; Russian + global).
//
// CONTEXT decisions enforced:
//   D5: keyword-pass detector.
//   D8: byte offsets via ctx.pp.normalizedToOriginalByte.
//   D9-D11: weights from ctx.policy.weights.classified_marking (default 50);
//       tier modifies (+10 severe / +0 standard / -10 mild).
//   D15: emitRedactedMatch only.
//   D27: ScanHit.category === 'classified_marking' (singular).
//
// L-CLS-1: the DETECTOR emits one ScanHit per matched marking; the
// composite-scoring module collapses cat='classified_marking' to MAX-not-sum
// (NOT diminishing, NOT capped at 1.5x). Multiple markings in the same email
// score as the worst single marking, never the sum.
//
// FP mitigations (dictionary section 2.8):
//   - Uppercase-only patterns for CONFIDENTIAL / SECRET / TOP SECRET / RESTRICTED
//     / NOFORN / FOUO to avoid matching "I have a secret" / "the secret menu".
//   - Russian markings are sufficiently uncommon as casual phrases that
//     case-folded substring matching is safe.
//   - КТ acronym ambiguity (КТ = коммерческая тайна vs КТ = compute tomography)
//     handled by requiring the full phrase "коммерческая тайна" or surrounding
//     "режим КТ" / "гриф КТ" context.
//
// Pure function over DetectorContext.

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { emitRedactedMatch } from '../../outbound-scan.js';

type Tier = 'severe' | 'standard' | 'mild';

interface MarkingSpec {
  // Token matched against. RU tokens are case-folded (matched against
  // ctx.pp.normalized which is case-folded). EN uppercase-only tokens are
  // matched against ctx.originalBody / originalSubject (case-sensitive) so
  // the upper-vs-lower disambiguation survives.
  token: string;
  tier: Tier;
  // 'normalized' -> match against ctx.pp.normalized (case-folded).
  // 'original_upper' -> match uppercase-only against ORIGINAL (preserves case).
  source: 'normalized' | 'original_upper';
  subCategory: string;
}

const MARKINGS: ReadonlyArray<MarkingSpec> = Object.freeze([
  // RU severe (государственная тайна grading)
  { token: 'государственная тайна',          tier: 'severe',   source: 'normalized', subCategory: 'gos_tayna' },
  { token: 'совершенно секретно',            tier: 'severe',   source: 'normalized', subCategory: 'sovsekretno' },
  { token: 'особой важности',                tier: 'severe',   source: 'normalized', subCategory: 'osoboy_vazhnosti' },
  // RU standard
  { token: 'для служебного пользования',     tier: 'standard', source: 'normalized', subCategory: 'dsp_full' },
  { token: 'дсп',                            tier: 'standard', source: 'normalized', subCategory: 'dsp' },
  { token: 'коммерческая тайна',             tier: 'standard', source: 'normalized', subCategory: 'kom_tayna' },
  { token: 'строго конфиденциально',         tier: 'standard', source: 'normalized', subCategory: 'strogo_konf' },
  { token: 'конфиденциальная информация',    tier: 'standard', source: 'normalized', subCategory: 'konf_info' },
  { token: 'не подлежит разглашению',        tier: 'standard', source: 'normalized', subCategory: 'ne_razglashat' },
  { token: 'гриф ограничения доступа',       tier: 'standard', source: 'normalized', subCategory: 'grif' },
  // RU mild
  { token: 'конфиденциально',                tier: 'mild',     source: 'normalized', subCategory: 'konf_short' },
  { token: 'служебная информация ограниченного распространения', tier: 'standard', source: 'normalized', subCategory: 'sluzhebnaya_ogr' },
  // EN severe -- uppercase only to disambiguate from casual prose
  { token: 'TOP SECRET',                     tier: 'severe',   source: 'original_upper', subCategory: 'top_secret' },
  { token: 'TOP-SECRET',                     tier: 'severe',   source: 'original_upper', subCategory: 'top_secret' },
  // EN standard -- uppercase only
  { token: 'CONFIDENTIAL',                   tier: 'standard', source: 'original_upper', subCategory: 'confidential' },
  { token: 'SECRET',                         tier: 'standard', source: 'original_upper', subCategory: 'secret' },
  { token: 'RESTRICTED',                     tier: 'standard', source: 'original_upper', subCategory: 'restricted' },
  { token: 'NOFORN',                         tier: 'standard', source: 'original_upper', subCategory: 'noforn' },
  { token: 'FOUO',                           tier: 'standard', source: 'original_upper', subCategory: 'fouo' },
  // EN normalized phrases -- low FP because they are full multi-word phrases.
  { token: 'strictly confidential',          tier: 'standard', source: 'normalized', subCategory: 'strictly_confidential' },
  { token: 'do not distribute',              tier: 'standard', source: 'normalized', subCategory: 'do_not_distribute' },
  { token: 'do not forward',                 tier: 'standard', source: 'normalized', subCategory: 'do_not_forward' },
  { token: 'do not share',                   tier: 'standard', source: 'normalized', subCategory: 'do_not_share' },
  { token: 'proprietary and confidential',   tier: 'standard', source: 'normalized', subCategory: 'proprietary_confidential' },
  { token: 'privileged and confidential',    tier: 'standard', source: 'normalized', subCategory: 'privileged_confidential' },
  { token: 'attorney-client privilege',      tier: 'standard', source: 'normalized', subCategory: 'attorney_client' },
  { token: 'under nda',                      tier: 'mild',     source: 'normalized', subCategory: 'under_nda' },
  { token: 'non-disclosure agreement',       tier: 'mild',     source: 'normalized', subCategory: 'nda' },
  { token: 'internal use only',              tier: 'mild',     source: 'normalized', subCategory: 'internal_only' },
  { token: 'internal only',                  tier: 'mild',     source: 'normalized', subCategory: 'internal_only' },
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

export const classifiedMarkingsDetector: DetectorFn = (ctx: DetectorContext): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.classified_markings) return [];

  const wStandard = policy.weights.classified_marking;
  const wSevere = wStandard + 10;
  const wMild = Math.max(1, wStandard - 10);

  const text = ctx.pp.normalized;
  const map = ctx.pp.normalizedToOriginalByte;
  const original = ctx.matchedIn === 'body' ? ctx.originalBody : ctx.originalSubject;
  const originalByteLen = ctx.pp.originalByteLength;

  // Cumulative byte-prefix table for original -- avoids O(N) Buffer.byteLength
  // calls per match.
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

  for (const spec of MARKINGS) {
    const tok = spec.token;
    const haystack = spec.source === 'normalized' ? text : original;
    let from = 0;
    while (from <= haystack.length - tok.length) {
      const idx = haystack.indexOf(tok, from);
      if (idx === -1) break;
      const end = idx + tok.length;
      from = end;
      if (!bounded(haystack, idx, end, tok)) continue;

      // For 'original_upper' source we still emit byte offsets via the
      // normalized map: translate the original-string JS index to a byte
      // position via Buffer.byteLength, then snap to the normalized index
      // closest to that byte. This keeps evidence offsets pointing at
      // ORIGINAL bytes per D8.
      let byteStart: number;
      let byteEnd: number;
      if (spec.source === 'normalized') {
        byteStart = map[idx] ?? 0;
        byteEnd = end < map.length ? map[end] : (map[map.length - 1] ?? originalByteLen);
      } else {
        byteStart = origByteAt[idx];
        byteEnd = origByteAt[end];
      }
      const prefix4 = tok.slice(0, 4);
      const weight = spec.tier === 'severe' ? wSevere :
                     spec.tier === 'mild'   ? wMild   : wStandard;
      emitRedactedMatch('classified_marking', spec.subCategory, byteStart, byteEnd, prefix4);
      hits.push({
        category: 'classified_marking',
        subCategory: spec.subCategory,
        weight,
        evidence: { byteStart, byteEnd, prefix4 },
        matchedIn: ctx.matchedIn,
      });
    }
  }

  return hits;
};

// Registration is performed by outbound-scan.ts _reregisterAllDetectors().
