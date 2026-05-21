// detectors/payment-cards.ts -- category 2.1 (PCI-DSS PAN) detector.
//
// CONTEXT decisions enforced:
//   D5: structural-pass detector; runs first.
//   D8: ScanHit.evidence.byteStart/byteEnd index into the ORIGINAL input bytes
//       via ctx.pp.normalizedToOriginalByte.
//   D9-D11: weight sourced from ctx.policy.weights.payment_card; never hardcoded.
//   D21: detector receives policy via DetectorContext; never calls getPolicy().
//   D27: ScanHit.category === 'payment_card' (singular).
//
// Plan 02-02 / L4: adjacency-window distance computed in NORMALIZED JS code-unit
//   space (we already operate on ctx.pp.normalized).
// Plan 02-02 / L6: all regex anchored at \b; no unbounded nested quantifiers.
//
// Pure function over DetectorContext. No I/O, no async.

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { emitRedactedMatch } from '../../outbound-scan.js';

// PAN candidate: 13-19 digits, optionally space/hyphen separated. The /g flag
// is mandatory since we call .exec in a loop / .matchAll.
// Anchored at \b to avoid catastrophic backtracking and to skip in-URL session
// IDs (see FP mitigation: URL exclusion handled below).
const PAN_CANDIDATE = /\b(?:\d[ -]?){12,18}\d\b/g;

// Brand classifiers operate AFTER separators are stripped. Order matters for
// scoring (mir wins on RU-context overlap with visa-like 4-prefix collisions).
export const PAN_BRANDS: Readonly<Record<string, RegExp>> = Object.freeze({
  mir:        /^220[0-4]\d{12,15}$/,
  visa:       /^4\d{12}(?:\d{3}){0,2}$/,
  mastercard: /^(?:5[1-5]\d{2}|2(?:2(?:2[1-9]|[3-9]\d)|[3-6]\d{2}|7(?:[01]\d|20)))\d{12}$/,
  amex:       /^3[47]\d{13}$/,
  discover:   /^6(?:011|5\d{2}|4[4-9]\d|22(?:1(?:2[6-9]|[3-9]\d)|[2-8]\d{2}|9(?:[01]\d|2[0-5])))\d{10,13}$/,
  jcb:        /^35(?:2[89]|[3-8]\d)\d{12}$/,
  unionpay:   /^62\d{14,17}$/,
  maestro:    /^(?:5018|5020|5038|5893|6304|6759|6761|6763)\d{8,15}$/,
  diners:     /^3(?:0[0-5]|[68]\d)\d{11}$/,
});

// Companion-window regex (CVV / CVC / security code). RU + EN.
const CVV_CONTEXT = /\b(?:cvv2?|cvc2?|csc|cid|код\s+(?:безопасности|проверки|cvv|cvc))\s*[:=#-]?\s*\d{3,4}\b/giu;

// Expiry context (MM/YY or MM/YYYY near keyword).
const EXPIRY_CONTEXT = /\b(?:exp|expiry|expiration|valid\s+(?:thru|until)|срок\s+действия|действительна\s+до|mm\/(?:yy|yyyy|гг))\b/giu;

// URL exclusion: skip PAN-shaped digits inside http(s):// ... whitespace.
const URL_RE = /https?:\/\/\S+/giu;

// Tracking-number / phone exclusion preceding context (search ~24 chars before).
const TRACKING_LEFT = /(?:track(?:ing)?|awb|номер\s+(?:заказа|отправления|телефона)|телефон)\W{0,4}$/iu;

// Luhn validator -- iterative O(N), reads the canonical algorithm.
export function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function classifyBrand(digits: string): string | null {
  for (const [brand, re] of Object.entries(PAN_BRANDS)) {
    if (re.test(digits)) return brand;
  }
  return null;
}

// Returns true if the match at [start, end) (NORMALIZED-space indices) falls
// inside a URL span. URL spans are computed once per detector invocation.
function isInsideUrl(normalized: string, start: number, end: number, urlSpans: Array<[number, number]>): boolean {
  for (const [a, b] of urlSpans) {
    if (start >= a && end <= b) return true;
  }
  return false;
}

function isTrackingShaped(normalized: string, start: number): boolean {
  const left = normalized.slice(Math.max(0, start - 24), start);
  return TRACKING_LEFT.test(left);
}

// Searches for CVV/expiry companion within +/- 200 NORMALIZED code units
// of [panStart, panEnd). Returns true on any hit.
function hasCardCompanion(normalized: string, panStart: number, panEnd: number): boolean {
  const lo = Math.max(0, panStart - 200);
  const hi = Math.min(normalized.length, panEnd + 200);
  const win = normalized.slice(lo, hi);
  CVV_CONTEXT.lastIndex = 0;
  EXPIRY_CONTEXT.lastIndex = 0;
  return CVV_CONTEXT.test(win) || EXPIRY_CONTEXT.test(win);
}

export const detectPaymentCards: DetectorFn = (ctx: DetectorContext): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.payment_cards) return [];

  const baseWeight = policy.weights.payment_card;
  const noLuhnWeight = Math.floor(baseWeight / 2);
  const adjacencyBump = 10;
  const ceiling = baseWeight + 15;

  const text = ctx.pp.normalized;
  const map = ctx.pp.normalizedToOriginalByte;
  const originalByteLen = ctx.pp.originalByteLength;
  const hits: ScanHit[] = [];

  // Pre-compute URL spans in normalized space (one pass).
  const urlSpans: Array<[number, number]> = [];
  URL_RE.lastIndex = 0;
  let urlM: RegExpExecArray | null;
  while ((urlM = URL_RE.exec(text)) !== null) {
    urlSpans.push([urlM.index, urlM.index + urlM[0].length]);
    if (urlM.index === URL_RE.lastIndex) URL_RE.lastIndex++;
  }

  PAN_CANDIDATE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = PAN_CANDIDATE.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    if (matchStr.length === PAN_CANDIDATE.lastIndex && PAN_CANDIDATE.lastIndex === start) {
      PAN_CANDIDATE.lastIndex++;
    }

    // FP filters.
    if (isInsideUrl(text, start, end, urlSpans)) continue;
    if (isTrackingShaped(text, start)) continue;

    // Strip separators.
    const digits = matchStr.replace(/[ -]/g, '');
    if (digits.length < 13 || digits.length > 19) continue;

    const brand = classifyBrand(digits);
    if (brand === null) {
      // No known brand -- emit at half-weight only if Luhn passes (otherwise
      // it's almost certainly not a PAN -- could be a tracking ID).
      if (!luhnValid(digits)) continue;
      // Fall through with brand='generic'.
    }

    const luhnOK = luhnValid(digits);
    let weight: number;
    let subCategory: string;
    if (luhnOK) {
      weight = baseWeight;
      subCategory = brand ?? 'generic';
    } else {
      if (brand === null) continue;  // brand miss + Luhn miss => drop
      weight = noLuhnWeight;
      subCategory = `${brand}_no_luhn`;
    }

    // Adjacency bump for CVV / expiry within +/- 200 normalized chars.
    if (hasCardCompanion(text, start, end)) {
      weight = Math.min(weight + adjacencyBump, ceiling);
    }

    // Translate normalized indices to ORIGINAL byte offsets (D8).
    const byteStart = map[start] ?? 0;
    const byteEnd = end < map.length ? map[end] : (map[map.length - 1] ?? originalByteLen);

    const prefix4 = matchStr.slice(0, 4);
    emitRedactedMatch('payment_card', subCategory, byteStart, byteEnd, prefix4);

    hits.push({
      category: 'payment_card',
      subCategory,
      weight,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
  }

  return hits;
};
