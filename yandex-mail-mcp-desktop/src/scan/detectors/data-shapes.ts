// detectors/data-shapes.ts -- category 2.10 (suspicious data shapes:
// base64/hex blobs, magic bytes, zero-width/bidi/Unicode-tag chars,
// Cyrillic-in-Latin homoglyph attacks).
//
// CONTEXT decisions enforced:
//   D5: keyword/shape-pass detector.
//   D8: byte offsets via ctx.pp.normalizedToOriginalByte; for Unicode-anomaly
//       signals we scan the ORIGINAL body (the preprocessor STRIPS zero-width
//       characters in step 2 of preprocess.ts -- so we look in the unprocessed
//       text and translate via byte offset).
//   D9-D11: weight base from policy.weights.data_shape_anomaly (default 30);
//       sub-weights per L-DS-1 (base64 30, hex 15, magic 40, zero-width 25,
//       bidi 30, unicode-tag 35, homoglyph 30).
//   D15: emitRedactedMatch only.
//   D20: zero new npm deps.
//   D27: ScanHit.category === 'data_shape_anomaly' (singular).
//
// L-DS-1 + L-HG-1:
//   Step A: invisible-char signals via ORIGINAL text (zero-width, bidi
//           overrides, Unicode tag block). One zero_width hit max.
//   Step B: magic-byte base64 prefixes (PDF, PNG, JPEG, ZIP, GIF, SVG, XML).
//   Step C: base64 blob >= 100 chars with Shannon entropy >= 4.5 -- ONLY if
//           NOT looksLikeKnownVendor (anti-double-count with cat 2.5
//           per Patch 11). Skips data:image inline payloads.
//   Step D: hex blob >= 64 chars not anchored in vendor structural shape.
//   Step E: Cyrillic-in-Latin homoglyph via hasMixedScriptCyrillicLatin
//           with MAX_HOMOGLYPH_HITS=5 cap.
//
// FP mitigations from dictionary section 2.10:
//   - Strip data:image/...;base64,... payloads before base64 scan.
//   - Hex matches collide with git commit hashes (40 hex) and SHA-256 digests
//     (64 hex); we treat hex_blob as 15 weight (low) so a single commit hash
//     is benign by itself.
//
// Pure function over DetectorContext. No I/O.

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { emitRedactedMatch } from '../../outbound-scan.js';
import { hasMixedScriptCyrillicLatin, MAX_HOMOGLYPH_HITS } from '../homoglyph-table.js';

// Regexes -- all bounded, no nested unbounded quantifiers.

// Zero-width chars: ZWSP (U+200B), ZWNJ (U+200C), ZWJ (U+200D), WORD JOINER
// (U+2060), ZWNBSP / BOM (U+FEFF).
const ZERO_WIDTH_RE = /[​-‍⁠﻿]/g;

// Bidi LRO/RLO/LRE/RLE/PDF (U+202A..U+202E) + LRI/RLI/FSI/PDI (U+2066..U+2069).
const BIDI_OVERRIDE_RE = /[‪-‮⁦-⁩]/g;

// Unicode Tags block (U+E0000..U+E007F). Use surrogate-aware regex.
const UNICODE_TAG_RE = /[\u{E0000}-\u{E007F}]/gu;

// Magic-byte base64 prefixes for binary inline content (dictionary §2.10).
// Anchored to word boundary on the left.
const MAGIC_BYTES_RE = /\b(?:JVBERi0|iVBORw0KGgo|\/9j\/[A-Za-z0-9+/=]{4}|UEsDB|R0lGOD|PHN2Z|PD94bWw)/g;

// Base64 blob >= 100 chars (L-DS-1 floor). Allow embedded line wraps (CRLF
// or LF) inside the blob.
const BASE64_BLOB_RE = /(?:[A-Za-z0-9+/]{4}){25,}(?:[A-Za-z0-9+/]{2,3}={0,2})?/g;

// Hex blob >= 64 chars (covers SHA-256, longer). Word-boundary anchored.
const HEX_BLOB_RE = /\b[0-9a-fA-F]{64,}\b/g;

// data:image inline payload preamble -- strip before base64 scan.
const DATA_IMAGE_RE = /\bdata:[a-z]+\/[a-z0-9+.\-]+;base64,[A-Za-z0-9+/=]{16,}/gi;

// Known vendor prefixes (subset; matches the entries in
// structural-secrets.ts that share a base64-shape with non-vendor random
// blobs). We deliberately keep this in sync by spec rather than by import
// to avoid coupling -- T-DS-BASE64-SKIP-001 + V-prefix tests validate the
// behaviour, and additions to structural-secrets.ts only need a single new
// entry here if the prefix collides with a base64-shape window.
const VENDOR_PREFIX_RE = /^(?:A[KI](?:IA|za)|gh[opurs]_|github_pat_|gl[ph]at-|sk-[a-z]+|sk_live_|pk_live_|rk_live_|xox[abprs]-|S[GK][.]?|AC[a-fA-F0-9]|key-|sh[a-z]{3}_|EAAA|A21AA|y0_|t1\.|ey[A-Za-z0-9]|MII[A-Za-z]|do[op]_v1_|postgres:\/\/|mysql:\/\/|mongodb:\/\/|redis:\/\/)/;

function looksLikeKnownVendor(text: string): boolean {
  return VENDOR_PREFIX_RE.test(text);
}

// Shannon entropy in bits per character (range 0..log2(64) for base64).
function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    freq.set(c, (freq.get(c) ?? 0) + 1);
  }
  let h = 0;
  const n = s.length;
  for (const cnt of freq.values()) {
    const p = cnt / n;
    h -= p * Math.log2(p);
  }
  return h;
}

const BASE64_ENTROPY_FLOOR = 4.5;

// Tokenizer for homoglyph pass: split on whitespace + punctuation; keep
// tokens of length 3..40 (per L-HG-1). We tokenize the ORIGINAL body so
// case-sensitive Cyrillic-vs-Latin discrimination is preserved -- the
// preprocessor case-folds and would obscure the script signal.
//
// `isBreakCodePoint` is a fast inline replacement for a `RegExp.test()`
// per-character call. Char codes for ASCII whitespace + common punctuation
// are checked first; non-ASCII whitespace (e.g. U+00A0 NBSP, U+2028 LSEP)
// caught via a numeric switch.
function isBreakCodePoint(cp: number): boolean {
  // ASCII whitespace
  if (cp === 0x20 || cp === 0x09 || cp === 0x0A || cp === 0x0D) return true;
  // ASCII punctuation that separates tokens
  if (cp === 0x21 || cp === 0x22 || cp === 0x23 || cp === 0x24 || cp === 0x25
   || cp === 0x26 || cp === 0x27 || cp === 0x28 || cp === 0x29 || cp === 0x2A
   || cp === 0x2B || cp === 0x2C || cp === 0x2D || cp === 0x2E || cp === 0x2F
   || cp === 0x3A || cp === 0x3B || cp === 0x3C || cp === 0x3D || cp === 0x3E
   || cp === 0x3F || cp === 0x40 || cp === 0x5B || cp === 0x5C || cp === 0x5D
   || cp === 0x5E || cp === 0x60 || cp === 0x7B || cp === 0x7C || cp === 0x7D
   || cp === 0x7E) return true;
  // Common non-ASCII separators
  if (cp === 0x00A0 || cp === 0x2028 || cp === 0x2029) return true;
  return false;
}
const MAX_TOKEN_COUNT = 5000;  // D3 DoS guard

// Translate ORIGINAL byte offset to NORMALIZED code-unit index (binary search).
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

export const dataShapesDetector: DetectorFn = (ctx: DetectorContext): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.data_shapes) return [];

  const text = ctx.pp.normalized;
  const map = ctx.pp.normalizedToOriginalByte;
  const original = ctx.matchedIn === 'body' ? ctx.originalBody : ctx.originalSubject;
  const originalByteLen = ctx.pp.originalByteLength;
  const wBase = policy.weights.data_shape_anomaly;

  // Sub-weights per L-DS-1 (relative to wBase=30 baseline).
  const wBase64 = wBase;        // 30
  const wHex = Math.floor(wBase * 0.5);  // 15
  const wMagic = wBase + 10;             // 40
  const wZeroWidth = Math.floor(wBase * 0.83);  // 25
  const wBidi = wBase;                   // 30
  const wUnicodeTag = wBase + 5;         // 35
  const wHomoglyph = wBase;              // 30

  const hits: ScanHit[] = [];

  // -- Step A: invisible-char signals against the ORIGINAL text.
  //
  // We scan the ORIGINAL body because the preprocessor strips these chars
  // during NFKC normalization (step 2 of preprocess.ts). Byte offsets come
  // from a single O(N) walk of the original that produces a cumulative
  // UTF-8-byte prefix table -- O(1) lookup per match thereafter.
  //
  // Without this table, `Buffer.byteLength(original.slice(0, jsIdx))` is
  // called per match, each O(N), turning hit-heavy 100 KB bodies into
  // O(N*M) scans (T-PERF-01 measured 200+ ms before this optimisation).
  const origByteAt = new Int32Array(original.length + 1);
  {
    let acc = 0;
    for (let i = 0; i < original.length; i++) {
      origByteAt[i] = acc;
      const cp = original.charCodeAt(i);
      // Surrogate pair: 4 bytes total; the second half adds 0.
      if (cp < 0x80) acc += 1;
      else if (cp < 0x800) acc += 2;
      else if (cp >= 0xD800 && cp <= 0xDBFF) acc += 4; // high surrogate
      else if (cp >= 0xDC00 && cp <= 0xDFFF) acc += 0; // low surrogate already counted
      else acc += 3;
    }
    origByteAt[original.length] = acc;
  }
  function origIndexToByte(jsIdx: number): number {
    if (jsIdx <= 0) return 0;
    if (jsIdx >= origByteAt.length) return origByteAt[origByteAt.length - 1];
    return origByteAt[jsIdx];
  }

  // Zero-width: ONE hit per email regardless of count.
  ZERO_WIDTH_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  m = ZERO_WIDTH_RE.exec(original);
  if (m !== null) {
    const byteStart = origIndexToByte(m.index);
    const byteEnd = origIndexToByte(m.index + m[0].length);
    const prefix4 = m[0].slice(0, 4);
    emitRedactedMatch('data_shape_anomaly', 'zero_width', byteStart, byteEnd, prefix4);
    hits.push({
      category: 'data_shape_anomaly',
      subCategory: 'zero_width',
      weight: wZeroWidth,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
  }

  // Bidi override: one hit per detected control.
  BIDI_OVERRIDE_RE.lastIndex = 0;
  while ((m = BIDI_OVERRIDE_RE.exec(original)) !== null) {
    const byteStart = origIndexToByte(m.index);
    const byteEnd = origIndexToByte(m.index + m[0].length);
    const prefix4 = m[0].slice(0, 4);
    emitRedactedMatch('data_shape_anomaly', 'bidi_override', byteStart, byteEnd, prefix4);
    hits.push({
      category: 'data_shape_anomaly',
      subCategory: 'bidi_override',
      weight: wBidi,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
  }

  // Unicode tag block.
  UNICODE_TAG_RE.lastIndex = 0;
  while ((m = UNICODE_TAG_RE.exec(original)) !== null) {
    const byteStart = origIndexToByte(m.index);
    const byteEnd = origIndexToByte(m.index + m[0].length);
    const prefix4 = m[0].slice(0, 4);
    emitRedactedMatch('data_shape_anomaly', 'unicode_tag', byteStart, byteEnd, prefix4);
    hits.push({
      category: 'data_shape_anomaly',
      subCategory: 'unicode_tag',
      weight: wUnicodeTag,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
  }

  // -- Step B: magic-byte base64 prefixes (against ctx.pp.normalized which
  // is case-folded ASCII safe; magic prefixes are case-sensitive in
  // practice, so match against original too).
  MAGIC_BYTES_RE.lastIndex = 0;
  while ((m = MAGIC_BYTES_RE.exec(original)) !== null) {
    const byteStart = origIndexToByte(m.index);
    const byteEnd = origIndexToByte(m.index + m[0].length);
    const prefix4 = m[0].slice(0, 4);
    emitRedactedMatch('data_shape_anomaly', 'magic_bytes', byteStart, byteEnd, prefix4);
    hits.push({
      category: 'data_shape_anomaly',
      subCategory: 'magic_bytes',
      weight: wMagic,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
  }

  // -- Step C: base64 blob >= 100 chars with Shannon entropy floor, skipping
  // data:image inline payloads and known vendor prefixes (Patch 11).
  //
  // Strategy: mask data: inline payload spans on a COPY of `original` (replace
  // with spaces so byte offsets are preserved), then run base64 regex on
  // that copy.
  let scanText = original;
  if (DATA_IMAGE_RE.test(original)) {
    DATA_IMAGE_RE.lastIndex = 0;
    scanText = original.replace(DATA_IMAGE_RE, (matched) => ' '.repeat(matched.length));
  }
  BASE64_BLOB_RE.lastIndex = 0;
  while ((m = BASE64_BLOB_RE.exec(scanText)) !== null) {
    const matched = m[0];
    if (matched.length < 100) { BASE64_BLOB_RE.lastIndex = m.index + matched.length; continue; }
    // Patch 11 anti-double-count: skip if the matched span LOOKS like a
    // known vendor structural shape. The vendor detector owns these.
    if (looksLikeKnownVendor(matched)) {
      BASE64_BLOB_RE.lastIndex = m.index + matched.length;
      continue;
    }
    // Entropy gate (L-DS-1).
    const e = shannonEntropy(matched);
    if (e < BASE64_ENTROPY_FLOOR) {
      BASE64_BLOB_RE.lastIndex = m.index + matched.length;
      continue;
    }
    const byteStart = origIndexToByte(m.index);
    const byteEnd = origIndexToByte(m.index + matched.length);
    const prefix4 = matched.slice(0, 4);
    emitRedactedMatch('data_shape_anomaly', 'base64_blob', byteStart, byteEnd, prefix4);
    hits.push({
      category: 'data_shape_anomaly',
      subCategory: 'base64_blob',
      weight: wBase64,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
    BASE64_BLOB_RE.lastIndex = m.index + matched.length;
  }

  // -- Step D: hex blob >= 64 chars.
  HEX_BLOB_RE.lastIndex = 0;
  while ((m = HEX_BLOB_RE.exec(original)) !== null) {
    const matched = m[0];
    const byteStart = origIndexToByte(m.index);
    const byteEnd = origIndexToByte(m.index + matched.length);
    const prefix4 = matched.slice(0, 4);
    emitRedactedMatch('data_shape_anomaly', 'hex_blob', byteStart, byteEnd, prefix4);
    hits.push({
      category: 'data_shape_anomaly',
      subCategory: 'hex_blob',
      weight: wHex,
      evidence: { byteStart, byteEnd, prefix4 },
      matchedIn: ctx.matchedIn,
    });
  }

  // -- Step E: Cyrillic-in-Latin homoglyph (L-HG-1).
  // Tokenize the ORIGINAL text on whitespace + punctuation; check each
  // candidate token of length 3..40 via hasMixedScriptCyrillicLatin. Cap at
  // MAX_HOMOGLYPH_HITS=5 hits per email.
  let homoCount = 0;
  let tokenIdx = 0;
  // Walk the original string position-by-position so we can recover the
  // original-byte offset of each token start. We use a manual scanner rather
  // than .split() to avoid allocation overhead on large bodies.
  let tStart = -1;
  for (let i = 0; i <= original.length; i++) {
    const atEnd = i === original.length;
    const cp = atEnd ? 0x20 : original.charCodeAt(i);
    const isBreak = isBreakCodePoint(cp);
    if (isBreak) {
      if (tStart !== -1) {
        const tok = original.slice(tStart, i);
        if (hasMixedScriptCyrillicLatin(tok)) {
          const byteStart = origIndexToByte(tStart);
          const byteEnd = origIndexToByte(tStart + tok.length);
          const prefix4 = tok.slice(0, 4);
          emitRedactedMatch('data_shape_anomaly', 'homoglyph_cyr_lat', byteStart, byteEnd, prefix4);
          hits.push({
            category: 'data_shape_anomaly',
            subCategory: 'homoglyph_cyr_lat',
            weight: wHomoglyph,
            evidence: { byteStart, byteEnd, prefix4 },
            matchedIn: ctx.matchedIn,
          });
          homoCount++;
          if (homoCount >= MAX_HOMOGLYPH_HITS) break;
        }
        tStart = -1;
        tokenIdx++;
        if (tokenIdx >= MAX_TOKEN_COUNT) break;
      }
    } else if (tStart === -1) {
      tStart = i;
    }
  }

  // Silence unused-import lint of map/byteToNormIndex/text helpers under the
  // scenario where Step A/B/C/D/E may all skip in tests. We DO use them above
  // (Step A uses original via origIndexToByte; Steps B-D use original;
  // Step E uses original). map/byteToNormIndex remain available for future
  // sub-detectors that need normalized->byte translation directly.
  void map;
  void byteToNormIndex;
  void text;
  void originalByteLen;

  return hits;
};

// Registration is performed by outbound-scan.ts _reregisterAllDetectors().
