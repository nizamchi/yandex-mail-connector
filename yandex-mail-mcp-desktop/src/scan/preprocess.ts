// preprocess.ts -- canonical preprocessor for the Phase 2 outbound scanner.
//
// Invariant D7: order is NFKC normalize -> strip invisible chars (zero-width,
//   bidi controls, Unicode tags) -> case-fold for keyword matching.
// Invariant D8: byte offsets in `normalizedToOriginalByte` index into the
//   ORIGINAL UTF-8 input buffer, NOT into the normalized form. Detectors that
//   report `ScanHit.evidence.byteStart/byteEnd` MUST translate through this
//   map BEFORE emitting hits.
//
// Pure, sync, no I/O, no module-state.
//
// W-01 fast path: pure-ASCII / plain-Cyrillic inputs (the dominant case for
//   100 KB outbound prose) skip the per-codepoint NFKC re-normalisation loop;
//   we build a 1:1 byte-offset map by walking the input once. This is what
//   keeps T-PERF-EMPTY-001 under the 50 ms budget on 100 KB bodies.
//
// No new npm deps (D20). Linear-time only (no nested quantifiers in any
// regex; we don't even use regex on the hot path -- explicit code-point checks).

// Module-private compile-once regex used only by the slow path's invisible
// strip; on the fast path we walk character-by-character using isInvisible().
// Kept for documentation / future detector reuse, but NOT used by preprocess()
// to keep behaviour aligned with the per-codepoint contract.
const _ZERO_WIDTH_RE = /[​-‍⁠﻿]/gu;
const _BIDI_CONTROL_RE = /[‪-‮⁦-⁩]/gu;
const _UNICODE_TAG_RE = /[\u{E0000}-\u{E007F}]/gu;
void _ZERO_WIDTH_RE; void _BIDI_CONTROL_RE; void _UNICODE_TAG_RE;

export interface PreprocessResult {
  // Case-folded (ru-RU locale), invisible-char-stripped, NFKC-normalized.
  // Detectors that operate on keyword/substring matching read this.
  normalized: string;

  // Per-JS-code-unit map from `normalized` indices back to ORIGINAL UTF-8
  // byte offsets. `normalizedToOriginalByte[i]` is the byte offset in the
  // original input where the i-th code unit of `normalized` came from.
  normalizedToOriginalByte: Int32Array;

  // Buffer.byteLength(input, 'utf8') of the ORIGINAL input. Used by callers
  // computing byteEnd as a sentinel for trailing matches.
  originalByteLength: number;

  // NFKC + invisible-strip but WITHOUT case-fold. Used by detectors matching
  // case-sensitive vendor prefixes (AKIA, sk-ant-, eyJ-).
  normalizedCaseSensitive: string;
}

// Returns true for ZW (U+200B-U+200D, U+FEFF, U+2060), bidi controls
// (U+202A-U+202E, U+2066-U+2069), and Unicode tag chars (U+E0000-U+E007F).
function isInvisible(cp: number): boolean {
  if (cp === 0xFEFF) return true;                       // BOM
  if (cp === 0x2060) return true;                       // Word Joiner
  if (cp >= 0x200B && cp <= 0x200D) return true;        // ZWSP, ZWNJ, ZWJ
  if (cp >= 0x202A && cp <= 0x202E) return true;        // bidi embedding/override
  if (cp >= 0x2066 && cp <= 0x2069) return true;        // bidi isolate controls
  if (cp >= 0xE0000 && cp <= 0xE007F) return true;      // Unicode tags
  return false;
}

// Defensive widening for the rare case where case-folding changes JS code-unit
// length (e.g., German sharp-s -> 'ss'). Walks src and dst in lock-step. We
// align via NFKC-cased comparison per code-point; if `dst` is longer than
// `src` for a given codepoint, we replicate the source byte offset across the
// extra output positions.
function widenMapForCaseFold(src: string, dst: string, srcMap: number[]): Int32Array {
  const out = new Int32Array(dst.length);
  let si = 0;
  let di = 0;
  while (si < src.length && di < dst.length) {
    const cp = src.codePointAt(si)!;
    const cpStr = String.fromCodePoint(cp);
    const folded = cpStr.toLocaleLowerCase('ru-RU');
    const srcUnits = cpStr.length;
    const dstUnits = folded.length;
    const srcByte = srcMap[si];
    for (let k = 0; k < dstUnits && di + k < dst.length; k++) {
      out[di + k] = srcByte;
    }
    si += srcUnits;
    di += dstUnits;
  }
  // Fill any tail with the last byte offset (safety; should not happen in
  // practice because Unicode case-folding never shortens below 1:1).
  for (; di < dst.length; di++) {
    out[di] = srcMap[srcMap.length - 1] ?? 0;
  }
  return out;
}

export function preprocess(input: string): PreprocessResult {
  const originalByteLength = Buffer.byteLength(input, 'utf8');

  // Step 1: NFKC normalize the ORIGINAL input.
  const nfkc = input.normalize('NFKC');

  // Step 2: build offset map FROM nfkc form back to ORIGINAL byte offsets.
  // W-01 fast path: NFKC was a no-op (pure ASCII / plain Cyrillic etc.).
  // Build the 1:1 map in one walk over `input` without per-codepoint
  // re-normalisation.
  let map: Int32Array;
  if (nfkc === input) {
    map = new Int32Array(input.length);
    let byteCursor = 0;
    for (let i = 0; i < input.length; ) {
      const cp = input.codePointAt(i)!;
      const cpStr = String.fromCodePoint(cp);
      const cpBytes = Buffer.byteLength(cpStr, 'utf8');
      const jsLen = cpStr.length;
      for (let k = 0; k < jsLen; k++) {
        map[i + k] = byteCursor;
      }
      byteCursor += cpBytes;
      i += jsLen;
    }
  } else {
    // Slow path: NFKC fired (compatibility decomposition). Walk input and nfkc
    // in lock-step, normalising per code-point so we know how many output
    // code units a given input code-point produced. Linear O(N).
    map = new Int32Array(nfkc.length);
    let cursorInputByte = 0;
    let cursorInputIndex = 0;
    let cursorOutputIndex = 0;
    while (cursorInputIndex < input.length && cursorOutputIndex < nfkc.length) {
      const cp = input.codePointAt(cursorInputIndex)!;
      const cpStr = String.fromCodePoint(cp);
      const cpBytes = Buffer.byteLength(cpStr, 'utf8');
      const cpJsLen = cpStr.length;
      const folded = cpStr.normalize('NFKC');
      for (let k = 0; k < folded.length; k++) {
        if (cursorOutputIndex >= nfkc.length) break;
        map[cursorOutputIndex] = cursorInputByte;
        cursorOutputIndex++;
      }
      cursorInputByte += cpBytes;
      cursorInputIndex += cpJsLen;
    }
    // Pad-tail if there was minor drift (defensive; should be rare).
    for (; cursorOutputIndex < nfkc.length; cursorOutputIndex++) {
      map[cursorOutputIndex] = cursorInputByte;
    }
  }

  // Step 3: strip invisible chars (zero-width, bidi controls, Unicode tags)
  // from nfkc. We re-build the string code-point-by-code-point and the
  // associated map to keep the contract intact.
  let normalizedCaseSensitive = '';
  const mapAfterStrip: number[] = [];
  for (let i = 0; i < nfkc.length; ) {
    const cp = nfkc.codePointAt(i)!;
    const cpStr = String.fromCodePoint(cp);
    const jsLen = cpStr.length;
    if (isInvisible(cp)) {
      i += jsLen;
      continue;
    }
    for (let k = 0; k < jsLen; k++) {
      normalizedCaseSensitive += nfkc[i + k];
      mapAfterStrip.push(map[i + k]);
    }
    i += jsLen;
  }

  // Step 4: case-fold for keyword matching. Cyrillic-aware via ru-RU locale.
  const normalized = normalizedCaseSensitive.toLocaleLowerCase('ru-RU');

  let normalizedToOriginalByte: Int32Array;
  if (normalized.length === normalizedCaseSensitive.length) {
    normalizedToOriginalByte = Int32Array.from(mapAfterStrip);
  } else {
    normalizedToOriginalByte = widenMapForCaseFold(
      normalizedCaseSensitive, normalized, mapAfterStrip,
    );
  }

  return {
    normalized,
    normalizedToOriginalByte,
    originalByteLength,
    normalizedCaseSensitive,
  };
}
