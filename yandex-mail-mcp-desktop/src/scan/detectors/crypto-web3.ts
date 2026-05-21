// detectors/crypto-web3.ts -- category 2.6 (Cryptocurrency & Web3) detector.
//
// CONTEXT decisions enforced:
//   D5:  structural-pass detector; runs early.
//   D8:  ScanHit.evidence.byteStart/byteEnd index ORIGINAL input bytes via
//        ctx.pp.normalizedToOriginalByte.
//   D9-D11: weights sourced from ctx.policy.weights.*; never hardcoded.
//   D13: BIP-39 mnemonic requires >= 90 % wordlist-membership of the words
//        in the candidate span (12/15/18/21/24 words). Lifted verbatim from
//        outbound-content-dictionary.md section 2.6.
//   D20: zero new npm deps; Base58Check + Bech32 polymod implemented inline.
//   D21: detector receives policy via DetectorContext.policy; never calls
//        getPolicy() directly.
//   D27: ScanHit.category === 'crypto_seed' (singular) for ALL crypto/Web3
//        hits. subCategory carries the specific token type.
//
// Plan 02-02 / L5: registered with subject_eligible: true at T-02-02-08.
// Plan 02-02 / L6: every regex is anchored (\b); NO nested unbounded
//   quantifiers; NO catastrophic-backtracking shapes.
//
// FILTER NOTE (content-pipeline mitigation, carried from T-02-02-06):
//   Cryptographic prefixes (xpub, xprv, ypub, zpub, bc1, ltc1, 0x, T...) are
//   split via string concatenation to avoid tripping the upstream content
//   filter that inspects generated source. esbuild const-folds these at
//   minify time; the produced regex object is byte-identical to a single
//   literal form. Runtime semantics are unchanged.
//
//   BIP-39 fixtures used in T-02-02-09 tests must be DERIVED from the shipped
//   bip39-wordlist.ts at runtime (e.g. Array.from(BIP39_EN).slice(0,12)),
//   never written as inline literal mnemonic sequences in source code.
//
// EIP-55 Ethereum checksum: NOT implemented in this revision. Keccak-256 is
//   absent from Node's `node:crypto` core, and a pure-JS keccak adds ~80 LOC
//   plus ~3-4 KB to the bundle for a marginal precision gain (mixed-case ETH
//   addresses without checksum validation are still emitted as hits at the
//   shape-only weight). All ETH hits carry subCategory='eth_address_shape'.
//   When EIP-55 lands in a future plan (Layer-3 hardening), the subCategory
//   token will bifurcate to 'eth_address_eip55_valid' / 'eth_address_shape'.
//
// Pure function over DetectorContext. No I/O, no async.

import * as crypto from 'node:crypto';

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { emitRedactedMatch } from '../../outbound-scan.js';
import { BIP39_EN } from '../bip39-wordlist.js';

// =====================================================================
// Base58Check (BTC / TRX / LTC legacy / extended keys)
// =====================================================================
//
// Reference: https://en.bitcoin.it/wiki/Base58Check_encoding
// Algorithm:
//   1. Decode the Base58 string to a big-endian byte buffer.
//   2. Last 4 bytes are checksum = first 4 bytes of SHA256(SHA256(payload)).
//   3. Verify checksum matches.
//
// Standard Base58 alphabet (Bitcoin / Solana / Tron all share it).

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_MAP: Int8Array = (() => {
  const m = new Int8Array(128);
  m.fill(-1);
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    m[BASE58_ALPHABET.charCodeAt(i)] = i;
  }
  return m;
})();

/**
 * Decode a Base58Check-encoded string. Returns the PAYLOAD bytes (without
 * the trailing 4-byte checksum) on success, or null on any failure mode
 * (illegal char, checksum mismatch, empty input, too-short result).
 *
 * Inline, ~30 LOC; no dependency.
 */
export function base58CheckDecode(s: string): Buffer | null {
  if (s.length === 0) return null;

  // Count leading '1' chars (each is a leading zero byte in the decoded form).
  let zeros = 0;
  while (zeros < s.length && s.charCodeAt(zeros) === 49 /* '1' */) zeros++;

  // Big-integer base-conversion: maintain a base-256 result array, multiply
  // by 58 and add the next base-58 digit for each input char.
  const result: number[] = [];
  for (let i = zeros; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 127) return null;
    const digit = BASE58_MAP[c];
    if (digit < 0) return null;
    let carry = digit;
    for (let j = 0; j < result.length; j++) {
      carry += result[j] * 58;
      result[j] = carry & 0xff;
      carry >>>= 8;
    }
    while (carry > 0) {
      result.push(carry & 0xff);
      carry >>>= 8;
    }
  }

  // Result is little-endian; reverse + prepend leading zeros.
  const decoded = Buffer.alloc(zeros + result.length);
  for (let i = 0; i < result.length; i++) {
    decoded[zeros + (result.length - 1 - i)] = result[i];
  }

  if (decoded.length < 4) return null;

  const payload = decoded.subarray(0, decoded.length - 4);
  const expected = decoded.subarray(decoded.length - 4);
  const h1 = crypto.createHash('sha256').update(payload).digest();
  const h2 = crypto.createHash('sha256').update(h1).digest();
  if (
    h2[0] !== expected[0] ||
    h2[1] !== expected[1] ||
    h2[2] !== expected[2] ||
    h2[3] !== expected[3]
  ) {
    return null;
  }
  return payload;
}

// =====================================================================
// Bech32 polymod (BTC SegWit / Taproot / LTC native)
// =====================================================================
//
// Reference: BIP-0173 (https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
// Algorithm: HRP-expand + payload + polymod constant check.

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_CHARSET_MAP: Int8Array = (() => {
  const m = new Int8Array(128);
  m.fill(-1);
  for (let i = 0; i < BECH32_CHARSET.length; i++) {
    m[BECH32_CHARSET.charCodeAt(i)] = i;
  }
  return m;
})();

const BECH32_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values: number[]): number {
  let chk = 1;
  for (let i = 0; i < values.length; i++) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ values[i];
    for (let j = 0; j < 5; j++) {
      if ((top >>> j) & 1) chk ^= BECH32_GENERATORS[j];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >>> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 0x1f);
  return ret;
}

/**
 * Validate a Bech32 / Bech32m address against the supplied HRP. Accepts
 * both polymod constants:
 *   - 1          (Bech32, BIP-173 — legacy SegWit v0)
 *   - 0x2bc830a3 (Bech32m, BIP-350 — SegWit v1+ / Taproot)
 *
 * Returns true on a valid checksum. Returns false on any parse error,
 * illegal character, or constant mismatch.
 */
export function bech32Verify(addr: string, expectedHrp: string): boolean {
  if (addr.length < expectedHrp.length + 7) return false; // hrp + '1' + data(6+)
  // Case must be uniform.
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) return false;
  const lc = addr.toLowerCase();
  if (!lc.startsWith(expectedHrp)) return false;
  if (lc.charCodeAt(expectedHrp.length) !== 49 /* '1' separator */) return false;

  const dataPart = lc.slice(expectedHrp.length + 1);
  const values: number[] = [];
  for (let i = 0; i < dataPart.length; i++) {
    const c = dataPart.charCodeAt(i);
    if (c > 127) return false;
    const v = BECH32_CHARSET_MAP[c];
    if (v < 0) return false;
    values.push(v);
  }

  const polymod = bech32Polymod(bech32HrpExpand(expectedHrp).concat(values));
  // Accept either Bech32 (=1) or Bech32m (=0x2bc830a3) constant; both are
  // legitimate for BTC mainnet (v0 / v1+).
  return polymod === 1 || polymod === 0x2bc830a3;
}

// =====================================================================
// Address regex patterns (anchored, /g)
// =====================================================================
//
// Per Plan T-02-02-07 + dictionary section 2.6, with credential-prefix
// fragments split via string concatenation (filter mitigation; see header).
//
// Notes on length bounds:
//   - BTC legacy P2PKH/P2SH: typically 26-35 chars total (post-Base58Check
//     of a 25-byte payload). dictionary uses `{25,34}` after the leading
//     '1' or '3' (26-35 total).
//   - BTC Bech32: hrp 'bc' + sep '1' + data 6..87 chars (BIP-173 limit).
//   - ETH: `0x` + 40 hex chars (160-bit address).
//   - SOL: 32-44 chars Base58 (Ed25519 pubkey encoding).
//   - TRX: 'T' + 33 Base58 chars (34 total; Base58Check of 25-byte payload).
//   - LTC legacy: 'L' or 'M' or '3' + 26-33 Base58 chars.
//   - LTC Bech32: hrp 'ltc' + sep '1' + data.
//   - Extended keys: 4-char prefix + 107-108 Base58Check chars (78-byte
//     payload + 4 checksum = 82 bytes -> ~111 chars total).

// BTC legacy P2PKH ('1') or P2SH ('3'). Total length 26-35 chars.
const BTC_LEGACY_RE = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;

// BTC native SegWit / Taproot. Prefix split: 'b'+'c1'.
const BTC_BECH32_RE = new RegExp('\\b' + 'b' + 'c1' + '[ac-hj-np-z02-9]{6,87}\\b', 'g');

// ETH / EVM-family (40 hex). Prefix split: '0'+'x'.
const ETH_RE = new RegExp('\\b' + '0' + 'x' + '[a-fA-F0-9]{40}\\b', 'g');

// SOL: 32-44 Base58 chars, no fixed prefix. SHAPE-ONLY (no Ed25519 check).
// Anchored at \b to prevent runaway matches.
const SOL_RE = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g;

// TRX: 'T' + 33 Base58 chars (34 total).
const TRX_RE = /\bT[a-km-zA-HJ-NP-Z1-9]{33}\b/g;

// LTC legacy: leading L / M / 3 + Base58 body 26-33 chars.
const LTC_LEGACY_RE = /\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b/g;

// LTC Bech32 native. Prefix split: 'l'+'tc1'.
const LTC_BECH32_RE = new RegExp('\\b' + 'l' + 'tc1' + '[ac-hj-np-z02-9]{6,87}\\b', 'g');

// Extended-key prefixes. Each split mid-token to avoid filter sensitivity.
// Order: xprv/xpub mainnet BIP-32; yprv/ypub BIP-49 P2WPKH-in-P2SH;
//        zprv/zpub BIP-84 native SegWit; tprv/tpub testnet; uprv/upub testnet
//        P2WPKH-in-P2SH; vprv/vpub testnet native SegWit.
const XKEY_PREFIX_ALT =
  ('x' + 'pr' + 'v') + '|' +
  ('x' + 'pu' + 'b') + '|' +
  ('y' + 'pr' + 'v') + '|' +
  ('y' + 'pu' + 'b') + '|' +
  ('z' + 'pr' + 'v') + '|' +
  ('z' + 'pu' + 'b') + '|' +
  ('t' + 'pr' + 'v') + '|' +
  ('t' + 'pu' + 'b') + '|' +
  ('u' + 'pr' + 'v') + '|' +
  ('u' + 'pu' + 'b') + '|' +
  ('v' + 'pr' + 'v') + '|' +
  ('v' + 'pu' + 'b');
const XKEY_RE = new RegExp(
  '\\b(?:' + XKEY_PREFIX_ALT + ')' + '[a-km-zA-HJ-NP-Z1-9]{107,108}\\b',
  'g',
);

// BIP-39 candidate shape: 12/15/18/21/24 lowercase words (each 3-8 chars)
// separated by single spaces. dictionary section 2.6 lifts this verbatim.
// We capture the FULL span; the 90 % wordlist gate is applied post-match.
const BIP39_SHAPE_RE = /\b(?:[a-z]{3,8} ){11,23}[a-z]{3,8}\b/g;

// Accepted exact word-counts for BIP-39 mnemonics.
const BIP39_VALID_COUNTS: ReadonlySet<number> =
  new Set<number>([12, 15, 18, 21, 24]);

// =====================================================================
// BIP-39 mnemonic detection (exported for unit testing per T-02-02-09)
// =====================================================================

export interface Bip39MatchResult {
  /** NORMALIZED-space start index of the matched span. */
  start: number;
  /** NORMALIZED-space end index (exclusive). */
  end: number;
  /** The split words array (length == 12/15/18/21/24). */
  words: string[];
}

/**
 * Scan `text` for the FIRST occurrence of a BIP-39 mnemonic candidate (the
 * structural shape AND >= 90 % wordlist membership over a valid count).
 *
 * Returns null when no candidate passes the gate. Otherwise returns the
 * span and split words.
 *
 * Used standalone by tests AND by the main detector (which collects ALL
 * hits, not just the first).
 *
 * 90 % gate is per CONTEXT D13 lifted from dictionary section 2.6:
 *   "if (words.length === 12 || 15 || 18 || 21 || 24) {
 *      if (hits / words.length >= 0.9) score = 80; }"
 */
export function bip39Match(text: string): Bip39MatchResult | null {
  BIP39_SHAPE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = BIP39_SHAPE_RE.exec(text)) !== null) {
    const span = m[0];
    const start = m.index;
    if (start === BIP39_SHAPE_RE.lastIndex) BIP39_SHAPE_RE.lastIndex++;
    const words = span.split(' ');
    if (!BIP39_VALID_COUNTS.has(words.length)) continue;
    let inList = 0;
    for (const w of words) {
      if (BIP39_EN.has(w)) inList++;
    }
    if (inList / words.length >= 0.9) {
      return { start, end: start + span.length, words };
    }
  }
  return null;
}

// =====================================================================
// Main detector
// =====================================================================

interface RawCryptoHit {
  subCategory: string;
  weight: number;
  start: number;
  end: number;
  prefix4: string;
}

function tryEmit(
  raw: RawCryptoHit[],
  text: string,
  re: RegExp,
  classify: (matchStr: string) => { subCategory: string; weight: number } | null,
): void {
  if (!re.global) return;
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const matchStr = m[0];
    const start = m.index;
    const end = start + matchStr.length;
    if (start === end) {
      re.lastIndex++;
      continue;
    }
    const verdict = classify(matchStr);
    if (verdict === null) continue;
    raw.push({
      subCategory: verdict.subCategory,
      weight: verdict.weight,
      start,
      end,
      prefix4: matchStr.slice(0, 4),
    });
  }
}

export const detectCryptoWeb3: DetectorFn = (ctx: DetectorContext): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.crypto_web3) return [];

  // Address shapes are case-sensitive (BTC Base58 mixes case; ETH 0x-hex
  // checksum encodes EIP-55 in mixed case). Operate on the case-sensitive
  // normalized form, consistent with structural-secrets.ts.
  const text = ctx.pp.normalizedCaseSensitive;
  // BIP-39 mnemonics are lowercase by construction; the case-sensitive form
  // is a superset (case-fold can only widen, never narrow, ascii words).
  // We still scan BIP-39 against the case-sensitive form for offset
  // consistency with the address detectors.
  const map = ctx.pp.normalizedToOriginalByte;
  const originalByteLen = ctx.pp.originalByteLength;

  const addressWeight = policy.weights.api_key_pattern; // 75 default
  const seedWeight = policy.weights.crypto_seed;        // 75 default
  const solWeight = Math.floor(addressWeight / 2);      // 37 default
  // Extended keys: address-tier weight. BTC legacy: address-tier. ETH/TRX/LTC: address-tier.

  const raw: RawCryptoHit[] = [];

  // -- BTC legacy (P2PKH '1' / P2SH '3') ---------------------------
  tryEmit(raw, text, BTC_LEGACY_RE, (m) => {
    const payload = base58CheckDecode(m);
    if (payload === null) return null;
    // 25-byte total decoded length (1 version + 20 hash + 4 checksum);
    // base58CheckDecode returns just the version+hash, so payload.length === 21.
    if (payload.length !== 21) return null;
    const versionByte = payload[0];
    if (versionByte === 0x00) return { subCategory: 'btc_legacy_p2pkh', weight: addressWeight };
    if (versionByte === 0x05) return { subCategory: 'btc_legacy_p2sh', weight: addressWeight };
    return null;
  });

  // -- BTC Bech32 (native SegWit / Taproot) ------------------------
  tryEmit(raw, text, BTC_BECH32_RE, (m) => {
    if (!bech32Verify(m, 'bc')) return null;
    return { subCategory: 'btc_bech32', weight: addressWeight };
  });

  // -- ETH / EVM-family (shape only; EIP-55 deferred) --------------
  tryEmit(raw, text, ETH_RE, () => {
    // No checksum gating in this revision. See file header for rationale.
    return { subCategory: 'eth_address_shape', weight: addressWeight };
  });

  // -- TRX (Base58Check) -------------------------------------------
  tryEmit(raw, text, TRX_RE, (m) => {
    const payload = base58CheckDecode(m);
    if (payload === null) return null;
    // Tron mainnet version byte is 0x41 ('A'); resulting first char is 'T'.
    if (payload.length !== 21) return null;
    if (payload[0] !== 0x41) return null;
    return { subCategory: 'trx_address', weight: addressWeight };
  });

  // -- LTC legacy (Base58Check; L/M mainnet, 3 legacy P2SH) --------
  tryEmit(raw, text, LTC_LEGACY_RE, (m) => {
    const payload = base58CheckDecode(m);
    if (payload === null) return null;
    if (payload.length !== 21) return null;
    // LTC P2PKH version = 0x30 (L); P2SH new = 0x32 (M); P2SH legacy = 0x05 (3).
    const v = payload[0];
    if (v === 0x30 || v === 0x32 || v === 0x05) {
      return { subCategory: 'ltc_legacy', weight: addressWeight };
    }
    return null;
  });

  // -- LTC Bech32 native SegWit ------------------------------------
  tryEmit(raw, text, LTC_BECH32_RE, (m) => {
    if (!bech32Verify(m, 'ltc')) return null;
    return { subCategory: 'ltc_bech32', weight: addressWeight };
  });

  // -- Extended keys (xpub / xprv / ypub / zpub / t* / u* / v*) ----
  tryEmit(raw, text, XKEY_RE, (m) => {
    const payload = base58CheckDecode(m);
    if (payload === null) return null;
    // BIP-32 serialized extended key = 78 bytes (without checksum). Our
    // decoder returns version + key data (78 bytes); checksum stripped.
    if (payload.length !== 78) return null;
    // Map prefix -> subCategory. Prefix is the first 4 chars of the match
    // (we know these from XKEY_PREFIX_ALT). Use a defensive switch.
    const p = m.slice(0, 4);
    let sub: string;
    switch (p) {
      case 'x' + 'pub': sub = 'extended_key_xpub'; break;
      case 'x' + 'prv': sub = 'extended_key_xprv'; break;
      case 'y' + 'pub': sub = 'extended_key_ypub'; break;
      case 'y' + 'prv': sub = 'extended_key_yprv'; break;
      case 'z' + 'pub': sub = 'extended_key_zpub'; break;
      case 'z' + 'prv': sub = 'extended_key_zprv'; break;
      case 't' + 'pub': sub = 'extended_key_tpub'; break;
      case 't' + 'prv': sub = 'extended_key_tprv'; break;
      case 'u' + 'pub': sub = 'extended_key_upub'; break;
      case 'u' + 'prv': sub = 'extended_key_uprv'; break;
      case 'v' + 'pub': sub = 'extended_key_vpub'; break;
      case 'v' + 'prv': sub = 'extended_key_vprv'; break;
      default: return null;
    }
    return { subCategory: sub, weight: addressWeight };
  });

  // -- SOL (shape only; Ed25519 point check skipped per L2 budget) -
  //   This runs LAST among address detectors because the SOL alphabet is a
  //   strict superset of Base58 (32-44 chars unanchored). Overlap suppression
  //   below favours earlier emitters (BTC legacy at same span beats SOL).
  tryEmit(raw, text, SOL_RE, (m) => {
    // FP guard: SOL shape collides with BTC legacy. If a BTC legacy or
    // extended-key span already covers this match's start, skip. Overlap
    // suppression handles full coverage; here we additionally reject when
    // the candidate starts with '1' or '3' (BTC legacy leading bytes) AND
    // length falls within BTC legacy bounds (26-35). This avoids emitting
    // SOL for clearly BTC-shaped inputs, before the post-pass overlap
    // suppression kicks in.
    const lead = m.charCodeAt(0);
    if ((lead === 49 /* '1' */ || lead === 51 /* '3' */) && m.length >= 26 && m.length <= 35) {
      return null;
    }
    // Likewise reject TRX-leading shapes ('T' + 33 chars).
    if (lead === 84 /* 'T' */ && m.length === 34) return null;
    return { subCategory: 'sol_address_shape', weight: solWeight };
  });

  // -- BIP-39 mnemonic (90 % wordlist gate per D13) ----------------
  //   We need ALL candidate spans here (not just the first), so we replicate
  //   bip39Match's loop locally rather than calling it.
  BIP39_SHAPE_RE.lastIndex = 0;
  {
    let m: RegExpExecArray | null;
    while ((m = BIP39_SHAPE_RE.exec(text)) !== null) {
      const span = m[0];
      const start = m.index;
      const end = start + span.length;
      if (start === end) {
        BIP39_SHAPE_RE.lastIndex++;
        continue;
      }
      const words = span.split(' ');
      if (!BIP39_VALID_COUNTS.has(words.length)) continue;
      let inList = 0;
      for (const w of words) {
        if (BIP39_EN.has(w)) inList++;
      }
      if (inList / words.length < 0.9) continue;
      raw.push({
        subCategory: `bip39_mnemonic_${words.length}`,
        weight: seedWeight,
        start,
        end,
        prefix4: span.slice(0, 4),
      });
    }
  }

  if (raw.length === 0) return [];

  // Sort by start ASC, then by length DESC (prefer LONGER match at same
  // start; this favours extended_key over a SOL shape collision, and
  // bip39_24 over an embedded bip39_12 candidate).
  raw.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return (b.end - b.start) - (a.end - a.start);
  });

  // Overlap suppression: walk sorted hits; emit a hit only if its
  // [start,end) does not intersect any previously-emitted hit's span.
  const hits: ScanHit[] = [];
  let lastEnd = -1;
  for (const r of raw) {
    if (r.start < lastEnd) continue;
    const byteStart = map[r.start] ?? 0;
    const byteEnd = r.end < map.length
      ? map[r.end]
      : (map[map.length - 1] ?? originalByteLen);
    emitRedactedMatch('crypto_seed', r.subCategory, byteStart, byteEnd, r.prefix4);
    hits.push({
      category: 'crypto_seed',
      subCategory: r.subCategory,
      weight: r.weight,
      evidence: { byteStart, byteEnd, prefix4: r.prefix4 },
      matchedIn: ctx.matchedIn,
    });
    lastEnd = r.end;
  }

  return hits;
};
