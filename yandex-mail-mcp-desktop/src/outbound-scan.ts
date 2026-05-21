// outbound-scan.ts -- Phase 2 Outbound Content Scanner public surface.
//
// CONTEXT decisions enforced here:
//   D1: file path src/outbound-scan.ts.
//   D2: sole entry point scanOutbound({body, subject?}): ScanResult.
//   D3: typed ScanResult / ScanHit.
//   D4: pure, sync, no I/O, no network, no async.
//   D15: REDACTED-MATCH log discipline -- emitRedactedMatch is the only seam.
//   D16: summary contains category names + weights only (content-free).
//   D21: getPolicy() called ONCE per scanOutbound at entry; detectors receive
//        the snapshot via ctx.policy and MUST NOT re-call.
//
// LOCKED CONTRACTS (per 02-CHECK.md revision 1, Patches 1 + 2):
//   - DetectorContext shape: field name is `pp` (NOT `pre`); DetectorFn returns
//     ScanHit[] (NOT void; there is NO emitMatch callback).
//   - scanOutbound main loop is FROZEN at the end of plan 02-01. Plans 02-02
//     and 02-03 install hook bodies via _setCat24CompanionHook /
//     _setCompositeHook; they MUST NOT rewrite the loop.
//
// THIS file owns: type exports + entry-point dispatch + summary builder +
//   REDACTED-MATCH helper + body-size guard (L3) + policy snapshot wiring +
//   named hook stubs (applyCat24CompanionCheck filled by 02-02,
//   applyComposite filled by 02-03).
//
// No `any`. ESM `.js` suffix on internal imports. ASCII-only.

import * as crypto from 'node:crypto';

import { getPolicy } from './policy.js';
import { auditLogAction } from './audit.js';
import { preprocess, type PreprocessResult } from './scan/preprocess.js';
import type { RiskPolicy } from './policy-defaults.js';

// 02-02-08: named imports for the 6 detector modules (categories 2.1-2.6).
// _reregisterAllDetectors() below uses these to (re)populate the registry
// after _resetForTests(). The side-effect of importing these modules has no
// global effect on its own -- registration happens via the
// _reregisterAllDetectors() call at the bottom of this file.
import { detectPaymentCards } from './scan/detectors/payment-cards.js';
import { detectRuBanking } from './scan/detectors/ru-banking.js';
import { detectGovtIds } from './scan/detectors/govt-ids.js';
import { detectCredentialsFuzzy } from './scan/detectors/credentials.js';
import { detectStructuralSecrets } from './scan/detectors/structural-secrets.js';
import { detectCryptoWeb3 } from './scan/detectors/crypto-web3.js';

// 02-03-07: named imports for the 5 keyword-pass detector modules
// (categories 2.7-2.11). Side-effect imports register each detector at
// module load; the explicit named imports here keep the dependency on
// _reregisterAllDetectors() so that _resetForTests() -> reregister flow
// works in tests.
import './scan/detectors/medical.js';
import './scan/detectors/classified-markings.js';
import './scan/detectors/exfil-multipliers.js';
import './scan/detectors/data-shapes.js';
import './scan/detectors/demographic-pii.js';
import { medicalDetector } from './scan/detectors/medical.js';
import { classifiedMarkingsDetector } from './scan/detectors/classified-markings.js';
import { exfilMultipliersDetector } from './scan/detectors/exfil-multipliers.js';
import { dataShapesDetector } from './scan/detectors/data-shapes.js';
import { demographicPiiDetector } from './scan/detectors/demographic-pii.js';
import { composeFinalScore } from './scan/composite-scoring.js';

// -- Public types -------------------------------------------------

export interface ScanHit {
  // Canonical singular per CONTEXT D27 (e.g., 'payment_card', 'api_key_pattern').
  category: string;
  subCategory?: string;
  // Sourced from policy.weights.* at call time. RAW per-hit weight; composite
  // math in 02-03 may diminish this downstream into totalScore.
  weight: number;
  evidence: {
    // Byte offsets index into the ORIGINAL input UTF-8 buffer (D8).
    byteStart: number;
    byteEnd: number;
    // First 4 chars of the match. Used ONLY by emitRedactedMatch for the
    // stderr line under YANDEX_SCAN_DEBUG=1. Never propagated into audit.
    prefix4: string;
  };
  matchedIn: 'body' | 'subject';
}

export interface ScanResult {
  hits: ScanHit[];
  // [0, 100] composite score. Plans 02-02/03 fill the math via the
  // applyComposite hook; the 02-01 stub returns a simple capped sum.
  totalScore: number;
  // Human-readable one-line content-free summary (D16). Format spec: L4 of
  // 02-01-PLAN.md. Empty string when no hits. 'body too large' on L3 guard.
  summary: string;
}

// LOCKED CONTRACT per Patch 1 (B-1) of 02-CHECK.md revision 1.
// Plans 02-02 and 02-03 detectors MUST match this shape exactly.
// Field name is `pp` (NOT `pre`). DetectorFn returns ScanHit[] (NOT void;
// there is NO emitMatch callback).
export interface DetectorContext {
  pp: PreprocessResult;
  policy: RiskPolicy;
  originalBody: string;
  originalSubject: string;
  matchedIn: 'body' | 'subject';
}

export type DetectorFn = (ctx: DetectorContext) => ScanHit[];

// -- Module-private state -----------------------------------------

// L3: body cap. Bodies above this size short-circuit with the 'body too large'
// summary; one audit line is emitted.
const BODY_CAP_BYTES = 1_048_576;

interface DetectorEntry {
  category: string;
  fn: DetectorFn;
  subject_eligible: boolean;
}

const detectorRegistry: DetectorEntry[] = [];

// -- Detector registry seam ---------------------------------------

// Plans 02-02 + 02-03 call this once per detector at module load. `category`
// is the canonical D27 singular name -- registerDetector does not enforce
// this (the canonical names are caller-supplied strings), but the executor
// must align registration with D27 column 3.
export function registerDetector(
  category: string,
  fn: DetectorFn,
  subject_eligible: boolean = false,
): void {
  detectorRegistry.push({ category, fn, subject_eligible });
}

// -- LOCKED hook stubs (Patch 2 of 02-CHECK.md revision 1) --------
//
// Per L8 + Patch 2: NO plan rewrites the main scanOutbound loop.
//   02-02 fills `applyCat24CompanionCheck` (pending cat-2.4 buffer -> promoted hits).
//   02-03 fills `applyComposite` (raw hits -> composite totalScore).
// 02-01 stubs below are pass-through identity / capped simple SUM.

let applyCat24CompanionCheck: (pending: ScanHit[], realHits: ScanHit[]) => ScanHit[] =
  (pending, _realHits) => pending;   // 02-01 stub: pass-through identity

// 02-03-07: hook return-type widened per W-R2-2 carve-out documented in
// 02-01-SUMMARY (the ONE permitted narrow type extension beyond 02-01's
// FROZEN surface). The composite hook may optionally return `finalHits`
// alongside `totalScore`. When `finalHits` is present, scanOutbound uses
// it as the result `hits` array (after multiplier stripping per Patch 12);
// otherwise the orchestrator falls back to `allHits` to preserve the 02-01
// stub contract.
let applyComposite: (hits: ScanHit[]) => { totalScore: number; finalHits?: ScanHit[] } =
  (hits) => ({ totalScore: Math.min(100, hits.reduce((s, h) => s + h.weight, 0)) }); // 02-01 stub: capped SUM

// Test + 02-02 + 02-03 seams to swap stubs at runtime.
export function _setCat24CompanionHook(fn: typeof applyCat24CompanionCheck): void {
  applyCat24CompanionCheck = fn;
}
export function _setCompositeHook(fn: typeof applyComposite): void {
  applyComposite = fn;
}

// 02-02-08: register the 6 structural-pass detectors in deterministic order.
// 02-03 will append its 5 keyword-pass detectors after this comment line.
//
// Subject-eligibility (per plan L5): only structural_secrets (cat 2.5) and
// crypto_web3 (cat 2.6) are scanned on the subject. The other four are
// body-only -- subjects of 50-80 chars are not a realistic surface for PAN /
// SNILS / etc.
//
// Stable order is mandatory for deterministic test output (plan <interfaces>).
export function _reregisterAllDetectors(): void {
  detectorRegistry.length = 0;
  registerDetector('payment_card', detectPaymentCards, false);
  registerDetector('ru_banking', detectRuBanking, false);
  registerDetector('govt_id', detectGovtIds, false);
  registerDetector('credentials_fuzzy', detectCredentialsFuzzy, false);
  registerDetector('api_key_pattern', detectStructuralSecrets, true);
  registerDetector('crypto_seed', detectCryptoWeb3, true);
  // 02-03 keyword-pass detectors (categories 2.7-2.11).
  registerDetector('medical', medicalDetector, false);
  registerDetector('classified_marking', classifiedMarkingsDetector, false);
  registerDetector('exfil_phrase', exfilMultipliersDetector, false);
  registerDetector('data_shape_anomaly', dataShapesDetector, false);
  registerDetector('demographic_pii', demographicPiiDetector, false);
  // Reinstall the cat-2.4 hook in case _resetForTests cleared it.
  _setCat24CompanionHook(applyCat24Companion);
  // Reinstall the composite hook (02-03) -- the real composite-scoring math
  // replaces the 02-01 simple-SUM stub. Adapter returns { totalScore,
  // finalHits } per the widened return type (W-R2-2 / Patch 12 contract).
  _setCompositeHook((hits) => {
    const composite = composeFinalScore(hits);
    return { totalScore: composite.totalScore, finalHits: composite.finalHits };
  });
}

// 02-02-08: cat-2.4 companion-check hook.
//
// Contract (per plan L4 / Patch 6 / B-2.2):
//   - pending = ScanHit[] from detectCredentialsFuzzy (category =
//     'credentials_fuzzy'). The detector encodes the normalized JS code-unit
//     start index in subCategory as '<tag>:<idx>' so this hook can recover
//     the normalized position without translating original-byte offsets back
//     through the offset map.
//   - realHits = ScanHit[] from every OTHER detector. Their evidence.byteStart
//     is in ORIGINAL bytes; we translate to normalized indices via the
//     PreprocessResult captured at scanOutbound entry (currentBodyPP /
//     currentSubjectPP module-locals).
//   - Promote a pending hit iff at least one realHit OR another pending hit
//     lives within +/- 200 normalized code units of the pending hit's
//     normalized start position. Subject and body windows are evaluated
//     INDEPENDENTLY (no cross-section companion lookup) per L4.
//   - Apply cap: total promoted cat-2.4 weight <= policy.weights.outbound_keyword_cap.
//     Excess promotions dropped lowest-weight first; all cat-2.4 hits share
//     the same per-keyword weight today, so excess is dropped tail-first
//     (later-emitted hits get dropped first to keep the earliest companions).
//
// Note on subject parsing: 02-01's main loop already passes `matchedIn` on
// every hit. We bucket by matchedIn and run window logic per-bucket using the
// appropriate PreprocessResult.
const CAT24_WINDOW = 200;

// Module-locals refreshed on every scanOutbound entry. Read by the hook.
// The hook is invoked synchronously inside scanOutbound, so this is race-free
// (D4: no async, no I/O).
let currentBodyPP: PreprocessResult | null = null;
let currentSubjectPP: PreprocessResult | null = null;
let currentPolicyCap: number = 40;

// Parse the trailing ':<idx>' from a credentials_fuzzy subCategory string.
// Returns null if the format does not match (defensive; the detector always
// emits the suffix, but a future re-implementer may forget).
function parseNormalizedIdxFromSub(sub: string | undefined): number | null {
  if (sub === undefined) return null;
  const colon = sub.lastIndexOf(':');
  if (colon < 0 || colon === sub.length - 1) return null;
  const tail = sub.slice(colon + 1);
  // Pure ASCII digits only -- no signs, no whitespace.
  for (let i = 0; i < tail.length; i++) {
    const c = tail.charCodeAt(i);
    if (c < 48 || c > 57) return null;
  }
  const n = Number(tail);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

// Translate an ORIGINAL byte offset to a normalized JS code-unit index by
// binary-searching the offset map. Map is monotonically non-decreasing per
// preprocess.ts contract. Returns the SMALLEST normalized index whose mapped
// byte >= targetByte; if no such index exists, returns map.length (one past
// end). Linear-search fallback for tiny maps to avoid edge cases.
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

function applyCat24Companion(pending: ScanHit[], realHits: ScanHit[]): ScanHit[] {
  if (pending.length === 0) return [];

  // Bucket by matchedIn. The companion search is per-section (L4: subject and
  // body evaluated independently).
  const pendingBody: Array<{ hit: ScanHit; idx: number }> = [];
  const pendingSubj: Array<{ hit: ScanHit; idx: number }> = [];
  for (const h of pending) {
    const idx = parseNormalizedIdxFromSub(h.subCategory);
    if (idx === null) continue;  // malformed -- drop
    if (h.matchedIn === 'body') pendingBody.push({ hit: h, idx });
    else pendingSubj.push({ hit: h, idx });
  }

  // Pre-compute realHit normalized indices per section.
  const realBodyIdx: number[] = [];
  const realSubjIdx: number[] = [];
  if (currentBodyPP !== null) {
    for (const r of realHits) {
      if (r.matchedIn !== 'body') continue;
      realBodyIdx.push(byteToNormIndex(currentBodyPP.normalizedToOriginalByte, r.evidence.byteStart));
    }
  }
  if (currentSubjectPP !== null) {
    for (const r of realHits) {
      if (r.matchedIn !== 'subject') continue;
      realSubjIdx.push(byteToNormIndex(currentSubjectPP.normalizedToOriginalByte, r.evidence.byteStart));
    }
  }

  function hasCompanionWithin(
    target: number,
    realIdx: number[],
    pendingIdx: ReadonlyArray<{ idx: number }>,
  ): boolean {
    for (const r of realIdx) {
      if (Math.abs(r - target) <= CAT24_WINDOW) return true;
    }
    for (const p of pendingIdx) {
      if (p.idx === target) continue;  // skip self
      if (Math.abs(p.idx - target) <= CAT24_WINDOW) return true;
    }
    return false;
  }

  const promoted: ScanHit[] = [];
  for (const p of pendingBody) {
    if (hasCompanionWithin(p.idx, realBodyIdx, pendingBody)) promoted.push(p.hit);
  }
  for (const p of pendingSubj) {
    if (hasCompanionWithin(p.idx, realSubjIdx, pendingSubj)) promoted.push(p.hit);
  }

  // Cap enforcement -- sum of promoted weights <= currentPolicyCap.
  // All cat-2.4 hits share the per-keyword weight; drop tail-first.
  let total = 0;
  const capped: ScanHit[] = [];
  for (const h of promoted) {
    if (total + h.weight > currentPolicyCap) break;
    capped.push(h);
    total += h.weight;
  }
  return capped;
}

// Install the hook so scanOutbound's main loop (FROZEN) sees the real body.
_setCat24CompanionHook(applyCat24Companion);

// Run registration at module load. Production startup, dist bundle init, and
// every `import './outbound-scan.js'` statement get the 6 detectors auto-
// registered. Tests reset via _resetForTests() then re-populate via
// _reregisterAllDetectors() if they want the full registry.
_reregisterAllDetectors();

// -- REDACTED-MATCH logging helper (D15, L2) ----------------------

// L2: composes the bracketed string AND emits auditLogAction with `prefix4_hash`
// (SHA-256-first-8 hex) in extras -- NEVER the raw 4 chars. The raw-prefix
// bracketed line goes to stderr ONLY when YANDEX_SCAN_DEBUG === '1' (opt-in
// developer mode).
export function emitRedactedMatch(
  category: string,
  subCategory: string | null,
  byteStart: number,
  byteEnd: number,
  prefix4: string,
): void {
  const prefix4_hash = crypto.createHash('sha256').update(prefix4).digest('hex').slice(0, 8);
  const extras: Record<string, unknown> = {
    category,
    byteStart,
    byteEnd,
    prefix4_hash,
  };
  if (subCategory !== null) extras.subCategory = subCategory;
  auditLogAction('outbound_scan_match', 'attempt', extras);

  if (process.env.YANDEX_SCAN_DEBUG === '1') {
    process.stderr.write(
      `[REDACTED-MATCH 4chars=${prefix4} at ${byteStart}..${byteEnd}]\n`,
    );
  }
}

// -- Summary builder (L4, W-03) -----------------------------------
//
// Format:
//   - '' when hits.length === 0.
//   - 'body too large' set by scanOutbound L3 guard (NOT here).
//   - '{N} hit(s): {cat1} (+{w1}), {cat2} (+{w2}), ...' for non-empty hits.
// Sorted by weight desc, ties by category asc. Max 6 listed; if more, append
// ', and {M} more'. NEVER includes subCategory or prefix4 (D16).
// Weights are the RAW per-hit weights (NOT composite-diminished) per W-03.
function buildSummary(hits: ScanHit[]): string {
  if (hits.length === 0) return '';

  // Stable copy + sort (weight desc, category asc).
  const sorted = hits.slice().sort((a, b) => {
    if (b.weight !== a.weight) return b.weight - a.weight;
    return a.category < b.category ? -1 : a.category > b.category ? 1 : 0;
  });

  const shown = sorted.slice(0, 6);
  const overflow = sorted.length - shown.length;

  const parts = shown.map(h => `${h.category} (+${h.weight})`);
  let s = `${hits.length} hit(s): ${parts.join(', ')}`;
  if (overflow > 0) s += `, and ${overflow} more`;
  return s;
}

// -- Entry point (D2) ----------------------------------------------
//
// The structure below is FROZEN (L8 + Patch 2 of 02-CHECK.md rev 1). Plans
// 02-02 / 02-03 install hook bodies via _setCat24CompanionHook /
// _setCompositeHook; they MUST NOT rewrite this loop.

export function scanOutbound(input: { body: string; subject?: string }): ScanResult {
  // D21: snapshot policy ONCE here. Detectors receive it via ctx.policy.
  const policy = getPolicy();
  const body = input.body ?? '';
  const subject = input.subject ?? '';

  // L3: body cap guard.
  const bodyBytes = Buffer.byteLength(body, 'utf8');
  if (bodyBytes > BODY_CAP_BYTES) {
    // body_length is the AuditRecord schema field for non-negative integers
    // describing body size; reusing it keeps audit.ts strict-zod compatible.
    auditLogAction('outbound_scan_oversize', 'attempt', {
      body_length: bodyBytes,
    });
    return { hits: [], totalScore: 0, summary: 'body too large' };
  }

  const ppBody = preprocess(body);
  const ppSubject = subject.length > 0 ? preprocess(subject) : null;

  // 02-02-08: capture state for the cat-2.4 companion hook. The hook signature
  // (LOCKED per Patch 2) is (pending, realHits) => ScanHit[]; the hook needs
  // the PreprocessResult to translate real-hit byte offsets to normalized
  // indices, and the policy cap to enforce the per-scan ceiling. Module-locals
  // are race-free because scanOutbound is pure-sync (D4).
  currentBodyPP = ppBody;
  currentSubjectPP = ppSubject;
  currentPolicyCap = policy.weights.outbound_keyword_cap;

  const realHits: ScanHit[] = [];
  const pendingCat24: ScanHit[] = [];   // credentials_fuzzy (cat 2.4) accumulator

  for (const det of detectorRegistry) {
    const bodyHits = det.fn({
      pp: ppBody,
      policy,
      originalBody: body,
      originalSubject: subject,
      matchedIn: 'body',
    });
    for (const h of bodyHits) {
      if (h.category === 'credentials_fuzzy') pendingCat24.push(h);
      else realHits.push(h);
    }
    if (ppSubject !== null && det.subject_eligible) {
      const subjectHits = det.fn({
        pp: ppSubject,
        policy,
        originalBody: body,
        originalSubject: subject,
        matchedIn: 'subject',
      });
      for (const h of subjectHits) {
        if (h.category === 'credentials_fuzzy') pendingCat24.push(h);
        else realHits.push(h);
      }
    }
  }

  // Promote pending cat-2.4 hits via hook (02-02 fills; 02-01 stub = identity).
  const promotedCat24 = applyCat24CompanionCheck(pendingCat24, realHits);
  const allHits = realHits.concat(promotedCat24);

  // Composite scoring via hook (02-03 fills; 02-01 stub = capped simple SUM).
  // W-R2-2 widening (02-03): the hook may return `finalHits` -- when present
  // it replaces `allHits` for the result `hits` and the summary input. This
  // lets composeFinalScore strip exfil multiplier markers (Patch 12) without
  // touching the main loop body (L8 / Patch 2 FROZEN).
  const composite = applyComposite(allHits);
  const totalScore = composite.totalScore;
  const resultHits = composite.finalHits ?? allHits;

  const summary = buildSummary(resultHits);
  return { hits: resultHits, totalScore, summary };
}

// -- Test seam ----------------------------------------------------

export function _resetForTests(): void {
  detectorRegistry.length = 0;
  // Reset hook stubs to 02-01 defaults.
  applyCat24CompanionCheck = (pending, _realHits) => pending;
  applyComposite = (hits) => ({ totalScore: Math.min(100, hits.reduce((s, h) => s + h.weight, 0)) });
  // 02-02-08: clear cat-2.4 hook state to defaults so a fresh test cannot see
  // stale PreprocessResult / cap from a previous scanOutbound call.
  currentBodyPP = null;
  currentSubjectPP = null;
  currentPolicyCap = 40;
}
