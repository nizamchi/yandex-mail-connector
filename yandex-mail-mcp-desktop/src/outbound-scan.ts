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

let applyComposite: (hits: ScanHit[]) => { totalScore: number } =
  (hits) => ({ totalScore: Math.min(100, hits.reduce((s, h) => s + h.weight, 0)) }); // 02-01 stub: capped SUM

// Test + 02-02 + 02-03 seams to swap stubs at runtime.
export function _setCat24CompanionHook(fn: typeof applyCat24CompanionCheck): void {
  applyCat24CompanionCheck = fn;
}
export function _setCompositeHook(fn: typeof applyComposite): void {
  applyComposite = fn;
}

// 02-02 will append registerDetector calls for its 6 detectors here.
// 02-03 will append registerDetector calls for its 5 detectors here.
// 02-01 stub does nothing.
export function _reregisterAllDetectors(): void {
  // Intentionally empty in 02-01. See W-02 of 02-01-PLAN.md.
}

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
    auditLogAction('outbound_scan_oversize', 'attempt', {
      body_byte_length: bodyBytes,
    });
    return { hits: [], totalScore: 0, summary: 'body too large' };
  }

  const ppBody = preprocess(body);
  const ppSubject = subject.length > 0 ? preprocess(subject) : null;

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
  const { totalScore } = applyComposite(allHits);

  const summary = buildSummary(allHits);
  return { hits: allHits, totalScore, summary };
}

// -- Test seam ----------------------------------------------------

export function _resetForTests(): void {
  detectorRegistry.length = 0;
  // Reset hook stubs to 02-01 defaults.
  applyCat24CompanionCheck = (pending, _realHits) => pending;
  applyComposite = (hits) => ({ totalScore: Math.min(100, hits.reduce((s, h) => s + h.weight, 0)) });
}
