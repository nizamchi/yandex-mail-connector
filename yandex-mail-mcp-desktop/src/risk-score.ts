// risk-score.ts -- PMLF Layer C / Phase 4 v2.1.0 composite risk calculator.
//
// Public surface (CONTEXT D2):
//   computeRiskScore(ctx: RiskContext): RiskResult
//
// Produces score (integer [0,100]) + reasons[] (human-readable rationale)
// + tier ('low'|'medium'|'high'|'block') per PMLF-RISK-01..05. The score
// composes the nine signal sources (Phase 1 policy weights, Phase 2
// content-scan hits, Phase 3 post-read provenance flag, v2.0.0 allowlist
// trust state, v2.0.0 dedup velocity counter) via pure SUM + integer
// rounding + clamp to [0,100] + tier mapping with half-open intervals.
//
// CONTEXT D11 (determinism) -- enforced by T-RISK-DETERMINISM-01 grep gate:
//   - NO Math.random.
//   - NO Date.now (the only timestamp source is ctx.nowMs).
//   - NO process.hrtime.
//   - NO setTimeout / setInterval.
//   - NO async / Promise / await / I/O.
//   - ctx is treated as READ-ONLY (no in-place sort, no .push on sub-fields).
//
// CONTEXT D8 (stateless invariant): the caller (tools.ts send-pipeline, lands
// in Phase 5) pre-fetches every signal value -- postReadFlag,
// autoTrustedThisCall, trustAddedAtMs, firstUse, recentSendCount -- and
// hands a fully materialized RiskContext to computeRiskScore. risk-score.ts
// does NOT import provenance/allowlist/guards/audit/recipients -- the
// integration glue lives in Phase 5 send-pipeline. This keeps Phase 4
// deterministic, side-effect free, and import-graph isolated.
//
// CONTEXT D12 (Phase 5 boundary): computeRiskScore returns RiskResult and
// stops. Caller routes to Phase 5 UX based on tier (low=silent,
// medium=augment, high=strict, block=CLI-override). No dispatch here.
//
// PHASE 6 INTEGRATION NOTE (D14):
//   risk-score.ts ships UNCHANGED in Phase 6 -- no function bodies modified,
//   no signal evaluators touched, no tier mapping shifted. The trustAddedAtMs
//   and firstUse fields on RiskContext (Phase 4 D8) are now FILLED with real
//   values by the send-pipeline.ts:computeRisk stage:
//
//     trustAddedAtMs <- allowlist.getTrustEntry(primaryRecipient)?.added
//     firstUse       <- allowlist.getTrustEntry(primaryRecipient)?.useCount === 0
//     autoTrustedThisCall <- !!ctx.allowlistDecision.autoTrusted (H-3 snapshot diff)
//     recentSendCount <- guards.getDailyCounter().count(ctx.nowMs)
//
//   The new_trust signal (evalNewTrust) reads trustAddedAtMs and the first_use
//   signal (evalFirstUse) reads the firstUse boolean. CONTEXT amendment H-2
//   holds: session-scope trust entries report useCount=0 always; the "just
//   auto-trusted" 60s signal is timestamp-based via (now - entry.added < 60s)
//   inside the just_auto_trusted evaluator (Phase 4 surface; Phase 6 wiring).
//
//   No `any`. ESM `.js` suffix on internal imports (NodeNext). ASCII-only.

import { getPolicy } from './policy.js';
import type { ScanResult, ScanHit } from './outbound-scan.js';
import type { RiskPolicy } from './policy-defaults.js';

// -- Public types (CONTEXT D2/D3/D4/D8) ---------------------------

export type RiskTier = 'low' | 'medium' | 'high' | 'block';

export interface RiskReason {
  signal: string;
  weight: number;
  detail: string;
}

export interface RiskResult {
  score: number;
  reasons: RiskReason[];
  tier: RiskTier;
}

export interface RiskContext {
  // Phase 2 ScanResult -- Phase 4 reads .hits[].category for api_key_pattern
  // AND .hits[].subCategory for base64_blob (D5 rev 1 amendment).
  scanResult: ScanResult;

  // Flat, deduped, lowercase recipient list. Caller MUST source this from
  // recipients.ts:normalizeRecipients(input).addresses. Phase 4 reads
  // .length and uses entries verbatim in detail strings.
  recipients: string[];

  // Body size in BYTES (Buffer.byteLength). Caller computes once.
  bodySize: number;

  // Required for determinism -- caller passes the same ms-epoch used
  // for postReadFlag, dedup checks, etc.
  nowMs: number;

  // Pre-fetched signal flags (purity discipline -- see file header).
  postReadFlag: boolean;
  autoTrustedThisCall: boolean;
  trustAddedAtMs?: number;
  firstUse: boolean;
  recentSendCount: number;
}

// -- File-local helpers -------------------------------------------

// Common shape for the 9 evaluators -- enables a single deterministic
// iteration order in computeRiskScore (CONTEXT D5 canonical order).
type SignalEvaluator = (ctx: RiskContext, policy: RiskPolicy) => RiskReason | null;

// Sentinel for the addr placeholder when ctx.recipients is empty. D10
// templates require a literal "(no recipient)" rather than undefined /
// empty-string. Locked by T-RISK-EMPTY-RECIPIENTS-01.
function pickAddr(ctx: RiskContext): string {
  if (ctx.recipients.length === 0) return '(no recipient)';
  return ctx.recipients[0];
}

// -- Per-signal evaluators (CONTEXT D5 canonical order) -----------
//
// All evaluators:
//   - Take (ctx, policy), return RiskReason | null.
//   - Do NOT mutate ctx (no in-place sort, no .push on sub-fields).
//   - Use ONLY policy.weights.<signal>, policy.provenance_window_sec,
//     policy.burst_window_sec, policy.burst_threshold.
//   - Return null (NOT undefined, NOT { weight: 0 }) when the signal
//     does not fire -- the composite step filters by `!== null`.

// 1. new_trust -- predicate is STRICT-LT on the 7d window (D5 row 1).
//    A trust entry added EXACTLY 7d ago does NOT fire (locked by
//    T-RISK-NEW-TRUST-BOUNDARY-EQ-01); 7d-minus-1ms DOES fire (locked
//    by T-RISK-NEW-TRUST-BOUNDARY-EDGE-01).
function evalNewTrust(ctx: RiskContext, policy: RiskPolicy): RiskReason | null {
  if (ctx.trustAddedAtMs === undefined) return null;
  const ageMs = ctx.nowMs - ctx.trustAddedAtMs;
  if (ageMs < 0) return null;            // future trustAddedAtMs -- defensive
  if (ageMs >= 7 * 86400_000) return null;
  const days = Math.floor(ageMs / 86400_000);
  return {
    signal: 'new_trust',
    weight: policy.weights.new_trust,
    detail: 'new trust: ' + pickAddr(ctx) + ' added ' + days + 'd ago',
  };
}

// 2. first_use -- boolean firstUse passed by caller.
function evalFirstUse(ctx: RiskContext, policy: RiskPolicy): RiskReason | null {
  if (!ctx.firstUse) return null;
  return {
    signal: 'first_use',
    weight: policy.weights.first_use,
    detail: 'first send to ' + pickAddr(ctx),
  };
}

// 3. just_auto_trusted -- session-scope trust just added this call (H-1).
function evalJustAutoTrusted(ctx: RiskContext, policy: RiskPolicy): RiskReason | null {
  if (!ctx.autoTrustedThisCall) return null;
  return {
    signal: 'just_auto_trusted',
    weight: policy.weights.just_auto_trusted,
    detail: 'trust auto-elevated this call for ' + pickAddr(ctx),
  };
}

// 4. api_key_pattern -- Phase 2 top-level category. NOT a subCategory.
function evalApiKeyPattern(ctx: RiskContext, policy: RiskPolicy): RiskReason | null {
  const matches = ctx.scanResult.hits.filter(
    (h: ScanHit) => h.category === 'api_key_pattern',
  );
  if (matches.length === 0) return null;
  return {
    signal: 'api_key_pattern',
    weight: policy.weights.api_key_pattern,
    detail: 'body contains ' + matches.length + ' api_key_pattern hit(s)',
  };
}

// 5. base64_in_body -- B-1 CORRECTION per CONTEXT D5 amendment rev 1.
//    Phase 2's src/scan/detectors/data-shapes.ts:313-320 emits base64
//    hits under category 'data_shape_anomaly' with subCategory
//    'base64_blob'. The string 'base64_blob' appears ONLY as a
//    subCategory across the entire detector codebase -- NEVER as a
//    top-level category. Phase 4 evaluator MUST match on h.subCategory.
//    The signal id 'base64_in_body' is the policy-weight key and the
//    Phase 4 signal id -- it is NOT a ScanHit field value.
function evalBase64InBody(ctx: RiskContext, policy: RiskPolicy): RiskReason | null {
  const matches = ctx.scanResult.hits.filter(
    (h: ScanHit) => h.subCategory === 'base64_blob',
  );
  if (matches.length === 0) return null;
  const totalSpan = matches.reduce(
    (sum: number, h: ScanHit) => sum + (h.evidence.byteEnd - h.evidence.byteStart),
    0,
  );
  // Defensive: byteStart === byteEnd (zero-span) yields totalSpan=0 ->
  // approxChars=0 -- never NaN, never undefined, never negative. The
  // signal still fires (boolean-presence semantics per D6). Locked by
  // T-RISK-BASE64-ZEROSPAN-01.
  const approxChars = Math.round(totalSpan / 10) * 10;
  return {
    signal: 'base64_in_body',
    weight: policy.weights.base64_in_body,
    detail:
      'body contains ' +
      matches.length +
      ' base64 blob(s) (~' +
      approxChars +
      ' chars)',
  };
}

// 6. post_read_send -- Phase 3 boolean. Window for display only.
function evalPostReadSend(ctx: RiskContext, policy: RiskPolicy): RiskReason | null {
  if (!ctx.postReadFlag) return null;
  return {
    signal: 'post_read_send',
    weight: policy.weights.post_read_send,
    detail: 'send within ' + policy.provenance_window_sec + 's of inbound read',
  };
}

// 7. multi_recipient -- strict GT 5 (D5 row 7). 6 fires, 5 does not.
function evalMultiRecipient(ctx: RiskContext, policy: RiskPolicy): RiskReason | null {
  if (ctx.recipients.length <= 5) return null;
  return {
    signal: 'multi_recipient',
    weight: policy.weights.multi_recipient,
    detail: ctx.recipients.length + ' recipients (>5)',
  };
}

// 8. large_body -- strict GT 50000 bytes (D5 row 8). 50000 does NOT fire.
// W-3 (v2.1.1 cosmetic): if bodySize is non-finite (Infinity/NaN) or negative,
// the signal must not fire AND the detail string must not leak "Infinity" /
// "NaN" tokens. NaN comparisons are already false (signal silent), but
// Infinity > 50_000 is true and would surface "~Infinity KB" in detail.
function evalLargeBody(ctx: RiskContext, policy: RiskPolicy): RiskReason | null {
  if (!Number.isFinite(ctx.bodySize) || ctx.bodySize < 0) return null;
  if (ctx.bodySize <= 50_000) return null;
  const approxKB = Math.round(ctx.bodySize / 1000);
  return {
    signal: 'large_body',
    weight: policy.weights.large_body,
    detail: 'body ~' + approxKB + ' KB (>50 KB)',
  };
}

// 9. burst_pattern -- GTE policy.burst_threshold (D5 row 9).
function evalBurstPattern(ctx: RiskContext, policy: RiskPolicy): RiskReason | null {
  if (ctx.recentSendCount < policy.burst_threshold) return null;
  return {
    signal: 'burst_pattern',
    weight: policy.weights.burst_pattern,
    detail: ctx.recentSendCount + ' sends within ' + policy.burst_window_sec + 's',
  };
}

// CONTEXT D3 + D6. Non-finite input cannot occur given integer weights,
// but guard defensively so a future policy with a fractional weight cannot
// leak NaN into the tier mapper (NaN comparisons would always be false ->
// tier would incorrectly drop to 'low').
function clamp01_100(n: number): number {
  if (!Number.isFinite(n)) return 0;
  if (n < 0) return 0;
  if (n > 100) return 100;
  return n;
}

// CONTEXT D7 boundary semantics:
//   score < augment           -> low
//   >= augment && < strict    -> medium
//   >= strict  && < block     -> high
//   >= block                  -> block
// Half-open intervals -- score === augment maps to 'medium', score ===
// block maps to 'block'. Locked by T-RISK-TIER-MEDIUM-01 + T-RISK-TIER-
// BLOCK-01.
function mapTier(score: number, t: RiskPolicy['thresholds']): RiskTier {
  if (score >= t.block) return 'block';
  if (score >= t.strict) return 'high';
  if (score >= t.augment) return 'medium';
  return 'low';
}

// PMLF-RISK-01 public surface -- LOCKED per CONTEXT D2.
export function computeRiskScore(ctx: RiskContext): RiskResult {
  const policy = getPolicy();

  // Evaluators in CONTEXT D5 canonical order. The array literal is the
  // SINGLE source of truth for ordering; reasons[] mirrors it.
  const evaluators: SignalEvaluator[] = [
    evalNewTrust,
    evalFirstUse,
    evalJustAutoTrusted,
    evalApiKeyPattern,
    evalBase64InBody,
    evalPostReadSend,
    evalMultiRecipient,
    evalLargeBody,
    evalBurstPattern,
  ];

  const reasons: RiskReason[] = [];
  let rawSum = 0;
  for (const ev of evaluators) {
    const r = ev(ctx, policy);
    if (r === null) continue;
    reasons.push(r);
    rawSum += r.weight;
  }

  // D6 pure SUM. D3 clamp [0,100] + integer rounding.
  const score = clamp01_100(Math.round(rawSum));
  const tier = mapTier(score, policy.thresholds);

  return { score, reasons, tier };
}
