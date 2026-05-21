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
// No `any`. ESM `.js` suffix on internal imports (NodeNext). ASCII-only.

import { getPolicy } from './policy.js';
import type { ScanResult, ScanHit } from './outbound-scan.js';

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

// PMLF-RISK-01 public surface -- LOCKED per CONTEXT D2.
export function computeRiskScore(ctx: RiskContext): RiskResult {
  // Stub body. T-04-01-02 / T-04-01-03 fill the real logic. Silences
  // unused parameter warnings while preserving the locked signature.
  void ctx;
  return { score: 0, reasons: [], tier: 'low' as RiskTier };
}
