// send-pipeline.ts -- Phase 6 (D1-D7) explicit Stage[] pipeline for
// yandex_send_email.
//
// Why this file exists:
//
//   In v2.0.0 the entire send pipeline lived inline inside tools.ts's
//   yandex_send_email handler -- ~322 LOC of validation, normalization,
//   allowlist gate, scan, provenance, risk calculation, confirmation
//   dispatch, guard enforcement, SMTP call, and recordSend, mutating a
//   set of locally-scoped vars across one giant function. That worked
//   when there were three checks; it does not scale to nine.
//
//   Phase 6 extracts the pipeline into an explicit Stage[] driver:
//
//     - Each stage is a pure async function (SendContext) -> StageResult.
//     - StageResult is a discriminated union -- pass / block / pending.
//     - The driver runPipeline(ctx) iterates the array, accumulating ctx
//       on `pass`, terminating early on `block` / `pending`.
//     - Stages NEVER mutate fields they did not declare (D5: add-only
//       SendContext discipline -- enforced by per-stage tests).
//
//   The handler in tools.ts shrinks to a <=60 LOC driver (D4): build the
//   initial SendContext, runPipeline, render PipelineResult to the SDK
//   shape, catch errors. All business logic lives in stages.
//
//   The 10 canonical stages (D3 order, FROZEN):
//     1. validateSchema
//     2. normalizeRecipients
//     3. checkAllowlist
//     4. scanOutbound
//     5. trackProvenance
//     6. computeRisk
//     7. riskAdaptiveConfirm
//     8. enforceGuards
//     9. smtpSend         -- substeps 9.1..9.5 locked (B-4 H-2 invariant)
//    10. recordSend
//
// This file is Task 4 (skeleton) -- types + 10 stub stages + driver +
// test seams. Real submodule wiring lands in Task 5.
//
// No tsc -- esbuild transpiles. Library signatures verified manually.
// ESM .js suffix on internal imports. ASCII only. No `any`.

import type { ValidatedInput } from './send-schemas.js';
import type { ScanResult } from './outbound-scan.js';
import type { RiskResult } from './risk-score.js';
import type { GuardResult } from './guards.js';
import type { AuthLevel } from './auth.js';

// -- Public types (D2 + D5) ----------------------------------------------

// PendingRequirement: 3 known kinds. Pipeline returns these when the
// send cannot complete in a single call (confirmation code minted but
// not yet supplied, override token expected but not yet supplied,
// elicit dialog needs to be shown).
export type PendingRequirement =
  | {
      kind: 'confirmation_code';
      actionFingerprint: string;
      tier: 'medium' | 'high';
      score: number;
      expiresAt: number;
    }
  | {
      kind: 'override_token';
      riskFingerprint: string;
      score: number;
    }
  | {
      kind: 'elicit_dialog';
      actionFingerprint: string;
      tier: 'medium' | 'high';
    };

// AuditPayload: free-form audit attachment. Each stage that emits an
// audit on block/pending may carry the audit fields here for the driver
// to surface (or for the handler to log). The shape mirrors the
// auditLog input contract.
export interface AuditPayload {
  action: string;
  status: 'success' | 'denied' | 'warn';
  level?: 'info' | 'warn';
  reason?: string;
  riskFingerprint?: string;
  error?: string;
  recipients?: number;
  subject_hash?: string;
  message_id?: string;
  from_domain?: string;
}

// StageResult: discriminated union (D2). A stage returns exactly one
// of pass/block/pending. `pass` propagates ctx forward. `block` ends
// the run with a denial. `pending` ends the run with an out-of-band
// requirement (the caller re-runs with the requirement satisfied).
export type StageResult =
  | { kind: 'pass';    ctx: SendContext }
  | { kind: 'block';   reason: string; audit: AuditPayload; ctx: SendContext }
  | { kind: 'pending'; requires: PendingRequirement; ctx: SendContext };

// PipelineResult: the runPipeline return. Mirrors StageResult but the
// success path carries the final accumulated ctx instead of `pass`.
export type PipelineResult =
  | { kind: 'success'; ctx: SendContext }
  | { kind: 'block';   reason: string; audit: AuditPayload; ctx: SendContext }
  | { kind: 'pending'; requires: PendingRequirement; ctx: SendContext };

// SendContext: the accumulator threaded through every stage. ALL
// fields except `input` (the validated input) and the initial frame
// (authLevel, nowMs, dryRun) are OPTIONAL -- each stage adds its own
// outputs and never overwrites a prior stage's. The add-only invariant
// is per-stage-test enforced (mutation gate via JSON.stringify diff).
export interface SendContext {
  // Initial frame (provided by the handler driver).
  rawParams: unknown;
  authLevel: AuthLevel;
  nowMs: number;

  // Stage 1: validateSchema
  input?: ValidatedInput;

  // Stage 2: normalizeRecipients
  recipients?: {
    to: string[];
    cc: string[];
    bcc: string[];
    all: string[];
  };
  actionFingerprint?: string;

  // Stage 3: checkAllowlist
  allowlistDecision?: {
    trusted: string[];
    untrusted: string[];
    autoTrusted: string | null;
  };

  // Stage 4: scanOutbound
  scanResult?: ScanResult;

  // Stage 5: trackProvenance
  postReadFlag?: boolean;

  // Stage 6: computeRisk
  riskResult?: RiskResult;
  riskFingerprint?: string;

  // Stage 7: riskAdaptiveConfirm
  confirmation?: {
    tier: 'low' | 'medium' | 'high' | 'block';
    score: number;
    reasons?: ReadonlyArray<{ signal: string; weight: number; detail: string }>;
    code?: string;
    codeVerified?: boolean;
    overrideConsumed?: boolean;
  };

  // Stage 8: enforceGuards
  guardResult?: GuardResult;

  // Stage 9: smtpSend
  sendResult?: { success: boolean; messageId?: string; error?: string };
}

// Stage: a named async function (ctx) -> StageResult. Driver iterates
// the const pipeline array in order; ordering is FROZEN per D3.
export type Stage = (ctx: SendContext) => Promise<StageResult>;

// -- Test seam (M-4) -----------------------------------------------------
//
// _setSmtpFnForTests: install a mock smtpSend implementation so stage 9
// can be unit-tested without opening a real SMTP socket. The smtpSend
// stage prefers this mock over the real sendEmail. Tests set it via
// _setSmtpFnForTests, run, and reset to null via _resetForTests.
//
// _resetForTests (M-4 spec): resets the mock SMTP fn to null ONLY. Does
// NOT cascade-reset other modules (allowlist, confirm, etc.). Tests
// that touch those modules must call their respective _resetForTests
// separately. The intent is a single-responsibility lifecycle for the
// pipeline's own state, not a global test harness.

type SmtpFnLike = (
  creds: { user: string; pass: string },
  opts: unknown,
) => Promise<{ success: boolean; messageId?: string; error?: string }>;

let _smtpMock: SmtpFnLike | null = null;

export function _setSmtpFnForTests(fn: SmtpFnLike | null): void {
  _smtpMock = fn;
}

export function _getSmtpMockForTests(): SmtpFnLike | null {
  return _smtpMock;
}

export function _resetForTests(): void {
  _smtpMock = null;
}

// -- Stub stages (Task 4 -- real bodies land in Task 5) ------------------

export const validateSchema: Stage = async (ctx) => {
  return { kind: 'pass', ctx };
};

export const normalizeRecipients: Stage = async (ctx) => {
  return { kind: 'pass', ctx };
};

export const checkAllowlist: Stage = async (ctx) => {
  return { kind: 'pass', ctx };
};

export const scanOutbound: Stage = async (ctx) => {
  return { kind: 'pass', ctx };
};

export const trackProvenance: Stage = async (ctx) => {
  return { kind: 'pass', ctx };
};

export const computeRisk: Stage = async (ctx) => {
  return { kind: 'pass', ctx };
};

export const riskAdaptiveConfirm: Stage = async (ctx) => {
  return { kind: 'pass', ctx };
};

export const enforceGuards: Stage = async (ctx) => {
  return { kind: 'pass', ctx };
};

export const smtpSend: Stage = async (ctx) => {
  return { kind: 'pass', ctx };
};

export const recordSend: Stage = async (ctx) => {
  return { kind: 'pass', ctx };
};

// -- Pipeline driver (D3 + D6) ------------------------------------------

// pipeline: const array of 10 stages in the FROZEN canonical D3 order.
// Any reorder is a phase plan violation; T-PIPE-ORDER asserts the names
// in this order match the constant order in src/__tests__/send-pipeline-ordering.test.ts.
export const pipeline: Stage[] = [
  validateSchema,
  normalizeRecipients,
  checkAllowlist,
  scanOutbound,
  trackProvenance,
  computeRisk,
  riskAdaptiveConfirm,
  enforceGuards,
  smtpSend,
  recordSend,
];

// runPipeline(ctxIn): iterate the pipeline. On `pass` accumulate; on
// `block` / `pending` return immediately. After the loop a `pass`
// becomes `success`. The function is total -- no throw paths from the
// driver itself; stage exceptions propagate to the handler caller.
export async function runPipeline(ctxIn: SendContext): Promise<PipelineResult> {
  let ctx = ctxIn;
  for (const stage of pipeline) {
    const r = await stage(ctx);
    if (r.kind === 'block')   return { kind: 'block',   reason: r.reason,   audit: r.audit,    ctx: r.ctx };
    if (r.kind === 'pending') return { kind: 'pending', requires: r.requires, ctx: r.ctx };
    ctx = r.ctx;
  }
  return { kind: 'success', ctx };
}
