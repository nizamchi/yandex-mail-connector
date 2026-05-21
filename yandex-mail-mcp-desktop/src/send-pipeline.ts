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
// H-2 invariant (locked by T-PIPE-H2-REORDER-01):
//   Inside stage 9 (smtpSend), substeps execute in this order:
//     9.1 verifyCode (if ctx.confirmation.code)
//     9.2 consumeOverrideToken (if ctx.confirmation.tier === 'block')
//     9.3 loadCredentials  -- NEVER reached if 9.1 OR 9.2 fails
//     9.4 sendEmail
//     9.5 success audit
//   No credentials are loaded and no SMTP socket is opened on a
//   confirm/override failure. Failure paths emit ONE audit then return
//   block immediately.
//
// No tsc -- esbuild transpiles. Library signatures verified manually.
// ESM .js suffix on internal imports. ASCII only. No `any`.

import { loadCredentials } from './token.js';
import { sendEmail } from './smtp.js';
import {
  generateCode,
  verifyCode,
  actionFingerprint,
} from './confirm.js';
import { scanOutbound as runScan } from './outbound-scan.js';
import { computeRiskScore } from './risk-score.js';
import {
  riskFingerprint,
  consumeOverrideToken,
} from './override-tokens.js';
import { postReadFlag } from './provenance.js';
import {
  enforceSendGuards,
  recordSend as guardsRecordSend,
  isAdvisory,
  getDailyCounter,
  type SendGuardPayload,
} from './guards.js';
import * as allowlist from './allowlist.js';
import { normalizeRecipients as normRcpt } from './recipients.js';
import { auditLog, subjectHash } from './audit.js';
import {
  sendEmailBaseSchema,
  type ValidatedInput,
} from './send-schemas.js';
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
// fields except `rawParams`, `authLevel`, `nowMs`, and `dryRun` are
// OPTIONAL -- each stage adds its own outputs and never overwrites a
// prior stage's. The add-only invariant is per-stage-test enforced
// (mutation gate via JSON.stringify diff).
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
// separately.

type SmtpFnLike = (
  creds: { user?: string; pass?: string; email?: string; oauthToken?: string },
  opts: SmtpOpts,
) => Promise<{ success: boolean; messageId?: string; error?: string }>;

interface SmtpOpts {
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  text?: string;
  html?: string;
  replyTo?: string;
  inReplyTo?: string;
  references?: string[];
}

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

// -- Helpers (file-local) -----------------------------------------------

function bodyText(input: ValidatedInput): string {
  return input.text ?? input.html ?? '';
}

function bodyBytes(input: ValidatedInput): number {
  return Buffer.byteLength(bodyText(input), 'utf8');
}

function domainOf(addr: string): string {
  const at = addr.indexOf('@');
  return at >= 0 ? addr.slice(at + 1) : '(none)';
}

function nowIso(ctx: SendContext): string {
  return new Date(ctx.nowMs).toISOString();
}

function buildSmtpOpts(ctx: SendContext): SmtpOpts {
  const r = ctx.recipients!;
  const inp = ctx.input!;
  return {
    to: r.to,
    cc: r.cc.length > 0 ? r.cc : undefined,
    bcc: r.bcc.length > 0 ? r.bcc : undefined,
    subject: inp.subject,
    text: inp.text,
    html: inp.html,
    replyTo: inp.reply_to,
    inReplyTo: inp.in_reply_to,
    references: inp.references,
  };
}

// -- Stage 1: validateSchema ---------------------------------------------

// Lifts the existing sendEmailBaseSchema.parse(params) into a stage.
// Blocks with reason='invalid_schema' on Zod failure. Adds ctx.input.
export const validateSchema: Stage = async (ctx) => {
  let parsed: ValidatedInput;
  try {
    parsed = sendEmailBaseSchema.parse(ctx.rawParams);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      kind: 'block',
      reason: 'invalid_schema',
      audit: {
        action: 'yandex_send_email',
        status: 'denied',
        level: 'warn',
        reason: 'schema_parse_failed',
        error: msg.slice(0, 240),
      },
      ctx,
    };
  }
  // text/html exclusive-or check (matches v2.0.0 handler behavior).
  if (parsed.text === undefined && parsed.html === undefined) {
    return {
      kind: 'block',
      reason: 'invalid_schema',
      audit: {
        action: 'yandex_send_email',
        status: 'denied',
        level: 'warn',
        reason: 'missing_body',
      },
      ctx,
    };
  }
  return { kind: 'pass', ctx: { ...ctx, input: parsed } };
};

// -- Stage 2: normalizeRecipients (B-6 fix: 3-call decomposition) -------

// normalizeRecipients(input) returns { addresses, normalized } -- NO `meta`.
// Stage calls it ONCE per to/cc/bcc (B-6). Builds ctx.recipients +
// ctx.actionFingerprint (matches v2.0.0 tools.ts:1080-1083 fingerprint shape).
export const normalizeRecipients: Stage = async (ctx) => {
  const inp = ctx.input!;
  const toN  = normRcpt(inp.to);
  const ccN  = normRcpt(inp.cc);
  const bccN = normRcpt(inp.bcc);
  const all = Array.from(
    new Set<string>([...toN.normalized, ...ccN.normalized, ...bccN.normalized]),
  );
  const recipients = {
    to:  toN.normalized,
    cc:  ccN.normalized,
    bcc: bccN.normalized,
    all,
  };
  // Fingerprint shape mirrors tools.ts v2.0.0:
  //   action='send', payload={to,cc?,bcc?,subject,text?,html?,reply_to?,
  //                          in_reply_to?,references?}
  // confirmation_token, dry_run, override_token are control-plane fields
  // and are stripped from the fingerprint payload.
  const payload: Record<string, unknown> = {
    to: recipients.to,
    subject: inp.subject,
  };
  if (recipients.cc.length > 0)  payload.cc  = recipients.cc;
  if (recipients.bcc.length > 0) payload.bcc = recipients.bcc;
  if (inp.text !== undefined)        payload.text        = inp.text;
  if (inp.html !== undefined)        payload.html        = inp.html;
  if (inp.reply_to !== undefined)    payload.reply_to    = inp.reply_to;
  if (inp.in_reply_to !== undefined) payload.in_reply_to = inp.in_reply_to;
  if (inp.references !== undefined)  payload.references  = inp.references;
  const fp = actionFingerprint('send', payload);
  return {
    kind: 'pass',
    ctx: { ...ctx, recipients, actionFingerprint: fp },
  };
};

// -- Stage 3: checkAllowlist (H-3 snapshot-diff for autoTrusted) ---------

// At authLevel>=1: optional in_reply_to auto-trust (best-effort), then
// recipient gate. autoTrusted derivation uses _listTrusted snapshot diff
// (H-3) because autoTrustOnReply returns void.
//
// At authLevel===0: SHOULD NOT reach here in practice (yandex_send_email
// requires L2); kept as a defence-in-depth no-op pass-through.
//
// Note: the in_reply_to lookup uses imap.findByMessageId in v2.0.0. To
// keep send-pipeline.ts cycle-free with the wider tools.ts import graph,
// the auto-trust path inside the pipeline does NOT call imap directly;
// callers that want auto-trust must precompute the find result and feed
// it into ctx via a future extension. For Phase 6 the pipeline does the
// allowlist gate, NOT the imap lookup -- v2.0.0 path semantics for plain
// (non-reply) sends are byte-equal. This is the same anti-scope as the
// canonical v2.0.0 send-pipeline-ordering test (which does not exercise
// in_reply_to).
export const checkAllowlist: Stage = async (ctx) => {
  if (ctx.authLevel === 0) {
    // L0 cannot reach yandex_send_email at all (tool not registered);
    // defensive no-op.
    return {
      kind: 'pass',
      ctx: {
        ...ctx,
        allowlistDecision: { trusted: [], untrusted: [], autoTrusted: null },
      },
    };
  }
  const all = ctx.recipients!.all;

  const sessionBefore = new Set(
    allowlist._listTrusted()
      .filter(t => t.scope === 'session')
      .map(t => t.address),
  );

  // (We do NOT invoke autoTrustOnReply from inside the pipeline -- the
  // imap lookup remains in tools.ts to avoid pulling imapflow into the
  // pipeline's import graph. The snapshot-diff infra is in place so that
  // if a future iteration moves the auto-trust call into the pipeline,
  // the autoTrusted derivation works without API change.)

  const sessionAfter = new Set(
    allowlist._listTrusted()
      .filter(t => t.scope === 'session')
      .map(t => t.address),
  );
  const newlyTrusted: string[] = [];
  for (const a of sessionAfter) {
    if (!sessionBefore.has(a)) newlyTrusted.push(a);
  }
  const autoTrusted: string | null = newlyTrusted[0] ?? null;

  const trusted: string[] = [];
  const untrusted: string[] = [];
  for (const a of all) {
    if (allowlist.isAllowed(a)) trusted.push(a);
    else untrusted.push(a);
  }
  if (untrusted.length > 0) {
    return {
      kind: 'block',
      reason: 'untrusted_recipient',
      audit: {
        action: 'untrusted_block',
        status: 'denied',
        level: 'warn',
        reason: 'trusted_count=' + trusted.length + ',level=' + ctx.authLevel,
        from_domain: untrusted[0] ? domainOf(untrusted[0]) : '(none)',
      },
      ctx,
    };
  }
  return {
    kind: 'pass',
    ctx: {
      ...ctx,
      allowlistDecision: { trusted, untrusted, autoTrusted },
    },
  };
};

// -- Stage 4: scanOutbound ------------------------------------------------

// Calls outbound-scan.scanOutbound on body+subject. Adds ctx.scanResult.
export const scanOutbound: Stage = async (ctx) => {
  const inp = ctx.input!;
  const result = runScan({
    body:    bodyText(inp),
    subject: inp.subject,
  });
  return { kind: 'pass', ctx: { ...ctx, scanResult: result } };
};

// -- Stage 5: trackProvenance --------------------------------------------

// Reads provenance.postReadFlag using ctx.nowMs (determinism). Adds
// ctx.postReadFlag.
export const trackProvenance: Stage = async (ctx) => {
  const flag = postReadFlag(ctx.nowMs);
  return { kind: 'pass', ctx: { ...ctx, postReadFlag: flag } };
};

// -- Stage 6: computeRisk (D14) ------------------------------------------

// Builds RiskContext per D14 using getTrustEntry(primaryRecipient).
// firstUse = useCount === 0; trustAddedAtMs = entry.added when known.
// autoTrustedThisCall = !!ctx.allowlistDecision.autoTrusted.
// recentSendCount = DailyCounter.count(ctx.nowMs) (matches the v2.0.0
// dedup velocity signal).
export const computeRisk: Stage = async (ctx) => {
  const all = ctx.recipients!.all;
  const inp = ctx.input!;
  const primary = all[0] ?? '';
  const entry = primary ? allowlist.getTrustEntry(primary) : undefined;
  const firstUse = entry !== undefined ? (entry.useCount === 0) : false;
  // trustAddedAtMs: only meaningful for persisted-scope entries. Session
  // entries always report useCount=0 (H-2 amendment) and we synthesize
  // entry.added from added_at -- the value is still useful for the
  // 'new_trust' signal which only checks (now - added) < 7d.
  const trustAddedAtMs = entry?.added;
  const autoTrustedThisCall = !!ctx.allowlistDecision?.autoTrusted;
  const recentSendCount = getDailyCounter().count(ctx.nowMs);

  const riskCtx = {
    scanResult: ctx.scanResult!,
    recipients: all,
    bodySize: bodyBytes(inp),
    nowMs: ctx.nowMs,
    postReadFlag: ctx.postReadFlag ?? false,
    autoTrustedThisCall,
    trustAddedAtMs,
    firstUse,
    recentSendCount,
  };
  const riskResult = computeRiskScore(riskCtx);
  const rfp = riskFingerprint(
    'send',
    {
      recipients: all,
      subject: inp.subject,
      bodyLength: bodyBytes(inp),
    },
    riskResult.score,
  );
  return {
    kind: 'pass',
    ctx: { ...ctx, riskResult, riskFingerprint: rfp },
  };
};

// -- Stage 7: riskAdaptiveConfirm ----------------------------------------

// Dispatches per riskResult.tier:
//   low:    silent pass (v2.0.0 parity).
//   medium / high:
//     - if ctx.input.confirmation_token set: STASH in ctx.confirmation.code
//       (verifyCode runs in stage 9.1, NOT here -- H-2 invariant).
//     - else: generateCode + return pending with confirmation_code requirement.
//   block:  STASH ctx.confirmation with tier='block'. Do NOT call
//           consumeOverrideToken (defer to stage 9.2 so loadCredentials
//           is never reached on failure).
export const riskAdaptiveConfirm: Stage = async (ctx) => {
  const r = ctx.riskResult!;
  const inp = ctx.input!;
  const fp = ctx.actionFingerprint!;
  const rfp = ctx.riskFingerprint!;
  if (r.tier === 'low') {
    return { kind: 'pass', ctx };
  }
  if (r.tier === 'medium' || r.tier === 'high') {
    if (inp.confirmation_token !== undefined) {
      return {
        kind: 'pass',
        ctx: {
          ...ctx,
          confirmation: {
            tier: r.tier,
            score: r.score,
            reasons: r.reasons,
            code: inp.confirmation_token,
          },
        },
      };
    }
    const gen = generateCode(fp, {
      riskTier: r.tier,
      reasons: r.reasons,
      score: r.score,
      riskFingerprint: rfp,
    });
    return {
      kind: 'pending',
      requires: {
        kind: 'confirmation_code',
        actionFingerprint: fp,
        tier: r.tier,
        score: r.score,
        expiresAt: gen.expiresAt,
      },
      ctx: {
        ...ctx,
        confirmation: {
          tier: r.tier,
          score: r.score,
          reasons: r.reasons,
        },
      },
    };
  }
  // tier === 'block': stash and continue. Stage 9.2 owns the
  // consumeOverrideToken call so loadCredentials is never reached on a
  // missing / invalid token.
  return {
    kind: 'pass',
    ctx: {
      ...ctx,
      confirmation: {
        tier: 'block',
        score: r.score,
        reasons: r.reasons,
      },
    },
  };
};

// -- Stage 8: enforceGuards ----------------------------------------------

// Pure guards check. L1/L2 violation -> block. L3 (advisory) -> warn audit
// then pass. Adds ctx.guardResult.
export const enforceGuards: Stage = async (ctx) => {
  const r = ctx.recipients!;
  const payload: SendGuardPayload = {
    to: r.to,
    cc:  r.cc.length  > 0 ? r.cc  : undefined,
    bcc: r.bcc.length > 0 ? r.bcc : undefined,
  };
  const result = enforceSendGuards(payload, ctx.authLevel, ctx.actionFingerprint!);
  if (result.ok) {
    return { kind: 'pass', ctx: { ...ctx, guardResult: result } };
  }
  if (isAdvisory(ctx.authLevel)) {
    auditLog({
      action: 'yandex_send_email',
      status: 'denied',
      level: 'warn',
      ts: nowIso(ctx),
      reason: result.reason + '_L3_advisory',
      from_domain: '(self)',
    });
    return { kind: 'pass', ctx: { ...ctx, guardResult: result } };
  }
  return {
    kind: 'block',
    reason: result.reason,
    audit: {
      action: 'yandex_send_email',
      status: 'denied',
      level: 'warn',
      reason: result.reason,
      from_domain: '(self)',
    },
    ctx: { ...ctx, guardResult: result },
  };
};

// -- Stage 9: smtpSend (B-4 substep ordering lock + B-1 arg order) ------

// EXACT substep order (H-2 invariant; verified by T-PIPE-H2-REORDER-01):
//   9.1 verifyCode (if applicable)
//   9.2 consumeOverrideToken (block-tier only; fingerprint FIRST, token SECOND)
//   9.3 loadCredentials  -- NEVER called if 9.1 OR 9.2 fails
//   9.4 sendEmail
//   9.5 success-only audit
export const smtpSend: Stage = async (ctx) => {
  const conf = ctx.confirmation;
  const inp = ctx.input!;
  const fp = ctx.actionFingerprint!;
  const rfp = ctx.riskFingerprint;

  // 9.1 verifyCode
  if (conf?.code !== undefined) {
    const v = verifyCode(fp, conf.code);
    if (v !== true) {
      auditLog({
        action: 'verify_failed',
        status: 'denied',
        level: 'warn',
        ts: nowIso(ctx),
        reason: 'code_' + v,
      });
      return {
        kind: 'block',
        reason: 'confirm_failed',
        audit: {
          action: 'yandex_send_email',
          status: 'denied',
          level: 'warn',
          reason: 'code_' + v,
        },
        ctx,
      };
    }
    // Mark verified (visible to recordSend; ctx mutation is local to this
    // stage's frame, not the parent ctx -- we re-emit conf in the pass).
  }

  // 9.2 consumeOverrideToken (block-tier only).
  let overrideConsumed = false;
  if (conf?.tier === 'block') {
    const rawToken = inp.override_token ?? process.env.YANDEX_OVERRIDE_TOKEN;
    if (!rawToken || !rfp) {
      return {
        kind: 'block',
        reason: 'risk_block',
        audit: {
          action: 'yandex_send_email',
          status: 'denied',
          level: 'warn',
          reason: 'risk_block_no_override',
          riskFingerprint: rfp,
        },
        ctx,
      };
    }
    // B-1: arg order is (fingerprint, token). LOAD-BEARING.
    const r = consumeOverrideToken(rfp, rawToken);
    if (!r.ok) {
      // B-2: forward the raw reason. 'forged' maps to override_forged for
      // forensic clarity; everything else maps to 'override_<reason>'.
      const blockReason = r.reason === 'forged'
        ? 'override_forged'
        : 'override_' + r.reason;
      return {
        kind: 'block',
        reason: blockReason,
        audit: {
          action: 'yandex_send_email',
          status: 'denied',
          level: 'warn',
          reason: blockReason,
          riskFingerprint: rfp,
        },
        ctx,
      };
    }
    overrideConsumed = true;
  }

  // 9.3 loadCredentials -- only after 9.1 AND 9.2 pass.
  const creds = loadCredentials();

  // 9.4 sendEmail (mock-aware).
  const smtpFn = _smtpMock ?? (sendEmail as unknown as SmtpFnLike);
  const result = await smtpFn(creds, buildSmtpOpts(ctx));
  if (!result.success) {
    auditLog({
      action: 'send_failed',
      status: 'denied',
      level: 'warn',
      ts: nowIso(ctx),
      reason: 'smtp_error',
    });
    return {
      kind: 'block',
      reason: 'smtp_error',
      audit: {
        action: 'yandex_send_email',
        status: 'denied',
        level: 'warn',
        reason: 'smtp_error',
        error: (result.error ?? '').slice(0, 240),
      },
      ctx: { ...ctx, sendResult: result },
    };
  }

  // 9.5 success audit + stash result.
  auditLog({
    action: 'send_succeeded',
    status: 'success',
    level: 'info',
    ts: nowIso(ctx),
    recipients: ctx.recipients!.all.length,
    subject_hash: subjectHash(inp.subject),
    message_id: result.messageId ?? '<no-message-id>',
  });

  const nextConf = conf
    ? { ...conf, codeVerified: conf.code !== undefined ? true : conf.codeVerified, overrideConsumed }
    : undefined;
  return {
    kind: 'pass',
    ctx: {
      ...ctx,
      sendResult: result,
      ...(nextConf ? { confirmation: nextConf } : {}),
    },
  };
};

// -- Stage 10: recordSend (H-1 atomic batch) -----------------------------

// On send success: guards.recordSend + ONE bumpUseCountBatch over ALL
// recipients (single load+sign+write per H-1).
export const recordSend: Stage = async (ctx) => {
  if (!ctx.sendResult?.success) {
    // Defensive: stage 9 would have blocked already; pass-through harmless.
    return { kind: 'pass', ctx };
  }
  const r = ctx.recipients!;
  const payload: SendGuardPayload = {
    to: r.to,
    cc:  r.cc.length  > 0 ? r.cc  : undefined,
    bcc: r.bcc.length > 0 ? r.bcc : undefined,
  };
  guardsRecordSend(payload, ctx.actionFingerprint!);
  allowlist.bumpUseCountBatch(r.all, ctx.nowMs);
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
