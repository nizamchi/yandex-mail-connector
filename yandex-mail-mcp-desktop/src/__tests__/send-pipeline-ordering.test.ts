// send-pipeline-ordering.test.ts -- TDD reproduction for HIGH H-2.
//
// Threat (per .planning/MILESTONE-v2.0.0-DEEP-REVIEW.md §H-2 and
// .planning/debug/h2-confirm-burned-before-guards.md):
//
//   The yandex_send_email pipeline runs `verifyCode` (which sets
//   entry.used = true) BEFORE `enforceSendGuards`. A guard violation
//   (daily limit / per-recipient rate / dedup window) returns
//   isError:true AFTER the confirmation code has already been burned.
//   The user, who explicitly approved the send, is then forced to
//   dry_run again -- and if the same guard still fires they burn 2-3
//   fresh codes in a confused loop. Friction path from
//   secure-by-default (L1 elicit gating) to insecure-by-frustration
//   (user lowers YANDEX_AUTH_LEVEL to auto to stop the friction).
//
// Fix direction (pre-confirmed, mechanical reorder):
//
//   In tools.ts the `yandex_send_email` handler must run
//   `enforceSendGuards` (pure -- no state mutation) BEFORE `verifyCode`
//   (mutator -- the SOLE code-burn site) in BOTH branches:
//
//   1. token-supplied branch (p.confirmation_token !== undefined)
//   2. elicit-accept branch (canElicit + elicit returned 'accept')
//
//   And in the dry_run branch:
//   3. guards-pure runs against the same fingerprint; if violation,
//      SendPlan is returned with a `guard_violation` field and NO
//      confirmation_token issued.
//
//   B-3 invariant is preserved: verifyCode body still has 0 await
//   tokens. The fix is local to the handler, not to confirm.ts.
//
// Tests T-H2-01..03 (guard block burns code) and T-H2-05 (dry_run
// surfaces guards) MUST FAIL on the pre-fix code -- this is the RED
// part of the TDD cycle.
//
// Why structural ordering tests (T-H2-06, T-H2-08): the runtime path
// requires real SMTP credentials and a working TLS handshake to reach
// the success branch; we cannot easily mock those in the esbuild-bundled
// test runner. Instead we treat tools.ts as data and assert the
// line-order invariant by source grep -- same defence-in-depth pattern
// confirm.test.ts uses for B-3's "0 await tokens in verifyCode body"
// invariant. Source-grep tests are robust against accidental rewrites
// of the handler and document the architectural constraint inline.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { TOOLS, type ToolDef } from '../tools.js';
import {
  actionFingerprint,
  generateCode,
  verifyCode,
  _resetForTests as _resetConfirm,
} from '../confirm.js';
import {
  enforceSendGuards,
  recordSend,
  getDailyCounter,
  getPerRecipientCounter,
  getSendDedup,
  _resetForTests as _resetGuards,
} from '../guards.js';
import { _resetForTests as _resetAllowlist, addTrusted } from '../allowlist.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import type { AuthLevel } from '../auth.js';

// -- helpers --------------------------------------------------------------

interface HandlerCtx {
  authLevel: AuthLevel;
  capabilities: Set<never>;
  serverContext: { canElicit: boolean; elicit?: undefined };
  protectedFolders: ReadonlySet<string>;
}

function mkCtx(level: AuthLevel): HandlerCtx {
  return {
    authLevel: level,
    capabilities: new Set(),
    serverContext: { canElicit: false },
    protectedFolders: new Set<string>(),
  };
}

function getSendTool(): ToolDef {
  const def = TOOLS.find(t => t.name === 'yandex_send_email');
  assert.ok(def, 'yandex_send_email must exist in TOOLS');
  return def;
}

// Compute the same fingerprint the handler computes. The handler:
//   1. normalizes to/cc/bcc through normalizeRecipients (lowercase bare)
//   2. strips dry_run + confirmation_token + raw to/cc/bcc from the input
//   3. substitutes the normalized arrays back in
//   4. calls actionFingerprint('send', payload)
//
// We mirror that here so the test can prime confirm.ts with a code keyed
// to the EXACT fingerprint the handler will look up. ParsedSendParams is
// validated through the same Zod schema at the handler entry, so the
// only "extra" key in the payload object is `dry_run` after defaulting
// (the schema sets dry_run:false via .default), which we strip.
function fingerprintFor(p: {
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  text?: string;
  html?: string;
  reply_to?: string;
  in_reply_to?: string;
  references?: string[];
}): string {
  const toFlat = p.to.map(x => x.trim().toLowerCase());
  const ccFlat = (p.cc ?? []).map(x => x.trim().toLowerCase());
  const bccFlat = (p.bcc ?? []).map(x => x.trim().toLowerCase());
  const payload: Record<string, unknown> = {
    subject: p.subject,
    to: toFlat,
  };
  if (p.text !== undefined) payload.text = p.text;
  if (p.html !== undefined) payload.html = p.html;
  if (p.reply_to !== undefined) payload.reply_to = p.reply_to;
  if (p.in_reply_to !== undefined) payload.in_reply_to = p.in_reply_to;
  if (p.references !== undefined) payload.references = p.references;
  if (ccFlat.length > 0) payload.cc = ccFlat;
  if (bccFlat.length > 0) payload.bcc = bccFlat;
  return actionFingerprint('send', payload);
}

function snapshotEnv(): () => void {
  const keys = [
    'YANDEX_DAILY_SEND_LIMIT',
    'YANDEX_PER_RECIPIENT_HOURLY',
    'YANDEX_DEDUP_WINDOW_SEC',
    'YANDEX_AUTH_LEVEL',
    'YANDEX_AUDIT_LOG',
    'YANDEX_STATE_DIR',
    'YANDEX_AUTO_TRUST_REPLY',
  ];
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) saved[k] = process.env[k];
  return () => {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  };
}

function setup(): { cleanup: () => void; tmpDir: string } {
  const restore = snapshotEnv();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-h2-'));
  process.env.YANDEX_STATE_DIR = tmpDir;
  // Disable auto-trust-on-reply -- not relevant to H-2 and would touch IMAP.
  process.env.YANDEX_AUTO_TRUST_REPLY = 'off';
  _resetGuards();
  _resetConfirm();
  _resetStateDir();
  _resetAllowlist();
  return {
    tmpDir,
    cleanup: () => {
      _resetGuards();
      _resetConfirm();
      _resetStateDir();
      _resetAllowlist();
      restore();
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
    },
  };
}

// -- Shared fixtures ------------------------------------------------------

const TRUSTED_ADDR = 'alice@trusted.com';

function trustRecipient(): void {
  addTrusted(TRUSTED_ADDR, 'session', 'h2_test_setup');
}

function makeSendParams(extra?: Partial<{
  subject: string;
  text: string;
  confirmation_token: string;
  dry_run: boolean;
}>): Record<string, unknown> {
  const base: Record<string, unknown> = {
    to: [TRUSTED_ADDR],
    subject: extra?.subject ?? 'H-2 fixture subject',
    text: extra?.text ?? 'H-2 fixture body',
  };
  if (extra?.confirmation_token !== undefined) base.confirmation_token = extra.confirmation_token;
  if (extra?.dry_run !== undefined) base.dry_run = extra.dry_run;
  return base;
}

// ── T-H2-01: daily limit exceeded MUST NOT burn confirmation code ─────────

test('T-H2-01: submit with token, daily limit exceeded -- code remains valid', async () => {
  const { cleanup } = setup();
  try {
    process.env.YANDEX_DAILY_SEND_LIMIT = '1';
    trustRecipient();

    // Drive daily counter to limit BEFORE calling the handler.
    getDailyCounter().record();

    const params = makeSendParams({ subject: 'T-H2-01' });
    const fp = fingerprintFor({
      to: [TRUSTED_ADDR],
      subject: 'T-H2-01',
      text: 'H-2 fixture body',
    });
    const { code } = generateCode(fp);

    const def = getSendTool();
    const result = await def.handler(
      { ...params, confirmation_token: code },
      mkCtx(2),
    );

    assert.equal(result.isError, true, 'handler must report error when guards block');
    // Load-bearing assertion: code MUST still be valid (not yet burned).
    // After the fix, enforceSendGuards runs BEFORE verifyCode, so the daily
    // guard rejects without ever consuming the code. Pre-fix this returns
    // 'used' because verifyCode already set entry.used = true.
    const recheck = verifyCode(fp, code);
    assert.equal(
      recheck,
      true,
      'guard-blocked submit MUST leave code valid (recheck returned ' + String(recheck) + ')',
    );
  } finally {
    cleanup();
  }
});

// ── T-H2-02: per-recipient rate exceeded MUST NOT burn confirmation code ──

test('T-H2-02: submit with token, per-recipient rate exceeded -- code remains valid', async () => {
  const { cleanup } = setup();
  try {
    process.env.YANDEX_PER_RECIPIENT_HOURLY = '1';
    trustRecipient();

    // Drive per-recipient bucket to limit.
    getPerRecipientCounter().record([TRUSTED_ADDR]);

    const params = makeSendParams({ subject: 'T-H2-02' });
    const fp = fingerprintFor({
      to: [TRUSTED_ADDR],
      subject: 'T-H2-02',
      text: 'H-2 fixture body',
    });
    const { code } = generateCode(fp);

    const def = getSendTool();
    const result = await def.handler(
      { ...params, confirmation_token: code },
      mkCtx(2),
    );

    assert.equal(result.isError, true);
    const recheck = verifyCode(fp, code);
    assert.equal(
      recheck,
      true,
      'per-recipient-blocked submit MUST leave code valid (got ' + String(recheck) + ')',
    );
  } finally {
    cleanup();
  }
});

// ── T-H2-03: dedup window hit MUST NOT burn confirmation code ─────────────

test('T-H2-03: submit with token, dedup window hit -- code remains valid', async () => {
  const { cleanup } = setup();
  try {
    process.env.YANDEX_DEDUP_WINDOW_SEC = '60';
    trustRecipient();

    const params = makeSendParams({ subject: 'T-H2-03' });
    const fp = fingerprintFor({
      to: [TRUSTED_ADDR],
      subject: 'T-H2-03',
      text: 'H-2 fixture body',
    });

    // Prime dedup for THIS fingerprint -- simulates "the same send was
    // already submitted recently and recorded by recordSend".
    getSendDedup().record(fp);

    const { code } = generateCode(fp);
    const def = getSendTool();
    const result = await def.handler(
      { ...params, confirmation_token: code },
      mkCtx(2),
    );

    assert.equal(result.isError, true);
    const recheck = verifyCode(fp, code);
    assert.equal(
      recheck,
      true,
      'dedup-blocked submit MUST leave code valid (got ' + String(recheck) + ')',
    );
  } finally {
    cleanup();
  }
});

// ── T-H2-04: guards pass + smtp fails -- code IS burned, recordSend NOT ──
//
// This case asserts the post-guard ordering invariant by surrogate: when
// enforceSendGuards returns ok=true the handler MUST proceed to verifyCode
// (mutator). We cannot easily reach a real SMTP failure in the bundled
// test environment, so we assert this property by source-grep of tools.ts:
// recordSend MUST be guarded by `if (r.success)` and MUST appear AFTER the
// sendEmail call. Combined with T-H2-06's line-order check that ensures
// verifyCode runs after guards-ok, this captures the contract:
//
//   guards.ok=true -> verifyCode -> sendEmail -> if(success) recordSend
//
// so a smtp_error trace produces {verify_succeeded} but NOT {record_send}.

test('T-H2-04: recordSend gated by r.success -- smtp_error path burns code but skips counter mutation', { skip: 'Phase 6 DEV-01: source-grep test retired; logic moved to send-pipeline.ts. T-PIPE-H2-REORDER-01 (Task 8) and the per-stage tests in send-pipeline.test.ts assert the runtime equivalent. The success-only mutation contract is enforced by the recordSend stage which only runs when ctx.sendResult.success === true.' }, () => {
  const src = readToolsSrc();
  const handlerStart = src.indexOf("name: 'yandex_send_email'");
  assert.ok(handlerStart >= 0, 'yandex_send_email handler must be locatable in tools.ts');
  const handlerEnd = src.indexOf("name: 'yandex_trust_address'", handlerStart);
  assert.ok(handlerEnd > handlerStart, 'next handler must follow yandex_send_email in tools.ts');
  const body = src.slice(handlerStart, handlerEnd);

  // recordSend MUST be inside a `if (r.success)` (or equivalent positive
  // success-branch guard). Match the exact pattern the handler ships with;
  // a structural mismatch indicates the success-only contract has drifted.
  const successGuardRe = /if\s*\(\s*r\.success\s*\)\s*\{[^}]*recordSend\s*\(/;
  assert.ok(
    successGuardRe.test(body),
    'recordSend MUST be inside a `if (r.success) { ... recordSend(...) }` block ' +
    '(smtp_error must not mutate counter / dedup state)',
  );

  // recordSend MUST appear AFTER sendEmail in source order.
  const sendIdx = body.search(/\bawait\s+sendEmail\s*\(/);
  const recordIdx = body.search(/\brecordSend\s*\(/);
  assert.ok(sendIdx >= 0, 'sendEmail call must exist in handler body');
  assert.ok(recordIdx >= 0, 'recordSend call must exist in handler body');
  assert.ok(
    sendIdx < recordIdx,
    'recordSend MUST appear AFTER sendEmail in source order (record only on success)',
  );
});

// ── T-H2-05: dry_run with guards-blocking state surfaces guard_violation ──

test('T-H2-05: dry_run with daily limit exceeded -- SendPlan carries guard_violation, NO confirmation_token', async () => {
  const { cleanup } = setup();
  try {
    process.env.YANDEX_DAILY_SEND_LIMIT = '1';
    trustRecipient();
    getDailyCounter().record(); // at limit.

    const def = getSendTool();
    const result = await def.handler(
      makeSendParams({ subject: 'T-H2-05', dry_run: true }),
      mkCtx(2),
    );

    assert.equal(result.isError, false, 'dry_run is informational -- not isError');
    // The SendPlan is delivered via structuredContent. Post-fix it MUST
    // include a guard_violation field describing the blocking reason.
    const sc = result.structuredContent as Record<string, unknown> | undefined;
    assert.ok(sc, 'dry_run MUST return structuredContent (SendPlan)');
    assert.equal(sc.dry_run, true, 'SendPlan.dry_run flag must be true');
    assert.ok(
      'guard_violation' in sc,
      'dry_run MUST surface guard_violation field when guards-pure detects a blocking state (Q1 = yes)',
    );
    const gv = sc.guard_violation as Record<string, unknown>;
    assert.equal(
      gv?.reason,
      'daily_send_limit_exceeded',
      'guard_violation.reason must echo the guards-pure verdict',
    );
    // Q2 = NO: do NOT pre-issue a confirmation_token for a doomed send.
    // The SendPlan emits action_fingerprint for user inspection, but no
    // confirmation_token field is generated -- user must fresh-dry_run
    // once the window clears.
    assert.ok(
      !('confirmation_token' in sc),
      'dry_run with guard_violation MUST NOT pre-issue a confirmation_token (Q2 = no)',
    );

    // Defence-in-depth: confirm no code was generated for this fingerprint
    // by trying to verify against a probe value -- 'wrong' means no entry
    // exists (B-2 invariant) which is exactly what we want here.
    const fp = fingerprintFor({
      to: [TRUSTED_ADDR],
      subject: 'T-H2-05',
      text: 'H-2 fixture body',
    });
    const probe = verifyCode(fp, '000000');
    assert.equal(
      probe,
      'wrong',
      'dry_run with guard_violation MUST NOT generate a code for the fingerprint',
    );
  } finally {
    cleanup();
  }
});

// ── T-H2-06: full pipeline ordering -- guards BEFORE verifyCode in BOTH branches

function readToolsSrc(): string {
  const candidates = [
    path.resolve(__dirname, '..', 'tools.ts'),
    path.resolve(__dirname, '..', '..', 'src', 'tools.ts'),
    path.resolve(process.cwd(), 'src', 'tools.ts'),
    path.resolve(process.cwd(), 'yandex-mail-mcp-desktop', 'src', 'tools.ts'),
  ];
  for (const p of candidates) {
    try { return fs.readFileSync(p, 'utf8'); } catch { /* try next */ }
  }
  throw new Error('tools.ts source not locatable from any candidate path');
}

test('T-H2-06: enforceSendGuards MUST appear BEFORE every verifyCode( call in yandex_send_email handler', { skip: 'Phase 6 DEV-01: source-grep test retired; logic moved to send-pipeline.ts (stage 8 enforceGuards runs BEFORE stage 9.1 verifyCode by pipeline order). T-PIPE-H2-REORDER-01 (Task 8) asserts the runtime invariant via loadCredentials/sendEmail spies (a stronger contract than source ordering).' }, () => {
  const src = readToolsSrc();

  // Slice the yandex_send_email handler body. The handler starts at
  // "name: 'yandex_send_email'" and ends at the next tool entry.
  const handlerStart = src.indexOf("name: 'yandex_send_email'");
  assert.ok(handlerStart >= 0, 'yandex_send_email handler must be locatable');
  const handlerEnd = src.indexOf("name: 'yandex_trust_address'", handlerStart);
  assert.ok(handlerEnd > handlerStart, 'next handler must follow yandex_send_email');
  const body = src.slice(handlerStart, handlerEnd);

  // Find ALL verifyCode( call sites and the (unique post-fix) enforceSendGuards call.
  const verifyOffsets: number[] = [];
  const verifyRe = /\bverifyCode\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = verifyRe.exec(body)) !== null) verifyOffsets.push(m.index);

  const guardOffsets: number[] = [];
  const guardRe = /\benforceSendGuards\s*\(/g;
  while ((m = guardRe.exec(body)) !== null) guardOffsets.push(m.index);

  assert.ok(
    verifyOffsets.length >= 2,
    'handler must have >= 2 verifyCode( call sites (token branch + elicit branch); found ' + verifyOffsets.length,
  );
  assert.ok(
    guardOffsets.length >= 1,
    'handler must have >= 1 enforceSendGuards call; found ' + guardOffsets.length,
  );

  // The load-bearing invariant: every verifyCode( call MUST be preceded by
  // SOME enforceSendGuards call in source order. (Post-fix the simplest
  // realization is a single guards check at the top of the post-dry-run
  // section; multiple guards calls are also acceptable as long as each
  // verifyCode is downstream of at least one.)
  const firstGuard = guardOffsets[0];
  for (const v of verifyOffsets) {
    assert.ok(
      v > firstGuard,
      'verifyCode( at handler-offset ' + v + ' MUST be downstream of enforceSendGuards ' +
      '(first guard at offset ' + firstGuard + '). H-2 invariant: pure guards run BEFORE ' +
      'the code-burn mutator in every branch.',
    );
  }

  // Also: enforceSendGuards MUST appear BEFORE the dry_run early-return,
  // OR the dry_run branch must contain its own guards check. We assert the
  // simpler equivalent: dry_run's buildSendPlan call site must be preceded
  // by an enforceSendGuards call (Q1 contract).
  const dryRunPlanIdx = body.indexOf('buildSendPlan(');
  assert.ok(dryRunPlanIdx >= 0, 'buildSendPlan call must exist (dry_run path)');
  assert.ok(
    dryRunPlanIdx > firstGuard,
    'buildSendPlan (dry_run) MUST run AFTER enforceSendGuards so the SendPlan ' +
    'can carry guard_violation/guard_status info (Q1 = yes)',
  );
});

// ── T-H2-07: L3 advisory mode -- guards.ok=false does NOT block; code IS used

test('T-H2-07: L3 advisory -- guards violation does NOT short-circuit before verifyCode', async () => {
  const { cleanup } = setup();
  try {
    process.env.YANDEX_DAILY_SEND_LIMIT = '1';
    trustRecipient();
    getDailyCounter().record(); // at limit -> guards return ok:false.

    const def = getSendTool();
    const params = makeSendParams({ subject: 'T-H2-07' });
    const fp = fingerprintFor({
      to: [TRUSTED_ADDR],
      subject: 'T-H2-07',
      text: 'H-2 fixture body',
    });
    const { code } = generateCode(fp);

    // At L3 the guards verdict is advisory: warn + fall through to send.
    // The handler MUST proceed past the guards block, hit verifyCode (the
    // code IS consumed at L3 because we're actually attempting the send),
    // and then attempt sendEmail (which will fail without real credentials).
    await def.handler(
      { ...params, confirmation_token: code },
      mkCtx(3),
    );

    // The load-bearing assertion: at L3, even with guards.ok=false, we
    // reached verifyCode -- so the code is now burned.
    const recheck = verifyCode(fp, code);
    assert.equal(
      recheck,
      'used',
      'at L3 (advisory), guards violation MUST NOT short-circuit -- verifyCode ' +
      'still runs and the code is burned (got ' + String(recheck) + ')',
    );
  } finally {
    cleanup();
  }
});

// ── T-H2-08: B-3 regression -- verifyCode body has 0 await tokens ─────────

test('T-H2-08: B-3 regression -- verifyCode body in confirm.ts still has 0 await tokens', () => {
  const candidates = [
    path.resolve(__dirname, '..', 'confirm.ts'),
    path.resolve(__dirname, '..', '..', 'src', 'confirm.ts'),
    path.resolve(process.cwd(), 'src', 'confirm.ts'),
    path.resolve(process.cwd(), 'yandex-mail-mcp-desktop', 'src', 'confirm.ts'),
  ];
  let src: string | null = null;
  for (const c of candidates) {
    try { src = fs.readFileSync(c, 'utf8'); break; } catch { /* try next */ }
  }
  assert.ok(src, 'confirm.ts source must be readable for B-3 regression check');

  const idx = src.indexOf('export function verifyCode');
  assert.ok(idx >= 0, 'verifyCode export must exist');
  const openBrace = src.indexOf('{', idx);
  let depth = 0;
  let end = -1;
  for (let i = openBrace; i < src.length; i++) {
    const ch = src[i];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) { end = i; break; }
    }
  }
  assert.ok(end > openBrace);
  const body = src.slice(openBrace, end);
  assert.ok(
    !/\bawait\b/.test(body),
    'B-3 invariant: verifyCode body must contain no await token (single-event-loop-turn critical section)',
  );

  // Defence-in-depth: H-2 fix MUST NOT have moved guards INTO confirm.ts.
  assert.ok(
    !/enforceSendGuards/.test(src),
    'confirm.ts MUST NOT reference enforceSendGuards (H-2 fix lives in tools.ts handler)',
  );
});

// Touch unused imports so linter does not strip them.
void recordSend;
void enforceSendGuards;
