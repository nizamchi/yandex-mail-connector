// HMAC confirmation code service (Phase 4, AUTH-03/04/05).
//
// Why HMAC + per-fingerprint lockout + single-use:
//   The threat is a confused-deputy / prompt-injection L2 send. We bind a
//   6-digit user-visible code to a canonical fingerprint of the action+params
//   via HMAC over a process-local secret. The LLM cannot forge a token that
//   verifies — it would have to see the code out-of-band (elicit dialog,
//   stderr, or OS toast). Single-use prevents replay; per-fingerprint lockout
//   blunts brute force without enabling global DoS of the user.
//
//   Secret persistence across restarts is intentionally NOT implemented here —
//   deferred to Phase 5 (see CONTEXT.md > Deferred Ideas). Process-local
//   randomBytes(32) is sufficient because in-memory state is also lost on
//   restart; you cannot verify a code whose generator state no longer exists.
//
//   _*ForTests helpers are NOT part of the public API. Do not call from
//   src/tools.ts or src/index.ts. They exist so the test suite can fast-forward
//   expiry/lockout without depending on real wall-clock time.

import * as crypto from 'node:crypto';
import { auditLog } from './audit.js';
import type { RiskTier, RiskReason } from './risk-score.js';

export type VerifyResult = true | 'expired' | 'used' | 'locked' | 'wrong';

interface CodeEntry {
  code: string;
  expiresAt: number;
  used: boolean;
}

interface FailureEntry {
  timestamps: number[];
  lockoutUntil: number;
}

const SECRET: Buffer = crypto.randomBytes(32);
const CODE_TTL_MS = 5 * 60 * 1000;
const FAIL_WINDOW_MS = 60_000;
const LOCKOUT_MS = 5 * 60 * 1000;
const FAIL_THRESHOLD = 5;
const REAP_GRACE_MS = 60_000;

const codes: Map<string, CodeEntry> = new Map();
const failures: Map<string, FailureEntry> = new Map();

const ADDRESS_LIST_FIELDS = new Set(['to', 'cc', 'bcc', 'recipients']);

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === 'object') {
    const input = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(input).sort()) {
      let v = input[key];
      if (ADDRESS_LIST_FIELDS.has(key) && Array.isArray(v) && v.every(x => typeof x === 'string')) {
        v = [...(v as string[])].sort();
      }
      out[key] = canonicalize(v);
    }
    return out;
  }
  return value;
}

function reap(now: number): void {
  for (const [fp, entry] of codes) {
    if (entry.expiresAt + REAP_GRACE_MS < now) codes.delete(fp);
  }
  for (const [fp, entry] of failures) {
    if (entry.lockoutUntil + REAP_GRACE_MS < now && !codes.has(fp)) {
      failures.delete(fp);
    }
  }
}

function recordFailure(fp: string, now: number): void {
  let entry = failures.get(fp);
  if (!entry) {
    entry = { timestamps: [], lockoutUntil: 0 };
    failures.set(fp, entry);
  }
  entry.timestamps.push(now);
  entry.timestamps = entry.timestamps.filter(t => now - t <= FAIL_WINDOW_MS);
  if (entry.timestamps.length >= FAIL_THRESHOLD) {
    entry.lockoutUntil = now + LOCKOUT_MS;
    // Audit only the threshold-crossing event (NOT every failure beyond).
    // reason carries only the 8-hex fingerprint prefix — never the raw code,
    // never the SECRET buffer, never the full fingerprint hex.
    auditLog({
      action: 'lockout',
      status: 'denied',
      level: 'warn',
      ts: new Date().toISOString(),
      reason: 'fp=' + fp.slice(0, 8) + ',threshold=' + FAIL_THRESHOLD + ',window_ms=' + FAIL_WINDOW_MS,
    });
  }
}

export function actionFingerprint(action: string, params: Record<string, unknown>): string {
  const canonical = JSON.stringify(canonicalize(params));
  return crypto
    .createHmac('sha256', SECRET)
    .update(`${action}|${canonical}`)
    .digest('hex')
    .slice(0, 32);
}

// Back-compat path (callers that do NOT pass opts.score): reconstruct the
// score by SUM + clamp + round of reason weights. Acceptable for v2.1.0
// because Phase 4 v2.1.0 score is itself pure SUM + clamp + round. Any
// future Phase 4 revision that introduces diminishing returns or non-linear
// aggregation MUST pass opts.score to preserve audit-truth fidelity (REV 2
// W-1 / threat T-05-16).
function estimateScoreFromReasons(rs: RiskReason[]): number {
  const sum = rs.reduce((s, r) => s + (r.weight | 0), 0);
  return Math.max(0, Math.min(100, Math.round(sum)));
}

// Phase 5 generateCode (D1, D2 rev 1 amended, D6, D8, D10, REV 2 W-1).
//
// Backwards compatibility (D8): a caller that omits opts entirely (v2.0.0
// callers, Phase 1/2/3 callers) gets identical v2.0.0 behavior:
//   - audit record has EXACTLY 5 keys (action/status/level/ts/reason);
//     NO risk_score / risk_reasons / risk_tier emitted on 'low' tier.
//   - return shape has { code, expiresAt, tier: 'low' } -- tier is NEW but
//     defaults to 'low'; reasons[] is OMITTED (not undefined-as-key) on low.
//   - stderr emission: NONE on low.
//   - HMAC code TTL / lockout / fail threshold / reap grace: UNCHANGED.
//
// Block tier (D2 row 4): returns { code: null, expiresAt: 0, tier: 'block',
//   reasons } and emits a denied/warn audit + risk_block stderr.
//
// REV 2 B-1/B-2: medium/high/block return shape includes reasons[] (frozen)
// for the Phase 6 elicit consumer to render the prompt without an out-of-
// band channel. Detail strings stay IN-PROCESS; the audit boundary still
// receives signal IDs only (privacy carry from Phase 4 D10).
export function generateCode(
  fingerprint: string,
  opts?: {
    riskTier?: RiskTier;
    reasons?: RiskReason[];
    score?: number;
    // REV 3 WR-06: optional riskFingerprint for block-tier stderr. Phase 5
    // callers do NOT have this -- the block-tier stderr emits a
    // <RISK_FINGERPRINT> placeholder and the operator obtains the real
    // value from the Phase 6 audit / dry_run output. Phase 6 callers wire
    // computeRiskFingerprint(action, params, score) into this opt so the
    // operator sees the exact riskFingerprint that consumeOverrideToken
    // will look up. The previous behavior (embedding `fingerprint` --
    // which is actionFingerprint) caused a latent UX failure: operator
    // copy-pastes actionFingerprint into --high-risk-send, mint binds to
    // actionFingerprint, Phase 6 consume looks up by riskFingerprint and
    // MISSES with reason='unknown'.
    riskFingerprint?: string;
  },
): {
  code: string | null;
  expiresAt: number;
  tier: RiskTier;
  reasons?: readonly RiskReason[];
} {
  const tier: RiskTier = opts?.riskTier ?? 'low';
  const reasons: RiskReason[] = opts?.reasons ?? [];
  const explicitScore: number | undefined = opts?.score;
  const riskFingerprintOpt: string | undefined = opts?.riskFingerprint;
  const now = Date.now();
  reap(now);

  // Score resolution: explicit score (Phase 4 truth) wins; otherwise
  // estimate by SUM of reason weights (back-compat fallback).
  const auditScore: number =
    explicitScore !== undefined
      ? Math.max(0, Math.min(100, Math.round(explicitScore)))
      : estimateScoreFromReasons(reasons);

  // BLOCK BRANCH: early-exit, no code minted (D2 row 4).
  if (tier === 'block') {
    auditLog({
      action: 'code_generated',
      status: 'denied',
      level: 'warn',
      ts: new Date().toISOString(),
      reason: 'fp=' + fingerprint.slice(0, 8) + ',risk_block',
      risk_score: auditScore,
      risk_reasons: reasons.map(r => r.signal),
      risk_tier: 'block',
    });
    // REV 3 WR-06: emit riskFingerprint when caller supplied one (Phase 6
    // send-pipeline wiring); otherwise emit a <RISK_FINGERPRINT> placeholder
    // (Phase 5 callers, which do not yet have a riskFingerprint available).
    // The earlier behavior of embedding `fingerprint` (actionFingerprint) was
    // a latent UX failure: copy-pasting it into --high-risk-send would mint
    // a record bound to actionFingerprint, while Phase 6 consume looks up by
    // riskFingerprint -> reason='unknown'. See SUMMARY follow-up section.
    const riskFpForStderr = riskFingerprintOpt ?? '<RISK_FINGERPRINT>';
    process.stderr.write(
      '[yandex-mail-mcp] risk_block: send refused. Run\n' +
      '  yandex-mail-mcp-trust --high-risk-send=' + riskFpForStderr + '\n' +
      '  to mint a single-use override token (TTL 30 min).\n' +
      '[yandex-mail-mcp] risk signals: ' + reasons.map(r => r.signal).join(', ') + '\n'
    );
    return {
      code: null,
      expiresAt: 0,
      tier: 'block',
      reasons: Object.freeze(reasons.slice()),
    };
  }

  // Code mint (shared by low / medium / high).
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  const expiresAt = now + CODE_TTL_MS;
  codes.set(fingerprint, { code, expiresAt, used: false });

  // LOW BRANCH: v2.0.0 parity (D8). NO stderr, NO risk fields in audit,
  // NO reasons in return shape.
  if (tier === 'low') {
    auditLog({
      action: 'code_generated',
      status: 'success',
      level: 'info',
      ts: new Date().toISOString(),
      reason: 'fp=' + fingerprint.slice(0, 8) + ',ttl_sec=' + Math.round(CODE_TTL_MS / 1000),
    });
    return { code, expiresAt, tier: 'low' };
  }

  // MEDIUM / HIGH BRANCH: per-tier stderr + risk fields in audit + reasons echo.
  // PRIVACY: signalIds map is canonical IDs only. reasons.detail NEVER passes
  // through the audit boundary. The full reasons[] (with detail) is echoed in
  // the return shape for the in-process Phase 6 elicit consumer (D2 rev 1).
  const signalIds = reasons.map(r => r.signal);
  if (tier === 'medium') {
    process.stderr.write(
      '[yandex-mail-mcp] medium-risk send -- review signals before approving: ' +
      signalIds.join(', ') + '\n'
    );
  } else if (tier === 'high') {
    process.stderr.write(
      '[yandex-mail-mcp] high-risk send: please type the 6-digit code manually; do not paste.\n' +
      '[yandex-mail-mcp] risk signals: ' + signalIds.join(', ') + '\n'
    );
  }
  auditLog({
    action: 'code_generated',
    status: 'success',
    level: 'info',
    ts: new Date().toISOString(),
    reason: 'fp=' + fingerprint.slice(0, 8) + ',ttl_sec=' + Math.round(CODE_TTL_MS / 1000),
    risk_score: auditScore,
    risk_reasons: signalIds,
    risk_tier: tier,
  });
  return {
    code,
    expiresAt,
    tier,
    reasons: Object.freeze(reasons.slice()),
  };
}

export function verifyCode(fingerprint: string, code: string): VerifyResult {
  const now = Date.now();
  reap(now);

  const entry = codes.get(fingerprint);
  // B-2: unknown fingerprint MUST NOT touch failures map (prevents memory
  // explosion from attacker probing random fingerprints).
  if (!entry) return 'wrong';

  const failure = failures.get(fingerprint);
  if (failure && failure.lockoutUntil > now) return 'locked';

  if (entry.expiresAt < now) return 'expired';

  // Timing-safe compare. Length mismatch → counts as 'wrong'.
  const a = Buffer.from(entry.code);
  const b = Buffer.from(code);
  if (a.length !== b.length) {
    recordFailure(fingerprint, now);
    auditLog({
      action: 'verify_failed',
      status: 'denied',
      level: 'warn',
      ts: new Date().toISOString(),
      reason: 'fp=' + fingerprint.slice(0, 8) + ',mode=length',
    });
    return 'wrong';
  }
  if (!crypto.timingSafeEqual(a, b)) {
    recordFailure(fingerprint, now);
    auditLog({
      action: 'verify_failed',
      status: 'denied',
      level: 'warn',
      ts: new Date().toISOString(),
      reason: 'fp=' + fingerprint.slice(0, 8) + ',mode=mismatch',
    });
    return 'wrong';
  }
  // B-3 INVARIANT: critical section below runs synchronously in one event-loop
  // turn. NEVER introduce a yield-point (the four-letter keyword spelled
  // a-w-a-i-t) between the read of entry.used and the write entry.used = true.
  // Task 2 grep-checks this function body for that token.
  // auditLog is sync (void return; enqueues internally) — safe to call here.
  if (entry.used) return 'used';
  entry.used = true;
  auditLog({
    action: 'verify_succeeded',
    status: 'success',
    level: 'info',
    ts: new Date().toISOString(),
    reason: 'fp=' + fingerprint.slice(0, 8),
  });
  return true;
}

export function _resetForTests(): void {
  codes.clear();
  failures.clear();
}

export function _expireForTests(fingerprint: string): void {
  const e = codes.get(fingerprint);
  // Use Date.now() - 1 so the entry is past expiry but still within the reap
  // grace window — reap() only purges entries older than expiresAt + 60s.
  if (e) e.expiresAt = Date.now() - 1;
}

export function _expireLockoutForTests(fingerprint: string): void {
  const e = failures.get(fingerprint);
  if (e) {
    e.lockoutUntil = 0;
    e.timestamps = [];
  }
}

export function _internalFailuresSize(): number {
  return failures.size;
}
