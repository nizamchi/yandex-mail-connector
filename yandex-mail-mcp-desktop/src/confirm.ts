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

export function generateCode(fingerprint: string): { code: string; expiresAt: number } {
  const now = Date.now();
  reap(now);
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  const expiresAt = now + CODE_TTL_MS;
  codes.set(fingerprint, { code, expiresAt, used: false });
  return { code, expiresAt };
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
    return 'wrong';
  }
  if (!crypto.timingSafeEqual(a, b)) {
    recordFailure(fingerprint, now);
    return 'wrong';
  }
  // B-3 INVARIANT: critical section below runs synchronously in one event-loop
  // turn. NEVER introduce a yield-point (the four-letter keyword spelled
  // a-w-a-i-t) between the read of entry.used and the write entry.used = true.
  // Task 2 grep-checks this function body for that token.
  if (entry.used) return 'used';
  entry.used = true;
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
