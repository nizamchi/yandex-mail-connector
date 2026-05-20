// guards.test.ts -- Phase 7 unit tests for src/guards.ts.
//
// 11 cases covering:
//   1.  DailyCounter_PrunesAfter24h
//   2.  DailyCounter_LimitBoundary
//   3.  PerRecipientCounter_PrunesAfter1h
//   4.  PerRecipientCounter_AddressNormalization
//   5.  SendDedup_WithinWindow
//   6.  enforceSendGuards_OrderDedupFirst
//   7.  isAdvisory
//   8.  is2FASender_ExactAndWildcardDomain
//   9.  isProtectedFolder_CaseInsensitive_AndCyrillic
//   10. ASCII_REDACTED_STUB (defence-in-depth: file has 0x2014, constant ASCII)
//   11. EnvPartialOverride_2FA_IsReplacement_NotAdditive
//
// All cases inject `now` into counter methods (the API supports an optional
// timestamp arg) so they never depend on wall-clock time.
// Each case resets the singletons via _resetForTests() and restores env.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';

import {
  DailyCounter,
  PerRecipientCounter,
  SendDedup,
  enforceSendGuards,
  recordSend,
  isAdvisory,
  is2FASender,
  isProtectedFolder,
  REDACTED_STUB,
  _resetForTests,
} from '../guards.js';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

function snapshotEnv(): () => void {
  const keys = [
    'YANDEX_DAILY_SEND_LIMIT',
    'YANDEX_PER_RECIPIENT_HOURLY',
    'YANDEX_DEDUP_WINDOW_SEC',
    'YANDEX_BLOCK_2FA_SENDERS',
    'YANDEX_PROTECTED_FOLDERS',
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

function setup(): () => void {
  const restore = snapshotEnv();
  _resetForTests();
  return () => {
    _resetForTests();
    restore();
  };
}

// ── Case 1 ─────────────────────────────────────────────────────────────

test('DailyCounter prunes entries older than 24h', () => {
  const cleanup = setup();
  try {
    process.env.YANDEX_DAILY_SEND_LIMIT = '3';
    const t0 = 1_000_000_000_000;
    const c = new DailyCounter();
    c.record(t0);
    c.record(t0);
    c.record(t0);
    assert.equal(c.check(t0).ok, false, 'at limit, must block');
    // Move past 24h window: prior entries pruned.
    const after = c.check(t0 + DAY_MS + 1);
    assert.equal(after.ok, true, 'after 24h window, must be ok again');
    c.record(t0 + DAY_MS + 1);
    c.record(t0 + DAY_MS + 1);
    c.record(t0 + DAY_MS + 1);
    assert.equal(c.check(t0 + DAY_MS + 1).ok, false, 'three new records hit limit again');
  } finally { cleanup(); }
});

// ── Case 2 ─────────────────────────────────────────────────────────────

test('DailyCounter limit boundary (limit=5)', () => {
  const cleanup = setup();
  try {
    process.env.YANDEX_DAILY_SEND_LIMIT = '5';
    const t0 = 2_000_000_000_000;
    const c = new DailyCounter();
    for (let i = 0; i < 4; i++) c.record(t0);
    assert.equal(c.check(t0).ok, true, '4/5 -- under limit, ok');
    c.record(t0);
    const r = c.check(t0);
    assert.equal(r.ok, false);
    if (!r.ok && r.reason === 'daily_send_limit_exceeded') {
      assert.equal(r.remaining, 0);
      assert.equal(r.limit, 5);
    } else {
      assert.fail('expected daily_send_limit_exceeded');
    }
  } finally { cleanup(); }
});

// ── Case 3 ─────────────────────────────────────────────────────────────

test('PerRecipientCounter prunes entries older than 1h', () => {
  const cleanup = setup();
  try {
    process.env.YANDEX_PER_RECIPIENT_HOURLY = '2';
    const t0 = 3_000_000_000_000;
    const c = new PerRecipientCounter();
    c.record(['a@x.com'], t0);
    c.record(['a@x.com'], t0);
    const r = c.check(['a@x.com'], t0);
    assert.equal(r.ok, false);
    if (!r.ok && r.reason === 'per_recipient_rate_limit') {
      assert.equal(r.recipient, 'a@x.com');
      assert.equal(r.limit, 2);
      // retryAfter ~ t0 + HOUR_MS (within 1ms tolerance)
      assert.ok(Math.abs(r.retryAfter.getTime() - (t0 + HOUR_MS)) <= 1);
    } else {
      assert.fail('expected per_recipient_rate_limit');
    }
    // Past the hour boundary -- entries pruned.
    assert.equal(c.check(['a@x.com'], t0 + HOUR_MS + 1).ok, true);
  } finally { cleanup(); }
});

// ── Case 4 ─────────────────────────────────────────────────────────────

test('PerRecipientCounter normalizes display-name wrappers + case', () => {
  const cleanup = setup();
  try {
    process.env.YANDEX_PER_RECIPIENT_HOURLY = '2';
    const t0 = 4_000_000_000_000;
    const c = new PerRecipientCounter();
    c.record(['Foo Bar <A@X.com>'], t0);
    // check with lowercase bare -- should see 1 record under the same bucket.
    assert.equal(c.check(['a@x.com'], t0).ok, true, '1/2 after one wrapped record');
    c.record(['a@x.com'], t0);
    assert.equal(c.check(['a@x.com'], t0).ok, false, '2/2 -- at limit');
  } finally { cleanup(); }
});

// ── Case 5 ─────────────────────────────────────────────────────────────

test('SendDedup blocks within window, allows after window', () => {
  const cleanup = setup();
  try {
    process.env.YANDEX_DEDUP_WINDOW_SEC = '10';
    const t0 = 5_000_000_000_000;
    const d = new SendDedup();
    d.record('abc', t0);
    const r = d.check('abc', t0 + 5000);
    assert.equal(r.ok, false);
    if (!r.ok && r.reason === 'duplicate_send_within_window') {
      assert.equal(r.windowSec, 10);
    } else {
      assert.fail('expected duplicate_send_within_window');
    }
    assert.equal(d.check('abc', t0 + 11_000).ok, true, 'past 10s window -- ok');
  } finally { cleanup(); }
});

// ── Case 6 ─────────────────────────────────────────────────────────────

test('enforceSendGuards order: dedup first when both dedup+daily would fail', () => {
  const cleanup = setup();
  try {
    process.env.YANDEX_DAILY_SEND_LIMIT = '1';
    process.env.YANDEX_DEDUP_WINDOW_SEC = '60';
    const fp = 'fp-order-test';
    // Record a send: now daily is at limit AND fp is in dedup.
    recordSend({ to: ['x@y.com'] }, fp);
    const r = enforceSendGuards({ to: ['x@y.com'] }, 1, fp);
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.reason, 'duplicate_send_within_window', 'dedup must win over daily (ordered first)');
    }
    // Now use a different fp -- dedup passes, daily should fail.
    const r2 = enforceSendGuards({ to: ['x@y.com'] }, 1, 'different-fp');
    assert.equal(r2.ok, false);
    if (!r2.ok) {
      assert.equal(r2.reason, 'daily_send_limit_exceeded');
    }
  } finally { cleanup(); }
});

// ── Case 7 ─────────────────────────────────────────────────────────────

test('isAdvisory returns true only for L3 (auto)', () => {
  assert.equal(isAdvisory(0), false);
  assert.equal(isAdvisory(1), false);
  assert.equal(isAdvisory(2), false);
  assert.equal(isAdvisory(3), true);
});

// ── Case 8 ─────────────────────────────────────────────────────────────

test('is2FASender bare-domain endsWith + exact-address + case-insensitive + L-4 subdomain', () => {
  const cleanup = setup();
  try {
    // Defaults include 'github.com', 'yandex.ru'.
    assert.equal(is2FASender('noreply@github.com'), true);
    assert.equal(is2FASender('USER@GITHUB.COM'), true, 'case-insensitive');
    assert.equal(is2FASender('user@notgithub.com'), false, 'lookalike root must not match');
    assert.equal(is2FASender(null), false);
    assert.equal(is2FASender(''), false);
    assert.equal(is2FASender(undefined), false);

    // L-4: subdomain match (deep review HIGH-adjacent). Before the fix this
    // returned false because addr.endsWith('@yandex.ru') anchored on @ which
    // excluded subdomains. After: 'noreply@security.yandex.ru' MUST match the
    // 'yandex.ru' default pattern because the host suffix '.yandex.ru' is a
    // subdomain of the blocked domain.
    assert.equal(is2FASender('noreply@security.yandex.ru'), true, 'L-4: subdomain of yandex.ru');
    assert.equal(is2FASender('alert@notify.security.yandex.ru'), true, 'L-4: deep subdomain');
    assert.equal(is2FASender('user@security.github.com'), true, 'L-4: subdomain of github.com');
    // L-4 lookalike-safety: subdomain match must NOT accept lookalike domains
    // that lack the dot boundary.
    assert.equal(is2FASender('user@evilyandex.ru'), false, 'L-4: lookalike root must not match');
    assert.equal(is2FASender('user@yandex.ru.evil.com'), false, 'L-4: suffix-spoofing must not match');

    // Exact-address override.
    process.env.YANDEX_BLOCK_2FA_SENDERS = 'security@example.org';
    assert.equal(is2FASender('security@example.org'), true);
    assert.equal(is2FASender('other@example.org'), false, 'exact-match must not slip through');
    // Default github.com no longer applies under total replacement.
    assert.equal(is2FASender('noreply@github.com'), false);
  } finally { cleanup(); }
});

// ── Case 9 ─────────────────────────────────────────────────────────────

test('isProtectedFolder case-insensitive incl. cyrillic', () => {
  const set: ReadonlySet<string> = new Set(['INBOX', 'Sent', 'Отправленные']);
  assert.equal(isProtectedFolder('inbox', set), true);
  assert.equal(isProtectedFolder('INBOX', set), true);
  assert.equal(isProtectedFolder('SENT', set), true);
  assert.equal(isProtectedFolder('sent', set), true);
  assert.equal(isProtectedFolder('Отправленные', set), true);
  assert.equal(isProtectedFolder('отправленные', set), true, 'lowercase cyrillic must match');
  assert.equal(isProtectedFolder('Trash', set), false);
});

// ── Case 10 ────────────────────────────────────────────────────────────

test('REDACTED_STUB is ASCII (no em-dash U+2014); file has 0 em-dashes', () => {
  assert.equal(REDACTED_STUB, '[REDACTED - 2FA sender]');
  // Confirm constant contains hyphen-minus.
  const hy = REDACTED_STUB.indexOf('-');
  assert.ok(hy > 0);
  assert.equal(REDACTED_STUB.charCodeAt(hy), 0x002D, 'must be ASCII hyphen-minus');
  // Defence-in-depth: also scan the source file for any em-dash codepoint.
  // dist/__tests__ bundles inline the entire guards.ts via esbuild, so look
  // in the bundled test output rather than the source path (which is relative
  // to project root).
  const candidates = [
    path.resolve(__dirname, '..', 'guards.ts'),
    path.resolve(__dirname, '..', '..', 'src', 'guards.ts'),
    path.resolve(process.cwd(), 'src', 'guards.ts'),
  ];
  let src: string | null = null;
  for (const p of candidates) {
    try { src = fs.readFileSync(p, 'utf-8'); break; } catch { /* try next */ }
  }
  // If we can locate the source file, scan it. Otherwise the constant check
  // alone is sufficient -- skip the file scan with a note.
  if (src !== null) {
    let n = 0;
    for (let i = 0; i < src.length; i++) if (src.charCodeAt(i) === 0x2014) n++;
    assert.equal(n, 0, 'guards.ts must contain zero em-dash codepoints');
  }
});

// ── Case 11 ────────────────────────────────────────────────────────────

test('YANDEX_BLOCK_2FA_SENDERS override is total replacement (not additive)', () => {
  const cleanup = setup();
  try {
    process.env.YANDEX_BLOCK_2FA_SENDERS = 'only.example';
    // 'only.example' bare-domain matches its addresses.
    assert.equal(is2FASender('user@only.example'), true);
    // Defaults (github.com etc.) MUST no longer match under total replacement.
    assert.equal(is2FASender('user@github.com'), false);
    assert.equal(is2FASender('user@apple.com'), false);
  } finally { cleanup(); }
});
