// auto-trust-reply.test.ts -- TDD reproduction for HIGH H-1.
//
// Threat (per MILESTONE-v2.0.0-DEEP-REVIEW.md §H-1):
//   The yandex_send_email auto-trust block (tools.ts) calls
//   allowlist.addTrusted(found.from, 'auto', 'auto_trust_reply') as soon as
//   imap.findByMessageId() resolves a message-id -- regardless of WHICH folder
//   the message was found in. Because findByMessageId searches INBOX first
//   then Sent, an attacker who emails the user and persuades a prompt-injected
//   LLM to quote that email's message-id in `in_reply_to` can permanently
//   elevate themselves to the file-backed (scope='auto', persisted)
//   allowlist. The fresh entry then passes the very recipient gate that is
//   supposed to block it on the same call.
//
// Fix direction (preferred: (1)+(2)+(3) combined):
//   1. Sent-only auto-trust: only fire on findByMessageId resolutions that
//      came from the Sent folder. Inbound-only metadata is not trust evidence.
//   2. Session-scoped auto-trust: addTrusted(addr, 'session', ...) keeps the
//      entry in an in-memory Set; isAllowed() consults it; the entry is NEVER
//      written to allowlist.json. Blast radius: one process lifetime.
//   3. Opt-out env var: YANDEX_AUTO_TRUST_REPLY=off disables the entire
//      auto-trust block (defaults to 'on').
//
// Test seams introduced by the fix (asserted here so the fix MUST land them):
//   - allowlist.addTrusted(addr, 'session', source) -- in-memory only, no I/O.
//   - allowlist._listTrusted() -- returns persisted+session entries (Q1).
//   - allowlist.autoTrustOnReply(findResult, opts?) -- the policy helper that
//     encapsulates (1)+(2)+(3). tools.ts will call it instead of inlining.
//
// Invariants (must NOT regress):
//   - B-1 normalizeRecipients/addressparser-symmetric gate.
//   - Phase 1-8 invariants from earlier sessions.
//   - 127-test baseline (after B-1): this file adds 7 cases.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import * as allowlist from '../allowlist.js';
import {
  loadAllowlist,
  isAllowed,
  addTrusted,
  getAllowlistPath,
  _resetForTests,
} from '../allowlist.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';

// Optional helpers introduced by the H-1 fix. We import them via the namespace
// object so a missing symbol surfaces as `undefined` at runtime rather than a
// module-load failure -- which lets each test report a precise assertion
// rather than crashing the whole file.
type ListedEntry = { address: string; scope: string; source: string };
type FindResult = { from: string; folder: string; uid: number } | null;

interface AutoTrustModuleShape {
  autoTrustOnReply?: (
    found: FindResult,
    opts?: { onSkip?: (reason: string) => void },
  ) => void;
  _listTrusted?: () => ListedEntry[];
}

const ext = allowlist as unknown as AutoTrustModuleShape;

function mkTmpStateDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-h1-'));
  process.env.YANDEX_STATE_DIR = dir;
  delete process.env.YANDEX_AUTO_TRUST_REPLY;
  _resetStateDir();
  _resetForTests();
  return dir;
}

function cleanupTmpStateDir(dir: string): void {
  delete process.env.YANDEX_STATE_DIR;
  delete process.env.YANDEX_AUTO_TRUST_REPLY;
  _resetStateDir();
  _resetForTests();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// ── T-H1-01: INBOX source must NOT add trust ──────────────────────────────

test('T-H1-01: autoTrustOnReply on INBOX source -- sender MUST NOT be elevated', () => {
  const dir = mkTmpStateDir();
  try {
    assert.ok(
      typeof ext.autoTrustOnReply === 'function',
      'fix MUST export allowlist.autoTrustOnReply (the policy helper)',
    );

    let skipReason: string | null = null;
    ext.autoTrustOnReply!(
      { from: 'evil@attacker.com', folder: 'INBOX', uid: 42 },
      { onSkip: (r) => { skipReason = r; } },
    );

    assert.equal(
      isAllowed('evil@attacker.com'),
      false,
      'INBOX-source lookup must NOT elevate the sender (H-1 exploit defence)',
    );
    // The skip path must NOT write allowlist.json.
    assert.equal(
      fs.existsSync(getAllowlistPath()),
      false,
      'INBOX-source skip MUST NOT create or mutate allowlist.json',
    );
    assert.equal(
      skipReason,
      'inbox_source',
      'forensics: INBOX skip MUST report reason=inbox_source for audit trail (T-H1-07)',
    );
  } finally {
    cleanupTmpStateDir(dir);
  }
});

// ── T-H1-02: Sent source -> session-scoped, NOT persisted to disk ─────────

test('T-H1-02: autoTrustOnReply on Sent source -- trust added as scope=session, NOT persisted', () => {
  const dir = mkTmpStateDir();
  try {
    assert.ok(typeof ext.autoTrustOnReply === 'function', 'fix MUST export autoTrustOnReply');

    ext.autoTrustOnReply!({ from: 'contact@partner.com', folder: 'Sent', uid: 7 });

    assert.equal(
      isAllowed('contact@partner.com'),
      true,
      'Sent-source lookup MUST elevate the sender for the session',
    );

    // The session entry MUST NOT be written to allowlist.json. Either the
    // file does not exist OR it exists but does not contain this address.
    if (fs.existsSync(getAllowlistPath())) {
      const file = loadAllowlist();
      const persistedAddrs = file.entries.map(e => e.address);
      assert.ok(
        !persistedAddrs.includes('contact@partner.com'),
        'session-scoped entry MUST NOT be persisted to allowlist.json',
      );
    }
  } finally {
    cleanupTmpStateDir(dir);
  }
});

// ── T-H1-03: no message found -> no trust mutation ────────────────────────

test('T-H1-03: autoTrustOnReply(null) -- no trust added, no file mutation', () => {
  const dir = mkTmpStateDir();
  try {
    assert.ok(typeof ext.autoTrustOnReply === 'function', 'fix MUST export autoTrustOnReply');
    ext.autoTrustOnReply!(null);
    assert.equal(fs.existsSync(getAllowlistPath()), false, 'null lookup -> no file created');
    assert.equal(isAllowed('anyone@example.com'), false);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

// ── T-H1-04: session entry visible for process lifetime, gone after reset ──

test('T-H1-04: session entry observable to isAllowed; cleared by _resetForTests; visible to _listTrusted', () => {
  const dir = mkTmpStateDir();
  try {
    // Drive the session-scope behavior through the public addTrusted API --
    // the H-1 fix MUST accept scope='session' as "in-memory only".
    addTrusted('sessionish@partner.com', 'session', 'auto_trust_reply');
    assert.equal(isAllowed('sessionish@partner.com'), true);

    // Session scope MUST NOT touch allowlist.json. (No prior addTrusted with
    // a persisted scope ran in this test, so the file's existence is itself
    // a regression signal.)
    assert.equal(
      fs.existsSync(getAllowlistPath()),
      false,
      'scope=session addTrusted MUST NOT write allowlist.json (H-1 invariant)',
    );

    // Q1: _listTrusted MUST surface session entries with scope='session' so
    // the user has a UX channel to see ephemeral grants.
    assert.ok(
      typeof ext._listTrusted === 'function',
      'fix MUST export _listTrusted for visibility into session entries (Q1)',
    );
    const all = ext._listTrusted!();
    const found = all.find(e => e.address === 'sessionish@partner.com');
    assert.ok(found !== undefined, '_listTrusted must include the session entry');
    assert.equal(found?.scope, 'session', '_listTrusted must mark scope=session');

    // _resetForTests MUST clear the in-memory session store.
    _resetForTests();
    assert.equal(
      isAllowed('sessionish@partner.com'),
      false,
      '_resetForTests must clear the in-memory session store',
    );
  } finally {
    cleanupTmpStateDir(dir);
  }
});

// ── T-H1-05 (regression): permanent scope still persists + signs ──────────

test('T-H1-05: regression -- addTrusted(scope=permanent) still persists + signs', () => {
  const dir = mkTmpStateDir();
  try {
    addTrusted('manual@trusted.com', 'permanent', 'user_trust_token');
    assert.equal(isAllowed('manual@trusted.com'), true);
    assert.equal(fs.existsSync(getAllowlistPath()), true, 'permanent entries are persisted');
    const file = loadAllowlist();
    assert.ok(
      file.entries.some(e => e.address === 'manual@trusted.com' && e.scope === 'permanent'),
      'permanent entry written with original scope',
    );
  } finally {
    cleanupTmpStateDir(dir);
  }
});

// ── T-H1-06 (regression): B-1 invariants survive ──────────────────────────

test('T-H1-06: regression -- comma-smuggling defence (B-1) still operative', () => {
  // Lazy require so test loads even if recipients module moves.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { normalizeRecipients, countAddresses } = require('../recipients.js') as {
    normalizeRecipients: (a: string[]) => { addresses: string[]; normalized: string[] };
    countAddresses: (s: string) => number;
  };
  const r = normalizeRecipients(['Alice <alice@trusted.com>, attacker@evil.com']);
  assert.deepEqual(
    r.addresses.sort(),
    ['alice@trusted.com', 'attacker@evil.com'].sort(),
    'B-1: gate must still see both smuggled addresses',
  );
  for (const entry of r.normalized) {
    assert.equal(countAddresses(entry), 1);
  }
});

// ── T-H1-07: opt-out env disables the whole auto-trust block ──────────────

test('T-H1-07: YANDEX_AUTO_TRUST_REPLY=off -- no trust elevation even on Sent path', () => {
  const dir = mkTmpStateDir();
  try {
    process.env.YANDEX_AUTO_TRUST_REPLY = 'off';

    assert.ok(typeof ext.autoTrustOnReply === 'function', 'fix MUST export autoTrustOnReply');
    let skipReason: string | null = null;
    ext.autoTrustOnReply!(
      { from: 'contact@partner.com', folder: 'Sent', uid: 9 },
      { onSkip: (r) => { skipReason = r; } },
    );

    assert.equal(
      isAllowed('contact@partner.com'),
      false,
      'YANDEX_AUTO_TRUST_REPLY=off MUST short-circuit auto-trust entirely',
    );
    // Opt-out is silent (not a per-call skip -- it's a global policy gate).
    // We accept either no skip event OR a distinct reason; the load-bearing
    // assertion is non-elevation.
    if (skipReason !== null) {
      assert.notEqual(skipReason, 'inbox_source', 'opt-out is not an inbox_source skip');
    }
  } finally {
    cleanupTmpStateDir(dir);
  }
});
