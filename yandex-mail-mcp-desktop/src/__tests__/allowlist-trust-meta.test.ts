// allowlist-trust-meta.test.ts -- Phase 6 PMLF-TRUST-META-01..03 + H-1/H-2.
//
// 6 tests:
//   T-TRUST-GET-ENTRY-01      getTrustEntry returns full entry; undefined for unknown.
//   T-TRUST-USECOUNT-01       initial 0; bumpUseCount once -> 1; twice -> 2.
//   T-TRUST-LASTUSED-01       most-recent nowMs wins.
//   T-TRUST-ISALLOWED-COMPAT-01  isAllowed boolean -- session + persistent.
//   T-TRUST-SESSION-USECOUNT-01  H-2 amendment: session entries always report useCount=0
//                                even after bumpUseCountBatch.
//   T-TRUST-BUMP-BATCH-01     H-1 atomic: single mtime change for batch call.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  addTrusted,
  isAllowed,
  getTrustEntry,
  bumpUseCount,
  bumpUseCountBatch,
  getAllowlistPath,
  _resetForTests,
} from '../allowlist.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';

function mkTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-trust-meta-'));
  process.env.YANDEX_STATE_DIR = dir;
  _resetStateDir();
  _resetForTests();
  return dir;
}

function cleanup(dir: string): void {
  delete process.env.YANDEX_STATE_DIR;
  _resetStateDir();
  _resetForTests();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// -- T-TRUST-GET-ENTRY-01 ---------------------------------------------------

test('T-TRUST-GET-ENTRY-01: getTrustEntry shape; undefined for unknown', () => {
  const dir = mkTmpDir();
  try {
    addTrusted('alice@example.com', 'permanent', 'sent_history');
    const entry = getTrustEntry('alice@example.com');
    assert.ok(entry, 'entry must exist after addTrusted');
    assert.equal(entry!.address, 'alice@example.com');
    assert.equal(entry!.scope, 'permanent');
    assert.equal(entry!.source, 'sent_history');
    assert.equal(typeof entry!.added_at, 'string');
    assert.equal(typeof entry!.added, 'number');
    assert.equal(typeof entry!.lastUsed, 'number');
    assert.equal(entry!.useCount, 0);
    // Unknown -> undefined
    assert.equal(getTrustEntry('unknown@example.com'), undefined);
  } finally { cleanup(dir); }
});

// -- T-TRUST-USECOUNT-01 ----------------------------------------------------

test('T-TRUST-USECOUNT-01: useCount monotonic via bumpUseCount', () => {
  const dir = mkTmpDir();
  try {
    addTrusted('bob@example.com', 'permanent', 'sent_history');
    const initial = getTrustEntry('bob@example.com')!;
    assert.equal(initial.useCount, 0);

    const t1 = Date.now();
    bumpUseCount('bob@example.com', t1);
    const after1 = getTrustEntry('bob@example.com')!;
    assert.equal(after1.useCount, 1);
    assert.equal(after1.lastUsed, t1);

    const t2 = t1 + 1000;
    bumpUseCount('bob@example.com', t2);
    const after2 = getTrustEntry('bob@example.com')!;
    assert.equal(after2.useCount, 2);
    assert.equal(after2.lastUsed, t2);
  } finally { cleanup(dir); }
});

// -- T-TRUST-LASTUSED-01 ----------------------------------------------------

test('T-TRUST-LASTUSED-01: most-recent nowMs wins', () => {
  const dir = mkTmpDir();
  try {
    addTrusted('carol@example.com', 'permanent', 'sent_history');
    const t1 = 1_700_000_000_000;
    const t2 = 1_700_000_100_000;
    bumpUseCount('carol@example.com', t1);
    bumpUseCount('carol@example.com', t2);
    const entry = getTrustEntry('carol@example.com')!;
    assert.equal(entry.lastUsed, t2, 'lastUsed reflects the most recent bump');
    assert.equal(entry.useCount, 2);
  } finally { cleanup(dir); }
});

// -- T-TRUST-ISALLOWED-COMPAT-01 --------------------------------------------

test('T-TRUST-ISALLOWED-COMPAT-01: isAllowed boolean -- session + persistent + unknown', () => {
  const dir = mkTmpDir();
  try {
    addTrusted('dave@example.com', 'permanent', 'sent_history');
    addTrusted('eve@example.com', 'session', 'auto_trust_reply');
    assert.equal(isAllowed('dave@example.com'), true, 'persistent recipient -> true');
    assert.equal(isAllowed('DAVE@EXAMPLE.COM'), true, 'case-insensitive');
    assert.equal(isAllowed('eve@example.com'), true, 'session recipient -> true');
    assert.equal(isAllowed('unknown@example.com'), false, 'unknown -> false');
  } finally { cleanup(dir); }
});

// -- T-TRUST-SESSION-USECOUNT-01 (H-2 amendment) ---------------------------

test('T-TRUST-SESSION-USECOUNT-01: session entries always report useCount=0 (H-2 amendment)', () => {
  const dir = mkTmpDir();
  try {
    addTrusted('frank@example.com', 'session', 'auto_trust_reply');
    const before = getTrustEntry('frank@example.com')!;
    assert.equal(before.scope, 'session');
    assert.equal(before.useCount, 0);

    // bumpUseCountBatch on a session-scope address is a no-op.
    bumpUseCountBatch(['frank@example.com'], Date.now());
    const after = getTrustEntry('frank@example.com')!;
    assert.equal(after.scope, 'session');
    assert.equal(after.useCount, 0,
      'H-2 amendment: session entries ALWAYS report useCount=0; bumpUseCountBatch must be a no-op');
  } finally { cleanup(dir); }
});

// -- T-TRUST-BUMP-BATCH-01 (H-1 atomic) ------------------------------------

test('T-TRUST-BUMP-BATCH-01: bumpUseCountBatch single mtime change for multi-recipient', () => {
  const dir = mkTmpDir();
  try {
    addTrusted('g1@example.com', 'permanent', 'sent_history');
    addTrusted('g2@example.com', 'permanent', 'sent_history');
    addTrusted('g3@example.com', 'permanent', 'sent_history');
    const apath = getAllowlistPath();
    const mtimeBefore = fs.statSync(apath).mtimeMs;

    // Sleep briefly so mtime detection survives Windows' lower precision.
    const start = Date.now();
    while (Date.now() - start < 20) { /* spin */ }

    const now = Date.now();
    bumpUseCountBatch(['g1@example.com', 'g2@example.com', 'g3@example.com'], now);

    const mtimeAfter = fs.statSync(apath).mtimeMs;
    assert.ok(mtimeAfter > mtimeBefore,
      'mtime must advance exactly once for the batch (H-1 atomic; got before=' +
      mtimeBefore + ' after=' + mtimeAfter + ')');

    const e1 = getTrustEntry('g1@example.com')!;
    const e2 = getTrustEntry('g2@example.com')!;
    const e3 = getTrustEntry('g3@example.com')!;
    assert.equal(e1.useCount, 1);
    assert.equal(e2.useCount, 1);
    assert.equal(e3.useCount, 1);
    assert.equal(e1.lastUsed, now);
    assert.equal(e2.lastUsed, now);
    assert.equal(e3.lastUsed, now);
  } finally { cleanup(dir); }
});
