// recent-sends.test.ts -- Phase 7 PMLF-CLI-02 buffer module + stage-10
// wiring integration tests (CONTEXT D17 #15-16 + Rev-2 patches).
//
// Coverage:
//   T-RECENT-01..05: append + rotate + readRecentSends + corrupt-line drop.
//   T-RECENT-03b (M1): refine count >= unique-domains rejects.
//   T-RECENT-05b (W1): version:2 line dropped on read.
//   T-RECENT-06..07: stage-10 recordSend wiring -- append on success only.
//   T-RECENT-08 (H2 rewritten): rotation-fail hook injection (no global
//   fs.renameSync monkey-patch).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  appendRecentSend,
  readRecentSends,
  _resetForTests as _resetRecent,
  _setRotationFailHookForTests,
  type RecentSendRecord,
} from '../recent-sends.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import { _resetForTests as _resetAllowlist, addTrusted } from '../allowlist.js';
import { recordSend, type SendContext } from '../send-pipeline.js';

function mkTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'y7-recent-'));
  process.env.YANDEX_STATE_DIR = dir;
  process.env.NODE_ENV = 'test';
  _resetStateDir();
  _resetAllowlist();
  _resetRecent();
  return dir;
}

function cleanup(dir: string): void {
  delete process.env.YANDEX_STATE_DIR;
  _resetStateDir();
  _resetAllowlist();
  _resetRecent();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

function mkRec(over: Partial<RecentSendRecord> = {}): RecentSendRecord {
  return {
    version: 1,
    ts: new Date().toISOString(),
    message_id: '<msgid@example.com>',
    recipients_count: 1,
    recipients_domains: ['example.com'],
    subject_hash: 'a'.repeat(16),
    body_length: 100,
    risk_tier: 'low',
    risk_score: 10,
    action_fingerprint: 'fp123abc',
    ...over,
  };
}

function bufferPath(dir: string): string {
  return path.join(dir, 'recent-sends.jsonl');
}

// -- T-RECENT-01 -------------------------------------------

test('T-RECENT-01: appendRecentSend creates file + writes valid JSONL with version:1', () => {
  const dir = mkTmpDir();
  try {
    appendRecentSend(mkRec({ message_id: '<one@x>' }));
    const p = bufferPath(dir);
    assert.ok(fs.existsSync(p), 'file should exist');
    const lines = fs.readFileSync(p, 'utf8').trim().split('\n');
    assert.equal(lines.length, 1);
    const parsed = JSON.parse(lines[0]!) as RecentSendRecord;
    assert.equal(parsed.version, 1);
    assert.equal(parsed.message_id, '<one@x>');
    if (process.platform !== 'win32') {
      const mode = fs.statSync(p).mode & 0o777;
      assert.equal(mode, 0o600, `expected mode 0o600; got ${mode.toString(8)}`);
    }
  } finally { cleanup(dir); }
});

// -- T-RECENT-02: rotation cap ----------------------------

test('T-RECENT-02: 51st append rotates -- file contains exactly 50 records', () => {
  const dir = mkTmpDir();
  try {
    for (let i = 0; i < 51; i++) {
      appendRecentSend(mkRec({ message_id: `<id-${i}@x>` }));
    }
    const records = readRecentSends();
    assert.equal(records.length, 50);
    // Oldest (id-0) dropped; newest (id-50) preserved.
    assert.equal(records[0]!.message_id, '<id-1@x>');
    assert.equal(records[49]!.message_id, '<id-50@x>');
  } finally { cleanup(dir); }
});

// -- T-RECENT-03: strict schema rejects extra fields ------

test('T-RECENT-03: appendRecentSend with extra field rejected by strict schema', () => {
  const dir = mkTmpDir();
  try {
    // Force an extra field by casting through unknown.
    const evil = { ...mkRec(), extra_field: 'malicious' } as unknown as RecentSendRecord;
    appendRecentSend(evil);
    assert.ok(!fs.existsSync(bufferPath(dir)), 'no file should have been written');
  } finally { cleanup(dir); }
});

// -- T-RECENT-03b (M1) ------------------------------------

test('T-RECENT-03b (M1): recipients_count=0 with recipients_domains=[a] rejected by refine', () => {
  const dir = mkTmpDir();
  try {
    appendRecentSend(mkRec({ recipients_count: 0, recipients_domains: ['a.com'] }));
    assert.ok(!fs.existsSync(bufferPath(dir)), 'no file should have been written');
  } finally { cleanup(dir); }
});

// -- T-RECENT-04: read ENOENT -> [] -----------------------

test('T-RECENT-04: readRecentSends with ENOENT returns []', () => {
  const dir = mkTmpDir();
  try {
    assert.deepEqual(readRecentSends(), []);
  } finally { cleanup(dir); }
});

// -- T-RECENT-05: corrupt line dropped ---------------------

test('T-RECENT-05: readRecentSends with one corrupt line drops it + returns good records', () => {
  const dir = mkTmpDir();
  try {
    const good = JSON.stringify(mkRec({ message_id: '<good@x>' }));
    const corrupt = '{not-valid-json';
    fs.writeFileSync(bufferPath(dir), good + '\n' + corrupt + '\n' + good + '\n');
    const records = readRecentSends();
    assert.equal(records.length, 2);
  } finally { cleanup(dir); }
});

// -- T-RECENT-05b (W1): version:2 dropped on read ---------

test('T-RECENT-05b (W1): readRecentSends drops version:2 line', () => {
  const dir = mkTmpDir();
  try {
    const v1 = JSON.stringify(mkRec({ message_id: '<v1@x>' }));
    // Hand-crafted v2 line (no schema yet exists). Must be dropped at version
    // gate even before strict parse.
    const v2 = JSON.stringify({ ...mkRec({ message_id: '<v2@x>' }), version: 2 });
    fs.writeFileSync(bufferPath(dir), v1 + '\n' + v2 + '\n');
    const records = readRecentSends();
    assert.equal(records.length, 1);
    assert.equal(records[0]!.message_id, '<v1@x>');
  } finally { cleanup(dir); }
});

// -- T-RECENT-06: stage-10 recordSend appends on success ---

function mkSendCtx(): SendContext {
  return {
    rawParams: {},
    authLevel: 2,
    nowMs: 1_700_000_000_000,
    input: {
      to: ['rec@example.com'],
      subject: 'Subject Test',
      text: 'Body text here',
      dry_run: false,
    } as SendContext['input'],
    recipients: {
      to: ['rec@example.com'],
      cc: [],
      bcc: [],
      all: ['rec@example.com'],
    },
    actionFingerprint: 'fp-stage10',
    sendResult: { success: true, messageId: '<m-stage10@x>' },
    confirmation: { tier: 'medium', score: 55 },
  };
}

test('T-RECENT-06: stage-10 recordSend on success appends one matching record', async () => {
  const dir = mkTmpDir();
  try {
    addTrusted('rec@example.com', 'permanent', 'sent_history');
    const ctx = mkSendCtx();
    await recordSend(ctx);
    const records = readRecentSends();
    assert.equal(records.length, 1);
    const rec = records[0]!;
    assert.equal(rec.version, 1);
    assert.equal(rec.message_id, '<m-stage10@x>');
    assert.equal(rec.recipients_count, 1);
    assert.deepEqual(rec.recipients_domains, ['example.com']);
    assert.equal(rec.risk_tier, 'medium');
    assert.equal(rec.risk_score, 55);
    assert.equal(rec.action_fingerprint, 'fp-stage' /* sliced to 8 */);
  } finally { cleanup(dir); }
});

// -- T-RECENT-07: pass-through branch (success=false) ------

test('T-RECENT-07: stage-10 recordSend on success=false does NOT append', async () => {
  const dir = mkTmpDir();
  try {
    const ctx = mkSendCtx();
    ctx.sendResult = { success: false, error: 'fake-failure' };
    await recordSend(ctx);
    assert.ok(!fs.existsSync(bufferPath(dir)), 'no file should have been written');
  } finally { cleanup(dir); }
});

// -- T-RECENT-08 (H2 rewritten): rotation-fail hook --------

test('T-RECENT-08 (H2): rotation-fail hook causes silent skip; recovery on next write', async () => {
  const dir = mkTmpDir();
  try {
    addTrusted('rec@example.com', 'permanent', 'sent_history');

    // First write: ok.
    appendRecentSend(mkRec({ message_id: '<first@x>' }));
    const after1 = fs.readFileSync(bufferPath(dir), 'utf8');
    assert.ok(after1.includes('<first@x>'));

    // Second write with hook throwing -- must not propagate.
    _setRotationFailHookForTests(() => { throw new Error('disk full'); });
    try {
      appendRecentSend(mkRec({ message_id: '<second@x>' }));
    } finally {
      _setRotationFailHookForTests(null);
    }
    // File unchanged (still has the first record only).
    const after2 = fs.readFileSync(bufferPath(dir), 'utf8');
    assert.ok(!after2.includes('<second@x>'), `second should be absent:\n${after2}`);
    assert.ok(after2.includes('<first@x>'), `first should still be present:\n${after2}`);

    // Third write after clearing hook: lands.
    appendRecentSend(mkRec({ message_id: '<third@x>' }));
    const after3 = fs.readFileSync(bufferPath(dir), 'utf8');
    assert.ok(after3.includes('<third@x>'), `third should land:\n${after3}`);
    assert.ok(after3.includes('<first@x>'), `first should still be present:\n${after3}`);
  } finally { cleanup(dir); }
});
