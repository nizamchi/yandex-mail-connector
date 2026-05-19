// audit.test.ts — Phase 6 unit tests for src/audit.ts.
//
// Coverage:
//   1.  SchemaValidation — valid record round-trips through JSON line.
//   2.  EnvOff_NoOp — YANDEX_AUDIT_LOG=off produces no file.
//   3.  CustomPath — YANDEX_AUDIT_LOG=<path> overrides default.
//   4.  Mode0600 — POSIX-only file-permission check.
//   5.  Rotation — oversized file is renamed to .1 on first write.
//   6.  RotationOverwritesPriorOne — existing .1 is replaced.
//   7.  Redaction_ForbiddenKeys — secrets are stripped + redacted[] populated.
//   8.  Hook2_EmailActionMissingMessageId — stderr violation + warn record.
//   9.  Hook2_NonEmailAction_NoViolation — list_folders without message_id ok.
//   10. QueueOrdering — 50 records appear in enqueue order.
//   11. SchemaInvalid_NoCrash_NoWrite — invalid input is stderr-logged only.
//
// All tests sandbox YANDEX_STATE_DIR + YANDEX_AUDIT_LOG so the real config
// directory is never touched. Each test resets module state via
// _resetForTests() (audit + state-dir).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  auditLog,
  _drainForTests,
  _resetForTests as _resetAudit,
} from '../audit.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';

// ── Test scaffolding ──────────────────────────────────────

let _tmpCounter = 0;
function makeSandbox(): string {
  _tmpCounter++;
  const dir = path.join(
    os.tmpdir(),
    'audit-test-' + Date.now() + '-' + _tmpCounter,
  );
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function snapshotEnv(): () => void {
  const keys = ['YANDEX_STATE_DIR', 'YANDEX_AUDIT_LOG', 'YANDEX_AUDIT_LOG_MAX_MB'];
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) saved[k] = process.env[k];
  return () => {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  };
}

function resetAll(): void {
  _resetAudit();
  _resetStateDir();
}

function captureStderr(): { restore: () => void; lines: string[] } {
  const lines: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  // Monkey-patch process.stderr.write to capture. Cast through unknown to
  // satisfy the overloaded signature without using `any`.
  (process.stderr as unknown as { write: (s: string) => boolean }).write =
    (s: string): boolean => {
      lines.push(String(s));
      return true;
    };
  return {
    restore: () => {
      (process.stderr as unknown as { write: typeof original }).write = original;
    },
    lines,
  };
}

const ISO = (): string => new Date().toISOString();

// ── Tests ─────────────────────────────────────────────────

test('SchemaValidation: valid record writes one JSON line', async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  process.env.YANDEX_STATE_DIR = sandbox;
  delete process.env.YANDEX_AUDIT_LOG;
  delete process.env.YANDEX_AUDIT_LOG_MAX_MB;
  resetAll();
  try {
    auditLog({ action: 'sample', status: 'success', level: 'info', ts: ISO() });
    await _drainForTests();
    const p = path.join(sandbox, 'audit.jsonl');
    const lines = fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean);
    assert.equal(lines.length, 1, 'one line written');
    const rec = JSON.parse(lines[0]) as Record<string, unknown>;
    assert.equal(rec.action, 'sample');
    assert.equal(rec.status, 'success');
    assert.equal(rec.level, 'info');
    assert.equal(typeof rec.ts, 'string');
  } finally {
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('EnvOff_NoOp: YANDEX_AUDIT_LOG=off produces no file', async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  process.env.YANDEX_STATE_DIR = sandbox;
  process.env.YANDEX_AUDIT_LOG = 'off';
  resetAll();
  try {
    auditLog({ action: 'should-noop', status: 'success', level: 'info', ts: ISO() });
    await _drainForTests();
    const p = path.join(sandbox, 'audit.jsonl');
    assert.equal(fs.existsSync(p), false, 'audit.jsonl must not exist');
  } finally {
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('CustomPath: YANDEX_AUDIT_LOG=<path> overrides default', async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  const custom = path.join(sandbox, 'custom-audit.jsonl');
  process.env.YANDEX_STATE_DIR = sandbox;
  process.env.YANDEX_AUDIT_LOG = custom;
  resetAll();
  try {
    auditLog({ action: 'sample', status: 'success', level: 'info', ts: ISO() });
    await _drainForTests();
    assert.equal(fs.existsSync(custom), true, 'custom path must exist');
    assert.equal(
      fs.existsSync(path.join(sandbox, 'audit.jsonl')),
      false,
      'default path must NOT exist',
    );
  } finally {
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('Mode0600: POSIX file permissions are 0o600', { skip: process.platform === 'win32' }, async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  process.env.YANDEX_STATE_DIR = sandbox;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    auditLog({ action: 'sample', status: 'success', level: 'info', ts: ISO() });
    await _drainForTests();
    const p = path.join(sandbox, 'audit.jsonl');
    const st = fs.statSync(p);
    assert.equal(st.mode & 0o777, 0o600);
  } finally {
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('Rotation: oversized file is renamed to .1 on first write', async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  process.env.YANDEX_STATE_DIR = sandbox;
  delete process.env.YANDEX_AUDIT_LOG;
  // Pre-seed audit.jsonl with content larger than max.
  const p = path.join(sandbox, 'audit.jsonl');
  // Use YANDEX_AUDIT_LOG_MAX_MB=0 → clamped to default; instead write > 10MB
  // would be wasteful. We bypass clamp by using a moderate-size file and
  // setting YANDEX_AUDIT_LOG_MAX_MB to a small positive fractional value.
  // 0.0001 MB = ~100 bytes is below the clamp (n > 0 passes), so clamp keeps it.
  process.env.YANDEX_AUDIT_LOG_MAX_MB = '0.0001';
  const seedContent = 'x'.repeat(500); // 500 bytes > 100 bytes threshold
  fs.writeFileSync(p, seedContent);
  resetAll();
  try {
    auditLog({ action: 'after-rotate', status: 'success', level: 'info', ts: ISO() });
    await _drainForTests();
    const prior = path.join(sandbox, 'audit.jsonl.1');
    assert.equal(fs.existsSync(prior), true, 'audit.jsonl.1 must exist');
    const newContent = fs.readFileSync(p, 'utf-8');
    assert.ok(newContent.length < 500, 'new audit.jsonl is small');
    assert.ok(newContent.includes('after-rotate'), 'new record is present');
    const priorContent = fs.readFileSync(prior, 'utf-8');
    assert.equal(priorContent, seedContent, 'prior content moved to .1');
  } finally {
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('RotationOverwritesPriorOne: existing .1 is replaced', async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  process.env.YANDEX_STATE_DIR = sandbox;
  delete process.env.YANDEX_AUDIT_LOG;
  process.env.YANDEX_AUDIT_LOG_MAX_MB = '0.0001';
  const p = path.join(sandbox, 'audit.jsonl');
  const prior = path.join(sandbox, 'audit.jsonl.1');
  // Pre-seed BOTH the current and the prior file. The "new" oversized content
  // in audit.jsonl must overwrite the prior .1 on rotation.
  fs.writeFileSync(prior, 'old-prior-content');
  const currentContent = 'y'.repeat(500);
  fs.writeFileSync(p, currentContent);
  resetAll();
  try {
    auditLog({ action: 'trigger', status: 'success', level: 'info', ts: ISO() });
    await _drainForTests();
    const priorAfter = fs.readFileSync(prior, 'utf-8');
    assert.equal(priorAfter, currentContent, '.1 was overwritten with current content');
  } finally {
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('Redaction_ForbiddenKeys: secrets stripped, redacted[] populated', async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  process.env.YANDEX_STATE_DIR = sandbox;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    auditLog({
      action: 'sample',
      status: 'success',
      level: 'info',
      ts: ISO(),
      body: 'secret-body',
      subject: 'secret-subject',
      oauth_token: 'AAAA',
      confirmation_token: '123456',
      trust_token: 'deadbeef',
      password: 'pw',
      secret: 's',
      code: '654321',
      access_token: 'tok',
      app_password: 'app',
    } as unknown);
    await _drainForTests();
    const p = path.join(sandbox, 'audit.jsonl');
    const lines = fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean);
    assert.equal(lines.length, 1);
    const rec = JSON.parse(lines[0]) as Record<string, unknown>;
    const forbidden = [
      'body', 'subject', 'oauth_token', 'confirmation_token', 'trust_token',
      'password', 'secret', 'code', 'access_token', 'app_password',
    ];
    for (const k of forbidden) {
      assert.equal(rec[k], undefined, `${k} must be absent`);
    }
    const redacted = rec.redacted as string[];
    assert.ok(Array.isArray(redacted), 'redacted[] is an array');
    for (const k of forbidden) {
      assert.ok(redacted.includes(k), `redacted[] contains ${k}`);
    }
  } finally {
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('Hook2_EmailActionMissingMessageId: stderr violation + warn record', async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  process.env.YANDEX_STATE_DIR = sandbox;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  const cap = captureStderr();
  try {
    auditLog({ action: 'yandex_get_email', status: 'success', level: 'info', ts: ISO() });
    await _drainForTests();
    cap.restore();
    const violation = cap.lines.find(l => l.includes('schema-violation') && l.includes('yandex_get_email'));
    assert.ok(violation, 'schema-violation stderr line captured');
    const p = path.join(sandbox, 'audit.jsonl');
    const lines = fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean);
    assert.equal(lines.length, 1, 'record still appended');
    const rec = JSON.parse(lines[0]) as Record<string, unknown>;
    assert.equal(rec.level, 'warn', 'level forced to warn');
    const redacted = rec.redacted as string[];
    assert.ok(Array.isArray(redacted) && redacted.includes('hook2_missing_message_id'), 'hook2 marker in redacted');
  } finally {
    cap.restore();
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('Hook2_NonEmailAction_NoViolation: list_folders without message_id is fine', async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  process.env.YANDEX_STATE_DIR = sandbox;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  const cap = captureStderr();
  try {
    auditLog({ action: 'yandex_list_folders', status: 'success', level: 'info', ts: ISO() });
    await _drainForTests();
    cap.restore();
    const violation = cap.lines.find(l => l.includes('schema-violation'));
    assert.equal(violation, undefined, 'no schema-violation stderr line');
    const p = path.join(sandbox, 'audit.jsonl');
    const lines = fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean);
    const rec = JSON.parse(lines[0]) as Record<string, unknown>;
    assert.equal(rec.level, 'info', 'level stays info');
  } finally {
    cap.restore();
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('QueueOrdering: 50 records appear in enqueue order', async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  process.env.YANDEX_STATE_DIR = sandbox;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    for (let i = 0; i < 50; i++) {
      auditLog({ action: 'order', status: 'success', level: 'info', ts: ISO(), reason: 'n=' + i });
    }
    await _drainForTests();
    const p = path.join(sandbox, 'audit.jsonl');
    const lines = fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean);
    assert.equal(lines.length, 50, '50 lines written');
    for (let i = 0; i < 50; i++) {
      const rec = JSON.parse(lines[i]) as Record<string, unknown>;
      assert.equal(rec.reason, 'n=' + i, 'record ' + i + ' in order');
    }
  } finally {
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});

test('SchemaInvalid_NoCrash_NoWrite: invalid input is stderr-logged only', async () => {
  const restore = snapshotEnv();
  const sandbox = makeSandbox();
  process.env.YANDEX_STATE_DIR = sandbox;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  const cap = captureStderr();
  try {
    // action is wrong type (number); schema parse must fail.
    auditLog({ action: 12345 } as unknown);
    await _drainForTests();
    cap.restore();
    const invalid = cap.lines.find(l => l.includes('schema-invalid'));
    assert.ok(invalid, 'schema-invalid stderr line captured');
    const p = path.join(sandbox, 'audit.jsonl');
    assert.equal(fs.existsSync(p), false, 'no audit.jsonl created');
  } finally {
    cap.restore();
    restore();
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
});
