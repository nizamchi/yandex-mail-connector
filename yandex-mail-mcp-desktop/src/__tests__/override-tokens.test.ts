// override-tokens.test.ts -- Phase 5 Layer D override-token system tests.
//
// REV 2 patch summary (test count 8 -> 10):
//   - B-3 split: T-OVERRIDE-FORGE-01 -> T-OVERRIDE-FORGE-TOKEN-HASH-01
//     (lookup-miss path, no FATAL) + T-OVERRIDE-FORGE-NONCE-01 (HMAC
//     re-derivation FATAL via _setFatalHooksForTests).
//   - B-4: NEW T-OVERRIDE-RACE-01 (Promise.all concurrent consume,
//     single-winner enforced by re-read-before-rewrite race guard).
//   - W-3: T-OVERRIDE-FINGERPRINT-PRIVACY-01 -- function-body extract
//     grep over riskFingerprint asserts bodyLength count >=1 AND bare-
//     body count === 0.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  mintOverrideToken,
  consumeOverrideToken,
  loadOverrideTokens,
  riskFingerprint,
  _resetForTests as _resetOverride,
  _setFatalHooksForTests,
} from '../override-tokens.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import { _resetForTests as _resetPolicy } from '../policy.js';
import { _resetForTests as _resetAudit } from '../audit.js';

// -- Helpers ------------------------------------------------

const VALID_FP = 'abcdef0123456789abcdef0123456789';
const OTHER_FP = '0123456789abcdef0123456789abcdef';

let _tmpCounter = 0;
function tmpStateDir(): string {
  _tmpCounter++;
  const dir = path.join(
    os.tmpdir(),
    'override-tokens-test-' + Date.now() + '-' + _tmpCounter,
  );
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function snapshotEnv(): () => void {
  const keys = ['YANDEX_STATE_DIR', 'YANDEX_AUDIT_LOG'];
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
  _resetOverride();
  _resetStateDir();
  _resetPolicy();
  _resetAudit();
}

// W-3: extract a function body from a source string by counting balanced
// braces, starting at the function declaration. Returns "" if not found.
function extractFnBody(source: string, fnName: string): string {
  const re = new RegExp(
    '(?:^|\\n)\\s*(?:export\\s+)?function\\s+' + fnName + '\\b[^{]*\\{',
    'm',
  );
  const m = source.match(re);
  if (!m) return '';
  const startIdx = m.index! + m[0].length;
  let depth = 1;
  for (let i = startIdx; i < source.length; i++) {
    const ch = source[i];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) {
        // Strip // line comments before returning.
        const body = source.slice(startIdx, i);
        return body.replace(/\/\/[^\n]*/g, '');
      }
    }
  }
  return '';
}

function locateSource(rel: string): string {
  const candidates = [
    path.resolve(process.cwd(), rel),
    path.resolve(__dirname, '../../', rel),
    path.resolve(__dirname, '../../../', rel),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return fs.readFileSync(c, 'utf-8');
  }
  throw new Error('source not found: ' + rel);
}

// -- Tests --------------------------------------------------

test('T-OVERRIDE-MINT-01: mint returns 64-hex token, JSONL has 1 record (token_hash != raw, nonce 8 hex)', () => {
  const restoreEnv = snapshotEnv();
  const stateDir = tmpStateDir();
  process.env.YANDEX_STATE_DIR = stateDir;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    const before = Date.now();
    const result = mintOverrideToken(VALID_FP);
    const after = Date.now();
    assert.match(result.token, /^[0-9a-f]{64}$/);
    assert.equal(result.fingerprint, VALID_FP);
    assert.ok(result.expiresAtMs > before + 29 * 60_000);
    assert.ok(result.expiresAtMs <= after + 30 * 60_000 + 5_000);
    const p = path.join(stateDir, 'override-tokens.jsonl');
    assert.ok(fs.existsSync(p));
    const lines = fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean);
    assert.equal(lines.length, 1);
    const rec = JSON.parse(lines[0]!) as Record<string, unknown>;
    assert.equal(rec.fingerprint, VALID_FP);
    assert.equal(rec.used_at_ms, null);
    assert.notEqual(rec.token_hash, result.token);  // stored hash != raw token
    assert.match(rec.token_hash as string, /^[0-9a-f]{32}$/);
    assert.match(rec.nonce as string, /^[0-9a-f]{8}$/);
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-OVERRIDE-CONSUME-01: consume returns ok and marks used_at_ms', () => {
  const restoreEnv = snapshotEnv();
  const stateDir = tmpStateDir();
  process.env.YANDEX_STATE_DIR = stateDir;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    const { token } = mintOverrideToken(VALID_FP);
    const result = consumeOverrideToken(VALID_FP, token);
    assert.equal(result.ok, true);
    const p = path.join(stateDir, 'override-tokens.jsonl');
    const lines = fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean);
    const rec = JSON.parse(lines[0]!) as Record<string, unknown>;
    assert.notEqual(rec.used_at_ms, null);
    assert.equal(typeof rec.used_at_ms, 'number');
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-OVERRIDE-REPLAY-01: second consume returns {ok:false, reason:used} (single-use)', () => {
  const restoreEnv = snapshotEnv();
  const stateDir = tmpStateDir();
  process.env.YANDEX_STATE_DIR = stateDir;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    const { token } = mintOverrideToken(VALID_FP);
    const r1 = consumeOverrideToken(VALID_FP, token);
    assert.equal(r1.ok, true);
    const r2 = consumeOverrideToken(VALID_FP, token);
    assert.equal(r2.ok, false);
    if (r2.ok === false) assert.equal(r2.reason, 'used');
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-OVERRIDE-WRONG-FINGERPRINT-01: consume with mismatched FP returns wrong_fingerprint and does NOT mark used', () => {
  const restoreEnv = snapshotEnv();
  const stateDir = tmpStateDir();
  process.env.YANDEX_STATE_DIR = stateDir;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    const { token } = mintOverrideToken(VALID_FP);
    const r = consumeOverrideToken(OTHER_FP, token);
    assert.equal(r.ok, false);
    if (r.ok === false) assert.equal(r.reason, 'wrong_fingerprint');
    const p = path.join(stateDir, 'override-tokens.jsonl');
    const lines = fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean);
    const rec = JSON.parse(lines[0]!) as Record<string, unknown>;
    assert.equal(rec.used_at_ms, null);
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-OVERRIDE-FORGE-TOKEN-HASH-01: tampered token_hash -> lookup miss -> unknown, NO FATAL (REV 2 B-3 split)', () => {
  const restoreEnv = snapshotEnv();
  const stateDir = tmpStateDir();
  process.env.YANDEX_STATE_DIR = stateDir;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  const fatalSink = { calls: [] as { code: number }[], stderr: '' };
  const undoFatal = _setFatalHooksForTests({
    exit: ((code: number) => {
      fatalSink.calls.push({ code });
      throw new Error('FATAL invoked unexpectedly with code ' + code);
    }) as (code: number) => never,
    stderr: (msg: string) => { fatalSink.stderr += msg; },
  });
  try {
    const { token } = mintOverrideToken(VALID_FP);
    // Tamper token_hash on disk.
    const p = path.join(stateDir, 'override-tokens.jsonl');
    const rec = JSON.parse(fs.readFileSync(p, 'utf-8').trim()) as Record<string, unknown>;
    const orig = rec.token_hash as string;
    rec.token_hash = (orig[0] === '0' ? '1' : '0') + orig.slice(1);
    fs.writeFileSync(p, JSON.stringify(rec) + '\n', { mode: 0o600 });
    // Force re-load of disk cache.
    _resetOverride();
    const result = consumeOverrideToken(VALID_FP, token);
    assert.equal(result.ok, false);
    if (result.ok === false) assert.equal(result.reason, 'unknown');
    assert.equal(fatalSink.calls.length, 0, 'FATAL must NOT be triggered on tampered-token_hash branch');
  } finally {
    undoFatal();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-OVERRIDE-FORGE-NONCE-01: tampered nonce -> lookup hit -> HMAC mismatch -> FATAL fires (REV 2 B-3 NEW)', () => {
  const restoreEnv = snapshotEnv();
  const stateDir = tmpStateDir();
  process.env.YANDEX_STATE_DIR = stateDir;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  const fatalSink = { calls: [] as { code: number }[], stderr: '' };
  const undoFatal = _setFatalHooksForTests({
    exit: ((code: number) => {
      fatalSink.calls.push({ code });
      // Throw to break out of the consume function without actually exiting.
      throw new Error('__FATAL_EXIT_FROM_TEST__');
    }) as (code: number) => never,
    stderr: (msg: string) => { fatalSink.stderr += msg; },
  });
  try {
    const { token } = mintOverrideToken(VALID_FP);
    // Tamper ONLY the nonce. token_hash stays valid (so lookup HITS by hash),
    // but HMAC re-derivation over the new nonce will produce a different hash.
    const p = path.join(stateDir, 'override-tokens.jsonl');
    const rec = JSON.parse(fs.readFileSync(p, 'utf-8').trim()) as Record<string, unknown>;
    const origNonce = rec.nonce as string;
    // Bit-flip every hex char of the nonce while keeping it 8 hex chars.
    let tamperedNonce = '';
    for (const ch of origNonce) {
      tamperedNonce += ch === '0' ? '1' : '0';
    }
    rec.nonce = tamperedNonce;
    fs.writeFileSync(p, JSON.stringify(rec) + '\n', { mode: 0o600 });
    _resetOverride();
    let threw = false;
    try {
      consumeOverrideToken(VALID_FP, token);
    } catch (e) {
      threw = true;
      assert.equal((e as Error).message, '__FATAL_EXIT_FROM_TEST__');
    }
    assert.ok(threw, 'consumeOverrideToken should hit the FATAL path');
    assert.equal(fatalSink.calls.length, 1);
    assert.equal(fatalSink.calls[0]!.code, 1);
    assert.match(fatalSink.stderr, /override-tokens\.jsonl/);
    assert.match(fatalSink.stderr, /token_hash signature mismatch/);
  } finally {
    undoFatal();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-OVERRIDE-RACE-01: concurrent Promise.all consume -- exactly one ok, one used (REV 2 B-4)', async () => {
  const restoreEnv = snapshotEnv();
  const stateDir = tmpStateDir();
  process.env.YANDEX_STATE_DIR = stateDir;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    const { token } = mintOverrideToken(VALID_FP);
    const [r1, r2] = await Promise.all([
      Promise.resolve().then(() => consumeOverrideToken(VALID_FP, token)),
      Promise.resolve().then(() => consumeOverrideToken(VALID_FP, token)),
    ]);
    const outcomes = [r1, r2];
    const oks = outcomes.filter((r) => r.ok === true);
    const used = outcomes.filter((r) => r.ok === false && r.reason === 'used');
    assert.equal(oks.length, 1, 'exactly ONE concurrent consume must win');
    assert.equal(used.length, 1, 'the other must be rejected as used');
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-OVERRIDE-PERSIST-01: token survives process-restart simulation (write, _resetForTests, loadOverrideTokens, consume)', () => {
  const restoreEnv = snapshotEnv();
  const stateDir = tmpStateDir();
  process.env.YANDEX_STATE_DIR = stateDir;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    const { token } = mintOverrideToken(VALID_FP);
    // Simulate process restart: drop in-memory cache.
    _resetOverride();
    // Fresh load -> consume should still succeed.
    loadOverrideTokens();
    const result = consumeOverrideToken(VALID_FP, token);
    assert.equal(result.ok, true);
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-OVERRIDE-FINGERPRINT-PRIVACY-01: riskFingerprint function body has 0 bare-body reads, >=1 bodyLength reads (REV 2 W-3)', () => {
  const src = locateSource('src/override-tokens.ts');
  const fnBody = extractFnBody(src, 'riskFingerprint');
  assert.ok(fnBody.length > 0, 'riskFingerprint function body not found');
  const bodyMatches = fnBody.match(/\bbody\b(?!Length)/g) || [];
  assert.equal(
    bodyMatches.length,
    0,
    'riskFingerprint must not read bare body; only bodyLength. Matches: ' + JSON.stringify(bodyMatches),
  );
  const bodyLengthMatches = fnBody.match(/\bbodyLength\b/g) || [];
  assert.ok(
    bodyLengthMatches.length >= 1,
    'riskFingerprint must read bodyLength per D4 (count=' + bodyLengthMatches.length + ')',
  );

  // Smoke test that riskFingerprint produces a 32-hex string.
  const fp = riskFingerprint(
    'send',
    { recipients: ['a@x.com', 'b@y.com'], subject: 'hello', bodyLength: 100 },
    50,
  );
  assert.match(fp, /^[0-9a-f]{32}$/);
});

test('T-OVERRIDE-EXPIRY-01: expired token returns {ok:false, reason:expired}', () => {
  const restoreEnv = snapshotEnv();
  const stateDir = tmpStateDir();
  process.env.YANDEX_STATE_DIR = stateDir;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    // Mint, then rewrite the JSONL with an artificially-past expires_at_ms.
    const { token } = mintOverrideToken(VALID_FP);
    const p = path.join(stateDir, 'override-tokens.jsonl');
    const rec = JSON.parse(fs.readFileSync(p, 'utf-8').trim()) as Record<string, unknown>;
    rec.expires_at_ms = Date.now() - 1000;
    // Keep within GC grace (1d) so the prune doesn't drop it.
    rec.minted_at_ms = Date.now() - 60_000;
    fs.writeFileSync(p, JSON.stringify(rec) + '\n', { mode: 0o600 });
    _resetOverride();
    const result = consumeOverrideToken(VALID_FP, token);
    assert.equal(result.ok, false);
    if (result.ok === false) assert.equal(result.reason, 'expired');
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});
