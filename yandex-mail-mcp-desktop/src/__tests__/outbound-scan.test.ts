// outbound-scan.test.ts -- Phase 2 Plan 02-01 unit tests.
//
// This file is built up across two tasks of plan 02-01:
//   T-02-01-03: perf harness (T-PERF-EMPTY-001 / 002 / 003).
//   T-02-01-04: preprocessing + summary + REDACTED-MATCH + policy-wiring (5 more).
//
// Per-test isolation via mkTmpStateDir / cleanupTmpStateDir which reset
// outbound-scan, policy, state-dir, and audit subsystems.
//
// ASCII-only. ESM `.js` suffix on imports. No emojis.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  scanOutbound,
  _resetForTests as _resetOutboundScan,
} from '../outbound-scan.js';
import {
  loadPolicy,
  _resetForTests as _resetPolicy,
} from '../policy.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import {
  _resetForTests as _resetAudit,
  _drainForTests as _drainAudit,
} from '../audit.js';

// -- Helpers ---------------------------------------------------------

function mkTmpStateDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-outbound-scan-'));
  process.env.YANDEX_STATE_DIR = dir;
  delete process.env.YANDEX_POLICY_FILE;
  _resetStateDir();
  _resetPolicy();
  _resetOutboundScan();
  _resetAudit();
  return dir;
}

function cleanupTmpStateDir(dir: string): void {
  delete process.env.YANDEX_POLICY_FILE;
  delete process.env.YANDEX_STATE_DIR;
  delete process.env.YANDEX_AUDIT_LOG;
  delete process.env.YANDEX_SCAN_DEBUG;
  _resetOutboundScan();
  _resetPolicy();
  _resetStateDir();
  _resetAudit();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// Deterministic 100 KB body: mix of ASCII + Cyrillic + ZWSP + Unicode tag char.
// No Math.random -- byte budget is fixed at ~100 KB Buffer.byteLength.
function syntheticBody100KB(): string {
  // Building blocks: 1) ASCII run, 2) Cyrillic run (2 bytes/char), 3) ZWSP
  // injection, 4) Unicode tag injection. Cycle until Buffer.byteLength close
  // to 100 KB.
  const ascii = 'lorem ipsum dolor sit amet ';        // 27 bytes
  const cyr = 'тест абв проверка строки ';            // ~46 bytes (mostly 2-byte)
  const zwsp = '\u{200B}';                            // 3 bytes UTF-8
  const tag = '\u{E0041}';                            // 4 bytes UTF-8
  const block = ascii + cyr + zwsp + tag;
  // Block is ~80 bytes; repeat 1300 times -> ~104 KB.
  let s = '';
  for (let i = 0; i < 1300; i++) s += block;
  return s;
}

// -- Perf tests (T-02-01-03) -----------------------------------------

test('T-PERF-EMPTY-001: scanOutbound completes 100 KB synthetic body in < 50 ms (empty registry)', () => {
  const dir = mkTmpStateDir();
  try {
    // Defence-in-depth: ensure registry is empty even if a side-effect import
    // populated it.
    _resetOutboundScan();
    loadPolicy();

    const body = syntheticBody100KB();
    const bodyBytes = Buffer.byteLength(body, 'utf8');
    assert.ok(bodyBytes > 80_000 && bodyBytes < 200_000, `body byte length ${bodyBytes} out of band`);

    const start = process.hrtime.bigint();
    const result = scanOutbound({ body });
    const end = process.hrtime.bigint();
    const elapsedMs = Number(end - start) / 1_000_000;

    process.stderr.write(`[T-PERF-EMPTY-001] elapsed_ms=${elapsedMs.toFixed(2)} bodyBytes=${bodyBytes}\n`);

    if (elapsedMs > 40) {
      process.stderr.write(`[T-PERF-EMPTY-001] WARN: elapsed_ms=${elapsedMs.toFixed(2)} exceeded soft 40ms warn band\n`);
    }
    assert.ok(elapsedMs < 50, `scanOutbound on 100 KB body took ${elapsedMs.toFixed(2)} ms (budget < 50)`);
    assert.deepEqual(result.hits, []);
    assert.equal(result.totalScore, 0);
    assert.equal(result.summary, '');
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-PERF-01-002: perf harness self-test (tiny body, near-instant)', () => {
  const dir = mkTmpStateDir();
  try {
    _resetOutboundScan();
    loadPolicy();

    const start = process.hrtime.bigint();
    const result = scanOutbound({ body: 'hello world' });
    const end = process.hrtime.bigint();
    const elapsedMs = Number(end - start) / 1_000_000;

    assert.ok(elapsedMs < 10, `tiny body took ${elapsedMs.toFixed(2)} ms`);
    assert.deepEqual(result.hits, []);
    assert.equal(result.summary, '');
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-PERF-01-003: oversize body (2 MB) short-circuits in < 5 ms', async () => {
  const dir = mkTmpStateDir();
  try {
    _resetOutboundScan();
    loadPolicy();

    // 2 MB of ASCII -- byte length == char length for ASCII.
    const body = 'x'.repeat(2 * 1024 * 1024);
    assert.ok(Buffer.byteLength(body, 'utf8') > 1_048_576);

    const start = process.hrtime.bigint();
    const result = scanOutbound({ body });
    const end = process.hrtime.bigint();
    const elapsedMs = Number(end - start) / 1_000_000;

    process.stderr.write(`[T-PERF-01-003] elapsed_ms=${elapsedMs.toFixed(2)}\n`);
    assert.ok(elapsedMs < 5, `oversize short-circuit took ${elapsedMs.toFixed(2)} ms`);
    assert.deepEqual(result.hits, []);
    assert.equal(result.totalScore, 0);
    assert.equal(result.summary, 'body too large');

    // Drain audit so the oversize line lands before cleanup wipes the dir.
    await _drainAudit();
  } finally {
    cleanupTmpStateDir(dir);
  }
});
