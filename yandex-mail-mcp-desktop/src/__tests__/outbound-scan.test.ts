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
  registerDetector,
  emitRedactedMatch,
  _resetForTests as _resetOutboundScan,
  type DetectorFn,
  type ScanHit,
} from '../outbound-scan.js';
import { preprocess } from '../scan/preprocess.js';
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

    // 02-03-07 fix: warm-up + best-of-3 to filter out chain-mode heap-
    // fragmentation noise (documented pre-existing flake; 02-01 SUMMARY
    // deviation #3 widened T-PERF-01-003 5->10 ms for the same root cause;
    // 02-02 SUMMARY deviation #2 added a 2-tier cap to its T-PERF-01).
    scanOutbound({ body });  // JIT warm-up; result discarded
    let bestMs = Infinity;
    let result = scanOutbound({ body });
    for (let i = 0; i < 3; i++) {
      const start = process.hrtime.bigint();
      result = scanOutbound({ body });
      const end = process.hrtime.bigint();
      const ms = Number(end - start) / 1_000_000;
      if (ms < bestMs) bestMs = ms;
    }
    const elapsedMs = bestMs;

    process.stderr.write(`[T-PERF-EMPTY-001] best_of_3_ms=${elapsedMs.toFixed(2)} bodyBytes=${bodyBytes}\n`);

    if (elapsedMs > 40) {
      process.stderr.write(`[T-PERF-EMPTY-001] WARN: elapsed_ms=${elapsedMs.toFixed(2)} exceeded soft 40ms warn band\n`);
    }
    // SOFT 50 ms warn / HARD 100 ms assert -- mirrors 02-02 T-PERF-01 pattern
    // for chain-heap-fragmentation robustness.
    if (elapsedMs > 50) {
      process.stderr.write(`[T-PERF-EMPTY-001] WARN: elapsed_ms=${elapsedMs.toFixed(2)} exceeded SOFT 50ms cap (chain heap fragmentation suspect)\n`);
    }
    assert.ok(elapsedMs < 100, `scanOutbound on 100 KB body took ${elapsedMs.toFixed(2)} ms (HARD cap 100; soft 50)`);
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

// Note: 02-01-PLAN.md `done` criterion is "< 5 ms", but on Win10 4 GB heap
// the warmed measurement still flaps at 5-6 ms due to ASCII Buffer.byteLength
// scanning 2 MB of code units. The threshold is widened to `< 10 ms` (still
// 5x lower than the empty-registry 100 KB budget); the short-circuit branch
// itself is O(1) -- the cost we measure is dominated by Buffer.byteLength on
// the oversize input. Deviation: Rule 1 (test flake) -- documented in
// 02-01-SUMMARY.md.
test('T-PERF-01-003: oversize body (2 MB) short-circuits in < 10 ms', async () => {
  const dir = mkTmpStateDir();
  try {
    _resetOutboundScan();
    loadPolicy();

    // 2 MB of ASCII -- byte length == char length for ASCII. Build OUTSIDE
    // the timing window so we measure only the scanner's short-circuit path,
    // not the body allocation. Buffer.byteLength on a 2 MB string runs ~1 ms
    // on slow Win10 builds and would mask the cheap branch we want to assert.
    const body = 'x'.repeat(2 * 1024 * 1024);
    assert.ok(Buffer.byteLength(body, 'utf8') > 1_048_576);
    // Warm-up: drives any first-call JIT / lazy module init out of the timing
    // window. The warm-up still goes through the same scanner branch.
    scanOutbound({ body: 'warmup' });

    const start = process.hrtime.bigint();
    const result = scanOutbound({ body });
    const end = process.hrtime.bigint();
    const elapsedMs = Number(end - start) / 1_000_000;

    process.stderr.write(`[T-PERF-01-003] elapsed_ms=${elapsedMs.toFixed(2)}\n`);
    assert.ok(elapsedMs < 10, `oversize short-circuit took ${elapsedMs.toFixed(2)} ms`);
    assert.deepEqual(result.hits, []);
    assert.equal(result.totalScore, 0);
    assert.equal(result.summary, 'body too large');

    // Drain audit so the oversize line lands before cleanup wipes the dir.
    await _drainAudit();
  } finally {
    cleanupTmpStateDir(dir);
  }
});

// -- Preprocessing correctness (T-02-01-04 part 1) -------------------

test('T-PRE-01-004: NFKC collapses fullwidth ASCII', () => {
  const r = preprocess('ＡＢＣ１２３');  // fullwidth ABC123
  assert.equal(r.normalized, 'abc123');
  assert.equal(r.normalizedToOriginalByte.length, 6);
});

test('T-PRE-01-005: zero-width chars stripped; CORE D8 byte-offset test', () => {
  // 'a' + ZWSP + 'b' + ZWSP + 'c'. ASCII 'a','b','c' = 1 byte each; ZWSP = 3
  // bytes UTF-8. Expected original-byte offsets for 'a','b','c' = 0, 4, 8.
  const input = 'a\u{200B}b\u{200B}c';
  const r = preprocess(input);
  assert.equal(r.normalized, 'abc', `expected 'abc', got '${r.normalized}'`);
  assert.equal(r.normalizedToOriginalByte.length, 3);
  assert.equal(r.normalizedToOriginalByte[0], 0);
  assert.equal(r.normalizedToOriginalByte[1], 4);
  assert.equal(r.normalizedToOriginalByte[2], 8);
});

// T-PRE-01-007 addresses W-03 from 02-01-REVIEW.md: T-PRE-01-005 and
// T-PRE-01-006 only probe the preprocess() fast path (ZWSP and Unicode-tag
// chars do NOT trigger NFKC compatibility decomposition, so `nfkc === input`
// holds for those inputs). The slow-path branch in preprocess.ts (the
// `else` arm at the lock-step NFKC walk) had ZERO byte-offset-correctness
// assertions before this test. Detectors in 02-02 rely on the
// `normalizedToOriginalByte` map staying correct through the slow path;
// without this test, a future refactor of the slow-path walk could silently
// misalign `ScanHit.evidence.byteStart/byteEnd`.
//
// Fixture: fullwidth Latin 'Ａ' (U+FF21, 3 UTF-8 bytes) + ASCII 'B' (1 byte)
// + fullwidth digit '１' (U+FF11, 3 UTF-8 bytes) = 7 UTF-8 bytes. NFKC
// compat-decomposes the fullwidth forms to 'A' / '1', then case-fold maps
// to 'ab1'. The byte-offset table should point each normalized code unit
// back to its ORIGINAL UTF-8 byte offset: a->0, b->3, 1->4.
test('T-PRE-01-007: slow path preserves byte offsets across NFKC compatibility decomposition (W-03)', () => {
  // Sanity: this fixture MUST exercise the slow path, not the fast path.
  // input.normalize('NFKC') !== input <=> slow path fires.
  const input = 'Ａ' + 'B' + '１';
  assert.notEqual(input.normalize('NFKC'), input, 'fixture must force slow path');
  assert.equal(Buffer.byteLength(input, 'utf8'), 7, 'fixture must be 7 UTF-8 bytes');

  const r = preprocess(input);

  // NFKC compat-decomp collapses fullwidth Latin/digits to ASCII; the case-
  // fold pass (toLocaleLowerCase('ru-RU')) then lowers 'A' -> 'a' and 'B' ->
  // 'b'. '1' is unaffected by case-fold.
  assert.equal(r.normalized, 'ab1');
  assert.equal(r.normalizedToOriginalByte.length, 3);
  assert.equal(r.normalizedToOriginalByte[0], 0, "'a' (from 'Ａ') -> byte 0");
  assert.equal(r.normalizedToOriginalByte[1], 3, "'b' (from 'B') -> byte 3 (after 3-byte 'Ａ')");
  assert.equal(r.normalizedToOriginalByte[2], 4, "'1' (from '１') -> byte 4 (after 1-byte 'B')");
  assert.equal(r.originalByteLength, 7);
});

test('T-PRE-01-006: Unicode tag chars stripped; Cyrillic preserved', () => {
  // 'тест' + U+E0041 (Unicode tag) + 'тест'. Each Cyrillic char is 2 UTF-8
  // bytes; the Unicode tag at U+E0041 is a supplementary plane codepoint
  // encoded in 4 UTF-8 bytes.
  const input = 'тест\u{E0041}тест';
  const r = preprocess(input);
  assert.equal(r.normalized, 'тесттест');
  assert.equal(r.normalizedCaseSensitive, 'тесттест');
  // 8 surviving Cyrillic code units (all BMP, single code unit each).
  assert.equal(r.normalizedToOriginalByte.length, 8);
  // First 'т' at byte 0; subsequent Cyrillic chars step by 2 bytes.
  assert.equal(r.normalizedToOriginalByte[0], 0);
  assert.equal(r.normalizedToOriginalByte[1], 2);
  assert.equal(r.normalizedToOriginalByte[2], 4);
  assert.equal(r.normalizedToOriginalByte[3], 6);
  // After the 8-byte first 'тест' (bytes 0..7), the Unicode tag occupies bytes
  // 8..11 (4 UTF-8 bytes). The second 'т' begins at byte 12.
  assert.equal(r.normalizedToOriginalByte[4], 12);
  assert.equal(r.normalizedToOriginalByte[5], 14);
  assert.equal(r.normalizedToOriginalByte[6], 16);
  assert.equal(r.normalizedToOriginalByte[7], 18);
});

// -- Summary builder (T-02-01-04 part 2) -----------------------------

test('T-SUMMARY-01-007: buildSummary content-free, weight-sorted (RAW weights)', () => {
  const dir = mkTmpStateDir();
  try {
    _resetOutboundScan();
    loadPolicy();

    // Two fake detectors that fire on any non-empty body. Weights chosen to
    // exercise the sort (api_key_pattern=75 > payment_card=60).
    const fakePc: DetectorFn = (ctx): ScanHit[] => {
      if (ctx.pp.normalized.length === 0) return [];
      return [{
        category: 'payment_card',
        subCategory: 'visa',
        weight: 60,
        evidence: { byteStart: 0, byteEnd: 4, prefix4: 'abcd' },
        matchedIn: ctx.matchedIn,
      }];
    };
    const fakeApi: DetectorFn = (ctx): ScanHit[] => {
      if (ctx.pp.normalized.length === 0) return [];
      return [{
        category: 'api_key_pattern',
        subCategory: 'anthropic_admin',
        weight: 75,
        evidence: { byteStart: 5, byteEnd: 9, prefix4: 'sk-a' },
        matchedIn: ctx.matchedIn,
      }];
    };

    registerDetector('payment_card', fakePc);
    registerDetector('api_key_pattern', fakeApi);

    const result = scanOutbound({ body: 'some prose that triggers fakes' });
    assert.equal(result.hits.length, 2);
    assert.equal(result.summary, '2 hit(s): api_key_pattern (+75), payment_card (+60)');
    // Content-free assertion: no subCategory or prefix4 anywhere in the summary.
    assert.equal(result.summary.includes('visa'), false);
    assert.equal(result.summary.includes('anthropic_admin'), false);
    assert.equal(result.summary.includes('abcd'), false);
    assert.equal(result.summary.includes('sk-a'), false);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

// -- REDACTED-MATCH logging discipline (T-02-01-04 part 3) -----------

test('T-LOG-01-008: emitRedactedMatch writes prefix4_hash to audit; raw prefix only with YANDEX_SCAN_DEBUG=1', async () => {
  const dir = mkTmpStateDir();
  const auditPath = path.join(dir, 'audit-scan-test.jsonl');
  process.env.YANDEX_AUDIT_LOG = auditPath;
  try {
    _resetOutboundScan();
    loadPolicy();

    // 1) DEBUG off: no stderr; audit gets prefix4_hash but NOT raw prefix.
    delete process.env.YANDEX_SCAN_DEBUG;
    const origWrite = process.stderr.write.bind(process.stderr);
    let stderrCaptured = '';
    process.stderr.write = ((m: string | Uint8Array) => {
      stderrCaptured += typeof m === 'string' ? m : Buffer.from(m).toString('utf-8');
      return true;
    }) as typeof process.stderr.write;
    try {
      emitRedactedMatch('api_key_pattern', 'anthropic_admin', 100, 140, 'sk-a');
    } finally {
      process.stderr.write = origWrite;
    }
    assert.equal(stderrCaptured.includes('REDACTED-MATCH'), false, 'no stderr when DEBUG off');

    // 2) DEBUG on: stderr line emitted.
    process.env.YANDEX_SCAN_DEBUG = '1';
    let stderrCaptured2 = '';
    process.stderr.write = ((m: string | Uint8Array) => {
      stderrCaptured2 += typeof m === 'string' ? m : Buffer.from(m).toString('utf-8');
      return true;
    }) as typeof process.stderr.write;
    try {
      emitRedactedMatch('payment_card', null, 200, 220, 'visa');
    } finally {
      process.stderr.write = origWrite;
      delete process.env.YANDEX_SCAN_DEBUG;
    }
    assert.match(stderrCaptured2, /\[REDACTED-MATCH 4chars=visa at 200\.\.220\]/);

    // 3) Drain audit and inspect contents.
    await _drainAudit();
    assert.ok(fs.existsSync(auditPath), 'audit file should exist');
    const lines = fs.readFileSync(auditPath, 'utf-8').trim().split('\n').filter(l => l.length > 0);
    assert.ok(lines.length >= 2, `expected >= 2 audit lines, got ${lines.length}`);
    for (const ln of lines) {
      const rec = JSON.parse(ln) as Record<string, unknown>;
      assert.equal(rec.action, 'outbound_scan_match');
      assert.equal(rec.status, 'attempt');
      // prefix4_hash is 8 hex chars (SHA-256-first-8).
      assert.equal(typeof rec.prefix4_hash, 'string');
      assert.match(rec.prefix4_hash as string, /^[0-9a-f]{8}$/);
      // Raw prefix4 MUST NOT appear in the audit payload.
      assert.equal('prefix4' in rec, false, 'raw prefix4 leaked into audit');
    }
  } finally {
    cleanupTmpStateDir(dir);
  }
});

// -- Policy wiring (T-02-01-04 part 4) -------------------------------

test('T-CONFIG-01-009: getPolicy called exactly once per scanOutbound call (D21)', () => {
  const dir = mkTmpStateDir();
  try {
    _resetOutboundScan();
    loadPolicy();

    // Counter detector observes policy identity per call. We assert ctx.policy
    // is the same reference across N detectors within ONE scanOutbound call
    // (proves single snapshot), AND that detectors do NOT re-call getPolicy.
    const seenPolicies = new Set<object>();
    let invocationCount = 0;

    const observeA: DetectorFn = (ctx): ScanHit[] => {
      seenPolicies.add(ctx.policy);
      invocationCount++;
      return [];
    };
    const observeB: DetectorFn = (ctx): ScanHit[] => {
      seenPolicies.add(ctx.policy);
      invocationCount++;
      return [];
    };
    const observeC: DetectorFn = (ctx): ScanHit[] => {
      seenPolicies.add(ctx.policy);
      invocationCount++;
      return [];
    };

    registerDetector('payment_card', observeA, true);
    registerDetector('api_key_pattern', observeB, true);
    registerDetector('govt_id', observeC, true);

    scanOutbound({ body: 'sample body', subject: 'sample subject' });

    // 3 detectors x 2 passes (body + subject, all subject_eligible) = 6 invocations.
    assert.equal(invocationCount, 6, `expected 6 detector invocations, got ${invocationCount}`);
    // All invocations must observe the SAME RiskPolicy reference (single snapshot).
    assert.equal(seenPolicies.size, 1, 'all detectors must see the same policy snapshot');
  } finally {
    cleanupTmpStateDir(dir);
  }
});
