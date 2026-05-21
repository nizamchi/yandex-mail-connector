// provenance.test.ts -- Phase 3 (Layer B) unit tests for RAM-only read tracker.
//
// Coverage (9 cases; target floor 9 per Revision 2 of 03-01-PLAN.md):
//   T-PROV-RECORD-01           -- record+read returns one entry, defensive
//                                  meta-aliasing guard (W-4).
//   T-PROV-PRUNE-01            -- read at t=0, query at t=window+1ms -> 0.
//   T-PROV-PRUNE-BOUNDARY-01   -- inclusive lower bound; BOTH edges asserted
//                                  (age===windowMs survives; age===windowMs+1
//                                  pruned) per D9 / B-3.
//   T-PROV-WINDOW-DISABLE-01   -- provenance_window_sec=0 -> no-op (D5).
//   T-PROV-FLAG-01             -- postReadFlag boundary cases via `now` arg.
//   T-PROV-RESET-01            -- _resetForTests clears Map only.
//   T-PROV-PRIVACY-DISK-01     -- loadPolicy + SHA-256 + cwd-snapshot guards
//                                  (B-4 strengthened); source-level negative
//                                  import grep (D6).
//   T-PROV-HOOK-PRESENT-01     -- tools.ts structural call-site grep
//                                  (EXACTLY 2 per B-1).
//   T-PROV-RACE-01             -- 100-burst no-corruption documentation (D10).
//
// Per-test isolation via mkTmpStateDir / cleanupTmpStateDir. ASCII-only.
// No emojis. ESM `.js` suffix on imports.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

import {
  recordRead,
  recentReads,
  postReadFlag,
  _resetForTests,
  type ReadEvent,
} from '../provenance.js';
import {
  loadPolicy,
  _resetForTests as _resetPolicy,
  _setPolicyForTests,
} from '../policy.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import { DEFAULT_POLICY } from '../policy-defaults.js';

// ── Helpers ───────────────────────────────────────────────────

// mkTmpStateDir bootstraps a fresh state dir and (optionally) installs a
// policy with a non-default provenance_window_sec via _setPolicyForTests.
//
// IMPORTANT: _setPolicyForTests BYPASSES Zod re-validation. Always SPREAD
// from DEFAULT_POLICY; never construct from scratch. The bypass is
// acceptable for the test seam because production code path goes through
// Zod via loadPolicy; the test exists to verify BEHAVIOR, not validation
// (W-8).
function mkTmpStateDir(provenanceWindowSec: number = 30): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-prov-'));
  process.env.YANDEX_STATE_DIR = dir;
  delete process.env.YANDEX_POLICY_FILE;
  _resetStateDir();
  _resetPolicy();
  _resetForTests();
  if (provenanceWindowSec !== 30) {
    _setPolicyForTests({ ...DEFAULT_POLICY, provenance_window_sec: provenanceWindowSec });
  } else {
    loadPolicy();
  }
  return dir;
}

function cleanupTmpStateDir(dir: string): void {
  delete process.env.YANDEX_POLICY_FILE;
  delete process.env.YANDEX_STATE_DIR;
  _resetForTests();
  _resetPolicy();
  _resetStateDir();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// ── Tests ─────────────────────────────────────────────────────

test('T-PROV-RECORD-01: record + read returns one entry; meta-alias guard (W-4)', () => {
  const dir = mkTmpStateDir();
  try {
    const meta = { folder: 'INBOX', uid: 7 };
    recordRead('m1', meta);

    const r = recentReads();
    assert.equal(r.length, 1);
    assert.equal(r[0].msgid, 'm1');
    assert.equal(r[0].folder, 'INBOX');
    assert.equal(r[0].uid, 7);
    assert.equal(typeof r[0].readAtMs, 'number');

    // W-4 anti-alias: post-recordRead caller mutation of meta must NOT
    // leak into the stored ReadEvent (recordRead defensive-copies on intake).
    meta.folder = 'HACKED';
    assert.equal(recentReads()[0].folder, 'INBOX');
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-PROV-PRUNE-01: read at t=0, query at t=window+1ms -> 0 entries', async () => {
  const dir = mkTmpStateDir(1);  // 1-second window
  try {
    recordRead('m1', { folder: 'INBOX' });
    // Wait > 1s so the entry's age exceeds windowMs (= 1000) strictly.
    await new Promise((r) => setTimeout(r, 1100));
    assert.equal(recentReads().length, 0);
    assert.equal(postReadFlag(), false);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-PROV-PRUNE-BOUNDARY-01: inclusive lower bound; BOTH edges (D9 / B-3)', () => {
  const dir = mkTmpStateDir(60);  // 60-second window -> windowMs = 60_000
  try {
    recordRead('m1', { folder: 'INBOX' });
    const t0 = Date.now();

    // Boundary HIT: age === windowMs exactly -> entry SURVIVES (strict-GT
    // predicate keeps equality). postReadFlag must report true.
    assert.equal(
      postReadFlag(t0 + 60_000),
      true,
      'age === windowMs must SURVIVE prune (inclusive lower bound)',
    );

    // The previous postReadFlag(t0+60_000) did NOT prune the entry (it
    // survived). Re-record to ensure a clean state for the MISS assertion.
    recordRead('m1', { folder: 'INBOX' });
    const t1 = Date.now();

    // Boundary MISS: age === windowMs + 1 -> entry PRUNED. postReadFlag false.
    assert.equal(
      postReadFlag(t1 + 60_001),
      false,
      'age === windowMs + 1 must be PRUNED (strict-greater predicate)',
    );
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-PROV-WINDOW-DISABLE-01: provenance_window_sec=0 -> tracking OFF (D5)', () => {
  // _setPolicyForTests BYPASSES Zod validation. Acceptable for the test
  // seam; production code path goes through Zod via loadPolicy. The test
  // exists to verify BEHAVIOR, not validation (W-8).
  const dir = mkTmpStateDir(0);
  try {
    for (let i = 0; i < 5; i++) {
      recordRead('m' + i, { folder: 'INBOX' });
    }
    // Window=0 is the OFF knob -- never the "match-all-time" knob.
    assert.equal(recentReads().length, 0);
    assert.equal(postReadFlag(), false);
    assert.equal(postReadFlag(0), false);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-PROV-FLAG-01: postReadFlag boundary cases via `now` arg', () => {
  const dir = mkTmpStateDir();  // default 30s
  try {
    assert.equal(postReadFlag(), false, 'no reads -> false');

    recordRead('m1', { folder: 'INBOX' });
    assert.equal(postReadFlag(), true);
    assert.equal(postReadFlag(Date.now()), true);

    // 31 seconds in the future -> entry age > windowMs (30_000) -> false.
    assert.equal(postReadFlag(Date.now() + 31_000), false);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-PROV-RESET-01: _resetForTests clears Map; window unchanged', () => {
  const dir = mkTmpStateDir();  // default 30s
  try {
    recordRead('m1', { folder: 'INBOX' });
    assert.equal(recentReads().length, 1);

    _resetForTests();
    assert.equal(recentReads().length, 0);
    assert.equal(postReadFlag(), false);

    // Window still 30s -- recording still works after reset.
    recordRead('m2', { folder: 'INBOX' });
    assert.equal(recentReads().length, 1);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-PROV-PRIVACY-DISK-01: directory + file-hash + cwd snapshot privacy (B-4)', () => {
  const dir = mkTmpStateDir();  // default 30s; loadPolicy() ran -> file exists.
  try {
    // (1) Confirm risk-policy.json was materialised on disk by loadPolicy.
    const policyPath = path.join(dir, 'risk-policy.json');
    assert.ok(fs.existsSync(policyPath), 'loadPolicy must have written risk-policy.json');

    // (2) SHA-256 of risk-policy.json before exercising provenance.
    const policyBefore = crypto
      .createHash('sha256')
      .update(fs.readFileSync(policyPath))
      .digest('hex');

    // (3) Snapshot state-dir AND process.cwd() listings.
    const dirBefore = fs.readdirSync(dir).sort();
    const cwdBefore = fs.readdirSync(process.cwd()).sort();
    const jsonlBefore = cwdBefore.filter((f) => f.endsWith('.jsonl')).length;

    // (4) Exercise ALL THREE public functions, heavily.
    for (let i = 0; i < 10; i++) {
      recordRead('test-msgid-' + i, { folder: 'INBOX', uid: i });
    }
    const _r = recentReads();
    void _r;
    const _f = postReadFlag(Date.now());
    void _f;

    // (5) Re-snapshot.
    const dirAfter = fs.readdirSync(dir).sort();
    const cwdAfter = fs.readdirSync(process.cwd()).sort();
    const policyAfter = crypto
      .createHash('sha256')
      .update(fs.readFileSync(policyPath))
      .digest('hex');
    const jsonlAfter = cwdAfter.filter((f) => f.endsWith('.jsonl')).length;

    // (6) Assertions.
    assert.deepEqual(dirBefore, dirAfter, 'state-dir listing unchanged -- no new files');
    assert.deepEqual(cwdBefore, cwdAfter, 'cwd listing unchanged -- catches cwd-relative regressions');
    assert.equal(policyBefore, policyAfter, 'risk-policy.json SHA-256 unchanged -- provenance did NOT mutate policy');
    assert.equal(jsonlAfter, jsonlBefore, 'no new *.jsonl in cwd -- provenance did NOT emit audit');

    // Structural source-level privacy check: provenance.ts must not import
    // ./audit.js and must not touch node:fs.
    const provSrcPath = path.join(process.cwd(), 'src', 'provenance.ts');
    if (fs.existsSync(provSrcPath)) {
      const provSrc = fs.readFileSync(provSrcPath, 'utf-8');
      assert.equal(
        /from\s+['"]\.\/audit/.test(provSrc),
        false,
        'provenance.ts MUST NOT import ./audit',
      );
      assert.equal(
        /['"]node:fs['"]/.test(provSrc),
        false,
        'provenance.ts MUST NOT import node:fs',
      );
    }
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-PROV-HOOK-PRESENT-01: tools.ts call-site grep (EXACTLY 2 per B-1)', () => {
  const dir = mkTmpStateDir();
  try {
    const toolsPath = path.join(process.cwd(), 'src', 'tools.ts');
    assert.ok(fs.existsSync(toolsPath), 'src/tools.ts must exist relative to cwd');
    const toolsSrc = fs.readFileSync(toolsPath, 'utf-8');

    // Count non-comment call sites of provenance.recordRead(.
    const callSiteCount = toolsSrc
      .split('\n')
      .filter((line) => !/^\s*\/\//.test(line))
      .filter((line) => /provenance\.recordRead\(/.test(line))
      .length;
    assert.equal(callSiteCount, 2, 'expected EXACTLY 2 non-comment provenance.recordRead( call sites (B-1)');

    assert.match(toolsSrc, /from\s+['"]\.\/provenance/, 'tools.ts must import ./provenance');
    assert.match(toolsSrc, /PMLF-PROV-04/, 'tools.ts must carry the PMLF-PROV-04 marker comment');
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-PROV-RACE-01: 100-burst no-corruption documentation (D10)', () => {
  const dir = mkTmpStateDir();  // default 30s
  try {
    for (let i = 0; i < 100; i++) {
      recordRead('m' + i, { folder: 'INBOX', uid: i });
    }
    const r: ReadEvent[] = recentReads();
    assert.equal(r.length, 100, 'all 100 reads present after burst');

    const ids = new Set(r.map((e) => e.msgid));
    assert.equal(ids.size, 100, 'all 100 msgids distinct (no collision)');

    // Spot-check coverage of the full m0..m99 range.
    assert.ok(ids.has('m0'));
    assert.ok(ids.has('m50'));
    assert.ok(ids.has('m99'));
  } finally {
    cleanupTmpStateDir(dir);
  }
});
