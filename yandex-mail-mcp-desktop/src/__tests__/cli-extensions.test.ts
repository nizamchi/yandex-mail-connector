// cli-extensions.test.ts -- Phase 7 PMLF v2.1.0 operator subcommands.
//
// Covers CONTEXT D17 cases #1-14 + Rev-2 patches (B1 audit-drain sanity,
// B2 EDITOR empty-string fix, H1 parser determinism, M3 session shape).
//
// Spawn pattern: `spawnSync(process.execPath, [CLI_BUNDLE, ...flags], env)`.
// Each test mints a fresh tmp YANDEX_STATE_DIR. The CLI internally drains
// the audit writeChain via flushAudit() so by the time spawnSync returns
// any auditLog enqueue has landed on disk -- this is the B1 patch assertion.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

import { _resetForTests as _resetStateDir } from '../state-dir.js';
import {
  addTrusted,
  _listTrusted,
  _setEntryLastUsedForTests,
  _resetForTests as _resetAllowlist,
} from '../allowlist.js';
import { _resetForTests as _resetPolicy } from '../policy.js';
import { DEFAULT_POLICY } from '../policy-defaults.js';

const CLI_BUNDLE = path.join(process.cwd(), 'dist', 'cli-trust.js');

interface SpawnOpts {
  args: string[];
  env?: Record<string, string | undefined>;
  input?: string;
}

function mkTmpStateDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'y7-cli-'));
  process.env.YANDEX_STATE_DIR = dir;
  _resetStateDir();
  _resetAllowlist();
  _resetPolicy();
  return dir;
}

function cleanupTmpStateDir(dir: string): void {
  delete process.env.YANDEX_STATE_DIR;
  _resetStateDir();
  _resetAllowlist();
  _resetPolicy();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

function runCli(stateDir: string, opts: SpawnOpts) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    YANDEX_STATE_DIR: stateDir,
    NODE_ENV: 'test',
    ...(opts.env ?? {}),
  };
  // Apply explicit deletes (env override of '' -> remove for empty-string semantics).
  if (opts.env !== undefined) {
    for (const k of Object.keys(opts.env)) {
      if (opts.env[k] === undefined) delete env[k];
    }
  }
  return spawnSync(process.execPath, [CLI_BUNDLE, ...opts.args], {
    env,
    encoding: 'utf-8',
    timeout: 15000,
    input: opts.input,
  });
}

function audit(dir: string): string {
  const p = path.join(dir, 'audit.jsonl');
  if (!fs.existsSync(p)) return '';
  return fs.readFileSync(p, 'utf8');
}

function skipIfNoBundle(): boolean {
  if (!fs.existsSync(CLI_BUNDLE)) {
    process.stderr.write(`[cli-extensions] skip: ${CLI_BUNDLE} not built\n`);
    return true;
  }
  return false;
}

// -- T-CLI-01: --help lists six commands --------------------

test('T-CLI-01: --help lists all subcommands', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, { args: ['--help'], env: { YANDEX_TRUST_ASSUME_YES: '1' } });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    for (const flag of ['--policy', '--recent', '--list-trust', '--revoke-trust', '--high-risk-send', '<address>']) {
      assert.ok(r.stdout.includes(flag), `help missing ${flag}; stdout:\n${r.stdout}`);
    }
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-02: --policy show prints parseable JSON ----------

test('T-CLI-02: --policy show prints parseable JSON', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, { args: ['--policy', 'show'] });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    const parsed = JSON.parse(r.stdout);
    assert.equal(typeof parsed, 'object');
    assert.ok('thresholds' in parsed, 'expected thresholds in policy JSON');
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-03: --policy set round-trips ---------------------

test('T-CLI-03: --policy set thresholds.augment 25 round-trips', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, {
      args: ['--policy', 'set', 'thresholds.augment', '25', '--yes'],
    });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    const r2 = runCli(dir, { args: ['--policy', 'show'] });
    const policy = JSON.parse(r2.stdout) as { thresholds: { augment: number } };
    assert.equal(policy.thresholds.augment, 25);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-04: --policy set negative value rejected (H1 verbatim) --

test('T-CLI-04: --policy set thresholds.augment -1 exits 2', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, {
      args: ['--policy', 'set', 'thresholds.augment', '-1', '--yes'],
    });
    assert.equal(r.status, 2, `expected 2; got ${r.status}\nstderr:\n${r.stderr}`);
    assert.ok(
      r.stderr.includes("'thresholds.augment'") && r.stderr.includes('non-negative'),
      `stderr should mention key + non-negative; got:\n${r.stderr}`,
    );
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-05: --policy set unknown key rejected ------------

test('T-CLI-05: --policy set unknown.key exits 2', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, {
      args: ['--policy', 'set', 'unknown.key', '1', '--yes'],
    });
    assert.equal(r.status, 2);
    assert.ok(r.stderr.includes('unknown key'), `stderr should mention unknown key; got:\n${r.stderr}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-06: --policy set boolean round-trips -------------

test('T-CLI-06: --policy set categories.medical false round-trips', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, {
      args: ['--policy', 'set', 'categories.medical', 'false', '--yes'],
    });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    const r2 = runCli(dir, { args: ['--policy', 'show'] });
    const policy = JSON.parse(r2.stdout) as { categories: { medical: boolean } };
    assert.equal(policy.categories.medical, false);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-07: --policy reset + audit drain (B1) ------------

test('T-CLI-07: --policy reset overwrites + audit.jsonl contains policy_reset', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    // First modify so reset is observable.
    runCli(dir, { args: ['--policy', 'set', 'thresholds.augment', '7', '--yes'] });
    const r = runCli(dir, { args: ['--policy', 'reset', '--yes'] });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    const r2 = runCli(dir, { args: ['--policy', 'show'] });
    const policy = JSON.parse(r2.stdout) as { thresholds: { augment: number } };
    assert.equal(policy.thresholds.augment, DEFAULT_POLICY.thresholds.augment);
    // B1 drain: audit.jsonl must have a policy_reset line BY TIME spawnSync returned.
    const log = audit(dir);
    assert.ok(log.includes('"action":"policy_reset"'), `audit.jsonl missing policy_reset:\n${log}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-08a: win32 + EDITOR undefined -> help-block, exit 0 --

test('T-CLI-08a (B2): --policy edit on win32 with EDITOR unset prints help + exit 0', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const env: Record<string, string | undefined> = {
      YANDEX_FORCE_PLATFORM_FOR_TESTS: 'win32',
      EDITOR: undefined,
    };
    // Need stdin.isTTY = true semantically; on non-TTY (test runner), our
    // code path exits 2. So skip this test if running on non-TTY (the
    // win32 + TTY scenario is what we want; CI does not have a TTY).
    if (!process.stdin.isTTY) {
      // Without TTY the TTY guard fires before the editor=null branch can
      // print help. That is the documented intended behavior. Assert that.
      const r = runCli(dir, { args: ['--policy', 'edit'], env });
      assert.equal(r.status, 2);
      assert.ok(r.stderr.includes('interactive TTY'), `stderr:\n${r.stderr}`);
      return;
    }
    const r = runCli(dir, { args: ['--policy', 'edit'], env });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    assert.ok(r.stdout.includes('$EDITOR'), `stdout should mention $EDITOR;\n${r.stdout}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-08b: linux + EDITOR='' (empty) + no TTY -> exit 2 --

test('T-CLI-08b (B2): --policy edit on linux with EDITOR= (empty) + no TTY exits 2', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const env = {
      YANDEX_FORCE_PLATFORM_FOR_TESTS: 'linux',
      EDITOR: '',
    };
    const r = runCli(dir, { args: ['--policy', 'edit'], env });
    assert.equal(r.status, 2, `expected 2; got ${r.status}\nstderr:\n${r.stderr}`);
    assert.ok(
      r.stderr.includes('--policy edit requires an interactive TTY'),
      `stderr verbatim mismatch:\n${r.stderr}`,
    );
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-09: --recent on empty buffer --------------------

test('T-CLI-09: --recent with no buffer exits 0 with "no sends recorded yet"', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, { args: ['--recent'] });
    assert.equal(r.status, 0);
    assert.ok(r.stderr.includes('no sends recorded yet'), `stderr:\n${r.stderr}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- Fixture seeder for --recent tests --

function seedRecentSends(dir: string, n: number, tiers: string[]): void {
  const lines: string[] = [];
  for (let i = 0; i < n; i++) {
    const tier = tiers[i % tiers.length] ?? 'low';
    lines.push(JSON.stringify({
      version: 1,
      ts: new Date(Date.now() - (n - i) * 60_000).toISOString(),
      message_id: `msgid-${i}@example.com`,
      recipients_count: 1,
      recipients_domains: ['example.com'],
      subject_hash: 'a'.repeat(16),
      body_length: 100,
      risk_tier: tier,
      risk_score: tier === 'low' ? 10 : tier === 'medium' ? 50 : 90,
      action_fingerprint: 'abcd1234',
    }));
  }
  fs.writeFileSync(path.join(dir, 'recent-sends.jsonl'), lines.join('\n') + '\n', { mode: 0o600 });
}

// -- T-CLI-10: --recent --limit 5 returns 5 of 7 ------------

test('T-CLI-10: --recent --limit 5 returns 5 of 7 fixtures', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    seedRecentSends(dir, 7, ['low', 'medium', 'high']);
    const r = runCli(dir, { args: ['--recent', '--limit', '5'] });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    const lines = r.stdout.trim().split('\n');
    assert.equal(lines.length, 5, `expected 5 rows; got ${lines.length}:\n${r.stdout}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-11: --recent --risk filters low ------------------

test('T-CLI-11: --recent --risk filters out low tier', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    seedRecentSends(dir, 9, ['low', 'medium', 'high']);
    const r = runCli(dir, { args: ['--recent', '--risk'] });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    assert.ok(!/\[low\]/.test(r.stdout), `should not contain [low]:\n${r.stdout}`);
    assert.ok(/\[medium\]/.test(r.stdout) || /\[high\]/.test(r.stdout));
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-12: --list-trust --source filter ------------------

test('T-CLI-12: --list-trust --source user_trust_token filters correctly', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    addTrusted('alice@example.com', 'permanent', 'user_trust_token');
    addTrusted('bob@example.com', 'permanent', 'sent_history');
    const r = runCli(dir, { args: ['--list-trust', '--source', 'user_trust_token'] });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    assert.ok(r.stdout.includes('alice@example.com'), `stdout:\n${r.stdout}`);
    assert.ok(!r.stdout.includes('bob@example.com'), `bob should be filtered:\n${r.stdout}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-12b (M3): _listTrusted session entry shape -------

test('T-CLI-12b (M3): _listTrusted on session-only entry returns useCount=0 + lastUsed=Date.parse(added_at)', () => {
  const dir = mkTmpStateDir();
  try {
    addTrusted('eve@example.com', 'session', 'auto_trust_reply');
    const entries = _listTrusted();
    const eve = entries.find(e => e.address === 'eve@example.com');
    assert.ok(eve, 'eve@example.com should be present');
    assert.equal(eve!.scope, 'session');
    assert.equal(eve!.useCount, 0, 'session entry must report useCount=0');
    const expected = Date.parse(eve!.added_at);
    assert.equal(eve!.lastUsed, expected,
      `lastUsed should equal Date.parse(added_at); got ${eve!.lastUsed} vs ${expected}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-13: --list-trust --stale Nd filters by lastUsed --

test('T-CLI-13: --list-trust --stale 90d filters by lastUsed cutoff', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    addTrusted('fresh@example.com', 'permanent', 'user_trust_token');
    addTrusted('stale@example.com', 'permanent', 'user_trust_token');
    // Backdate stale@... lastUsed to 200 days ago.
    _setEntryLastUsedForTests('stale@example.com', Date.now() - 200 * 86_400_000);
    const r = runCli(dir, { args: ['--list-trust', '--stale', '90d'] });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    assert.ok(r.stdout.includes('stale@example.com'), `stdout should contain stale; got:\n${r.stdout}`);
    assert.ok(!r.stdout.includes('fresh@example.com'), `fresh should be filtered:\n${r.stdout}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-14: --revoke-trust + audit-drain assertion (B1) --

test('T-CLI-14: --revoke-trust removes + audit allowlist_revoke present after spawn returns', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    addTrusted('alice@example.com', 'permanent', 'user_trust_token');
    const r = runCli(dir, { args: ['--revoke-trust', 'alice@example.com', '--yes'] });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    assert.ok(r.stdout.includes('revoked: alice@example.com'), `stdout:\n${r.stdout}`);
    // B1: audit drained before exit.
    const log = audit(dir);
    assert.ok(log.includes('"action":"allowlist_revoke"'), `audit.jsonl missing allowlist_revoke:\n${log}`);
    // Verify removal -- re-run --list-trust.
    const r2 = runCli(dir, { args: ['--list-trust'] });
    assert.ok(!r2.stdout.includes('alice@example.com'), `alice should be gone:\n${r2.stdout}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-15: --revoke-trust nonexistent -> exit 0, no audit --

test('T-CLI-15: --revoke-trust nonexistent@x --yes exits 0 + no audit', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, { args: ['--revoke-trust', 'ghost@example.com', '--yes'] });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    assert.ok(r.stderr.includes('no entry'), `stderr:\n${r.stderr}`);
    const log = audit(dir);
    assert.ok(!log.includes('allowlist_revoke'), `no allowlist_revoke expected:\n${log}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-16: mixed-mode flags -----------------------------

test('T-CLI-16: --policy show + --recent exits 2 mixed-mode', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, { args: ['--policy', 'show', '--recent'] });
    assert.equal(r.status, 2);
    assert.ok(
      r.stderr.includes('mixed-mode flags not allowed; got --policy and --recent'),
      `stderr verbatim mismatch:\n${r.stderr}`,
    );
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-17: --yes flag skips prompt on --policy set ------

test('T-CLI-17: --yes skips prompt on --policy set with closed stdin', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    // No YANDEX_TRUST_ASSUME_YES, but --yes flag should still skip prompt.
    const env = { YANDEX_TRUST_ASSUME_YES: undefined };
    const r = runCli(dir, {
      args: ['--policy', 'set', 'thresholds.augment', '15', '--yes'],
      env,
      input: '',
    });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    assert.ok(r.stdout.includes('policy updated'), `stdout:\n${r.stdout}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-17b (B1): --policy set drains policy_set audit ---

test('T-CLI-17b (B1): --policy set audit.jsonl contains policy_set after spawn returns', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, {
      args: ['--policy', 'set', 'thresholds.augment', '33', '--yes'],
    });
    assert.equal(r.status, 0, `stderr:\n${r.stderr}`);
    const log = audit(dir);
    assert.ok(log.includes('"action":"policy_set"'), `audit.jsonl missing policy_set:\n${log}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-PARSER-EDGE-01 (H1): four parser edge cases -----

test('T-CLI-PARSER-EDGE-01 (H1): parser determinism rules', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    // Empty argv -> exit 2 verbatim 'no command specified; try --help'.
    let r = runCli(dir, { args: [] });
    assert.equal(r.status, 2);
    assert.ok(r.stderr.includes('no command specified; try --help'), `empty argv stderr:\n${r.stderr}`);

    // Unknown flag -> exit 2 verbatim 'unknown flag: --frobnicate'.
    r = runCli(dir, { args: ['--frobnicate'] });
    assert.equal(r.status, 2);
    assert.ok(r.stderr.includes('unknown flag: --frobnicate'), `unknown flag stderr:\n${r.stderr}`);

    // Negative --limit -> exit 2 verbatim '--limit: must be 1..50, got -5'.
    r = runCli(dir, { args: ['--recent', '--limit', '-5'] });
    assert.equal(r.status, 2);
    assert.ok(r.stderr.includes('--limit: must be 1..50, got -5'), `negative limit stderr:\n${r.stderr}`);

    // Missing value -> exit 2 verbatim '--limit: expected an integer value'.
    r = runCli(dir, { args: ['--recent', '--limit'] });
    assert.equal(r.status, 2);
    assert.ok(
      r.stderr.includes('--limit: expected an integer value'),
      `missing value stderr:\n${r.stderr}`,
    );
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLI-PARSER-POLICY-EXTRA-01 (MD-01): --policy show extra positionals --

test('T-CLI-PARSER-POLICY-EXTRA-01 (MD-01): --policy show extra exits 2', () => {
  if (skipIfNoBundle()) return;
  const dir = mkTmpStateDir();
  try {
    const r = runCli(dir, { args: ['--policy', 'show', 'junk'] });
    assert.equal(r.status, 2, `expected 2; got ${r.status}\nstderr:\n${r.stderr}`);
    assert.ok(
      r.stderr.includes('unexpected positional: junk'),
      `stderr verbatim mismatch:\n${r.stderr}`,
    );
  } finally { cleanupTmpStateDir(dir); }
});
