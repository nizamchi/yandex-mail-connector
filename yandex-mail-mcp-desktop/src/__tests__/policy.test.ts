// policy.test.ts -- Phase 1 Policy Module unit tests.
//
// Coverage (17 cases; floor per Revision 2 of 01-01-PLAN.md is 14):
//   T-DEFAULTS-01 -- first-launch on missing file writes defaults.
//   T-RT-01       -- round-trip: write defaults, reset, load again succeeds.
//   T-SCHEMA-01/02/03 -- Zod rejects negative weight / string-in-numeric / missing version.
//   T-TAMPER-01   -- hand-edit without resign -> FATAL via _setFatalHooksForTests.
//   T-AT-01/02/03 -- anti-tamper reject / override-path / augment-allowed.
//   T-ENV-01/02   -- YANDEX_POLICY_FILE override path / missing-path throws.
//   T-RESET-01    -- _resetForTests clears cache.
//   T-DOMAIN-01   -- 'policy:' prefix isolates allowlist-style signature.
//   T-FATAL-01    -- spawn integration: tampered file -> exit 1 + FATAL banner.
//   T-FATAL-02/03/04 -- malformed JSON / schema violation / secret.bin corruption,
//                       all in-process via _setFatalHooksForTests (B-2).
//
// Per-test isolation via mkTmpStateDir / cleanupTmpStateDir. Every test body
// wraps action+assertions in try/finally; cleanupTmpStateDir defensively
// deletes BOTH YANDEX_STATE_DIR and YANDEX_POLICY_FILE env vars (W-5).
//
// No emojis. ASCII-only. ESM `.js` suffix on imports.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';

import {
  loadPolicy,
  getPolicy,
  getPolicyPath,
  RiskPolicySchema,
  _resetForTests,
  _setFatalHooksForTests,
} from '../policy.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import { DEFAULT_POLICY, type RiskPolicy } from '../policy-defaults.js';

// ── Helpers ───────────────────────────────────────────────────

function mkTmpStateDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-policy-'));
  process.env.YANDEX_STATE_DIR = dir;
  // W-5: defensive -- prior test may have set YANDEX_POLICY_FILE; do not
  // inherit it into our fresh isolate.
  delete process.env.YANDEX_POLICY_FILE;
  _resetStateDir();
  _resetForTests();
  return dir;
}

function cleanupTmpStateDir(dir: string): void {
  // W-5 symmetric cleanup: drop both env vars BEFORE rmSync so any later
  // test starting up cannot accidentally see a stale path.
  delete process.env.YANDEX_POLICY_FILE;
  delete process.env.YANDEX_STATE_DIR;
  _resetForTests();
  _resetStateDir();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// Canonical-stringify body MUST match allowlist.ts and policy.ts byte-for-byte
// (W-2 mirror). Used by T-DOMAIN-01 to forge an allowlist-style signature
// over a policy payload and confirm the 'policy:' prefix rejects it.
function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalStringify).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
}

class FatalExitSentinel extends Error {
  constructor(public code: number) { super('FATAL_EXIT:' + code); }
}

function captureFatal(action: () => void): { stderr: string; exitCode: number } {
  let capturedStderr = '';
  let capturedCode = -1;
  const restore = _setFatalHooksForTests({
    exit: (code) => { capturedCode = code; throw new FatalExitSentinel(code); },
    stderr: (msg) => { capturedStderr += msg; },
  });
  try {
    assert.throws(action, FatalExitSentinel, 'expected recoverFatal to fire');
  } finally {
    restore();
  }
  return { stderr: capturedStderr, exitCode: capturedCode };
}

function signWithPolicyDomain(policy: RiskPolicy, secret: Buffer): string {
  return createHmac('sha256', secret).update('policy:' + canonicalStringify(policy)).digest('hex');
}

function clonePolicy(p: RiskPolicy): RiskPolicy {
  return JSON.parse(JSON.stringify(p)) as RiskPolicy;
}

// ── Tests ─────────────────────────────────────────────────────

test('T-DEFAULTS-01: defaults_load_no_file -- first-launch writes file with defaults', () => {
  const dir = mkTmpStateDir();
  try {
    const p = loadPolicy();
    assert.equal(p.thresholds.block, 100);
    assert.equal(p.weights.api_key_pattern, 75);
    assert.equal(p.override_block_threshold, false);
    assert.ok(fs.existsSync(getPolicyPath()), 'first-launch must create the policy file');
    // file is signed -- the second load via separate run should succeed.
    const raw = JSON.parse(fs.readFileSync(getPolicyPath(), 'utf-8')) as { policy: unknown; signature: string };
    assert.equal(typeof raw.signature, 'string');
    assert.equal(raw.signature.length, 64);  // sha256 hex
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-RT-01: write_and_reload_round_trip -- defaults written, reset, load again succeeds', () => {
  const dir = mkTmpStateDir();
  try {
    loadPolicy();  // writes defaults
    _resetForTests();
    const p = loadPolicy();  // reads + verifies sig
    assert.equal(p.thresholds.block, 100);
    assert.equal(p.weights.crypto_seed, 75);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-SCHEMA-01: schema_rejects_negative_weight', () => {
  const bad = clonePolicy(DEFAULT_POLICY);
  bad.weights.new_trust = -5;
  assert.throws(() => RiskPolicySchema.parse(bad), /new_trust/);
});

test('T-SCHEMA-02: schema_rejects_string_in_numeric', () => {
  const bad = clonePolicy(DEFAULT_POLICY) as unknown as { thresholds: { augment: unknown; strict: number; block: number } };
  bad.thresholds = { augment: '30', strict: 60, block: 100 };
  assert.throws(() => RiskPolicySchema.parse(bad));
});

test('T-SCHEMA-03: schema_rejects_missing_version', () => {
  const x = clonePolicy(DEFAULT_POLICY) as Partial<RiskPolicy>;
  delete x.version;
  assert.throws(() => RiskPolicySchema.parse(x));
});

test('T-TAMPER-01: tamper_detection_lowered_weight_no_resign -- in-process FATAL via hooks (W-3/B-2)', () => {
  const dir = mkTmpStateDir();
  try {
    loadPolicy();  // bootstraps secret.bin + writes risk-policy.json
    const filePath = getPolicyPath();
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as { policy: RiskPolicy; signature: string };
    raw.policy.weights.api_key_pattern = 1;  // mutate WITHOUT recomputing signature
    fs.writeFileSync(filePath, JSON.stringify(raw, null, 2), { mode: 0o600 });

    _resetForTests();
    const result = captureFatal(() => loadPolicy());
    assert.match(result.stderr, /signature invalid/);
    assert.match(result.stderr, /Recovery options:/);
    assert.equal(result.exitCode, 1);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-AT-01: anti_tamper_reject_lowered_block -- defaults loaded + W-4 recovery hint emitted', () => {
  const dir = mkTmpStateDir();
  try {
    loadPolicy();  // bootstraps secret.bin + writes
    const filePath = getPolicyPath();
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as { policy: RiskPolicy; signature: string };
    raw.policy.thresholds.block = 50;
    // override_block_threshold stays false. Recompute the sig so HMAC passes.
    const secret = fs.readFileSync(path.join(dir, 'secret.bin'));
    raw.signature = signWithPolicyDomain(raw.policy, secret);
    fs.writeFileSync(filePath, JSON.stringify(raw, null, 2), { mode: 0o600 });
    _resetForTests();

    // Capture stderr -- production stderr.write is used (not _fatalStderr;
    // anti-tamper does NOT crash).
    const origWrite = process.stderr.write.bind(process.stderr);
    let captured = '';
    process.stderr.write = ((m: string | Uint8Array) => {
      captured += typeof m === 'string' ? m : Buffer.from(m).toString('utf-8');
      return true;
    }) as typeof process.stderr.write;
    let p: RiskPolicy;
    try {
      p = loadPolicy();
    } finally {
      process.stderr.write = origWrite;
    }
    assert.equal(p.thresholds.block, 100, 'fell back to defaults');
    assert.match(captured, /policy rejected/);
    assert.match(captured, /override_block_threshold:true/);
    assert.match(captured, /yandex-mail-mcp-trust --policy reset|deleting risk-policy\.json/);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-AT-02: anti_tamper_override_path_works -- override_block_threshold:true loads lowered block', () => {
  const dir = mkTmpStateDir();
  try {
    loadPolicy();
    const filePath = getPolicyPath();
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as { policy: RiskPolicy; signature: string };
    raw.policy.thresholds.block = 50;
    raw.policy.override_block_threshold = true;
    const secret = fs.readFileSync(path.join(dir, 'secret.bin'));
    raw.signature = signWithPolicyDomain(raw.policy, secret);
    fs.writeFileSync(filePath, JSON.stringify(raw, null, 2), { mode: 0o600 });
    _resetForTests();

    const origWrite = process.stderr.write.bind(process.stderr);
    let captured = '';
    process.stderr.write = ((m: string | Uint8Array) => {
      captured += typeof m === 'string' ? m : Buffer.from(m).toString('utf-8');
      return true;
    }) as typeof process.stderr.write;
    let p: RiskPolicy;
    try {
      p = loadPolicy();
    } finally {
      process.stderr.write = origWrite;
    }
    assert.equal(p.thresholds.block, 50, 'override accepted -- block lowered');
    assert.equal(p.override_block_threshold, true);
    assert.doesNotMatch(captured, /policy rejected/, 'no warning when override flag is set');
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-AT-03: anti_tamper_augment_lowered_allowed -- D3 only block is protected', () => {
  const dir = mkTmpStateDir();
  try {
    loadPolicy();
    const filePath = getPolicyPath();
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as { policy: RiskPolicy; signature: string };
    raw.policy.thresholds.augment = 5;  // lower augment dramatically; keep block at 100.
    const secret = fs.readFileSync(path.join(dir, 'secret.bin'));
    raw.signature = signWithPolicyDomain(raw.policy, secret);
    fs.writeFileSync(filePath, JSON.stringify(raw, null, 2), { mode: 0o600 });
    _resetForTests();

    const origWrite = process.stderr.write.bind(process.stderr);
    let captured = '';
    process.stderr.write = ((m: string | Uint8Array) => {
      captured += typeof m === 'string' ? m : Buffer.from(m).toString('utf-8');
      return true;
    }) as typeof process.stderr.write;
    let p: RiskPolicy;
    try {
      p = loadPolicy();
    } finally {
      process.stderr.write = origWrite;
    }
    assert.equal(p.thresholds.augment, 5, 'augment lowered as-is');
    assert.equal(p.thresholds.block, 100, 'block unchanged');
    assert.doesNotMatch(captured, /policy rejected/);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-ENV-01: env_override_path_used -- YANDEX_POLICY_FILE points at custom path', () => {
  const dir = mkTmpStateDir();
  const altDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-policy-alt-'));
  try {
    // Bootstrap secret.bin at the default state dir via a first load.
    loadPolicy();
    const secret = fs.readFileSync(path.join(dir, 'secret.bin'));
    _resetForTests();

    // Write a hand-signed policy file at the custom path.
    const custom = path.join(altDir, 'my-policy.json');
    const wrapper = {
      policy: DEFAULT_POLICY,
      signature: signWithPolicyDomain(DEFAULT_POLICY, secret),
    };
    fs.writeFileSync(custom, JSON.stringify(wrapper, null, 2), { mode: 0o600 });

    process.env.YANDEX_POLICY_FILE = custom;
    try {
      assert.equal(getPolicyPath(), path.resolve(custom));
      const p = loadPolicy();
      assert.equal(p.thresholds.block, 100);
    } finally {
      delete process.env.YANDEX_POLICY_FILE;  // W-5
    }
  } finally {
    try { fs.rmSync(altDir, { recursive: true, force: true }); } catch { /* ignore */ }
    cleanupTmpStateDir(dir);
  }
});

test('T-ENV-02: env_override_missing_path_throws -- typo surfaces, no silent fallback', () => {
  const dir = mkTmpStateDir();
  try {
    const ghost = path.join(dir, 'definitely-not-here', 'no.json');
    process.env.YANDEX_POLICY_FILE = ghost;
    try {
      assert.throws(() => loadPolicy(), /YANDEX_POLICY_FILE.*not readable/);
    } finally {
      delete process.env.YANDEX_POLICY_FILE;  // W-5
    }
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-RESET-01: _resetForTests_clears_cache', () => {
  const dir = mkTmpStateDir();
  try {
    loadPolicy();
    const p = getPolicy();
    assert.equal(p.thresholds.block, 100);
    _resetForTests();
    assert.throws(() => getPolicy(), /loadPolicy/);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-DOMAIN-01: domain_prefix_isolates_allowlist -- unprefixed sig rejected (D1, PMLF-POL-RISK)', () => {
  const dir = mkTmpStateDir();
  try {
    loadPolicy();  // bootstraps secret.bin
    const secret = fs.readFileSync(path.join(dir, 'secret.bin'));

    // Forge an allowlist-style signature: HMAC over canonicalStringify(policy)
    // WITHOUT the 'policy:' prefix.
    const unprefixed = createHmac('sha256', secret)
      .update(canonicalStringify(DEFAULT_POLICY))
      .digest('hex');
    const wrapper = { policy: DEFAULT_POLICY, signature: unprefixed };
    fs.writeFileSync(getPolicyPath(), JSON.stringify(wrapper, null, 2), { mode: 0o600 });

    _resetForTests();
    const result = captureFatal(() => loadPolicy());
    assert.match(result.stderr, /signature invalid/);
    assert.equal(result.exitCode, 1);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-FATAL-01: fatal_recovery_spawn -- tampered file makes the spawned bundle exit 1 with FATAL banner', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-policy-spawn-'));
  try {
    const bundlePath = path.join(process.cwd(), 'dist', 'yandex-mail-mcp.js');
    if (!fs.existsSync(bundlePath)) {
      // T-10 builds it; skip if not present.
      console.error(`[T-FATAL-01] skipping: ${bundlePath} not built yet`);
      return;
    }

    // 1) write a valid secret.bin used by BOTH allowlist + policy.
    const secret = Buffer.alloc(32, 0x7a);
    fs.writeFileSync(path.join(dir, 'secret.bin'), secret, { mode: 0o600 });

    // 2) write a fresh-state allowlist.json so the allowlist gate passes
    //    (verifySignature has the fresh-state shortcut at bootstrap_completed_at===null).
    const allowlist = {
      version: 1,
      schema: 'yandex-mail-mcp-allowlist/v1',
      bootstrap_completed_at: null,
      entries: [] as unknown[],
      signature: '',
    };
    fs.writeFileSync(path.join(dir, 'allowlist.json'), JSON.stringify(allowlist, null, 2), { mode: 0o600 });

    // 3) write a tampered risk-policy.json with a bogus signature.
    const bogusPolicy = {
      policy: DEFAULT_POLICY,
      signature: '00'.repeat(32),
    };
    fs.writeFileSync(path.join(dir, 'risk-policy.json'), JSON.stringify(bogusPolicy, null, 2), { mode: 0o600 });

    const res = spawnSync(process.execPath, [bundlePath], {
      env: {
        ...process.env,
        YANDEX_STATE_DIR: dir,
        YANDEX_AUTH_LEVEL: 'readonly',
        YANDEX_POLICY_FILE: '',
      },
      timeout: 15000,
      encoding: 'utf-8',
    });
    assert.equal(res.status, 1, `expected exit code 1, got ${res.status}; stderr:\n${res.stderr}`);
    assert.match(res.stderr, /FATAL: risk-policy\.json signature invalid/);
    assert.match(res.stderr, /yandex-mail-mcp-trust --policy reset/);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});

test('T-FATAL-02: fatal_recovery_malformed_json (B-2) -- parse failure routes through recoverFatal', () => {
  const dir = mkTmpStateDir();
  try {
    loadPolicy();  // bootstrap so secret.bin exists
    fs.writeFileSync(getPolicyPath(), 'not valid json {{', { mode: 0o600 });
    _resetForTests();

    const result = captureFatal(() => loadPolicy());
    assert.match(result.stderr, /parse failed/);
    assert.match(result.stderr, /Recovery options:/);
    assert.match(result.stderr, /Delete .*risk-policy\.json/);
    assert.equal(result.exitCode, 1);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-FATAL-03: fatal_recovery_schema_violation (B-2) -- Zod-rejecting payload with valid HMAC still fatals', () => {
  const dir = mkTmpStateDir();
  try {
    loadPolicy();  // bootstrap secret.bin
    const secret = fs.readFileSync(path.join(dir, 'secret.bin'));

    // Build a payload that parses (JSON-valid) but FAILS Zod (negative weight).
    // The schema layer rejects BEFORE the HMAC layer, per the loadPolicy
    // ordering (parse -> wrapper-shape -> schema -> hmac).
    const evil = clonePolicy(DEFAULT_POLICY);
    evil.weights.new_trust = -1;
    // Sign over the (invalid) policy so we exercise the schema branch -- if
    // we left a bogus signature, the timingSafeEqual branch fires first.
    const wrapper = {
      policy: evil,
      signature: signWithPolicyDomain(evil, secret),
    };
    fs.writeFileSync(getPolicyPath(), JSON.stringify(wrapper, null, 2), { mode: 0o600 });
    _resetForTests();

    const result = captureFatal(() => loadPolicy());
    assert.match(result.stderr, /schema validation failed/);
    assert.match(result.stderr, /new_trust/);
    assert.match(result.stderr, /Recovery options:/);
    assert.equal(result.exitCode, 1);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-FATAL-04: fatal_recovery_secret_corrupt (B-2) -- truncated secret.bin routes through recoverFatal', () => {
  const dir = mkTmpStateDir();
  try {
    loadPolicy();  // bootstrap secret.bin + risk-policy.json
    // Truncate secret.bin to length 16 (not 32) -- loadSecret rejects.
    fs.writeFileSync(path.join(dir, 'secret.bin'), Buffer.alloc(16), { mode: 0o600 });
    _resetForTests();

    const result = captureFatal(() => loadPolicy());
    assert.match(result.stderr, /secret\.bin corruption/);
    assert.match(result.stderr, /Recovery options:/);
    assert.equal(result.exitCode, 1);
  } finally {
    cleanupTmpStateDir(dir);
  }
});
