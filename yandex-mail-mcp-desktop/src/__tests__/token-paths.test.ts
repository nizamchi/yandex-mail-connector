// token-paths.test.ts -- M-2 fix from milestone v2.0.0 deep review.
//
// Validates the new findTokenFile resolution order:
//   1. YANDEX_TOKEN_FILE env (explicit path override; throws if unreadable)
//   2. <state_dir>/token.json (preferred for npx installs)
//   3. <project_root>/token.json (legacy: clone + npm start)
//   4. <cwd>/token.json (legacy: manual invoke)
//   5. YANDEX_OAUTH_TOKEN + YANDEX_EMAIL env-var fallback
//
// Test strategy mirrors token-perm.test.ts: write tokens into mkdtemp dirs,
// point env vars / process.chdir at them, assert loadCredentials() picks the
// right one. process.platform is left as-is (paths are platform-aware via
// state-dir module which is itself unit-tested elsewhere).
//
// State-dir caching: state-dir.ts caches the resolved dir module-locally.
// Each test calls stateDir._resetForTests() to flush the cache so that the
// just-set YANDEX_STATE_DIR is re-read.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { loadCredentials } from '../token.js';
import { _resetForTests as resetStateDir } from '../state-dir.js';

const TOKEN_PAYLOAD = JSON.stringify({
  access_token: 'y0_AgAAA_test_token_value_x',
  email:        'tester@yandex.ru',
});

interface EnvSnapshot { restore: () => void; }

function snapshotEnv(): EnvSnapshot {
  const keys = [
    'YANDEX_TOKEN_FILE',
    'YANDEX_STATE_DIR',
    'YANDEX_OAUTH_TOKEN',
    'YANDEX_EMAIL',
    'YANDEX_STRICT_FILE_PERMS',
  ];
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) saved[k] = process.env[k];
  return {
    restore: () => {
      for (const k of keys) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
    },
  };
}

function mkTempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `ymm-${prefix}-`));
}

function writeToken(dir: string, payload: string = TOKEN_PAYLOAD): string {
  const p = path.join(dir, 'token.json');
  fs.writeFileSync(p, payload, { mode: 0o600 });
  if (process.platform !== 'win32') {
    try { fs.chmodSync(p, 0o600); } catch { /* ignore */ }
  }
  return p;
}

function cleanupDir(dir: string): void {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// -- T-M2-01 ---------------------------------------------------------------

test('M-2 T-01: YANDEX_TOKEN_FILE explicit override wins over discovery', () => {
  const env = snapshotEnv();
  const explicitDir = mkTempDir('explicit');
  const stateDir   = mkTempDir('state');
  const cwdDir     = mkTempDir('cwd');
  const prevCwd = process.cwd();
  try {
    const explicitPath = writeToken(explicitDir, JSON.stringify({
      access_token: 'EXPLICIT_TOKEN', email: 'explicit@yandex.ru',
    }));
    writeToken(stateDir, JSON.stringify({
      access_token: 'STATE_TOKEN', email: 'state@yandex.ru',
    }));
    writeToken(cwdDir,   JSON.stringify({
      access_token: 'CWD_TOKEN',   email: 'cwd@yandex.ru',
    }));

    process.env.YANDEX_TOKEN_FILE = explicitPath;
    process.env.YANDEX_STATE_DIR  = stateDir;
    delete process.env.YANDEX_STRICT_FILE_PERMS;
    resetStateDir();
    process.chdir(cwdDir);

    const creds = loadCredentials();
    assert.equal(creds.email,      'explicit@yandex.ru', 'explicit override must win');
    assert.equal(creds.oauthToken, 'EXPLICIT_TOKEN');
  } finally {
    process.chdir(prevCwd);
    resetStateDir();
    env.restore();
    cleanupDir(explicitDir);
    cleanupDir(stateDir);
    cleanupDir(cwdDir);
  }
});

// -- T-M2-02 ---------------------------------------------------------------

test('M-2 T-02: YANDEX_TOKEN_FILE pointing at non-existent path throws (no silent fallback)', () => {
  const env = snapshotEnv();
  const stateDir = mkTempDir('state-fallback');
  try {
    // State dir has a valid token, but explicit override is broken: must NOT
    // silently fall back -- it must throw so the typo surfaces.
    writeToken(stateDir);
    process.env.YANDEX_TOKEN_FILE = path.join(os.tmpdir(), 'definitely-does-not-exist-ymm-' + Date.now() + '.json');
    process.env.YANDEX_STATE_DIR  = stateDir;
    delete process.env.YANDEX_STRICT_FILE_PERMS;
    resetStateDir();
    assert.throws(
      () => loadCredentials(),
      /YANDEX_TOKEN_FILE=.*is not readable/,
      'must throw with clear message when explicit override is broken',
    );
  } finally {
    resetStateDir();
    env.restore();
    cleanupDir(stateDir);
  }
});

// -- T-M2-03 ---------------------------------------------------------------

test('M-2 T-03: <state_dir>/token.json discovered when no explicit override and no cwd token', () => {
  const env = snapshotEnv();
  const stateDir = mkTempDir('state-discover');
  const cwdDir   = mkTempDir('cwd-empty');
  const prevCwd = process.cwd();
  try {
    writeToken(stateDir, JSON.stringify({
      access_token: 'STATE_TOKEN', email: 'state@yandex.ru',
    }));
    // cwdDir intentionally has NO token.json -- discovery must skip past cwd
    // and find the state-dir candidate.
    delete process.env.YANDEX_TOKEN_FILE;
    process.env.YANDEX_STATE_DIR = stateDir;
    delete process.env.YANDEX_STRICT_FILE_PERMS;
    resetStateDir();
    process.chdir(cwdDir);

    const creds = loadCredentials();
    assert.equal(creds.email,      'state@yandex.ru', 'state-dir candidate must be discovered');
    assert.equal(creds.oauthToken, 'STATE_TOKEN');
  } finally {
    process.chdir(prevCwd);
    resetStateDir();
    env.restore();
    cleanupDir(stateDir);
    cleanupDir(cwdDir);
  }
});

// -- T-M2-04 ---------------------------------------------------------------

test('M-2 T-04: state-dir token wins over cwd token (preferred location)', () => {
  const env = snapshotEnv();
  const stateDir = mkTempDir('state-pref');
  const cwdDir   = mkTempDir('cwd-pref');
  const prevCwd = process.cwd();
  try {
    writeToken(stateDir, JSON.stringify({
      access_token: 'STATE_TOKEN', email: 'state@yandex.ru',
    }));
    writeToken(cwdDir,   JSON.stringify({
      access_token: 'CWD_TOKEN',   email: 'cwd@yandex.ru',
    }));
    delete process.env.YANDEX_TOKEN_FILE;
    process.env.YANDEX_STATE_DIR = stateDir;
    delete process.env.YANDEX_STRICT_FILE_PERMS;
    resetStateDir();
    process.chdir(cwdDir);

    const creds = loadCredentials();
    assert.equal(creds.email, 'state@yandex.ru', 'state-dir must beat cwd in discovery order');
  } finally {
    process.chdir(prevCwd);
    resetStateDir();
    env.restore();
    cleanupDir(stateDir);
    cleanupDir(cwdDir);
  }
});

// -- T-M2-05 ---------------------------------------------------------------

test('M-2 T-05: error message names state-dir/token.json + YANDEX_TOKEN_FILE + env-var fallback when nothing found', () => {
  const env = snapshotEnv();
  const stateDir = mkTempDir('state-empty');
  const cwdDir   = mkTempDir('cwd-empty-2');
  const prevCwd = process.cwd();
  try {
    // Neither location has a token; env-var fallback also unset.
    delete process.env.YANDEX_TOKEN_FILE;
    delete process.env.YANDEX_OAUTH_TOKEN;
    delete process.env.YANDEX_EMAIL;
    process.env.YANDEX_STATE_DIR = stateDir;
    delete process.env.YANDEX_STRICT_FILE_PERMS;
    resetStateDir();
    process.chdir(cwdDir);

    let msg = '';
    try { loadCredentials(); } catch (e) { msg = (e as Error).message; }

    assert.match(msg, /credentials not found/i);
    assert.match(msg, /YANDEX_TOKEN_FILE/, 'error must mention explicit path env var');
    // state-dir path is platform-specific; just check the basename token.json
    // appears alongside the state-dir hint.
    assert.match(msg, /token\.json/);
    assert.match(msg, /YANDEX_OAUTH_TOKEN/, 'error must mention ephemeral env fallback');
    assert.match(msg, /YANDEX_EMAIL/);
  } finally {
    process.chdir(prevCwd);
    resetStateDir();
    env.restore();
    cleanupDir(stateDir);
    cleanupDir(cwdDir);
  }
});

// -- T-M2-06 ---------------------------------------------------------------

test('M-2 T-06: env-var fallback still works when no token.json anywhere', () => {
  const env = snapshotEnv();
  const stateDir = mkTempDir('state-novel');
  const cwdDir   = mkTempDir('cwd-novel');
  const prevCwd = process.cwd();
  try {
    delete process.env.YANDEX_TOKEN_FILE;
    process.env.YANDEX_STATE_DIR  = stateDir;
    process.env.YANDEX_OAUTH_TOKEN = 'y0_AgAAA_env_fallback_xxxx';
    process.env.YANDEX_EMAIL       = 'env@yandex.ru';
    delete process.env.YANDEX_STRICT_FILE_PERMS;
    resetStateDir();
    process.chdir(cwdDir);

    const creds = loadCredentials();
    assert.equal(creds.email,      'env@yandex.ru', 'env-var fallback must still resolve');
    assert.equal(creds.oauthToken, 'y0_AgAAA_env_fallback_xxxx');
  } finally {
    process.chdir(prevCwd);
    resetStateDir();
    env.restore();
    cleanupDir(stateDir);
    cleanupDir(cwdDir);
  }
});
