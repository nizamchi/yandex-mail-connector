// state-dir.test.ts — Hook 1 unit tests.
//
// Coverage:
//   - YANDEX_STATE_DIR override (absolute + relative).
//   - Unix branches: with/without XDG_CONFIG_HOME (mock process.platform).
//   - Windows branch: with APPDATA set (mock process.platform).
//   - Lazy mkdir + idempotency.
//   - _resetForTests() flushes cache.
//
// All process.env / process.platform mutations are wrapped in try/finally
// blocks so tests cannot leak state into siblings.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { getStateDir, _resetForTests } from '../state-dir.js';

function snapshotEnv(): () => void {
  const keys = ['YANDEX_STATE_DIR', 'XDG_CONFIG_HOME', 'APPDATA', 'HOME', 'USERPROFILE'];
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) saved[k] = process.env[k];
  return () => {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  };
}

function withPlatform(p: NodeJS.Platform, fn: () => void): void {
  const original = process.platform;
  Object.defineProperty(process, 'platform', { value: p, configurable: true });
  try {
    fn();
  } finally {
    Object.defineProperty(process, 'platform', { value: original, configurable: true });
  }
}

function mkTmp(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-statedir-'));
}

function cleanup(dir: string): void {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

test('getStateDir: YANDEX_STATE_DIR override (absolute) is honoured and dir is created', () => {
  const restore = snapshotEnv();
  const tmp = mkTmp();
  const target = path.join(tmp, 'override-abs');
  try {
    _resetForTests();
    process.env.YANDEX_STATE_DIR = target;
    const result = getStateDir();
    assert.equal(result, path.resolve(target));
    assert.ok(fs.existsSync(result), 'state dir should be created');
  } finally {
    _resetForTests();
    restore();
    cleanup(tmp);
  }
});

test('getStateDir: YANDEX_STATE_DIR override is path.resolved (relative input)', () => {
  const restore = snapshotEnv();
  const tmp = mkTmp();
  const cwd = process.cwd();
  try {
    _resetForTests();
    process.chdir(tmp);
    process.env.YANDEX_STATE_DIR = './rel-dir';
    const result = getStateDir();
    // On Windows path.resolve normalises slashes; compare via path.resolve.
    assert.equal(result, path.resolve(tmp, 'rel-dir'));
    assert.ok(fs.existsSync(result));
  } finally {
    _resetForTests();
    process.chdir(cwd);
    restore();
    cleanup(tmp);
  }
});

test('getStateDir: Unix branch with XDG_CONFIG_HOME', () => {
  const restore = snapshotEnv();
  const tmp = mkTmp();
  try {
    withPlatform('linux', () => {
      _resetForTests();
      delete process.env.YANDEX_STATE_DIR;
      process.env.XDG_CONFIG_HOME = tmp;
      const result = getStateDir();
      assert.equal(result, path.join(tmp, 'yandex-mail-mcp'));
      assert.ok(fs.existsSync(result));
    });
  } finally {
    _resetForTests();
    restore();
    cleanup(tmp);
  }
});

if (process.platform !== 'win32') {
  // Skip on win32 — os.homedir() on Windows reads USERPROFILE/HOMEDRIVE, not
  // HOME, so we cannot redirect it to a tmpdir from inside the test process
  // without module mocking. The structural intent (XDG_CONFIG_HOME defaults
  // to ~/.config) is exercised by the "with XDG_CONFIG_HOME" test above; this
  // sub-test only adds the explicit-fallback assertion. Real path is created
  // under the user's actual ~/.config on POSIX — cleanup is best-effort.
  test('getStateDir: Unix branch without XDG_CONFIG_HOME falls back to ~/.config', () => {
    const restore = snapshotEnv();
    try {
      withPlatform('linux', () => {
        _resetForTests();
        delete process.env.YANDEX_STATE_DIR;
        delete process.env.XDG_CONFIG_HOME;
        const result = getStateDir();
        const expected = path.join(os.homedir(), '.config', 'yandex-mail-mcp');
        assert.equal(result, expected);
      });
    } finally {
      _resetForTests();
      restore();
    }
  });
}

test('getStateDir: win32 branch with APPDATA set', () => {
  const restore = snapshotEnv();
  const tmp = mkTmp();
  try {
    withPlatform('win32', () => {
      _resetForTests();
      delete process.env.YANDEX_STATE_DIR;
      process.env.APPDATA = tmp;
      const result = getStateDir();
      assert.equal(path.normalize(result), path.normalize(path.join(tmp, 'yandex-mail-mcp')));
      assert.ok(fs.existsSync(result));
    });
  } finally {
    _resetForTests();
    restore();
    cleanup(tmp);
  }
});

test('getStateDir: second call is a no-op (cached, does not re-mkdir)', () => {
  const restore = snapshotEnv();
  const tmp = mkTmp();
  try {
    _resetForTests();
    process.env.YANDEX_STATE_DIR = path.join(tmp, 'cached');
    const first = getStateDir();
    const before = fs.statSync(first).mtimeMs;
    // Sleep a microtick is not enough on some FS — just call again and assert path equality.
    const second = getStateDir();
    assert.equal(second, first);
    assert.equal(fs.statSync(first).mtimeMs, before);
  } finally {
    _resetForTests();
    restore();
    cleanup(tmp);
  }
});

test('getStateDir: _resetForTests flushes cache so env changes take effect', () => {
  const restore = snapshotEnv();
  const tmp = mkTmp();
  try {
    _resetForTests();
    process.env.YANDEX_STATE_DIR = path.join(tmp, 'first');
    const first = getStateDir();
    assert.equal(first, path.resolve(path.join(tmp, 'first')));

    _resetForTests();
    process.env.YANDEX_STATE_DIR = path.join(tmp, 'second');
    const second = getStateDir();
    assert.equal(second, path.resolve(path.join(tmp, 'second')));
    assert.notEqual(first, second);
  } finally {
    _resetForTests();
    restore();
    cleanup(tmp);
  }
});

test('getStateDir: existing directory is not an error (EEXIST swallowed)', () => {
  const restore = snapshotEnv();
  const tmp = mkTmp();
  const target = path.join(tmp, 'pre-exists');
  fs.mkdirSync(target, { recursive: true });
  try {
    _resetForTests();
    process.env.YANDEX_STATE_DIR = target;
    const result = getStateDir();
    assert.equal(result, path.resolve(target));
  } finally {
    _resetForTests();
    restore();
    cleanup(tmp);
  }
});

// Mode 0o700 check only runs meaningfully on Unix. Skip on win32.
if (process.platform !== 'win32') {
  test('getStateDir: Unix mode is 0o700 on new dir', () => {
    const restore = snapshotEnv();
    const tmp = mkTmp();
    const target = path.join(tmp, 'mode-check');
    try {
      _resetForTests();
      process.env.YANDEX_STATE_DIR = target;
      getStateDir();
      const mode = fs.statSync(target).mode & 0o777;
      assert.equal(mode, 0o700, `expected 0o700, got 0o${mode.toString(8)}`);
    } finally {
      _resetForTests();
      restore();
      cleanup(tmp);
    }
  });
}
