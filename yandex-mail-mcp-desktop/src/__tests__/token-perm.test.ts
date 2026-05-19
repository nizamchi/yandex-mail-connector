// Tests for the Unix-only permission check on token.json in token.ts
// (Task 1, Phase 8, OPS-06, T-08-02).
//
// Test strategy:
//   * Bundle-loaded indirectly: we exercise permCheck via loadCredentials() by
//     placing a token.json in a temp directory and pointing process.cwd at it
//     through process.chdir() inside fs.mkdtempSync(...)/...
//   * Capture stderr by replacing process.stderr.write with a spy.
//   * Capture process.exit by replacing it with a function that throws a
//     sentinel error so the test can assert on it without aborting the runner.
//   * On win32 the perm-bit assertions are meaningless (chmod is a no-op);
//     we still assert that win32 path runs silently.

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadCredentials } from '../token.js';

interface StderrSpy {
  lines: string[];
  restore: () => void;
}

function spyStderr(): StderrSpy {
  const original = process.stderr.write.bind(process.stderr);
  const lines: string[] = [];
  (process.stderr as unknown as { write: (s: string) => boolean }).write = (s: string): boolean => {
    lines.push(s);
    return true;
  };
  return {
    lines,
    restore: () => {
      (process.stderr as unknown as { write: typeof original }).write = original;
    },
  };
}

interface ExitSpy {
  called: boolean;
  code: number | null;
  restore: () => void;
}

function spyExit(): ExitSpy {
  const original = process.exit;
  const state: { called: boolean; code: number | null } = { called: false, code: null };
  (process as unknown as { exit: (n?: number) => never }).exit = ((n?: number): never => {
    state.called = true;
    state.code = n ?? 0;
    throw new Error('__test_process_exit__');
  }) as (n?: number) => never;
  return {
    get called() { return state.called; },
    get code() { return state.code; },
    restore: () => {
      (process as unknown as { exit: typeof original }).exit = original;
    },
  };
}

function makeTokenFile(mode: number): { dir: string; tokenPath: string; cleanup: () => void; prevCwd: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ymm-perm-'));
  const tokenPath = path.join(dir, 'token.json');
  fs.writeFileSync(
    tokenPath,
    JSON.stringify({ access_token: 'y0_AgAAA_test_token_value_x', email: 'tester@yandex.ru' }),
    { mode },
  );
  if (process.platform !== 'win32') {
    try { fs.chmodSync(tokenPath, mode); } catch { /* ignore */ }
  }
  const prevCwd = process.cwd();
  process.chdir(dir);
  return {
    dir,
    tokenPath,
    prevCwd,
    cleanup: () => {
      process.chdir(prevCwd);
      try { fs.unlinkSync(tokenPath); } catch { /* ignore */ }
      try { fs.rmdirSync(dir); } catch { /* ignore */ }
    },
  };
}

test('permCheck: win32 always silent regardless of mode', { skip: process.platform !== 'win32' }, () => {
  const ctx = makeTokenFile(0o644);
  const stderr = spyStderr();
  const exit = spyExit();
  delete process.env.YANDEX_STRICT_FILE_PERMS;
  try {
    const creds = loadCredentials();
    assert.equal(creds.email, 'tester@yandex.ru');
    assert.equal(stderr.lines.length, 0, 'expected no stderr on win32');
    assert.equal(exit.called, false);
  } finally {
    stderr.restore();
    exit.restore();
    ctx.cleanup();
  }
});

test('permCheck: Unix 0o600 silent', { skip: process.platform === 'win32' }, () => {
  const ctx = makeTokenFile(0o600);
  const stderr = spyStderr();
  const exit = spyExit();
  delete process.env.YANDEX_STRICT_FILE_PERMS;
  try {
    const creds = loadCredentials();
    assert.equal(creds.email, 'tester@yandex.ru');
    assert.equal(stderr.lines.length, 0, `expected no stderr at 0o600 — got: ${stderr.lines.join('')}`);
    assert.equal(exit.called, false);
  } finally {
    stderr.restore();
    exit.restore();
    ctx.cleanup();
  }
});

test('permCheck: Unix 0o644 warns without exit when STRICT unset', { skip: process.platform === 'win32' }, () => {
  const ctx = makeTokenFile(0o644);
  const stderr = spyStderr();
  const exit = spyExit();
  delete process.env.YANDEX_STRICT_FILE_PERMS;
  try {
    const creds = loadCredentials();
    assert.equal(creds.email, 'tester@yandex.ru');
    const joined = stderr.lines.join('');
    assert.match(joined, /mode 644/);
    assert.match(joined, /chmod 600/);
    assert.equal(exit.called, false);
  } finally {
    stderr.restore();
    exit.restore();
    ctx.cleanup();
  }
});

test('permCheck: Unix 0o644 + STRICT calls process.exit(1)', { skip: process.platform === 'win32' }, () => {
  const ctx = makeTokenFile(0o644);
  const stderr = spyStderr();
  const exit = spyExit();
  process.env.YANDEX_STRICT_FILE_PERMS = 'true';
  try {
    assert.throws(() => loadCredentials(), /__test_process_exit__/);
    assert.equal(exit.called, true);
    assert.equal(exit.code, 1);
    const joined = stderr.lines.join('');
    assert.match(joined, /mode 644/);
    assert.match(joined, /STRICT_FILE_PERMS/);
  } finally {
    delete process.env.YANDEX_STRICT_FILE_PERMS;
    stderr.restore();
    exit.restore();
    ctx.cleanup();
  }
});
