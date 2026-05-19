// cli-trust.test.ts — file-handoff IPC + TTL tests for `yandex-mail-mcp-trust`.
//
// Coverage:
//   - Spawn `node dist/cli-trust.js bob@x.com` with YANDEX_TRUST_ASSUME_YES=1
//     → exit 0, pending-trust.json created with right shape + TTL ~5min.
//   - Spawn with no env (interactive) and pipe 'n' → exit 1, no file.
//   - Spawn with invalid address → exit 2, stderr 'Invalid address'.
//   - Spawn twice in a row → second overwrites the first (single-slot).
//   - Direct round-trip via yandex_trust_address handler:
//     * fresh pending → success path adds to allowlist + unlinks pending.
//     * expired pending → isError 'expired' + file deleted.
//     * wrong token (matching format) → isError; pending file STILL EXISTS
//       (typo recovery; TTL rate-limits).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

import { TOOLS } from '../tools.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import {
  isAllowed,
  loadAllowlist,
  _resetForTests as _resetAllowlist,
} from '../allowlist.js';

const CLI_BUNDLE = path.join(process.cwd(), 'dist', 'cli-trust.js');

function mkTmpStateDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-cli-trust-'));
  process.env.YANDEX_STATE_DIR = dir;
  _resetStateDir();
  _resetAllowlist();
  return dir;
}

function cleanupTmpStateDir(dir: string): void {
  delete process.env.YANDEX_STATE_DIR;
  _resetStateDir();
  _resetAllowlist();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

function pendingTrustFile(dir: string): string {
  return path.join(dir, 'pending-trust.json');
}

function getTrustTool() {
  const tool = TOOLS.find(t => t.name === 'yandex_trust_address');
  if (!tool) throw new Error('yandex_trust_address tool not found in TOOLS registry');
  return tool;
}

function makeCtx() {
  return {
    authLevel: 1 as 0 | 1 | 2 | 3,
    capabilities: new Set<never>(),
    serverContext: { canElicit: false },
  };
}

test('cli-trust: spawn with valid address + YANDEX_TRUST_ASSUME_YES=1 writes pending-trust.json', () => {
  if (!fs.existsSync(CLI_BUNDLE)) {
    console.error(`[cli-trust] skip: ${CLI_BUNDLE} not built`);
    return;
  }
  const dir = mkTmpStateDir();
  try {
    const res = spawnSync(process.execPath, [CLI_BUNDLE, 'bob@x.com'], {
      env: { ...process.env, YANDEX_STATE_DIR: dir, YANDEX_TRUST_ASSUME_YES: '1' },
      encoding: 'utf-8',
      timeout: 10000,
    });
    assert.equal(res.status, 0, `expected exit 0; stderr:\n${res.stderr}`);
    assert.match(res.stdout, /^trust_token: [0-9a-f]{64}\s*$/m, 'stdout must have trust_token line');
    const fpath = pendingTrustFile(dir);
    assert.ok(fs.existsSync(fpath), 'pending-trust.json must exist');
    const pending = JSON.parse(fs.readFileSync(fpath, 'utf-8'));
    assert.equal(pending.address, 'bob@x.com');
    assert.equal(pending.scope, 'permanent');
    assert.equal(typeof pending.trust_token, 'string');
    assert.equal(pending.trust_token.length, 64);
    assert.ok(/^[0-9a-f]{64}$/.test(pending.trust_token));
    const now = Date.now();
    assert.ok(pending.expires_at_ms > now + 4 * 60 * 1000, 'expiry must be > 4 min from now');
    assert.ok(pending.expires_at_ms <= now + 5 * 60 * 1000 + 10_000, 'expiry must be ≤ 5min + 10s from now');
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('cli-trust: piped "n" answer → exit 1, no file created', () => {
  if (!fs.existsSync(CLI_BUNDLE)) {
    console.error(`[cli-trust] skip: ${CLI_BUNDLE} not built`);
    return;
  }
  const dir = mkTmpStateDir();
  try {
    const res = spawnSync(process.execPath, [CLI_BUNDLE, 'eve@x.com'], {
      env: { ...process.env, YANDEX_STATE_DIR: dir },
      encoding: 'utf-8',
      input: 'n\n',
      timeout: 10000,
    });
    assert.equal(res.status, 1, `expected exit 1; stderr:\n${res.stderr}`);
    assert.match(res.stderr, /Aborted/);
    assert.equal(fs.existsSync(pendingTrustFile(dir)), false);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('cli-trust: invalid address → exit 2, stderr matches', () => {
  if (!fs.existsSync(CLI_BUNDLE)) {
    console.error(`[cli-trust] skip: ${CLI_BUNDLE} not built`);
    return;
  }
  const dir = mkTmpStateDir();
  try {
    const res = spawnSync(process.execPath, [CLI_BUNDLE, 'not-an-email'], {
      env: { ...process.env, YANDEX_STATE_DIR: dir, YANDEX_TRUST_ASSUME_YES: '1' },
      encoding: 'utf-8',
      timeout: 10000,
    });
    assert.equal(res.status, 2, `expected exit 2; stderr:\n${res.stderr}`);
    assert.match(res.stderr, /Invalid address/);
    assert.equal(fs.existsSync(pendingTrustFile(dir)), false);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('cli-trust: second invocation overwrites first (single-slot semantics)', () => {
  if (!fs.existsSync(CLI_BUNDLE)) {
    console.error(`[cli-trust] skip: ${CLI_BUNDLE} not built`);
    return;
  }
  const dir = mkTmpStateDir();
  try {
    spawnSync(process.execPath, [CLI_BUNDLE, 'first@x.com'], {
      env: { ...process.env, YANDEX_STATE_DIR: dir, YANDEX_TRUST_ASSUME_YES: '1' },
      encoding: 'utf-8',
      timeout: 10000,
    });
    const firstContent = JSON.parse(fs.readFileSync(pendingTrustFile(dir), 'utf-8'));
    spawnSync(process.execPath, [CLI_BUNDLE, 'second@x.com'], {
      env: { ...process.env, YANDEX_STATE_DIR: dir, YANDEX_TRUST_ASSUME_YES: '1' },
      encoding: 'utf-8',
      timeout: 10000,
    });
    const secondContent = JSON.parse(fs.readFileSync(pendingTrustFile(dir), 'utf-8'));
    assert.equal(secondContent.address, 'second@x.com');
    assert.notEqual(firstContent.trust_token, secondContent.trust_token);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('yandex_trust_address handler: round-trip — pending + matching token → success, allowlist updated, file deleted', async () => {
  const dir = mkTmpStateDir();
  try {
    const token = randomBytes(32).toString('hex');
    const pending = {
      address: 'carol@example.com',
      scope: 'permanent',
      trust_token: token,
      expires_at_ms: Date.now() + 5 * 60 * 1000,
    };
    fs.writeFileSync(pendingTrustFile(dir), JSON.stringify(pending));

    const tool = getTrustTool();
    const result = await tool.handler({ address: 'carol@example.com', scope: 'permanent', trust_token: token }, makeCtx());
    assert.equal(result.isError, undefined, `expected success; got: ${JSON.stringify(result)}`);
    assert.equal(isAllowed('carol@example.com'), true);
    assert.equal(fs.existsSync(pendingTrustFile(dir)), false, 'pending-trust.json must be deleted after success');
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('yandex_trust_address handler: expired pending → isError "expired" + file deleted', async () => {
  const dir = mkTmpStateDir();
  try {
    const token = randomBytes(32).toString('hex');
    const pending = {
      address: 'old@example.com',
      scope: 'permanent',
      trust_token: token,
      expires_at_ms: Date.now() - 1000, // already expired
    };
    fs.writeFileSync(pendingTrustFile(dir), JSON.stringify(pending));

    const tool = getTrustTool();
    const result = await tool.handler({ address: 'old@example.com', scope: 'permanent', trust_token: token }, makeCtx());
    assert.equal(result.isError, true);
    assert.match(result.content[0]?.text ?? '', /expired/i);
    assert.equal(fs.existsSync(pendingTrustFile(dir)), false, 'expired pending must be deleted');
    assert.equal(isAllowed('old@example.com'), false);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('yandex_trust_address handler: wrong token (matching format) → isError; pending STILL EXISTS', async () => {
  const dir = mkTmpStateDir();
  try {
    const token = randomBytes(32).toString('hex');
    const wrong = randomBytes(32).toString('hex');
    const pending = {
      address: 'dave@example.com',
      scope: 'permanent',
      trust_token: token,
      expires_at_ms: Date.now() + 5 * 60 * 1000,
    };
    fs.writeFileSync(pendingTrustFile(dir), JSON.stringify(pending));

    const tool = getTrustTool();
    const result = await tool.handler({ address: 'dave@example.com', scope: 'permanent', trust_token: wrong }, makeCtx());
    assert.equal(result.isError, true);
    assert.match(result.content[0]?.text ?? '', /invalid trust token/i);
    // Wrong-token attempts do NOT burn the pending slot — typo recovery; TTL bounds replay.
    assert.equal(fs.existsSync(pendingTrustFile(dir)), true, 'pending must remain after wrong-token attempt');
    const file = loadAllowlist();
    assert.equal(file.entries.length, 0);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('yandex_trust_address handler: address mismatch → isError, file NOT deleted', async () => {
  const dir = mkTmpStateDir();
  try {
    const token = randomBytes(32).toString('hex');
    const pending = {
      address: 'right@example.com',
      scope: 'permanent',
      trust_token: token,
      expires_at_ms: Date.now() + 5 * 60 * 1000,
    };
    fs.writeFileSync(pendingTrustFile(dir), JSON.stringify(pending));

    const tool = getTrustTool();
    const result = await tool.handler({ address: 'wrong@example.com', scope: 'permanent', trust_token: token }, makeCtx());
    assert.equal(result.isError, true);
    assert.match(result.content[0]?.text ?? '', /mismatch/i);
    assert.equal(fs.existsSync(pendingTrustFile(dir)), true);
    assert.equal(isAllowed('wrong@example.com'), false);
    assert.equal(isAllowed('right@example.com'), false);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('yandex_trust_address handler: no pending file → isError', async () => {
  const dir = mkTmpStateDir();
  try {
    const tool = getTrustTool();
    const token = randomBytes(32).toString('hex');
    const result = await tool.handler({ address: 'nobody@example.com', scope: 'permanent', trust_token: token }, makeCtx());
    assert.equal(result.isError, true);
    assert.match(result.content[0]?.text ?? '', /no pending trust request/i);
  } finally {
    cleanupTmpStateDir(dir);
  }
});
