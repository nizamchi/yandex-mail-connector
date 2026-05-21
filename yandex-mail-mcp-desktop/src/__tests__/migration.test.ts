// migration.test.ts -- Phase 6 (D10/D12) allowlist legacy migration coverage.
//
// 6 tests:
//   T-MIG-EMPTY-01      empty entries -> no migration.
//   T-MIG-FULLY-OLD-01  3 legacy entries -> all migrated; signature verifies.
//   T-MIG-FULLY-NEW-01  already-new -> no mutation; byte-equal on re-load.
//   T-MIG-PARTIAL-01    mixed legacy+new -> migrates only the legacy ones.
//   T-MIG-IDEMPOTENT-01 second loadAllowlist is byte-equal to the first.
//   T-MIG-TAMPER-01     metadata mutation w/o resign -> verifySignature false.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createHmac } from 'node:crypto';

import {
  loadAllowlist,
  verifySignature,
  getAllowlistPath,
  getSecretPath,
  _resetForTests,
} from '../allowlist.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';

function mkTmpStateDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-migration-'));
  process.env.YANDEX_STATE_DIR = dir;
  _resetStateDir();
  _resetForTests();
  return dir;
}

function cleanupTmpStateDir(dir: string): void {
  delete process.env.YANDEX_STATE_DIR;
  _resetStateDir();
  _resetForTests();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// Mirror canonicalStringify from allowlist.ts -- deterministic sorted-key JSON.
function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalStringify).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
}

interface AnyFile {
  version: 1;
  schema: 'yandex-mail-mcp-allowlist/v1';
  bootstrap_completed_at: string | null;
  entries: Array<Record<string, unknown>>;
  signature: string;
}

function writeSecret(stateDir: string): Buffer {
  const secret = Buffer.alloc(32, 0x42);
  fs.writeFileSync(path.join(stateDir, 'secret.bin'), secret);
  return secret;
}

function signFile(file: AnyFile, secret: Buffer): void {
  const { signature: _s, ...rest } = file;
  void _s;
  const canonical = canonicalStringify(rest);
  file.signature = createHmac('sha256', secret).update(canonical).digest('hex');
}

function writeFile(file: AnyFile): void {
  fs.writeFileSync(getAllowlistPath(), JSON.stringify(file, null, 2));
}

function readFile(): string {
  return fs.readFileSync(getAllowlistPath(), 'utf-8');
}

function legacyEntry(addr: string, source: string, addedAt: string): Record<string, unknown> {
  return { address: addr, scope: 'permanent', source, added_at: addedAt };
}

function newEntry(addr: string, source: string, addedAt: string, addedMs: number, useCount = 0): Record<string, unknown> {
  return { address: addr, scope: 'permanent', source, added_at: addedAt, added: addedMs, lastUsed: addedMs, useCount };
}

test('T-MIG-EMPTY-01: empty entries -> migration is a no-op', () => {
  const dir = mkTmpStateDir();
  try {
    const secret = writeSecret(dir);
    const file: AnyFile = {
      version: 1,
      schema: 'yandex-mail-mcp-allowlist/v1',
      bootstrap_completed_at: new Date(1700000000000).toISOString(),
      entries: [],
      signature: '',
    };
    signFile(file, secret);
    writeFile(file);
    const before = readFile();
    const loaded = loadAllowlist();
    assert.equal(loaded.entries.length, 0);
    assert.equal(verifySignature(), true);
    const after = readFile();
    assert.equal(after, before, 'no-entries file must be byte-equal after load');
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-MIG-FULLY-OLD-01: 3 legacy entries -> all migrated; signature verifies', () => {
  const dir = mkTmpStateDir();
  try {
    const secret = writeSecret(dir);
    const ts1 = '2025-11-01T00:00:00.000Z';
    const ts2 = '2025-11-15T00:00:00.000Z';
    const ts3 = '2025-12-01T00:00:00.000Z';
    const file: AnyFile = {
      version: 1,
      schema: 'yandex-mail-mcp-allowlist/v1',
      bootstrap_completed_at: ts1,
      entries: [
        legacyEntry('alice@example.com', 'sent_history',    ts1),
        legacyEntry('bob@example.com',   'user_trust_token', ts2),
        legacyEntry('carol@example.com', 'auto_trust_reply', ts3),
      ],
      signature: '',
    };
    signFile(file, secret);
    writeFile(file);
    // First load triggers migration + re-sign + persist.
    const loaded = loadAllowlist();
    assert.equal(loaded.entries.length, 3);
    for (const e of loaded.entries) {
      assert.equal(typeof (e as unknown as Record<string, unknown>)['added'], 'number');
      assert.equal(typeof (e as unknown as Record<string, unknown>)['lastUsed'], 'number');
      assert.equal(typeof (e as unknown as Record<string, unknown>)['useCount'], 'number');
      assert.equal(e.useCount, 0);
    }
    // alice should pull her Date.parse(added_at) for `added`.
    const alice = loaded.entries.find(e => e.address === 'alice@example.com');
    assert.ok(alice, 'alice present');
    assert.equal(alice!.added, Date.parse(ts1));
    // Signature now correct over migrated content.
    assert.equal(verifySignature(), true);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-MIG-FULLY-NEW-01: already-new file -> no mutation, byte-equal on second load', () => {
  const dir = mkTmpStateDir();
  try {
    const secret = writeSecret(dir);
    const ts = '2026-01-01T00:00:00.000Z';
    const tsMs = Date.parse(ts);
    const file: AnyFile = {
      version: 1,
      schema: 'yandex-mail-mcp-allowlist/v1',
      bootstrap_completed_at: ts,
      entries: [
        newEntry('dave@example.com', 'sent_history', ts, tsMs, 3),
        newEntry('eve@example.com',  'user_trust_token', ts, tsMs, 0),
      ],
      signature: '',
    };
    signFile(file, secret);
    writeFile(file);
    const before = readFile();
    void loadAllowlist();
    const after1 = readFile();
    assert.equal(after1, before, 'fully-new file must NOT be rewritten by migration');
    void loadAllowlist();
    const after2 = readFile();
    assert.equal(after2, before, 'second load also byte-equal');
    assert.equal(verifySignature(), true);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-MIG-PARTIAL-01: mixed legacy+new -> migrates only the legacy entries', () => {
  const dir = mkTmpStateDir();
  try {
    const secret = writeSecret(dir);
    const ts = '2026-02-01T00:00:00.000Z';
    const tsMs = Date.parse(ts);
    const file: AnyFile = {
      version: 1,
      schema: 'yandex-mail-mcp-allowlist/v1',
      bootstrap_completed_at: ts,
      entries: [
        legacyEntry('legacy1@example.com', 'sent_history', ts),
        newEntry('new1@example.com', 'sent_history', ts, tsMs, 5),
        legacyEntry('legacy2@example.com', 'auto_trust_reply', ts),
        legacyEntry('legacy3@example.com', 'user_trust_token', ts),
        newEntry('new2@example.com', 'user_trust_token', ts, tsMs, 0),
      ],
      signature: '',
    };
    signFile(file, secret);
    writeFile(file);
    const loaded = loadAllowlist();
    assert.equal(loaded.entries.length, 5);
    // new1 + new2 unchanged in field values.
    const new1 = loaded.entries.find(e => e.address === 'new1@example.com')!;
    assert.equal(new1.useCount, 5);
    assert.equal(new1.added, tsMs);
    assert.equal(new1.lastUsed, tsMs);
    const new2 = loaded.entries.find(e => e.address === 'new2@example.com')!;
    assert.equal(new2.useCount, 0);
    assert.equal(new2.added, tsMs);
    // legacy* now populated.
    const legacy1 = loaded.entries.find(e => e.address === 'legacy1@example.com')!;
    assert.equal(legacy1.useCount, 0);
    assert.equal(legacy1.added, tsMs);
    assert.equal(legacy1.lastUsed, tsMs);
    assert.equal(verifySignature(), true);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-MIG-IDEMPOTENT-01: post-migration second load is byte-equal to first', () => {
  const dir = mkTmpStateDir();
  try {
    const secret = writeSecret(dir);
    const ts = '2026-03-01T00:00:00.000Z';
    const file: AnyFile = {
      version: 1,
      schema: 'yandex-mail-mcp-allowlist/v1',
      bootstrap_completed_at: ts,
      entries: [
        legacyEntry('alice@example.com', 'sent_history', ts),
        legacyEntry('bob@example.com',   'sent_history', ts),
      ],
      signature: '',
    };
    signFile(file, secret);
    writeFile(file);
    // First load -> migrates + persists.
    void loadAllowlist();
    const after1 = readFile();
    // Second load -> must NOT rewrite.
    void loadAllowlist();
    const after2 = readFile();
    assert.equal(after2, after1, 'second load must produce byte-equal file (idempotency)');
    assert.equal(verifySignature(), true);
  } finally {
    cleanupTmpStateDir(dir);
  }
});

test('T-MIG-TAMPER-01: useCount mutation without resign -> verifySignature false (D12)', () => {
  const dir = mkTmpStateDir();
  try {
    const secret = writeSecret(dir);
    const ts = '2026-04-01T00:00:00.000Z';
    const tsMs = Date.parse(ts);
    const file: AnyFile = {
      version: 1,
      schema: 'yandex-mail-mcp-allowlist/v1',
      bootstrap_completed_at: ts,
      entries: [
        newEntry('alice@example.com', 'sent_history', ts, tsMs, 1),
      ],
      signature: '',
    };
    signFile(file, secret);
    writeFile(file);
    assert.equal(verifySignature(), true, 'baseline verifies');
    // Attacker mutates useCount directly, no resign.
    const raw = JSON.parse(readFile()) as AnyFile;
    (raw.entries[0] as Record<string, unknown>)['useCount'] = 999;
    fs.writeFileSync(getAllowlistPath(), JSON.stringify(raw, null, 2));
    // verifySignature reads RAW (Phase 6 D12 invariant); must detect the tamper.
    assert.equal(verifySignature(), false, 'metadata mutation must invalidate signature');
  } finally {
    cleanupTmpStateDir(dir);
  }
});
