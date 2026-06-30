import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  parseAutoConfig,
  decideAutoAction,
  runIndexAutoLifecycle,
  type AutoDeps,
} from '../index-auto.js';
import type { IndexStatus, FolderStatus, IndexResult } from '../mail-index.js';

// ── parseAutoConfig ───────────────────────────────────────────────────

test('parseAutoConfig: default OFF, default age 60', () => {
  const c = parseAutoConfig({});
  assert.equal(c.enabled, false);
  assert.equal(c.maxAgeMinutes, 60);
});

test('parseAutoConfig: on/true/1/yes enable (case-insensitive)', () => {
  for (const v of ['on', 'ON', 'true', 'True', '1', 'yes', '  on  ']) {
    assert.equal(parseAutoConfig({ YANDEX_INDEX_AUTO: v }).enabled, true, `"${v}" should enable`);
  }
});

test('parseAutoConfig: off/false/0/no/unset stay disabled', () => {
  for (const v of ['off', 'false', '0', 'no', '', 'maybe']) {
    assert.equal(parseAutoConfig({ YANDEX_INDEX_AUTO: v }).enabled, false, `"${v}" should stay off`);
  }
});

test('parseAutoConfig: custom age; invalid/<=0 falls back to 60', () => {
  assert.equal(parseAutoConfig({ YANDEX_INDEX_MAX_AGE_MINUTES: '15' }).maxAgeMinutes, 15);
  assert.equal(parseAutoConfig({ YANDEX_INDEX_MAX_AGE_MINUTES: '0' }).maxAgeMinutes, 60);
  assert.equal(parseAutoConfig({ YANDEX_INDEX_MAX_AGE_MINUTES: '-5' }).maxAgeMinutes, 60);
  assert.equal(parseAutoConfig({ YANDEX_INDEX_MAX_AGE_MINUTES: 'abc' }).maxAgeMinutes, 60);
});

// ── decideAutoAction (pure decision matrix) ───────────────────────────

const NOW = 100 * 60000; // 100 minutes in ms

test('decideAutoAction: disabled → skip', () => {
  assert.equal(decideAutoAction({ enabled: false, indexExists: false, oldestSyncMs: null, nowMs: NOW, maxAgeMinutes: 60 }), 'skip');
});

test('decideAutoAction: enabled + no index → build', () => {
  assert.equal(decideAutoAction({ enabled: true, indexExists: false, oldestSyncMs: null, nowMs: NOW, maxAgeMinutes: 60 }), 'build');
});

test('decideAutoAction: enabled + index but no sync data → build', () => {
  assert.equal(decideAutoAction({ enabled: true, indexExists: true, oldestSyncMs: null, nowMs: NOW, maxAgeMinutes: 60 }), 'build');
});

test('decideAutoAction: enabled + stale (older than threshold) → refresh', () => {
  assert.equal(decideAutoAction({ enabled: true, indexExists: true, oldestSyncMs: NOW - 61 * 60000, nowMs: NOW, maxAgeMinutes: 60 }), 'refresh');
});

test('decideAutoAction: enabled + fresh → skip', () => {
  assert.equal(decideAutoAction({ enabled: true, indexExists: true, oldestSyncMs: NOW - 10 * 60000, nowMs: NOW, maxAgeMinutes: 60 }), 'skip');
});

test('decideAutoAction: exactly at threshold → skip (strictly-older triggers refresh)', () => {
  assert.equal(decideAutoAction({ enabled: true, indexExists: true, oldestSyncMs: NOW - 60 * 60000, nowMs: NOW, maxAgeMinutes: 60 }), 'skip');
});

// ── runIndexAutoLifecycle (with injected deps — no IMAP, no disk) ──────

function fakeStatus(exists: boolean, folders: FolderStatus[] = []): IndexStatus {
  return { exists, account: 'a@example.com', folders, totalCount: 0, indexPath: '<test>', threadingReady: false };
}

function folder(name: string, lastSyncMs: number): FolderStatus {
  return { folder: name, count: 1, uidValidity: 1, uidNext: 2, lastSyncMs, schema: 3 };
}

const EMPTY_RESULT: IndexResult = { folders: [], added: 0, errors: [] };

test('runIndexAutoLifecycle: OFF → skip, neither build nor update called', async () => {
  let built = false, updated = false;
  const deps: AutoDeps = {
    getStatus: () => fakeStatus(false),
    build: async () => { built = true; return EMPTY_RESULT; },
    update: async () => { updated = true; return EMPTY_RESULT; },
    resolveBuildFolders: async () => ['INBOX', 'Sent'],
    now: () => NOW,
    env: {},
  };
  const r = await runIndexAutoLifecycle(deps);
  assert.equal(r.action, 'skip');
  assert.equal(built, false);
  assert.equal(updated, false);
});

test('runIndexAutoLifecycle: ON + empty index → build INBOX+Sent', async () => {
  let builtFolders: string[] | null = null;
  const deps: AutoDeps = {
    getStatus: () => fakeStatus(false),
    build: async (f) => { builtFolders = f; return { folders: [], added: 42, errors: [] }; },
    update: async () => { throw new Error('update must not run for first-build'); },
    resolveBuildFolders: async () => ['INBOX', 'Sent'],
    now: () => NOW,
    env: { YANDEX_INDEX_AUTO: 'on' },
  };
  const r = await runIndexAutoLifecycle(deps);
  assert.equal(r.action, 'build');
  assert.deepEqual(builtFolders, ['INBOX', 'Sent']);
  assert.equal(r.added, 42);
});

test('runIndexAutoLifecycle: ON + stale index → refresh indexed folders only', async () => {
  let updatedFolders: string[] | null = null;
  const deps: AutoDeps = {
    getStatus: () => fakeStatus(true, [folder('INBOX', NOW - 120 * 60000), folder('Sent', NOW - 90 * 60000)]),
    build: async () => { throw new Error('build must not run when index exists'); },
    update: async (f) => { updatedFolders = f; return { folders: [], added: 3, errors: [] }; },
    resolveBuildFolders: async () => ['INBOX', 'Sent'],
    now: () => NOW,
    env: { YANDEX_INDEX_AUTO: 'on', YANDEX_INDEX_MAX_AGE_MINUTES: '60' },
  };
  const r = await runIndexAutoLifecycle(deps);
  assert.equal(r.action, 'refresh');
  assert.deepEqual(updatedFolders, ['INBOX', 'Sent']);
  assert.equal(r.added, 3);
});

test('runIndexAutoLifecycle: ON + fresh index → skip', async () => {
  let built = false, updated = false;
  const deps: AutoDeps = {
    getStatus: () => fakeStatus(true, [folder('INBOX', NOW - 5 * 60000)]),
    build: async () => { built = true; return EMPTY_RESULT; },
    update: async () => { updated = true; return EMPTY_RESULT; },
    resolveBuildFolders: async () => ['INBOX'],
    now: () => NOW,
    env: { YANDEX_INDEX_AUTO: 'on' },
  };
  const r = await runIndexAutoLifecycle(deps);
  assert.equal(r.action, 'skip');
  assert.equal(built || updated, false);
});

test('runIndexAutoLifecycle: staleness uses the OLDEST folder (one stale folder forces refresh)', async () => {
  let updated = false;
  const deps: AutoDeps = {
    // INBOX fresh, Sent stale -> oldest is stale -> refresh.
    getStatus: () => fakeStatus(true, [folder('INBOX', NOW - 5 * 60000), folder('Sent', NOW - 200 * 60000)]),
    build: async () => { throw new Error('build must not run'); },
    update: async () => { updated = true; return { folders: [], added: 1, errors: [] }; },
    resolveBuildFolders: async () => ['INBOX', 'Sent'],
    now: () => NOW,
    env: { YANDEX_INDEX_AUTO: 'on', YANDEX_INDEX_MAX_AGE_MINUTES: '60' },
  };
  const r = await runIndexAutoLifecycle(deps);
  assert.equal(r.action, 'refresh');
  assert.equal(updated, true);
});
