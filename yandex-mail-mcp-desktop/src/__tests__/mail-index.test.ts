// mail-index.test.ts -- unit tests for the local envelope index (Layer 2).
//
// Each test points YANDEX_STATE_DIR at a fresh temp dir, drives the index via
// a FAKE EnvelopeSource (in-memory EmailHeader list -- never touches IMAP),
// resets the in-memory FTS cache, and cleans up the temp dir in finally.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import type { EmailHeader } from '../imap.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import {
  buildIndex,
  updateIndex,
  dropIndex,
  indexExists,
  getIndexStatus,
  searchFast,
  getThread,
  _resetForTests,
  type EnvelopeSource,
} from '../mail-index.js';

// ── Fixtures ──────────────────────────────────────────────────────────

function hdr(overrides: Partial<EmailHeader>): EmailHeader {
  return {
    uid: 1,
    messageId: '<m1@example.com>',
    from: [{ address: 'alice@example.com', name: 'Alice Smith' }],
    to: [{ address: 'you@yandex.ru', name: 'You' }],
    cc: [],
    subject: 'hello world',
    date: '2025-06-15T12:00:00.000Z',
    seen: false,
    flagged: false,
    hasAttachments: false,
    size: 5000,
    ...overrides,
  };
}

// FakeSource: a per-folder list of EmailHeader plus an advertised cursor. The
// stream honours opts.minUid (uid >= minUid) like the real IMAP "N:*" range,
// and deliberately echoes the boundary message so the dedup/keep logic is
// exercised.
class FakeSource implements EnvelopeSource {
  private folders = new Map<string, EmailHeader[]>();
  private cursors = new Map<string, { uidValidity: number; uidNext: number; exists: number }>();
  // When true, stream() echoes the message at exactly minUid (server boundary
  // echo) to verify updateIndex drops the duplicate.
  echoBoundary = false;

  setFolder(folder: string, headers: EmailHeader[], uidValidity: number): void {
    this.folders.set(folder, headers.slice());
    const maxUid = headers.reduce((m, h) => Math.max(m, h.uid), 0);
    this.cursors.set(folder, { uidValidity, uidNext: maxUid + 1, exists: headers.length });
  }

  async getCursor(folder: string): Promise<{ uidValidity: number; uidNext: number; exists: number }> {
    const c = this.cursors.get(folder);
    if (!c) return { uidValidity: 1, uidNext: 1, exists: 0 };
    return c;
  }

  async *stream(folder: string, opts?: { minUid?: number }): AsyncGenerator<EmailHeader, void, void> {
    const headers = this.folders.get(folder) ?? [];
    const minUid = opts?.minUid;
    for (const h of headers) {
      if (minUid !== undefined && minUid > 1) {
        if (h.uid < minUid) {
          // Echo the boundary message (uid === minUid - 1) when configured, to
          // mimic the IMAP range echoing the last existing message.
          if (this.echoBoundary && h.uid === minUid - 1) {
            yield h;
          }
          continue;
        }
      }
      yield h;
    }
  }
}

// ── Temp-dir harness ──────────────────────────────────────────────────

function withTempStateDir(fn: () => void | Promise<void>): () => Promise<void> {
  return async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ymc-index-'));
    const prev = process.env.YANDEX_STATE_DIR;
    process.env.YANDEX_STATE_DIR = dir;
    // state-dir.ts caches the resolved path in a module-local; flush it so this
    // test's fresh temp dir is honoured instead of a prior test's cached dir.
    _resetStateDir();
    _resetForTests();
    try {
      await fn();
    } finally {
      if (prev === undefined) delete process.env.YANDEX_STATE_DIR;
      else process.env.YANDEX_STATE_DIR = prev;
      _resetStateDir();
      _resetForTests();
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  };
}

// ── Tests ─────────────────────────────────────────────────────────────

test('T1: build then status reports folder count', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'first' }),
    hdr({ uid: 2, subject: 'second' }),
    hdr({ uid: 3, subject: 'third' }),
  ], 100);

  const res = await buildIndex(['INBOX'], src);
  assert.equal(res.added, 3);
  assert.equal(res.folders.length, 1);
  assert.equal(res.folders[0].count, 3);
  assert.equal(res.folders[0].uidNext, 4);
  assert.equal(res.folders[0].uidValidity, 100);

  const status = getIndexStatus();
  assert.equal(status.totalCount, 3);
  assert.equal(status.folders.length, 1);
  assert.equal(status.folders[0].folder, 'INBOX');
}));

test('T2: indexExists transitions false -> true', withTempStateDir(async () => {
  assert.equal(indexExists(), false);
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1 })], 100);
  await buildIndex(['INBOX'], src);
  assert.equal(indexExists(), true);
}));

test('T3: getIndexStatus.exists is false on a clean state dir', withTempStateDir(async () => {
  const status = getIndexStatus();
  assert.equal(status.exists, false);
  assert.equal(status.totalCount, 0);
  assert.equal(status.folders.length, 0);
}));

test('T4: incremental update appends only new UIDs', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1 }), hdr({ uid: 2 })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // New messages arrive (uid 3, 4); uidNext advances.
  src.setFolder('INBOX', [
    hdr({ uid: 1 }), hdr({ uid: 2 }), hdr({ uid: 3 }), hdr({ uid: 4 }),
  ], 100);

  const res = await updateIndex(['INBOX'], src);
  assert.equal(res.added, 2, 'only uid 3 and 4 are new');
  const status = getIndexStatus();
  assert.equal(status.totalCount, 4);
  assert.equal(status.folders[0].uidNext, 5);
}));

test('T5: incremental update drops boundary-echo duplicate', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1 }), hdr({ uid: 2 })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // uidNext is now 3. The server echoes uid 2 (boundary) AND delivers uid 3.
  src.echoBoundary = true;
  src.setFolder('INBOX', [
    hdr({ uid: 1 }), hdr({ uid: 2 }), hdr({ uid: 3 }),
  ], 100);

  const res = await updateIndex(['INBOX'], src);
  assert.equal(res.added, 1, 'echoed uid 2 must not be re-added; only uid 3 is new');
  assert.equal(getIndexStatus().totalCount, 3);
}));

test('T6: update with no new messages adds nothing', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1 }), hdr({ uid: 2 })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const res = await updateIndex(['INBOX'], src);
  assert.equal(res.added, 0);
  assert.equal(getIndexStatus().totalCount, 2);
}));

test('T7: uidValidity change triggers a folder rebuild', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 10, subject: 'old' }), hdr({ uid: 11, subject: 'old2' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // Server renumbered (uidValidity 100 -> 200) -- the old records are stale and
  // must be replaced wholesale, not appended.
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'fresh' })], 200);

  const res = await updateIndex(['INBOX'], src);
  const status = getIndexStatus();
  assert.equal(status.totalCount, 1, 'rebuild replaces, does not append');
  assert.equal(status.folders[0].uidValidity, 200);
  assert.equal(res.added, 1);
}));

test('T8: searchFast finds by subject token', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'Invoice from supplier' }),
    hdr({ uid: 2, subject: 'Lunch plans' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const hits = searchFast('invoice');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].record.uid, 1);
  assert.ok(hits[0].matchReasons.includes('subject'));
}));

test('T9: searchFast finds by sender', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'random', from: [{ address: 'billing@acme.io', name: 'Bob Jones' }] }),
    hdr({ uid: 2, subject: 'random', from: [{ address: 'alice@example.com', name: 'Alice' }] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const byName = searchFast('jones');
  assert.equal(byName.length, 1);
  assert.equal(byName[0].record.uid, 1);
  assert.ok(byName[0].matchReasons.includes('sender'));

  // The local-part of the address ('billing') is indexed too; the domain is
  // not (matches the spec: subject + fromName + fromEmail-localpart).
  const byLocal = searchFast('billing');
  assert.ok(byLocal.length >= 1);
  assert.ok(byLocal.some(h => h.record.uid === 1));
}));

test('T10: searchFast ranks full-substring match higher', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    // contains both tokens but not the exact phrase
    hdr({ uid: 1, subject: 'project status and budget review' }),
    // exact phrase substring "status review"
    hdr({ uid: 2, subject: 'weekly status review' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const hits = searchFast('status review');
  assert.ok(hits.length >= 2);
  assert.equal(hits[0].record.uid, 2, 'substring match should rank first');
  assert.ok(hits[0].matchReasons.includes('subject-substring'));
}));

test('T11: searchFast respects folder filter', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'report quarterly' })], 100);
  src.setFolder('Sent', [hdr({ uid: 1, subject: 'report monthly' })], 100);
  await buildIndex(['INBOX', 'Sent'], src);
  _resetForTests();

  const all = searchFast('report');
  assert.equal(all.length, 2);
  const inboxOnly = searchFast('report', { folder: 'INBOX' });
  assert.equal(inboxOnly.length, 1);
  assert.equal(inboxOnly[0].record.folder, 'INBOX');
}));

test('T12: searchFast respects limit', withTempStateDir(async () => {
  const src = new FakeSource();
  const headers: EmailHeader[] = [];
  for (let i = 1; i <= 10; i++) headers.push(hdr({ uid: i, subject: 'meeting notes ' + i }));
  src.setFolder('INBOX', headers, 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const hits = searchFast('meeting', { limit: 3 });
  assert.equal(hits.length, 3);
}));

test('T13: searchFast with no match returns empty', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'hello' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  assert.equal(searchFast('zzzznomatch').length, 0);
}));

test('T14: getThread groups Re/Fwd variants by normalized subject', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'Quarterly budget', date: '2025-01-01T10:00:00.000Z' }),
    hdr({ uid: 2, subject: 'Re: Quarterly budget', date: '2025-01-02T10:00:00.000Z' }),
    hdr({ uid: 3, subject: 'Fwd: Re: Quarterly budget', date: '2025-01-03T10:00:00.000Z' }),
    hdr({ uid: 4, subject: 'Unrelated thread', date: '2025-01-04T10:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const thread = getThread('quarterly budget');
  assert.equal(thread.length, 3, 'three messages share the normalized subject');
  // Sorted ascending by date: uid 1, 2, 3.
  assert.deepEqual(thread.map(h => h.record.uid), [1, 2, 3]);
  assert.ok(thread.every(h => h.matchReasons.includes('thread')));
}));

test('T15: getThread groups Russian Вс: prefix', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'Договор аренды', date: '2025-02-01T10:00:00.000Z' }),
    hdr({ uid: 2, subject: 'Вс: Договор аренды', date: '2025-02-02T10:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const thread = getThread('договор аренды');
  assert.equal(thread.length, 2);
  assert.deepEqual(thread.map(h => h.record.uid), [1, 2]);
}));

test('T16: getThread returns empty when nothing matches', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'hello' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  assert.deepEqual(getThread('nonexistent topic'), []);
}));

test('T17: Cyrillic tokenization is searchable', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'Счёт от ВТБ' }),
    hdr({ uid: 2, subject: 'Реклама' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const hits = searchFast('втб');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].record.uid, 1);
}));

test('T18: dropIndex removes files and resets exists', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1 })], 100);
  await buildIndex(['INBOX'], src);
  assert.equal(indexExists(), true);

  dropIndex();
  assert.equal(indexExists(), false);
  assert.equal(getIndexStatus().exists, false);
  assert.equal(getIndexStatus().totalCount, 0);
  // A search after drop is safe and empty.
  assert.equal(searchFast('anything').length, 0);
}));

test('T19: account is stamped on every record (default fallback)', withTempStateDir(async () => {
  // No token file in the temp state dir -> getConfiguredAccount falls back to
  // 'default' without throwing (the tool-registration safety contract).
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1 })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const status = getIndexStatus();
  assert.equal(status.account, 'default');
  const hits = searchFast('hello');
  assert.ok(hits.length >= 1);
  assert.equal(hits[0].record.account, 'default');
}));

test('T20: buildIndex of one folder preserves other folders', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'inbox msg' })], 100);
  src.setFolder('Sent', [hdr({ uid: 1, subject: 'sent msg' })], 100);
  await buildIndex(['INBOX', 'Sent'], src);
  _resetForTests();

  // Rebuild only INBOX with different content; Sent must survive untouched.
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'inbox msg' }), hdr({ uid: 2, subject: 'inbox msg2' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const status = getIndexStatus();
  assert.equal(status.totalCount, 3, 'INBOX(2) + Sent(1)');
  const sentHits = searchFast('sent', { folder: 'Sent' });
  assert.equal(sentHits.length, 1);
}));
