// unanswered.test.ts -- unit tests for unansweredThreads() (260622-k20).
//
// Mirrors the mail-index.test.ts harness exactly: withTempStateDir, FakeSource,
// _setAccountForTests, _resetForTests, cleanup-in-finally.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import type { EmailHeader } from '../imap.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import {
  buildIndex,
  unansweredThreads,
  _resetForTests,
  _setAccountForTests,
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
    date: '2025-06-01T12:00:00.000Z',
    seen: false,
    flagged: false,
    hasAttachments: false,
    size: 5000,
    ...overrides,
  };
}

class FakeSource implements EnvelopeSource {
  private folders = new Map<string, EmailHeader[]>();
  private cursors = new Map<string, { uidValidity: number; uidNext: number; exists: number }>();

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
      if (minUid !== undefined && minUid > 1 && h.uid < minUid) continue;
      yield h;
    }
  }
}

// ── Temp-dir harness ──────────────────────────────────────────────────

function withTempStateDir(fn: () => void | Promise<void>): () => Promise<void> {
  return async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ymc-unanswered-'));
    const prev = process.env.YANDEX_STATE_DIR;
    process.env.YANDEX_STATE_DIR = dir;
    _resetStateDir();
    _resetForTests();
    try {
      await fn();
    } finally {
      if (prev === undefined) delete process.env.YANDEX_STATE_DIR;
      else process.env.YANDEX_STATE_DIR = prev;
      _resetStateDir();
      _resetForTests();
      _setAccountForTests(null); // never leak an account override into the next test.
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  };
}

// ── Tests ─────────────────────────────────────────────────────────────

// U1: A thread where the owner replied last -> EXCLUDED.
// INBOX has inbound from alice (older), Sent has owner's reply (newer), linked
// by inReplyTo across folders. Thread latest is the owner -> not unanswered.
test('U1: owner-replied-latest thread is excluded', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  const nowMs = new Date('2026-01-15T00:00:00.000Z').getTime();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<in1@example.com>', subject: 'Project status',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: '2026-01-01T10:00:00.000Z' }),
  ], 100);
  src.setFolder('Sent', [
    hdr({ uid: 1, messageId: '<sent1@example.com>', inReplyTo: '<in1@example.com>',
          subject: 'Re: Project status',
          from: [{ address: 'you@yandex.ru', name: 'You' }],
          date: '2026-01-03T10:00:00.000Z' }),
  ], 200);
  await buildIndex(['INBOX', 'Sent'], src);
  _resetForTests();

  const page = unansweredThreads({ olderThanDays: 7, nowMs });
  assert.equal(page.ownerKnown, true);
  assert.equal(page.total, 0, 'owner replied last -> thread is answered, excluded');
}));

// U2: Inbound thread with no owner reply -> INCLUDED.
test('U2: inbound-latest thread is included with correct daysWaiting', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  const nowMs = new Date('2026-01-15T00:00:00.000Z').getTime();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<in2@example.com>', subject: 'Pending question',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: '2026-01-01T00:00:00.000Z' }), // 14 days old
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const page = unansweredThreads({ olderThanDays: 7, nowMs });
  assert.equal(page.ownerKnown, true);
  assert.equal(page.total, 1, 'one unanswered thread found');
  assert.equal(page.hits.length, 1);
  assert.equal(page.hits[0].record.uid, 1);
  assert.equal(page.hits[0].daysWaiting, 14);
}));

// U3: olderThanDays boundary — included at >= cutoff, excluded at cutoff-1 day.
test('U3: olderThanDays boundary (>= included, < excluded)', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  // nowMs: 2026-01-20 00:00:00 UTC. olderThanDays = 10.
  // Message date: 2026-01-10 -> exactly 10 days -> included.
  // Message date: 2026-01-11 -> 9 days -> excluded.
  const nowMs = new Date('2026-01-20T00:00:00.000Z').getTime();

  src.setFolder('INBOX', [
    hdr({ uid: 10, messageId: '<exact@example.com>', subject: 'Exact boundary',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: '2026-01-10T00:00:00.000Z' }), // exactly 10 days
    hdr({ uid: 11, messageId: '<under@example.com>', subject: 'Under boundary',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: '2026-01-11T00:00:00.000Z' }), // 9 days
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const included = unansweredThreads({ olderThanDays: 10, nowMs });
  assert.equal(included.total, 1, 'exactly olderThanDays old is included (>=)');
  assert.equal(included.hits[0].record.uid, 10);

  const excluded = unansweredThreads({ olderThanDays: 10 + 1, nowMs });
  assert.equal(excluded.total, 0, '10 days < cutoff 11 -> excluded');
}));

// U4: Cross-folder reply detection (Cyrillic folder name). Owner reply in
// 'Отправленные' folder, linked by inReplyTo -> thread answered -> EXCLUDED.
// This proves no folder-name hardcoding; classification is sender identity.
test('U4: reply in Cyrillic Sent folder is correctly identified by sender identity', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  const nowMs = new Date('2026-02-15T00:00:00.000Z').getTime();

  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<cyrillic1@example.com>', subject: 'Встреча',
          from: [{ address: 'bob@example.com', name: 'Bob' }],
          date: '2026-02-01T10:00:00.000Z' }),
  ], 100);
  // Reply in a Cyrillic-named Sent folder.
  src.setFolder('Отправленные', [
    hdr({ uid: 1, messageId: '<cyrillic2@example.com>', inReplyTo: '<cyrillic1@example.com>',
          subject: 'Re: Встреча',
          from: [{ address: 'you@yandex.ru', name: 'You' }],
          date: '2026-02-05T10:00:00.000Z' }),
  ], 200);
  await buildIndex(['INBOX', 'Отправленные'], src);
  _resetForTests();

  const page = unansweredThreads({ olderThanDays: 7, nowMs });
  assert.equal(page.ownerKnown, true);
  assert.equal(page.total, 0, 'reply in Cyrillic folder identified by sender -> thread is answered');
}));

// U5: Newsletter case -- inbound from news@example.com never replied to ->
// appears as unanswered (documents the known limitation). `from` filter excludes it.
test('U5: newsletter appears as unanswered; `from` filter narrows it away', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  const nowMs = new Date('2026-03-20T00:00:00.000Z').getTime();

  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<news1@example.com>', subject: 'Weekly digest',
          from: [{ address: 'news@example.com', name: 'News Digest' }],
          date: '2026-03-01T00:00:00.000Z' }),
    hdr({ uid: 2, messageId: '<alice1@example.com>', subject: 'Action needed',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: '2026-03-02T00:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const all = unansweredThreads({ olderThanDays: 7, nowMs });
  assert.equal(all.total, 2, 'both newsletter and alice message appear as unanswered');

  const filtered = unansweredThreads({ olderThanDays: 7, from: 'alice', nowMs });
  assert.equal(filtered.total, 1, '`from` filter narrows to alice only');
  assert.equal(filtered.hits[0].record.fromEmail, 'alice@example.com');
}));

// U6: 'default' account (no credentials) -> ownerKnown:false, 0 hits.
test('U6: default account degrades gracefully (ownerKnown:false, 0 hits)', withTempStateDir(async () => {
  _setAccountForTests('default');
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, from: [{ address: 'alice@example.com', name: 'Alice' }] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const page = unansweredThreads({ olderThanDays: 0 });
  assert.equal(page.ownerKnown, false, 'cannot classify without owner identity');
  assert.equal(page.total, 0);
  assert.equal(page.hits.length, 0);
}));

// U7: Account isolation -- two accounts in the index, only the configured one's
// inbound appears. The other account's inbound is never returned.
test('U7: account isolation - other account inbound never appears', withTempStateDir(async () => {
  const src = new FakeSource();
  const nowMs = new Date('2026-04-20T00:00:00.000Z').getTime();

  // Index messages for alice.
  _setAccountForTests('alice@ya.ru');
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<a1@x>', subject: 'For alice',
          from: [{ address: 'sender1@example.com', name: 'Sender One' }],
          date: '2026-04-01T00:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // Index messages for bob (shares the state dir).
  _setAccountForTests('bob@ya.ru');
  src.setFolder('INBOX', [
    hdr({ uid: 2, messageId: '<b1@x>', subject: 'For bob',
          from: [{ address: 'sender2@example.com', name: 'Sender Two' }],
          date: '2026-04-02T00:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // Alice should only see her own thread.
  _setAccountForTests('alice@ya.ru');
  _resetForTests();
  const alicePage = unansweredThreads({ olderThanDays: 7, nowMs });
  assert.equal(alicePage.total, 1, "alice sees only her own unanswered thread");
  assert.equal(alicePage.hits[0].record.account, 'alice@ya.ru');
  assert.equal(alicePage.hits[0].record.uid, 1);

  // Bob should only see his own thread.
  _setAccountForTests('bob@ya.ru');
  _resetForTests();
  const bobPage = unansweredThreads({ olderThanDays: 7, nowMs });
  assert.equal(bobPage.total, 1, "bob sees only his own unanswered thread");
  assert.equal(bobPage.hits[0].record.account, 'bob@ya.ru');
  assert.equal(bobPage.hits[0].record.uid, 2);
}));

// U8: Oldest-first ordering + offset/limit pagination over >limit threads.
test('U8: oldest-first ordering and offset/limit pagination', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  const nowMs = new Date('2026-05-30T00:00:00.000Z').getTime();

  // 5 separate threads from different senders on different dates.
  const threads: EmailHeader[] = [];
  for (let i = 1; i <= 5; i++) {
    // Day 1 = oldest (2026-05-01), Day 5 = newest (2026-05-05).
    const dateStr = `2026-05-0${i}T00:00:00.000Z`;
    threads.push(hdr({
      uid: i,
      messageId: `<thread${i}@example.com>`,
      subject: `Unique subject ${i} zxy${i}`,
      from: [{ address: `sender${i}@example.com`, name: `Sender ${i}` }],
      date: dateStr,
    }));
  }
  src.setFolder('INBOX', threads, 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // All 5 threads are unanswered (>7 days old by nowMs).
  const all = unansweredThreads({ olderThanDays: 7, nowMs });
  assert.equal(all.total, 5);

  // Verify oldest-first ordering: uid 1 (May 1) must come before uid 5 (May 5).
  const uids = all.hits.map(h => h.record.uid);
  for (let i = 1; i < uids.length; i++) {
    const prevDate = new Date(all.hits[i - 1].record.date).getTime();
    const currDate = new Date(all.hits[i].record.date).getTime();
    assert.ok(prevDate <= currDate, `hit ${i - 1} must be <= hit ${i} by date (oldest-first)`);
  }

  // Paginate: page 1 = first 2, page 2 = next 2.
  const page1 = unansweredThreads({ olderThanDays: 7, limit: 2, offset: 0, nowMs });
  const page2 = unansweredThreads({ olderThanDays: 7, limit: 2, offset: 2, nowMs });
  assert.equal(page1.total, 5, 'total is stable across pages');
  assert.equal(page1.hits.length, 2, 'page 1 has 2 hits');
  assert.equal(page2.hits.length, 2, 'page 2 has 2 hits');
  const p1uids = new Set(page1.hits.map(h => h.record.uid));
  assert.ok(page2.hits.every(h => !p1uids.has(h.record.uid)), 'pages do not overlap');

  // Beyond end.
  const beyond = unansweredThreads({ olderThanDays: 7, limit: 2, offset: 10, nowMs });
  assert.equal(beyond.total, 5, 'total stable even beyond end');
  assert.equal(beyond.hits.length, 0);
}));
