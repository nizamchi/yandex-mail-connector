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
  looksAutomated,
  _resetForTests,
  _setAccountForTests,
  type EnvelopeSource,
} from '../mail-index.js';

// ── looksAutomated (word-boundary heuristic) ──────────────────────────────

test('looksAutomated: flags noreply / no-reply / donotreply prefixes', () => {
  assert.equal(looksAutomated('noreply@bank.ru'), true);
  assert.equal(looksAutomated('no-reply@shop.com'), true);
  assert.equal(looksAutomated('donotreply@x.io'), true);
});

test('looksAutomated: flags newsletter/notification as a word (with separators)', () => {
  assert.equal(looksAutomated('daily-newsletter@news.com'), true);
  assert.equal(looksAutomated('notifications.team@app.io'), true);
  assert.equal(looksAutomated('newsletter@news.com'), true);
});

test('looksAutomated: does NOT flag a human whose name merely contains the word', () => {
  // The bug: bare includes() demoted real people; word boundaries fix it.
  assert.equal(looksAutomated('anna-newsletterova@yandex.ru'), false);
  assert.equal(looksAutomated('john.notificationsson@gmail.com'), false);
  assert.equal(looksAutomated('newsletterova@ya.ru'), false);
});

test('looksAutomated: ordinary human address is not automated', () => {
  assert.equal(looksAutomated('ivan.petrov@yandex.ru'), false);
});

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

// T-flagged: a flagged inbound vs a plain inbound of the SAME age.
// Flagged thread must have tier='reply_likely' and sort FIRST.
test('T-flagged: flagged inbound sorts above plain inbound of same age', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  const nowMs = new Date('2026-06-22T00:00:00.000Z').getTime();
  const sharedDate = '2026-06-01T00:00:00.000Z'; // 21 days ago

  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<plain@example.com>', subject: 'Plain thread',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: sharedDate, flagged: false }),
    hdr({ uid: 2, messageId: '<flagged@example.com>', subject: 'Flagged thread',
          from: [{ address: 'bob@example.com', name: 'Bob' }],
          date: sharedDate, flagged: true }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const page = unansweredThreads({ olderThanDays: 7, nowMs });
  assert.equal(page.total, 2, 'both threads present');

  const flaggedHit = page.hits.find(h => h.record.uid === 2);
  assert.ok(flaggedHit, 'flagged thread returned');
  assert.equal(flaggedHit!.tier, 'reply_likely', 'flagged -> reply_likely');

  // Flagged sorts first (higher priority).
  assert.equal(page.hits[0].record.uid, 2, 'flagged thread is first');
  assert.equal(page.hits[1].record.uid, 1, 'plain thread is second');
}));

// T-participation: a thread where the owner sent an earlier message but the latest
// is inbound -> tier='reply_likely', reasons includes participation reason, sorts
// above a no-history inbound of the same age.
test('T-participation: thread with owner earlier message sorts above no-history inbound', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  const nowMs = new Date('2026-06-22T00:00:00.000Z').getTime();

  // Thread A: owner wrote earlier (message in Sent), then alice replied (latest inbound).
  // Thread B: plain inbound, no owner history, same date as Thread A's latest.
  // Both in INBOX in a single setFolder call to avoid overwriting.
  src.setFolder('INBOX', [
    hdr({ uid: 10, messageId: '<a-initial@example.com>', subject: 'Discussion A',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: '2026-06-01T08:00:00.000Z' }),
    hdr({ uid: 12, messageId: '<a-reply-alice@example.com>', inReplyTo: '<a-owner@example.com>',
          subject: 'Re: Discussion A',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: '2026-06-10T08:00:00.000Z' }), // latest inbound in Thread A
    hdr({ uid: 20, messageId: '<b-only@example.com>', subject: 'Standalone B xyzq999',
          from: [{ address: 'carol@example.com', name: 'Carol' }],
          date: '2026-06-10T08:00:00.000Z' }), // Thread B: same date, no owner history
  ], 100);
  src.setFolder('Sent', [
    hdr({ uid: 11, messageId: '<a-owner@example.com>', inReplyTo: '<a-initial@example.com>',
          subject: 'Re: Discussion A',
          from: [{ address: 'you@yandex.ru', name: 'You' }],
          date: '2026-06-05T08:00:00.000Z' }), // owner's earlier reply -> participated
  ], 200);

  await buildIndex(['INBOX', 'Sent'], src);
  _resetForTests();

  const page = unansweredThreads({ olderThanDays: 7, nowMs });
  assert.equal(page.total, 2, 'both threads present');

  const threadA = page.hits.find(h => h.record.messageId === '<a-reply-alice@example.com>');
  assert.ok(threadA, 'Thread A (participated) found');
  assert.equal(threadA!.tier, 'reply_likely', 'participated thread -> reply_likely');
  assert.ok(threadA!.reasons.some(r => r.includes('уже писали')), 'participation reason present');

  // Thread A (participated) sorts before Thread B (no history), same date.
  assert.equal(page.hits[0].record.messageId, '<a-reply-alice@example.com>', 'participated thread is first');
}));

// T-automated: sender 'noreply@bank.example' -> tier='fyi_likely', reasons includes
// the automated reason, sorts BELOW a human inbound of the same age -- but is STILL
// present (recall preserved).
test('T-automated: noreply sender is fyi_likely and sorts below human sender; still present', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  const nowMs = new Date('2026-06-22T00:00:00.000Z').getTime();
  const sharedDate = '2026-06-01T00:00:00.000Z'; // 21 days ago

  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<human@example.com>', subject: 'Human message',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: sharedDate }),
    hdr({ uid: 2, messageId: '<auto@bank.example>', subject: 'Bank notification',
          from: [{ address: 'noreply@bank.example', name: 'Bank' }],
          date: sharedDate }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const page = unansweredThreads({ olderThanDays: 7, nowMs });
  assert.equal(page.total, 2, 'both threads returned (recall preserved)');

  const autoHit = page.hits.find(h => h.record.uid === 2);
  assert.ok(autoHit, 'automated thread is still present in results');
  assert.equal(autoHit!.tier, 'fyi_likely', 'noreply sender -> fyi_likely');
  assert.ok(autoHit!.reasons.some(r => r.includes('авто')), 'automated reason present');

  // Human sender sorts before automated sender (higher priority).
  assert.equal(page.hits[0].record.uid, 1, 'human sender sorts first');
  assert.equal(page.hits[1].record.uid, 2, 'automated sender sorts second but present');
}));

// T-recall-invariant: a mix of human + automated unanswered threads.
// page.total must equal the total number of unanswered threads (nothing hidden).
test('T-recall-invariant: total is identical with and without tiering -- nothing hidden', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  const nowMs = new Date('2026-06-22T00:00:00.000Z').getTime();

  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<h1@example.com>', subject: 'Human 1',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: '2026-06-01T00:00:00.000Z' }),
    hdr({ uid: 2, messageId: '<h2@example.com>', subject: 'Human 2',
          from: [{ address: 'bob@example.com', name: 'Bob' }],
          date: '2026-06-02T00:00:00.000Z' }),
    hdr({ uid: 3, messageId: '<auto1@mail.example>', subject: 'Newsletter 1',
          from: [{ address: 'noreply@news.example', name: 'News' }],
          date: '2026-06-03T00:00:00.000Z' }),
    hdr({ uid: 4, messageId: '<auto2@mail.example>', subject: 'Newsletter 2',
          from: [{ address: 'newsletter@updates.example', name: 'Updates' }],
          date: '2026-06-04T00:00:00.000Z' }),
    hdr({ uid: 5, messageId: '<h3@example.com>', subject: 'Human 3',
          from: [{ address: 'carol@example.com', name: 'Carol' }],
          date: '2026-06-05T00:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const page = unansweredThreads({ olderThanDays: 7, nowMs });
  // All 5 threads are unanswered and old enough.
  assert.equal(page.total, 5, 'all 5 unanswered threads returned; nothing hidden by tiering');
  assert.equal(page.hits.length, 5, 'all hits present in default page');

  // Verify fyi_likely threads are still present.
  const fyi = page.hits.filter(h => h.tier === 'fyi_likely');
  assert.ok(fyi.length >= 2, 'fyi_likely hits present (automated senders not dropped)');
}));

// T-ordering: same age, four threads (flagged, participated, plain, automated).
// Expected order: flagged, participated, plain, automated.
test('T-ordering: flagged > participated > plain > automated (same age)', withTempStateDir(async () => {
  _setAccountForTests('you@yandex.ru');
  const src = new FakeSource();
  const nowMs = new Date('2026-06-22T00:00:00.000Z').getTime();
  const sharedDate = '2026-06-01T00:00:00.000Z';

  // Thread P (participated): owner has earlier message, inbound is latest.
  // Thread F (flagged): flagged inbound.
  // Thread N (plain): normal inbound.
  // Thread A (automated): noreply sender.
  // All INBOX messages in one setFolder call (subsequent calls overwrite).
  src.setFolder('INBOX', [
    hdr({ uid: 10, messageId: '<p-initial@example.com>', subject: 'Participated thread pqrst',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: sharedDate }),
    hdr({ uid: 12, messageId: '<p-alice-reply@example.com>', inReplyTo: '<p-owner@example.com>',
          subject: 'Re: Participated thread pqrst',
          from: [{ address: 'alice@example.com', name: 'Alice' }],
          date: sharedDate }),
    hdr({ uid: 20, messageId: '<f-msg@example.com>', subject: 'Flagged thread abcde',
          from: [{ address: 'bob@example.com', name: 'Bob' }],
          date: sharedDate, flagged: true }),
    hdr({ uid: 30, messageId: '<n-msg@example.com>', subject: 'Plain thread mnopq',
          from: [{ address: 'carol@example.com', name: 'Carol' }],
          date: sharedDate }),
    hdr({ uid: 40, messageId: '<a-msg@example.com>', subject: 'Automated thread vwxyz',
          from: [{ address: 'noreply@bank.example', name: 'Bank' }],
          date: sharedDate }),
  ], 100);
  src.setFolder('Sent', [
    hdr({ uid: 11, messageId: '<p-owner@example.com>', inReplyTo: '<p-initial@example.com>',
          subject: 'Re: Participated thread pqrst',
          from: [{ address: 'you@yandex.ru', name: 'You' }],
          date: sharedDate }),
  ], 200);
  await buildIndex(['INBOX', 'Sent'], src);
  _resetForTests();

  const page = unansweredThreads({ olderThanDays: 7, nowMs });

  // We expect 4 unanswered threads (the owner's Sent message is not unanswered).
  assert.equal(page.total, 4, '4 unanswered threads');

  // Identify each hit by uid.
  const uidOrder = page.hits.map(h => h.record.uid);

  // flagged (uid=20) must come before participated (uid=12).
  assert.ok(uidOrder.indexOf(20) < uidOrder.indexOf(12), 'flagged before participated');
  // participated (uid=12) must come before plain (uid=30).
  assert.ok(uidOrder.indexOf(12) < uidOrder.indexOf(30), 'participated before plain');
  // plain (uid=30) must come before automated (uid=40).
  assert.ok(uidOrder.indexOf(30) < uidOrder.indexOf(40), 'plain before automated');

  // Verify tiers.
  const hitByUid = (uid: number) => page.hits.find(h => h.record.uid === uid)!;
  assert.equal(hitByUid(20).tier, 'reply_likely', 'flagged -> reply_likely');
  assert.equal(hitByUid(12).tier, 'reply_likely', 'participated -> reply_likely');
  assert.equal(hitByUid(30).tier, 'normal', 'plain -> normal');
  assert.equal(hitByUid(40).tier, 'fyi_likely', 'automated -> fyi_likely');
}));
