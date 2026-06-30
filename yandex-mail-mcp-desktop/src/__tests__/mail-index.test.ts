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
  searchFastResult,
  getThread,
  getIndexDir,
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
  // Folders whose getCursor throws (simulates a network drop / missing mailbox
  // for the per-folder error-resilience tests).
  private failFolders = new Set<string>();
  // Override the cursor.exists a folder advertises, decoupled from the streamed
  // header list -- lets a test simulate "server says N but we stream M".
  private existsOverride = new Map<string, number>();

  setFolder(folder: string, headers: EmailHeader[], uidValidity: number, uidNextOverride?: number): void {
    this.folders.set(folder, headers.slice());
    const maxUid = headers.reduce((m, h) => Math.max(m, h.uid), 0);
    const uidNext = uidNextOverride ?? maxUid + 1;
    this.cursors.set(folder, { uidValidity, uidNext, exists: headers.length });
  }

  failOn(folder: string): void { this.failFolders.add(folder); }
  setExists(folder: string, exists: number): void { this.existsOverride.set(folder, exists); }

  async getCursor(folder: string): Promise<{ uidValidity: number; uidNext: number; exists: number }> {
    if (this.failFolders.has(folder)) throw new Error(`fake cursor failure for ${folder}`);
    const c = this.cursors.get(folder);
    if (!c) return { uidValidity: 1, uidNext: 1, exists: 0 };
    const override = this.existsOverride.get(folder);
    return override === undefined ? c : { ...c, exists: override };
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
      _setAccountForTests(null); // never leak an account override into the next test.
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

test('T-morph-ru: inflected RU query matches base subject (выписку -> выписка)', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'Банковская выписка за июнь' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // The whole point: an accusative query form finds the nominative subject
  // because both reduce to the same stem ("выписк"). Before stemming this was 0.
  assert.equal(searchFast('выписку').length, 1, 'выписку must find subject "выписка"');
  assert.equal(searchFast('выписки').length, 1, 'выписки must find subject "выписка"');
  assert.equal(searchFast('выписка').length, 1);
}));

test('T-morph-en: plural EN query matches singular subject (invoices -> invoice)', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'Your invoice is attached' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  assert.equal(searchFast('invoices').length, 1, 'invoices must find subject "invoice"');
  assert.equal(searchFast('reporting').length, 0, 'unrelated stem must not match');
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

// ── Phase 1 (v2.7.0): structured filters on searchFast ────────────────

test('T21: pure-filter (unread) returns every unread record, no query needed', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'alpha', seen: true }),
    hdr({ uid: 2, subject: 'beta',  seen: false }),
    hdr({ uid: 3, subject: 'gamma', seen: false }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // No query at all -- this is the case the candidate-set fix exists for.
  const unread = searchFast('', { filters: { seen: false } });
  assert.equal(unread.length, 2, 'two unread messages');
  assert.deepEqual(unread.map(h => h.record.uid).sort(), [2, 3]);
  assert.ok(unread.every(h => h.matchReasons.includes('filter')));
}));

test('T22: from filter narrows by sender substring (email or name)', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'x', from: [{ address: 'billing@acme.io', name: 'Acme Billing' }] }),
    hdr({ uid: 2, subject: 'y', from: [{ address: 'kate@example.com', name: 'Катя Иванова' }] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const byEmail = searchFast('', { filters: { from: 'acme.io' } });
  assert.deepEqual(byEmail.map(h => h.record.uid), [1]);

  const byName = searchFast('', { filters: { from: 'Катя' } });
  assert.deepEqual(byName.map(h => h.record.uid), [2]);
}));

test('T23: since/before bound the date range (since inclusive, before exclusive)', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'jan', date: '2025-01-15T10:00:00.000Z' }),
    hdr({ uid: 2, subject: 'mar', date: '2025-03-10T10:00:00.000Z' }),
    hdr({ uid: 3, subject: 'apr', date: '2025-04-02T10:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const march = searchFast('', {
    filters: {
      since: new Date('2025-03-01').getTime(),
      before: new Date('2025-04-01').getTime(),
    },
  });
  assert.deepEqual(march.map(h => h.record.uid), [2], 'only the March message is in [Mar 1, Apr 1)');
}));

test('T24: filters compose with a content query', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'report quarterly', seen: false }),
    hdr({ uid: 2, subject: 'report monthly',   seen: true }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const unreadReports = searchFast('report', { filters: { seen: false } });
  assert.deepEqual(unreadReports.map(h => h.record.uid), [1], 'content match AND unread filter');
}));

test('T25: filter that matches nothing returns empty', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'hello', flagged: false })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  assert.equal(searchFast('', { filters: { flagged: true } }).length, 0);
}));

test('T26: pure-filter results are ordered newest-first', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'old',   flagged: true, date: '2025-01-01T00:00:00.000Z' }),
    hdr({ uid: 2, subject: 'newer', flagged: true, date: '2025-05-01T00:00:00.000Z' }),
    hdr({ uid: 3, subject: 'newest',flagged: true, date: '2025-06-01T00:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const flagged = searchFast('', { filters: { flagged: true } });
  assert.deepEqual(flagged.map(h => h.record.uid), [3, 2, 1], 'descending by date');
}));

// ── Layer 3 (v2.9.0): has_attachments filter on searchFast ───────────

test('T-HA1: has_attachments filter splits records with/without attachments', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'with', hasAttachments: true }),
    hdr({ uid: 2, subject: 'without', hasAttachments: false }),
    hdr({ uid: 3, subject: 'also-with', hasAttachments: true }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const withAtt = searchFast('', { filters: { has_attachments: true } });
  assert.deepEqual(withAtt.map(h => h.record.uid).sort(), [1, 3], 'only attachment-carrying records');

  const withoutAtt = searchFast('', { filters: { has_attachments: false } });
  assert.deepEqual(withoutAtt.map(h => h.record.uid), [2], 'only the no-attachment record');
}));

// Guards the `?? false` default in passesFilters: a pre-schema-3 on-disk record
// has NO has_attachments key (loadAllRecords raw-casts JSON -> undefined). It must
// be treated as "no attachments": returned by has_attachments:false, excluded by
// has_attachments:true -- never silently dropped from BOTH.
test('T-HA2: a record missing has_attachments on disk is treated as false', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'legacy', hasAttachments: false }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // Simulate a pre-v2.9.0 (schema 2) record: strip the has_attachments key from
  // the on-disk envelope JSONL, exactly as an index built before this milestone
  // would look. The auto-migration would normally rebuild it; here we read it raw.
  const envPath = path.join(getIndexDir(), 'envelopes.jsonl');
  const lines = fs.readFileSync(envPath, 'utf-8').split('\n').filter(l => l.trim());
  const rewritten = lines.map(l => {
    const rec = JSON.parse(l);
    delete rec.has_attachments;
    return JSON.stringify(rec);
  }).join('\n') + '\n';
  fs.writeFileSync(envPath, rewritten);
  _resetForTests();

  const asFalse = searchFast('', { filters: { has_attachments: false } });
  assert.deepEqual(asFalse.map(h => h.record.uid), [1], 'undefined has_attachments is returned by false-query');

  const asTrue = searchFast('', { filters: { has_attachments: true } });
  assert.equal(asTrue.length, 0, 'undefined has_attachments is NOT returned by true-query');
}));

// ── Phase 2 (v2.7.0): idf-weighted relevance ranking ─────────────────

test('T27: a rarer matched token outranks a common one (idf weighting)', withTempStateDir(async () => {
  const src = new FakeSource();
  const headers: EmailHeader[] = [
    // Rare token "quantum" appears in exactly one subject (df=1).
    hdr({ uid: 100, subject: 'quantum encryption', date: '2025-03-03T00:00:00.000Z' }),
    // "sale" is common: this doc + 10 fillers below (df=11).
    hdr({ uid: 200, subject: 'summer sale', date: '2025-03-03T00:00:00.000Z' }),
  ];
  for (let i = 1; i <= 10; i++) {
    headers.push(hdr({ uid: i, subject: 'weekly sale', date: '2025-03-03T00:00:00.000Z' }));
  }
  src.setFolder('INBOX', headers, 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // Query touches both tokens; uid 100 matches only the rare "quantum",
  // uid 200 (and fillers) match only the common "sale". The rare match must
  // rank first even though every doc has the same date.
  const hits = searchFast('quantum sale');
  assert.equal(hits[0].record.uid, 100, 'rare-token match ranks first');
  const saleHit = hits.find(h => h.record.uid === 200);
  assert.ok(saleHit, 'common-token match is still a hit');
  assert.ok(hits[0].score > saleHit!.score, 'rare match scores strictly higher');
}));

// ── Phase 3 (v2.7.0): Message-ID graph threading ─────────────────────

test('T28: getThread links by In-Reply-To across folders + renamed subjects', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<a@x>', subject: 'Проект Альфа: старт', date: '2025-03-01T10:00:00.000Z' }),
    // A later reply whose subject was renamed entirely (no subject overlap).
    hdr({ uid: 2, messageId: '<c@x>', inReplyTo: '<b@x>', subject: 'итоги встречи', date: '2025-03-03T10:00:00.000Z' }),
    hdr({ uid: 9, messageId: '<z@x>', subject: 'спам реклама', date: '2025-03-04T10:00:00.000Z' }),
  ], 100);
  src.setFolder('Sent', [
    // Reply lives in Sent and has a renamed subject; only In-Reply-To ties it in.
    hdr({ uid: 1, messageId: '<b@x>', inReplyTo: '<a@x>', subject: 'Re: договор по сделке', date: '2025-03-02T10:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX', 'Sent'], src);
  _resetForTests();

  const thread = getThread('Альфа');
  // a -> b (Sent, renamed) -> c (renamed) must all be linked by Message-ID,
  // in chronological order, despite living in two folders with three subjects.
  assert.deepEqual(thread.map(h => h.record.messageId), ['<a@x>', '<b@x>', '<c@x>']);
  assert.ok(!thread.some(h => h.record.messageId === '<z@x>'), 'unrelated mail excluded');
}));

test('T29: subject fallback stays folder-scoped (no cross-folder false grouping)', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, messageId: '<i@x>', subject: 'отчёт' })], 100);
  // Same normalized subject, different folder, NO In-Reply-To link -> unrelated.
  src.setFolder('Sent', [hdr({ uid: 5, messageId: '<s@x>', subject: 'отчёт' })], 100);
  await buildIndex(['INBOX', 'Sent'], src);
  _resetForTests();

  const thread = getThread('отчёт');
  assert.equal(thread.length, 1, 'only the seed folder match; no graph link to Sent');
  assert.equal(thread[0].record.messageId, '<i@x>');
}));

// ── v2.7.1: index schema auto-migration (threading without manual rebuild) ──

test('T30: a fresh build is threading-ready (folder schema == current)', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1 })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const status = getIndexStatus();
  assert.equal(status.threadingReady, true);
  assert.ok(status.folders[0].schema >= 2, 'folder stamped with the threading schema');
}));

test('T31: a pre-threading (schema 1) folder is auto-rebuilt on update', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<p1@x>', subject: 'Проект' }),
    hdr({ uid: 2, messageId: '<p2@x>', inReplyTo: '<p1@x>', subject: 'разное' }),
  ], 100);
  await buildIndex(['INBOX'], src);

  // Simulate an index built before schema tracking: downgrade the stored schema.
  const metaP = path.join(getIndexDir(), 'meta.json');
  const meta = JSON.parse(fs.readFileSync(metaP, 'utf-8'));
  meta.folders['INBOX'].schema = 1;
  fs.writeFileSync(metaP, JSON.stringify(meta));
  _resetForTests();

  assert.equal(getIndexStatus().threadingReady, false, 'schema 1 -> not threading-ready');

  // uidValidity is unchanged (100), so only the schema gap should force a rebuild.
  const r = await updateIndex(['INBOX'], src);
  assert.ok(r.added >= 2, 'stale-schema folder is re-streamed, not incrementally appended');
  assert.equal(getIndexStatus().threadingReady, true, 'auto-migration restores threading');
}));

// ── v2.9.0 (L3-P1): schema 2->3 auto-migration + has_attachments persistence ──

test('T-mig: schema 2->3 auto-migration — threadingReady stays true; folder re-streams to schema 3', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<q1@x>', subject: 'question' }),
    hdr({ uid: 2, messageId: '<q2@x>', inReplyTo: '<q1@x>', subject: 'Re: question' }),
  ], 100);
  await buildIndex(['INBOX'], src);

  // Simulate an index written by v2.x: downgrade the stored schema to 2.
  const metaP = path.join(getIndexDir(), 'meta.json');
  const meta = JSON.parse(fs.readFileSync(metaP, 'utf-8'));
  meta.folders['INBOX'].schema = 2;
  fs.writeFileSync(metaP, JSON.stringify(meta));
  _resetForTests();

  // schema 2 still meets THREADING_SCHEMA (= 2), so threadingReady must be true
  // even before the migration -- this is the THREADING_SCHEMA decouple guarantee.
  assert.equal(getIndexStatus().threadingReady, true, 'schema 2 meets THREADING_SCHEMA; threadingReady must not regress');

  // updateIndex should detect stored.schema (2) < INDEX_SCHEMA (3) and rebuild.
  const r = await updateIndex(['INBOX'], src);
  assert.ok(r.added >= 2, 'stale-schema folder (schema 2) is re-streamed to schema 3');
  assert.equal(r.errors.length, 0, 'migration is clean');
  _resetForTests();

  const status = getIndexStatus();
  assert.ok(status.folders[0].schema >= 3, 'folder is now at schema 3 after migration');
  assert.equal(status.threadingReady, true, 'threadingReady stays true after 2->3 bump');
}));

test('T-bit: has_attachments bit persists through EmailHeader -> toRecord -> IndexRecord', withTempStateDir(async () => {
  const src = new FakeSource();
  // One message with attachments, one without.
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<att@x>', subject: 'has attachment', hasAttachments: true }),
    hdr({ uid: 2, messageId: '<natt@x>', subject: 'no attachment', hasAttachments: false }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // searchFast returns SearchHit[]; .record carries has_attachments.
  const hits = searchFast('attachment');
  // Both messages match the term; sort by uid so assertions are deterministic.
  hits.sort((a, b) => a.record.uid - b.record.uid);
  assert.equal(hits.length, 2, 'both messages found');
  assert.equal(hits[0].record.has_attachments, true, 'uid 1: has_attachments persisted as true');
  assert.equal(hits[1].record.has_attachments, false, 'uid 2: has_attachments persisted as false');
}));

// ── v2.8.0 (L2-A): expunge reconciliation + measured count + resilience ──────

test('T32: a deleted message is reconciled out of the index on update', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, subject: 'first' }),
    hdr({ uid: 2, subject: 'second' }),
    hdr({ uid: 3, subject: 'third' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();
  assert.equal(searchFast('second').length, 1, 'precondition: uid 2 is searchable');

  // uid 2 is expunged. uidNext stays 4 (a deletion does not lower the high-water
  // mark), so the append path streams nothing new -- only the exists mismatch
  // (stored 3 vs server 2) reveals the deletion and forces a rebuild.
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'first' }), hdr({ uid: 3, subject: 'third' })], 100, 4);

  const res = await updateIndex(['INBOX'], src);
  assert.equal(res.errors.length, 0);
  _resetForTests();
  const status = getIndexStatus();
  assert.equal(status.totalCount, 2, 'count reflects the deletion (measured, not fabricated)');
  assert.equal(status.folders[0].count, 2);
  assert.equal(searchFast('second').length, 0, 'the deleted message is gone from search');
  assert.equal(searchFast('third').length, 1, 'surviving messages stay searchable');
}));

test('T33: a folder that fails to sync is reported, others still build', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'good message' })], 100);
  src.failOn('Spam');

  const res = await buildIndex(['INBOX', 'Spam'], src);
  assert.equal(res.errors.length, 1, 'the failing folder is surfaced, not swallowed');
  assert.equal(res.errors[0].folder, 'Spam');
  assert.equal(res.folders.length, 1, 'only the healthy folder is reported as synced');
  assert.equal(res.folders[0].folder, 'INBOX');
  _resetForTests();
  assert.equal(getIndexStatus().totalCount, 1, 'the healthy folder is fully usable');
  assert.equal(searchFast('good').length, 1);
}));

test('T34: a count drift from a prior bug self-heals on the next update', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1 }), hdr({ uid: 2 })], 100);
  await buildIndex(['INBOX'], src);

  // Corrupt the stored count to mimic the pre-fix fabricated-count drift.
  const metaP = path.join(getIndexDir(), 'meta.json');
  const meta = JSON.parse(fs.readFileSync(metaP, 'utf-8'));
  meta.folders['INBOX'].count = 99;
  fs.writeFileSync(metaP, JSON.stringify(meta));
  _resetForTests();

  // No real change on the server (exists still 2); the reconcile detects the
  // drift (99 != 2) and rebuilds to the true count.
  const res = await updateIndex(['INBOX'], src);
  assert.equal(res.errors.length, 0);
  assert.equal(res.added, 2, 'reconcile re-streams the whole folder (a no-op append would add 0)');
  assert.equal(getIndexStatus().totalCount, 2, 'drifted count is corrected to the measured value');
}));

test('T39: EXISTS exceeding the streamed count converges (no perpetual rebuild)', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1 }), hdr({ uid: 2 }), hdr({ uid: 3 })], 100);
  // The server's EXISTS reports 4 though only 3 messages stream -- e.g. an
  // in-flight delivery between the cursor and stream IMAP sessions, or a
  // deleted-not-expunged message. count tracks EXISTS, so the index converges
  // instead of rebuilding on every run.
  src.setExists('INBOX', 4);
  await buildIndex(['INBOX'], src);

  const r1 = await updateIndex(['INBOX'], src);
  const r2 = await updateIndex(['INBOX'], src);
  assert.equal(r1.added, 0, 'first update is a no-op append, not a rebuild');
  assert.equal(r2.added, 0, 'second update is STILL a no-op -- convergence, no perpetual rebuild');
  assert.equal(r1.errors.length, 0);
  assert.equal(r2.errors.length, 0);
}));

test('T40: updateIndex syncs healthy folders even when one fails mid-run', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'inbox alpha' })], 100);
  src.setFolder('Sent', [hdr({ uid: 1, subject: 'sentinel marker' })], 100);
  await buildIndex(['INBOX', 'Sent'], src);
  _resetForTests();

  // New INBOX mail arrives (distinct token 'zebra'); Sent's cursor now fails.
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'inbox alpha' }), hdr({ uid: 2, subject: 'zebra arrival' })], 100);
  src.failOn('Sent');

  const res = await updateIndex(['INBOX', 'Sent'], src);
  assert.equal(res.errors.length, 1, 'the failing folder is surfaced');
  assert.equal(res.errors[0].folder, 'Sent');
  _resetForTests();
  assert.equal(searchFast('zebra').length, 1, 'INBOX still synced its new message');
  assert.equal(searchFast('sentinel').length, 1, 'Sent records preserved (untouched on failure)');
}));

// ── v2.8.0 (L2-B): multi-account read isolation ─────────────────────────────

test('T35: a concrete account never sees another account\'s records', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'alice secret plan' })], 100);

  _setAccountForTests('alice@ya.ru');
  await buildIndex(['INBOX'], src);
  _resetForTests();
  assert.equal(searchFast('secret').length, 1, 'alice sees her own record');
  assert.equal(getIndexStatus().account, 'alice@ya.ru');

  // Bob shares the same state dir (misconfiguration) -- he must NOT read alice's mail.
  _setAccountForTests('bob@ya.ru');
  _resetForTests();
  assert.equal(searchFast('secret').length, 0, 'cross-account fast search is blocked');
  assert.equal(getThread('secret').length, 0, 'cross-account thread is blocked');

  // Back to alice: still visible (the records were never altered, only filtered).
  _setAccountForTests('alice@ya.ru');
  _resetForTests();
  assert.equal(searchFast('secret').length, 1);
}));

// ── v2.8.0 (L2-D/E): thread robustness (subjectless guard, stable seed) ──────

test('T36: subjectless messages are not collapsed into one bogus thread', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<n1@x>', subject: '', from: [{ address: 'a@x', name: 'Sender One' }] }),
    hdr({ uid: 2, messageId: '<n2@x>', subject: '', from: [{ address: 'b@x', name: 'Sender Two' }] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // The empty normalized subject must NOT group the two unrelated messages.
  const thread = getThread('Sender One');
  assert.equal(thread.length, 1, 'only the seed; no subject-collapse on empty subjects');
  assert.equal(thread[0].record.uid, 1);
}));

test('T37: getThread finds its seed after a cache rebuild (stable key, not identity)', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<a@x>', subject: 'Бюджет', date: '2025-01-01T10:00:00.000Z' }),
    hdr({ uid: 2, messageId: '<b@x>', inReplyTo: '<a@x>', subject: 'Re: Бюджет', date: '2025-01-02T10:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  // Do NOT _resetForTests between searchFast and getThread inside getThread:
  // the seed object identity differs from a freshly-read cache, but the
  // (account, folder, uid) key lookup still resolves it.
  _resetForTests();

  const thread = getThread('Бюджет');
  assert.deepEqual(thread.map(h => h.record.uid), [1, 2], 'Message-ID graph still links the reply');
}));

// ── v2.8.0 (L2-C): true total + offset pagination ───────────────────────────

test('T38: searchFastResult reports full total and paginates via offset', withTempStateDir(async () => {
  const src = new FakeSource();
  const headers: EmailHeader[] = [];
  for (let i = 1; i <= 10; i++) {
    headers.push(hdr({ uid: i, subject: 'meeting ' + i, date: `2025-06-${String(i).padStart(2, '0')}T00:00:00.000Z` }));
  }
  src.setFolder('INBOX', headers, 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const page1 = searchFastResult('meeting', { limit: 3, offset: 0 });
  assert.equal(page1.total, 10, 'total is the full match count, not the page size');
  assert.equal(page1.hits.length, 3, 'page is limited');

  const page2 = searchFastResult('meeting', { limit: 3, offset: 3 });
  assert.equal(page2.total, 10, 'total is stable across pages');
  assert.equal(page2.hits.length, 3);

  const p1uids = new Set(page1.hits.map(h => h.record.uid));
  assert.ok(page2.hits.every(h => !p1uids.has(h.record.uid)), 'pages do not overlap');

  // searchFast wrapper still returns just the hits (back-compat).
  assert.equal(searchFast('meeting', { limit: 3 }).length, 3);
}));

test('T41: a cross-account In-Reply-To link does not bridge two mailboxes in a thread', withTempStateDir(async () => {
  const src = new FakeSource();
  // alice owns the root message <a@x>.
  _setAccountForTests('alice@ya.ru');
  src.setFolder('INBOX', [hdr({ uid: 1, messageId: '<a@x>', subject: 'Alpha project' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // bob (sharing the state dir) has a reply whose In-Reply-To points at alice's <a@x>.
  _setAccountForTests('bob@ya.ru');
  src.setFolder('INBOX', [hdr({ uid: 2, messageId: '<b@x>', inReplyTo: '<a@x>', subject: 'Alpha reply' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // bob's thread must contain ONLY bob's message -- the Message-ID graph must not
  // pull alice's root in via the cross-account In-Reply-To edge.
  const thread = getThread('Alpha reply');
  assert.equal(thread.length, 1, 'no cross-account bridge through the reply graph');
  assert.equal(thread[0].record.messageId, '<b@x>');
  assert.equal(thread[0].record.account, 'bob@ya.ru');
}));

test('T42: offset paginates a pure-filter query (rangeIndices branch)', withTempStateDir(async () => {
  const src = new FakeSource();
  const headers: EmailHeader[] = [];
  for (let i = 1; i <= 5; i++) {
    headers.push(hdr({ uid: i, subject: 'm' + i, seen: false, date: `2025-05-0${i}T00:00:00.000Z` }));
  }
  src.setFolder('INBOX', headers, 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const page = searchFastResult('', { filters: { seen: false }, limit: 2, offset: 2 });
  assert.equal(page.total, 5, 'total counts all filter matches, not the page');
  assert.equal(page.hits.length, 2, 'offset+limit page of the pure-filter scan');
  // Beyond the end: empty page, total intact.
  const beyond = searchFastResult('', { filters: { seen: false }, limit: 2, offset: 10 });
  assert.equal(beyond.hits.length, 0);
  assert.equal(beyond.total, 5);
}));
