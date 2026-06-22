// find-attachments.test.ts -- unit tests for findAttachments (Layer 3, Phase 3)
// + the yandex_find_attachments tool handler.
//
// Covers: filter logic (from/filename_contains/mime/since/before + AND),
// dedup by (filename_lower, size) with occurrence_count = distinct (folder,uid)
// messages (NOT raw partId rows), null-filename non-collapse, earliest-dated
// representative, capped occurrences[], pagination (total = group count),
// account isolation, graceful degradation (no isError, no IMAP), the <50ms ship
// gate, and handler-level output sanitization of every structured field.
//
// Harness (hdr / att / FakeSource / withTempStateDir) mirrors
// attachments-manifest.test.ts (helpers there are not exported).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { performance } from 'node:perf_hooks';

import type { EmailHeader } from '../imap.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import {
  buildIndex,
  dropIndex,
  findAttachments,
  _resetForTests,
  _setAccountForTests,
  type EnvelopeSource,
} from '../mail-index.js';
import { TOOLS, type ToolCtx } from '../tools.js';

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

function att(overrides?: {
  filename?: string | null;
  mimeType?: string;
  size?: number;
  partId?: string;
  md5?: string | null;
}) {
  return {
    filename: overrides?.filename !== undefined ? overrides.filename : 'report.pdf',
    mimeType: overrides?.mimeType ?? 'application/pdf',
    size: overrides?.size ?? 12345,
    partId: overrides?.partId ?? '1',
    md5: overrides?.md5 !== undefined ? overrides.md5 : null,
  };
}

class FakeSource implements EnvelopeSource {
  private folders = new Map<string, EmailHeader[]>();
  private cursors = new Map<string, { uidValidity: number; uidNext: number; exists: number }>();

  setFolder(folder: string, headers: EmailHeader[], uidValidity: number, uidNextOverride?: number): void {
    this.folders.set(folder, headers.slice());
    const maxUid = headers.reduce((m, h) => Math.max(m, h.uid), 0);
    const uidNext = uidNextOverride ?? maxUid + 1;
    this.cursors.set(folder, { uidValidity, uidNext, exists: headers.length });
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

function withTempStateDir(fn: () => void | Promise<void>): () => Promise<void> {
  return async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ymc-find-'));
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
      _setAccountForTests(null);
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  };
}

// ── Filter tests ──────────────────────────────────────────────────────

test('FA-a: each filter narrows correctly; filters AND together', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<a@ex>', from: [{ address: 'bob@acme.io', name: 'Bob' }],
      date: '2025-02-01T00:00:00.000Z', hasAttachments: true,
      attachments: [att({ filename: 'contract.pdf', mimeType: 'application/pdf', size: 100, partId: '1' })] }),
    hdr({ uid: 2, messageId: '<b@ex>', from: [{ address: 'carol@other.com', name: 'Carol' }],
      date: '2025-05-01T00:00:00.000Z', hasAttachments: true,
      attachments: [att({ filename: 'photo.jpg', mimeType: 'image/jpeg', size: 200, partId: '1' })] }),
    hdr({ uid: 3, messageId: '<c@ex>', from: [{ address: 'bob@acme.io', name: 'Bob' }],
      date: '2025-08-01T00:00:00.000Z', hasAttachments: true,
      attachments: [att({ filename: 'invoice.pdf', mimeType: 'application/pdf', size: 300, partId: '1' })] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // from
  assert.deepEqual(findAttachments({ from: 'acme.io' }).hits.map(h => h.uid).sort(), [1, 3]);
  // filename_contains
  assert.deepEqual(findAttachments({ filename_contains: 'invoice' }).hits.map(h => h.uid), [3]);
  // mime substring
  assert.deepEqual(findAttachments({ mime: 'pdf' }).hits.map(h => h.uid).sort(), [1, 3]);
  assert.deepEqual(findAttachments({ mime: 'image/' }).hits.map(h => h.uid), [2]);
  // since inclusive / before exclusive
  assert.deepEqual(
    findAttachments({ since: new Date('2025-03-01').getTime(), before: new Date('2025-07-01').getTime() }).hits.map(h => h.uid),
    [2],
  );
  // AND: bob + pdf -> uid 1 and 3
  assert.deepEqual(findAttachments({ from: 'bob', mime: 'application/pdf' }).hits.map(h => h.uid).sort(), [1, 3]);
  // AND that matches nothing
  assert.equal(findAttachments({ from: 'bob', mime: 'image/' }).total, 0);
}));

test('FA-b: dedup by (filename_lower, size); occurrence_count; earliest representative', withTempStateDir(async () => {
  const src = new FakeSource();
  // Same file (report.pdf / size 999) in 3 messages across 2 folders, different dates.
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<r1@ex>', date: '2025-03-01T00:00:00.000Z', hasAttachments: true,
      attachments: [att({ filename: 'report.pdf', size: 999, partId: '1' })] }),
    hdr({ uid: 2, messageId: '<r2@ex>', date: '2025-01-01T00:00:00.000Z', hasAttachments: true,
      attachments: [att({ filename: 'report.pdf', size: 999, partId: '1' })] }),
  ], 100);
  src.setFolder('Archive', [
    hdr({ uid: 10, messageId: '<r3@ex>', date: '2025-06-01T00:00:00.000Z', hasAttachments: true,
      attachments: [att({ filename: 'report.pdf', size: 999, partId: '1' })] }),
  ], 200);
  await buildIndex(['INBOX', 'Archive'], src);
  _resetForTests();

  const page = findAttachments({ filename_contains: 'report' });
  assert.equal(page.total, 1, 'three identical files collapse to one group');
  assert.equal(page.hits.length, 1);
  const hit = page.hits[0];
  assert.equal(hit.occurrenceCount, 3, 'occurrence_count = 3 distinct messages');
  assert.equal(hit.date, '2025-01-01T00:00:00.000Z', 'representative = EARLIEST-dated message (uid 2)');
  assert.equal(hit.uid, 2, 'representative uid is the earliest');
  assert.equal(hit.occurrences.length, 3, 'all three occurrences enumerated (under cap)');
  assert.equal(hit.occurrencesTruncated, false);
  const occ = hit.occurrences.map(o => `${o.folder}#${o.uid}`).sort();
  assert.deepEqual(occ, ['Archive#10', 'INBOX#1', 'INBOX#2']);
}));

test('FA-c: dedup + mime filter are case-insensitive', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<u@ex>', date: '2025-02-01T00:00:00.000Z', hasAttachments: true,
      attachments: [att({ filename: 'Report.PDF', mimeType: 'Application/PDF', size: 555, partId: '1' })] }),
    hdr({ uid: 2, messageId: '<l@ex>', date: '2025-03-01T00:00:00.000Z', hasAttachments: true,
      attachments: [att({ filename: 'report.pdf', mimeType: 'application/pdf', size: 555, partId: '1' })] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const page = findAttachments({ mime: 'PDF' });
  assert.equal(page.total, 1, 'Report.PDF and report.pdf (same size) collapse case-insensitively');
  assert.equal(page.hits[0].occurrenceCount, 2);
}));

test('FA-d: occurrence_count counts distinct messages, not partId rows; occurrences cap at 10', withTempStateDir(async () => {
  const src = new FakeSource();
  // One message attaching the SAME file in TWO parts -> must add 1, not 2.
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<two@ex>', date: '2025-04-01T00:00:00.000Z', hasAttachments: true,
      attachments: [
        att({ filename: 'dup.pdf', size: 42, partId: '1' }),
        att({ filename: 'dup.pdf', size: 42, partId: '2' }),
      ] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();
  const single = findAttachments({ filename_contains: 'dup' });
  assert.equal(single.total, 1);
  assert.equal(single.hits[0].occurrenceCount, 1, 'same file in two parts of one message = 1 message');

  // 12 distinct messages, same file -> occurrence_count 12, occurrences capped at 10.
  const many: EmailHeader[] = [];
  for (let u = 1; u <= 12; u++) {
    many.push(hdr({ uid: u, messageId: `<h${u}@ex>`, date: `2025-07-${String(u).padStart(2, '0')}T00:00:00.000Z`,
      hasAttachments: true, attachments: [att({ filename: 'hot.pdf', size: 7, partId: '1' })] }));
  }
  src.setFolder('Bulk', many, 300);
  await buildIndex(['Bulk'], src);
  _resetForTests();
  const hot = findAttachments({ filename_contains: 'hot' });
  assert.equal(hot.hits[0].occurrenceCount, 12, 'true full count is 12');
  assert.equal(hot.hits[0].occurrences.length, 10, 'occurrences capped at 10');
  assert.equal(hot.hits[0].occurrencesTruncated, true);
}));

test('FA-e: null-filename rows are NOT collapsed by size; never match filename_contains', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<n1@ex>', hasAttachments: true,
      attachments: [att({ filename: null, size: 88, partId: '1' })] }),
    hdr({ uid: 2, messageId: '<n2@ex>', hasAttachments: true,
      attachments: [att({ filename: null, size: 88, partId: '1' })] }),
    hdr({ uid: 3, messageId: '<named@ex>', hasAttachments: true,
      attachments: [att({ filename: 'named.bin', size: 88, partId: '1' })] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const all = findAttachments({});
  // two distinct null rows (not collapsed) + one named = 3 groups.
  assert.equal(all.total, 3, 'null filenames do not collapse even with equal size');
  // filename_contains never matches a null filename.
  assert.deepEqual(findAttachments({ filename_contains: 'named' }).hits.map(h => h.uid), [3]);
  assert.equal(findAttachments({ filename_contains: 'bin' }).hits.every(h => h.filename !== null), true);
}));

test('FA-f: account isolation -- another account\'s rows never leak', withTempStateDir(async () => {
  const src = new FakeSource();
  _setAccountForTests('alice@ya.ru');
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<a@ya>', hasAttachments: true,
      attachments: [att({ filename: 'alice.pdf', size: 1, partId: '1' })] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  _setAccountForTests('bob@ya.ru');
  src.setFolder('INBOX', [
    hdr({ uid: 2, messageId: '<b@ya>', hasAttachments: true,
      attachments: [att({ filename: 'bob.pdf', size: 2, partId: '1' })] }),
  ], 200);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // Bob's session sees only bob's row.
  const bobView = findAttachments({});
  assert.deepEqual(bobView.hits.map(h => h.filename), ['bob.pdf']);

  _setAccountForTests('alice@ya.ru');
  _resetForTests();
  const aliceView = findAttachments({});
  assert.deepEqual(aliceView.hits.map(h => h.filename), ['alice.pdf']);
}));

test('FA-g: pagination -- total is group count and stable across pages', withTempStateDir(async () => {
  const src = new FakeSource();
  const headers: EmailHeader[] = [];
  for (let u = 1; u <= 5; u++) {
    headers.push(hdr({ uid: u, messageId: `<p${u}@ex>`, date: `2025-0${u}-01T00:00:00.000Z`,
      hasAttachments: true, attachments: [att({ filename: `f${u}.pdf`, size: u, partId: '1' })] }));
  }
  src.setFolder('INBOX', headers, 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const p1 = findAttachments({ limit: 2, offset: 0 });
  assert.equal(p1.total, 5, 'total = 5 groups');
  assert.equal(p1.hits.length, 2);
  const p2 = findAttachments({ limit: 2, offset: 2 });
  assert.equal(p2.total, 5, 'total stable across pages');
  assert.equal(p2.hits.length, 2);
  const p3 = findAttachments({ limit: 2, offset: 4 });
  assert.equal(p3.hits.length, 1, 'last page has the remainder');
  // No overlap between pages.
  const ids = new Set([...p1.hits, ...p2.hits, ...p3.hits].map(h => h.uid));
  assert.equal(ids.size, 5, 'pages partition the result set with no overlap');
}));

test('FA-h: graceful degradation -- empty manifest reports manifestBuilt:false', withTempStateDir(async () => {
  // No index built at all.
  const empty = findAttachments({ from: 'anything' });
  assert.equal(empty.manifestBuilt, false);
  assert.equal(empty.total, 0);
  assert.deepEqual(empty.hits, []);

  // After a drop, still degrades cleanly.
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<x@ex>', hasAttachments: true, attachments: [att({ partId: '1' })] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();
  assert.equal(findAttachments({}).manifestBuilt, true, 'built manifest reports true');
  dropIndex();
  _resetForTests();
  assert.equal(findAttachments({}).manifestBuilt, false, 'dropped manifest degrades to false');
}));

// ── <50ms ship gate (its own test so a perf flake never masks a logic bug) ──

test('FA-perf: find_attachments(from, mime=application/pdf) < 50ms on a 1000-row manifest', withTempStateDir(async () => {
  const src = new FakeSource();
  const headers: EmailHeader[] = [];
  for (let u = 1; u <= 1000; u++) {
    headers.push(hdr({
      uid: u,
      messageId: `<perf${u}@ex>`,
      from: [{ address: u % 7 === 0 ? 'consulco@partner.com' : `sender${u}@example.com`, name: `Sender ${u}` }],
      date: `2025-01-01T00:00:${String(u % 60).padStart(2, '0')}.000Z`,
      hasAttachments: true,
      attachments: [att({ filename: `doc${u}.pdf`, mimeType: 'application/pdf', size: u, partId: '1' })],
    }));
  }
  src.setFolder('INBOX', headers, 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // Warm the cache (first call parses dates + loads rows).
  findAttachments({ from: 'consulco', mime: 'application/pdf' });
  const t0 = performance.now();
  const page = findAttachments({ from: 'consulco', mime: 'application/pdf' });
  const elapsed = performance.now() - t0;
  assert.ok(page.total > 0, 'gate query returns matches');
  assert.ok(elapsed < 50, `ship gate: expected < 50ms, got ${elapsed.toFixed(2)}ms`);
}));

// ── Handler-level: output sanitization + degraded structured shape ────

function minimalCtx(): ToolCtx {
  return {
    authLevel: 0,
    capabilities: new Set(),
    serverContext: { canElicit: false },
    protectedFolders: new Set(),
  } as ToolCtx;
}

test('FA-handler: structured output re-sanitizes filename/sender/subject; manifest_built false has no isError', withTempStateDir(async () => {
  const def = TOOLS.find(t => t.name === 'yandex_find_attachments');
  assert.ok(def, 'yandex_find_attachments is registered');

  // Degraded path: no manifest -> manifest_built:false, NOT an error, no hits.
  const degraded = await def!.handler({}, minimalCtx());
  assert.notEqual(degraded.isError, true, 'degradation is never an error');
  const dsc = degraded.structuredContent as { manifest_built: boolean; hits: unknown[] };
  assert.equal(dsc.manifest_built, false);
  assert.deepEqual(dsc.hits, []);

  // Hostile strings built from code points (NEVER raw glyphs): RLO U+202E,
  // ZWSP U+200B, plus a newline -- all must be stripped/collapsed on output.
  const RLO = String.fromCharCode(0x202E);
  const ZWSP = String.fromCharCode(0x200B);
  const badName = 'Bad' + RLO + 'Name' + ZWSP;
  const badFile = 'in' + RLO + 'voice' + ZWSP + '.pdf';

  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<h@ex>',
      from: [{ address: 'evil@x.io', name: badName }],
      subject: 'sub\nject', hasAttachments: true,
      attachments: [att({ filename: badFile, size: 10, partId: '1' })] }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const res = await def!.handler({ filename_contains: 'voice' }, minimalCtx());
  assert.notEqual(res.isError, true);
  const sc = res.structuredContent as {
    manifest_built: boolean;
    total: number;
    hits: Array<{ filename: string | null; from: string; subject: string }>;
  };
  assert.equal(sc.manifest_built, true);
  assert.equal(sc.total, 1);
  const h = sc.hits[0];
  assert.ok(h.filename !== null && !h.filename.includes(RLO) && !h.filename.includes(ZWSP),
    'filename format chars stripped in structured output');
  assert.ok(!h.from.includes(RLO) && !h.from.includes(ZWSP), 'sender format chars stripped');
  assert.ok(!h.subject.includes('\n'), 'subject newline collapsed');
}));
