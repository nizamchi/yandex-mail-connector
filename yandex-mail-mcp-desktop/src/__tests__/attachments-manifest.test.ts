// attachments-manifest.test.ts -- unit tests for the attachments.jsonl manifest
// (Phase 2, plan 02-02).
//
// Covers all three write paths (build / updateIndex-append / drop) plus account
// isolation, per-folder failure resilience, sanitized filename storage, and the
// minimal-fixture shape contract.
//
// Harness (hdr / FakeSource / withTempStateDir) is replicated from
// mail-index.test.ts -- the helpers are not exported from that file so they are
// copied here rather than imported.

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
  getIndexDir,
  loadAllAttachments,
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

// FakeSource: replicated from mail-index.test.ts (not exported from there).
class FakeSource implements EnvelopeSource {
  private folders = new Map<string, EmailHeader[]>();
  private cursors = new Map<string, { uidValidity: number; uidNext: number; exists: number }>();
  private failFolders = new Set<string>();

  setFolder(folder: string, headers: EmailHeader[], uidValidity: number, uidNextOverride?: number): void {
    this.folders.set(folder, headers.slice());
    const maxUid = headers.reduce((m, h) => Math.max(m, h.uid), 0);
    const uidNext = uidNextOverride ?? maxUid + 1;
    this.cursors.set(folder, { uidValidity, uidNext, exists: headers.length });
  }

  failOn(folder: string): void { this.failFolders.add(folder); }

  async getCursor(folder: string): Promise<{ uidValidity: number; uidNext: number; exists: number }> {
    if (this.failFolders.has(folder)) throw new Error(`fake cursor failure for ${folder}`);
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
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ymc-att-'));
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

// Reads all rows from the manifest file directly (bypasses loadAllAttachments cache).
function readManifestRows(indexDir: string) {
  const p = path.join(indexDir, 'attachments.jsonl');
  if (!fs.existsSync(p)) return [];
  const raw = fs.readFileSync(p, 'utf-8');
  return raw.split('\n').filter(l => l.trim().length > 0).map(l => JSON.parse(l));
}

// ── Tests ─────────────────────────────────────────────────────────────

// (a) build a folder with two messages carrying attachments (2+1 leaves)
//     -> manifest has exactly 3 rows; file mode is 0o600.
test('AM-a: build produces one manifest row per attachment leaf; mode 0o600', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<m1@ex>', hasAttachments: true,
      attachments: [
        att({ filename: 'contract.pdf', partId: '1' }),
        att({ filename: 'invoice.xlsx', mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', partId: '2' }),
      ],
    }),
    hdr({ uid: 2, messageId: '<m2@ex>', hasAttachments: true,
      attachments: [
        att({ filename: 'photo.jpg', mimeType: 'image/jpeg', partId: '1' }),
      ],
    }),
    hdr({ uid: 3, messageId: '<m3@ex>', hasAttachments: false }),
  ], 100);

  await buildIndex(['INBOX'], src);
  _resetForTests();

  const rows = readManifestRows(getIndexDir());
  assert.equal(rows.length, 3, 'one row per attachment leaf (2+1); no row for uid 3 (no attachments)');

  const filenames = rows.map((r: { filename: string }) => r.filename).sort();
  assert.deepEqual(filenames, ['contract.pdf', 'invoice.xlsx', 'photo.jpg']);

  // File mode check (POSIX only -- node cannot represent posix perms on win32).
  if (process.platform !== 'win32') {
    const p = path.join(getIndexDir(), 'attachments.jsonl');
    const mode = fs.statSync(p).mode & 0o777;
    assert.equal(mode, 0o600, 'attachments.jsonl must be mode 0o600');
  }
}));

// (b) APPEND path: build INBOX (1 attachment), then add a NEW higher-uid email
//     carrying an attachment + bump the cursor, run updateIndex ->
//     the new attachment row appears WITHOUT a full rebuild.
//     (Highest-value test -- gates the Pitfall-7 silent-staleness bug.)
test('AM-b: updateIndex incremental append adds new attachment rows without full rebuild', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<m1@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'first.pdf', partId: '1' }) ],
    }),
  ], 100, 2);

  await buildIndex(['INBOX'], src);
  _resetForTests();

  const rowsBefore = readManifestRows(getIndexDir());
  assert.equal(rowsBefore.length, 1, 'precondition: one manifest row after initial build');

  // New email arrives (uid 2) with a different attachment.
  // setFolder re-configures the source; uidNext becomes 3.
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<m1@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'first.pdf', partId: '1' }) ],
    }),
    hdr({ uid: 2, messageId: '<m2@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'second.pdf', partId: '1', size: 9999 }) ],
    }),
  ], 100, 3);

  const res = await updateIndex(['INBOX'], src);
  assert.equal(res.errors.length, 0, 'no errors in append update');
  assert.equal(res.added, 1, 'only uid 2 is new');
  _resetForTests();

  const rowsAfter = readManifestRows(getIndexDir());
  assert.equal(rowsAfter.length, 2, 'new attachment row appeared via append, not rebuild');
  const filenames = rowsAfter.map((r: { filename: string }) => r.filename).sort();
  assert.deepEqual(filenames, ['first.pdf', 'second.pdf'], 'both rows present');

  // Verify the new row carries the correct denormalized fields.
  const newRow = rowsAfter.find((r: { filename: string; uid: number }) => r.uid === 2);
  assert.ok(newRow, 'uid 2 attachment row exists');
  assert.equal(newRow.filename, 'second.pdf');
  assert.equal(newRow.size, 9999);
  assert.ok('md5' in newRow, 'md5 key present');
  assert.equal(newRow.md5, null, 'md5 is null (Yandex sends null)');
}));

// (c) drop -> attachments.jsonl is gone; a fresh build of a different fixture
//     yields a manifest with ONLY the new rows (no stale leftovers).
test('AM-c: drop removes attachments.jsonl; fresh build has no stale rows', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<stale@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'stale.pdf', partId: '1' }) ],
    }),
  ], 100);

  await buildIndex(['INBOX'], src);
  _resetForTests();
  assert.equal(readManifestRows(getIndexDir()).length, 1, 'precondition: stale row present');

  const dirBefore = getIndexDir();
  dropIndex();
  _resetForTests();

  assert.equal(fs.existsSync(path.join(dirBefore, 'attachments.jsonl')), false,
    'attachments.jsonl is gone after drop');

  // Fresh build with different data -- must yield only the new row.
  src.setFolder('INBOX', [
    hdr({ uid: 5, messageId: '<fresh@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'fresh.pdf', partId: '1' }) ],
    }),
  ], 200);

  await buildIndex(['INBOX'], src);
  _resetForTests();

  const rows = readManifestRows(getIndexDir());
  assert.equal(rows.length, 1, 'exactly one row after fresh build');
  assert.equal(rows[0].filename, 'fresh.pdf', 'only the new row, no stale leftovers');
}));

// (d) Malicious filename (newline + RLO \u202E + ZWSP \u200B) is stored sanitized
//     as exactly one JSONL line (newline integrity + format-char strip).
test('AM-d: malicious filename (newline+RLO+ZWSP) stored sanitized; one JSONL line per row', withTempStateDir(async () => {
  const src = new FakeSource();
  // Construct the malicious filename using \uXXXX escape sequences (never raw glyphs).
  // Contains: LF (\n), RLO (\u202E), ZWSP (\u200B).
  const maliciousName = 'evil\nfile\u202Egpj.exe\u200B';

  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<mal@ex>', hasAttachments: true,
      attachments: [ att({ filename: maliciousName, partId: '1' }) ],
    }),
  ], 100);

  await buildIndex(['INBOX'], src);
  _resetForTests();

  const p = path.join(getIndexDir(), 'attachments.jsonl');
  assert.ok(fs.existsSync(p), 'manifest file exists');

  const raw = fs.readFileSync(p, 'utf-8');
  // The manifest must have exactly ONE physical line per row (not counting the
  // trailing newline). A newline in the filename that was NOT sanitized would
  // produce 2 physical lines for 1 row.
  const physicalLines = raw.split('\n').filter(l => l.length > 0);
  assert.equal(physicalLines.length, 1, 'exactly one physical line for one row (newline in filename was sanitized)');

  const row = JSON.parse(physicalLines[0]);
  const storedFilename: string = row.filename ?? '';

  // RLO codepoint U+202E must be absent from the stored filename.
  assert.ok(!storedFilename.includes('\u202E'), 'RLO (U+202E) removed from stored filename');
  // ZWSP codepoint U+200B must be absent.
  assert.ok(!storedFilename.includes('\u200B'), 'ZWSP (U+200B) removed from stored filename');
  // Raw LF must be absent (sanitizeForDisplay collapses newlines to a space,
  // then JSON.stringify would escape it anyway, but the key test is no \n in storedFilename).
  assert.ok(!storedFilename.includes('\n'), 'LF removed from stored filename');
}));

// (e) Multi-account (T35-analogue): alice builds INBOX (1 attachment); bob
//     (same state dir) builds INBOX (a DIFFERENT attachment); both rows coexist;
//     alice rebuilds -> bob's row still present (account-scoped filter).
test('AM-e: multi-account -- rebuild of one account does not delete the other\'s rows', withTempStateDir(async () => {
  const src = new FakeSource();

  _setAccountForTests('alice@ya.ru');
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<a1@ya>', from: [{ address: 'sender@example.com', name: 'Sender' }],
      hasAttachments: true,
      attachments: [ att({ filename: 'alice-doc.pdf', partId: '1' }) ],
    }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  _setAccountForTests('bob@ya.ru');
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<b1@ya>', from: [{ address: 'other@example.com', name: 'Other' }],
      hasAttachments: true,
      attachments: [ att({ filename: 'bob-doc.pdf', partId: '1' }) ],
    }),
  ], 200);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // Both rows coexist.
  const rowsAfterBoth = readManifestRows(getIndexDir());
  assert.equal(rowsAfterBoth.length, 2, 'both alice and bob attachment rows coexist');
  const accounts = rowsAfterBoth.map((r: { account: string }) => r.account).sort();
  assert.deepEqual(accounts, ['alice@ya.ru', 'bob@ya.ru']);

  // Alice rebuilds her INBOX -- bob's row must survive.
  _setAccountForTests('alice@ya.ru');
  src.setFolder('INBOX', [
    hdr({ uid: 2, messageId: '<a2@ya>', from: [{ address: 'sender@example.com', name: 'Sender' }],
      hasAttachments: true,
      attachments: [ att({ filename: 'alice-doc-v2.pdf', partId: '1' }) ],
    }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const rowsAfterRebuild = readManifestRows(getIndexDir());
  // Should now have alice's new row + bob's original row = 2 rows.
  assert.equal(rowsAfterRebuild.length, 2, 'bob\'s row still present after alice rebuild');
  const bobRows = rowsAfterRebuild.filter((r: { account: string }) => r.account === 'bob@ya.ru');
  assert.equal(bobRows.length, 1, 'exactly one bob row');
  assert.equal(bobRows[0].filename, 'bob-doc.pdf', 'bob\'s filename unchanged');
  const aliceRows = rowsAfterRebuild.filter((r: { account: string }) => r.account === 'alice@ya.ru');
  assert.equal(aliceRows.length, 1, 'alice has exactly one row after rebuild');
  assert.equal(aliceRows[0].filename, 'alice-doc-v2.pdf', 'alice row updated to v2');
}));

// (f) Per-folder failure (failOn): build INBOX+Sent each with an attachment,
//     then update with Sent failing and a new INBOX attachment ->
//     Sent's prior rows untouched, INBOX's new row present.
test('AM-f: per-folder failure leaves failed folder\'s prior rows untouched', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<i1@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'inbox-att.pdf', partId: '1' }) ],
    }),
  ], 100, 2);
  src.setFolder('Sent', [
    hdr({ uid: 10, messageId: '<s1@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'sent-att.pdf', partId: '1' }) ],
    }),
  ], 200, 11);

  await buildIndex(['INBOX', 'Sent'], src);
  _resetForTests();

  const rowsBefore = readManifestRows(getIndexDir());
  assert.equal(rowsBefore.length, 2, 'precondition: both INBOX and Sent attachment rows');

  // Now Sent fails; INBOX gets a new attachment.
  src.failOn('Sent');
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<i1@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'inbox-att.pdf', partId: '1' }) ],
    }),
    hdr({ uid: 2, messageId: '<i2@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'inbox-new.pdf', partId: '1', size: 777 }) ],
    }),
  ], 100, 3);

  const res = await updateIndex(['INBOX', 'Sent'], src);
  assert.equal(res.errors.length, 1, 'Sent error surfaced');
  assert.equal(res.errors[0].folder, 'Sent');
  _resetForTests();

  const rowsAfter = readManifestRows(getIndexDir());
  // INBOX: inbox-att.pdf (prior) + inbox-new.pdf (new via append) = 2 INBOX rows.
  // Sent: sent-att.pdf (prior, untouched because Sent failed) = 1 Sent row.
  assert.equal(rowsAfter.length, 3, '2 INBOX rows + 1 Sent row (Sent prior rows untouched)');
  const sentRows = rowsAfter.filter((r: { folder: string }) => r.folder === 'Sent');
  assert.equal(sentRows.length, 1, 'Sent prior rows preserved despite failure');
  assert.equal(sentRows[0].filename, 'sent-att.pdf');
  const inboxNewRows = rowsAfter.filter((r: { filename: string }) => r.filename === 'inbox-new.pdf');
  assert.equal(inboxNewRows.length, 1, 'new INBOX attachment appeared');
}));

// (g) Minimal fixture: an attachment with size omitted reloads with size===0
//     and the md5 key present as null.
test('AM-g: minimal fixture -- size undefined stored as 0; md5 key always present as null', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<min@ex>', hasAttachments: true,
      attachments: [
        // Construct attachment directly (bypassing att() helper defaults) so we
        // can supply the undefined size that tests the Number.isFinite backstop.
        {
          filename: 'minimal.txt',
          mimeType: 'text/plain',
          size: undefined as unknown as number,  // non-finite -> backstopped to 0
          partId: '2',
          md5: null,
        },
      ],
    }),
  ], 100);

  await buildIndex(['INBOX'], src);
  _resetForTests();

  const rows = readManifestRows(getIndexDir());
  assert.equal(rows.length, 1);
  const row = rows[0];

  assert.equal(row.size, 0, 'size backstop: undefined/non-finite stored as 0');
  assert.ok('md5' in row, 'md5 key always present in the row');
  assert.equal(row.md5, null, 'md5 is null when absent');
  assert.equal(row.filename, 'minimal.txt');
  assert.equal(row.partId, '2');
}));

// (h) Additional shape validation: AttachmentRecord carries all LD-7 fields
//     including denormalized date/fromEmail/fromName/subject.
test('AM-h: AttachmentRecord shape -- all LD-7 fields present including denormalized envelope', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({
      uid: 42,
      messageId: '<shape@example.com>',
      from: [{ address: 'Sender@Example.COM', name: 'The Sender' }],
      subject: 'Quarterly Report',
      date: '2026-01-15T09:00:00.000Z',
      hasAttachments: true,
      attachments: [
        att({ filename: 'Договор.pdf', mimeType: 'application/pdf', size: 4200, partId: '1.1', md5: null }),
      ],
    }),
  ], 100);

  await buildIndex(['INBOX'], src);
  _resetForTests();

  const rows = readManifestRows(getIndexDir());
  assert.equal(rows.length, 1);
  const r = rows[0];

  // Identity prefix.
  assert.equal(typeof r.account, 'string', 'account present');
  assert.equal(r.folder, 'INBOX');
  assert.equal(r.uid, 42);
  assert.equal(r.messageId, '<shape@example.com>');

  // Denormalized envelope (MR-2).
  assert.equal(r.date, '2026-01-15T09:00:00.000Z');
  assert.equal(r.fromEmail, 'sender@example.com', 'fromEmail lowercased');
  assert.equal(r.fromName, 'The Sender');
  assert.equal(r.subject, 'Quarterly Report');

  // Attachment payload.
  // 'Договор.pdf' = 'Договор.pdf' (Cyrillic -- must pass unchanged).
  assert.equal(r.filename, 'Договор.pdf', 'Cyrillic filename preserved');
  assert.equal(r.mimeType, 'application/pdf');
  assert.equal(r.size, 4200);
  assert.equal(r.partId, '1.1');
  assert.ok('md5' in r);
  assert.equal(r.md5, null);

  // sha256 MUST NOT be present (LD-7 / MR-1).
  assert.ok(!('sha256' in r), 'sha256 absent from AttachmentRecord');
}));

// (i) Crash self-heal: an orphan manifest row left by a prior run that crashed
//     between rewriteAttachments (MR-4 manifest-first) and rewriteEnvelopes/persistMeta
//     must NOT be duplicated when the append path re-streams the same uid. The append
//     path must self-heal like buildIndex (manifest-side dedup on account|folder|uid|partId).
test('AM-i: updateIndex append self-heals a crashed-run manifest orphan (no duplicate row)', withTempStateDir(async () => {
  const src = new FakeSource();
  // cursor uidNext=2 -> buildIndex stamps meta uidNext=2, count=1 (the crashed-run meta state).
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<m1@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'first.pdf', partId: '1' }) ],
    }),
  ], 100, 2);

  await buildIndex(['INBOX'], src);
  _resetForTests();

  // Simulate the crash: a prior append already wrote uid 2's attachment row to the
  // manifest, then crashed before rewriteEnvelopes/persistMeta -- so the envelope and
  // meta were never advanced. Inject the orphan row directly (clone base for a matching
  // account so the dedup key aligns with what updateIndex will compute).
  const dir = getIndexDir();
  const manifestPath = path.join(dir, 'attachments.jsonl');
  const base = JSON.parse(fs.readFileSync(manifestPath, 'utf-8').split('\n').filter(l => l.trim())[0]);
  const orphan = { ...base, uid: 2, messageId: '<m2@ex>', filename: 'second.pdf', partId: '1', size: 9999 };
  fs.appendFileSync(manifestPath, JSON.stringify(orphan) + '\n');
  assert.equal(readManifestRows(dir).length, 2, 'precondition: uid-1 row + injected uid-2 orphan');

  // The server now genuinely has uid 2 (uidNext -> 3); the append path re-streams uid 2
  // because stored.uidNext is still 2 (meta never advanced in the crashed run).
  src.setFolder('INBOX', [
    hdr({ uid: 1, messageId: '<m1@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'first.pdf', partId: '1' }) ],
    }),
    hdr({ uid: 2, messageId: '<m2@ex>', hasAttachments: true,
      attachments: [ att({ filename: 'second.pdf', partId: '1', size: 9999 }) ],
    }),
  ], 100, 3);

  const res = await updateIndex(['INBOX'], src);
  assert.equal(res.errors.length, 0, 'no errors on the self-heal append');
  _resetForTests();

  const rows = readManifestRows(dir);
  const uid2Rows = rows.filter((r: { uid: number }) => r.uid === 2);
  assert.equal(uid2Rows.length, 1, 'uid 2 has exactly ONE manifest row -- the crashed orphan was NOT duplicated');
  assert.equal(rows.length, 2, 'total 2 rows: uid 1 + the single (deduped) uid 2');
}));
