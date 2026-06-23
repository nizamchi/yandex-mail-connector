// read-top.test.ts -- unit tests for the read_top one-call recall path
// (v2.11.0): renderUntrustedBody (shared safe-body transform) + resolveReadTop
// (ambiguity / freshness probe / live fallback / 2FA redaction).
//
// resolveReadTop's index reads run against a REAL index built via FakeSource;
// the three LIVE-IMAP functions are injected through ReadTopPorts so the
// decision logic is exercised without a server. Harness mirrors
// find-attachments.test.ts. ASCII-only, no emojis, ESM .js import suffix.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import type { EmailHeader, EmailMessage } from '../imap.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import {
  buildIndex,
  _resetForTests,
  _setAccountForTests,
  type EnvelopeSource,
} from '../mail-index.js';
import {
  renderUntrustedBody,
  resolveReadTop,
  type ReadTopPorts,
} from '../tools.js';
import { loadPolicy, _resetForTests as _resetPolicy } from '../policy.js';

// ── Fixtures ──────────────────────────────────────────────────────────

function hdr(over: Partial<EmailHeader>): EmailHeader {
  return {
    uid: 1,
    messageId: '<m@ex>',
    from: [{ address: 'alice@example.com', name: 'Alice' }],
    to: [{ address: 'you@yandex.ru', name: 'You' }],
    cc: [],
    subject: 'subject',
    date: '2025-06-01T00:00:00.000Z',
    seen: false,
    flagged: false,
    hasAttachments: false,
    size: 1000,
    ...over,
  };
}

function fakeEmail(over: Partial<EmailMessage> = {}): EmailMessage {
  return {
    uid: 5,
    messageId: '<m5@ex>',
    from: [{ address: 'alice@example.com', name: 'Alice' }],
    to: [],
    cc: [],
    subject: 'Latest',
    date: '2025-06-10T00:00:00.000Z',
    seen: false,
    flagged: false,
    hasAttachments: false,
    size: 1000,
    textBody: 'body text',
    htmlBody: undefined,
    attachments: [],
    truncated: false,
    ...over,
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
    return this.cursors.get(folder) ?? { uidValidity: 1, uidNext: 1, exists: 0 };
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

// Injected LIVE-IMAP ports. Defaults: a fresh cursor (uidNext 6 == a one-message
// INBOX), one email, and an empty live search. Override per test.
function mkPorts(over: Partial<ReadTopPorts> = {}): ReadTopPorts {
  return {
    getEmail: async () => fakeEmail(),
    searchEmails: async () => [],
    getMailboxCursor: async () => ({ uidValidity: 100, uidNext: 6, exists: 1 }),
    ...over,
  };
}

function withTempStateDir(fn: () => void | Promise<void>): () => Promise<void> {
  return async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ymc-rt-'));
    const prev = process.env.YANDEX_STATE_DIR;
    process.env.YANDEX_STATE_DIR = dir;
    delete process.env.YANDEX_POLICY_FILE;
    _resetStateDir();
    _resetForTests();
    // readTopBody -> provenance.recordRead reads the loaded policy's window; load
    // the default policy so the 2FA/normal body-read paths don't throw.
    _resetPolicy();
    loadPolicy();
    try {
      await fn();
    } finally {
      if (prev === undefined) delete process.env.YANDEX_STATE_DIR;
      else process.env.YANDEX_STATE_DIR = prev;
      delete process.env.YANDEX_POLICY_FILE;
      _resetStateDir();
      _resetForTests();
      _resetPolicy();
      _setAccountForTests(null);
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  };
}

// ── renderUntrustedBody (shared security transform) ───────────────────

test('RUB-1: non-allowlisted sender gets the untrusted marker + keeps body', withTempStateDir(async () => {
  const out = renderUntrustedBody(fakeEmail({ from: [{ address: 'x@ext.com', name: 'X' }], textBody: 'hello world' }));
  assert.match(out, /UNTRUSTED SENDER: x@ext\.com/, 'marker present for a non-allowlisted sender');
  assert.match(out, /hello world/, 'original body retained');
}));

test('RUB-2: empty body collapses to the placeholder, not a bare string', withTempStateDir(async () => {
  const out = renderUntrustedBody(fakeEmail({ textBody: undefined, htmlBody: undefined }));
  assert.match(out, /\(пусто\)/);
}));

// ── resolveReadTop: decision logic ────────────────────────────────────

test('RT-ok: single sender + fresh index -> reads top, status ok, index_fresh true', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 5, messageId: '<a5@ex>', subject: 'Latest', date: '2025-06-10T00:00:00.000Z' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const ports = mkPorts({
    getMailboxCursor: async () => ({ uidValidity: 100, uidNext: 6, exists: 1 }), // == index uidNext -> fresh
    getEmail: async (folder, uid) => fakeEmail({ uid, subject: 'Latest', textBody: 'the latest message' }),
  });
  const rt = await resolveReadTop('', undefined, { from: 'alice@example.com' }, ports);
  assert.equal(rt.status, 'ok');
  assert.ok(rt.top, 'top block present');
  assert.equal(rt.top!.uid, 5);
  assert.equal(rt.top!.index_fresh, true);
  assert.equal(rt.top!.body_source, 'live_fetch');
  assert.match(rt.top!.body, /the latest message/);
}));

test('RT-ambiguous: from= matched 2 distinct senders -> ambiguous, NO body fetch', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 5, messageId: '<k1@ex>', from: [{ address: 'kate@a-corp.com', name: 'Kate A' }], subject: 'note a', date: '2025-06-01T00:00:00.000Z' }),
    hdr({ uid: 6, messageId: '<k2@ex>', from: [{ address: 'kate@b-corp.com', name: 'Kate B' }], subject: 'note b', date: '2025-06-09T00:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const ports = mkPorts({ getEmail: async () => { throw new Error('read_top must NOT fetch a body when ambiguous'); } });
  const rt = await resolveReadTop('', undefined, { from: 'kate@' }, ports);
  assert.equal(rt.status, 'ambiguous');
  assert.equal(rt.top, undefined);
}));

test('RT-ambiguous-3rd: a distinct sender beyond the top-2 still flags ambiguous', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    hdr({ uid: 5, from: [{ address: 'kate@a-corp.com', name: 'Kate A' }], subject: 'a1', date: '2025-06-08T00:00:00.000Z' }),
    hdr({ uid: 6, from: [{ address: 'kate@a-corp.com', name: 'Kate A' }], subject: 'a2', date: '2025-06-09T00:00:00.000Z' }),
    hdr({ uid: 7, from: [{ address: 'kate@b-corp.com', name: 'Kate B' }], subject: 'b1', date: '2025-01-01T00:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  // top-2 by score/recency are both Kate A; the older Kate B at rank 3 must still
  // be detected as a distinct sender (the old top-2-only gate would have missed it).
  const ports = mkPorts({ getEmail: async () => { throw new Error('must not read when >1 distinct sender matched'); } });
  const rt = await resolveReadTop('', undefined, { from: 'kate@' }, ports);
  assert.equal(rt.status, 'ambiguous');
}));

test('RT-newest-by-date: reads the NEWEST match, not the highest-scored', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [
    // exact subject 'report' -> higher relevance score, but OLDER
    hdr({ uid: 5, messageId: '<r1@ex>', from: [{ address: 'alice@example.com', name: 'Alice' }], subject: 'report', date: '2025-01-01T00:00:00.000Z' }),
    // reply -> lower score, but NEWER
    hdr({ uid: 6, messageId: '<r2@ex>', from: [{ address: 'alice@example.com', name: 'Alice' }], subject: 'Re: report update', date: '2025-06-01T00:00:00.000Z' }),
  ], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const ports = mkPorts({
    getMailboxCursor: async () => ({ uidValidity: 100, uidNext: 7, exists: 2 }), // fresh
    getEmail: async (folder, uid) => fakeEmail({ uid, textBody: `body of ${uid}` }),
  });
  const rt = await resolveReadTop('report', undefined, {}, ports);
  assert.equal(rt.status, 'ok');
  assert.ok(rt.top);
  assert.equal(rt.top!.uid, 6, 'newest-by-date wins over the higher relevance score');
}));

test('RT-uidvalidity: server renumber with no sender target -> stale_fallback, refuses to read', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 5, from: [{ address: 'alice@example.com', name: 'Alice' }], subject: 'x', date: '2025-06-01T00:00:00.000Z' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const ports = mkPorts({
    getMailboxCursor: async () => ({ uidValidity: 999, uidNext: 3, exists: 1 }), // uidValidity CHANGED -> stored uid invalid
    getEmail: async () => { throw new Error('must NOT read a stale uid under a changed uidValidity'); },
  });
  const rt = await resolveReadTop('x', undefined, {}, ports); // text query -> cannot re-resolve by sender
  assert.equal(rt.status, 'stale_fallback');
  assert.equal(rt.top, undefined);
}));

test('RT-stale: live uidNext ahead -> re-resolve live, index_fresh false, stale_fallback', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 5, messageId: '<a5@ex>', subject: 'old top', date: '2025-06-01T00:00:00.000Z' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const ports = mkPorts({
    getMailboxCursor: async () => ({ uidValidity: 100, uidNext: 9, exists: 4 }), // ahead of index uidNext 6 -> stale
    searchEmails: async () => [hdr({ uid: 8, subject: 'truly newest', date: '2025-06-20T00:00:00.000Z' })],
    getEmail: async (folder, uid) => fakeEmail({ uid, subject: 'truly newest', textBody: 'arrived after last sync' }),
  });
  const rt = await resolveReadTop('', undefined, { from: 'alice@example.com' }, ports);
  assert.equal(rt.status, 'stale_fallback');
  assert.ok(rt.top);
  assert.equal(rt.top!.uid, 8, 're-resolved to the live newest, not the stale index top');
  assert.equal(rt.top!.index_fresh, false);
}));

test('RT-fallback: empty index match + from filter -> one live lookup', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, from: [{ address: 'bob@example.com', name: 'Bob' }], subject: 'unrelated' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const ports = mkPorts({
    searchEmails: async () => [hdr({ uid: 3, from: [{ address: 'zoe@example.com', name: 'Zoe' }], subject: 'from live' })],
    getEmail: async (folder, uid) => fakeEmail({ uid, from: [{ address: 'zoe@example.com', name: 'Zoe' }], textBody: 'fetched live' }),
  });
  const rt = await resolveReadTop('', undefined, { from: 'zoe@example.com' }, ports);
  assert.equal(rt.status, 'stale_fallback');
  assert.ok(rt.top);
  assert.equal(rt.top!.uid, 3);
}));

test('RT-no-hits: empty match + no from -> no_hits, NO body fetch', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 1, subject: 'something else' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const ports = mkPorts({ getEmail: async () => { throw new Error('no fallback target -> must not fetch'); } });
  const rt = await resolveReadTop('zzznomatch', undefined, {}, ports);
  assert.equal(rt.status, 'no_hits');
  assert.equal(rt.top, undefined);
}));

test('RT-2fa: a 2FA-sender body is redacted, never leaked', withTempStateDir(async () => {
  const src = new FakeSource();
  src.setFolder('INBOX', [hdr({ uid: 5, messageId: '<s5@ex>', from: [{ address: 'noreply@sberbank.ru', name: 'Sber' }], subject: 'Code', date: '2025-06-10T00:00:00.000Z' })], 100);
  await buildIndex(['INBOX'], src);
  _resetForTests();

  const ports = mkPorts({
    getMailboxCursor: async () => ({ uidValidity: 100, uidNext: 6, exists: 1 }),
    getEmail: async (folder, uid) => fakeEmail({ uid, from: [{ address: 'noreply@sberbank.ru', name: 'Sber' }], subject: 'Code', textBody: 'your one-time code is 1234' }),
  });
  const rt = await resolveReadTop('', undefined, { from: 'sberbank.ru' }, ports);
  assert.equal(rt.status, 'redacted');
  assert.ok(rt.top);
  assert.equal(rt.top!.redacted, true);
  assert.match(rt.top!.body, /REDACTED - 2FA sender/);
  assert.doesNotMatch(rt.top!.body, /1234/, 'the 2FA code must never appear in the body');
}));
