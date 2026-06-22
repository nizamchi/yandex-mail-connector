import { ImapFlow, type FetchMessageObject, type ListResponse } from 'imapflow';
import { simpleParser } from 'mailparser';
import { loadCredentials, type Credentials } from './token.js';
import { extractAttachments, type ParsedAttachment } from './attachment-parser.js';

// ── Constants ──────────────────────────────────────────────
const IMAP_HOST = 'imap.yandex.com';
const IMAP_PORT = 993;
const MAX_BODY_CHARS = 8000;

// ── Types ──────────────────────────────────────────────────

export interface EmailAddress { name?: string; address: string; }

export interface EmailHeader {
  uid: number;
  messageId: string;
  // Message-ID of the parent message (In-Reply-To header). Present in the IMAP
  // envelope already, so capturing it costs no extra fetch. Optional: older
  // index records predate this field.
  inReplyTo?: string;
  from: EmailAddress[];
  to: EmailAddress[];
  cc: EmailAddress[];
  subject: string;
  date: string;
  seen: boolean;
  flagged: boolean;
  hasAttachments: boolean;
  // Attachment metadata extracted from BODYSTRUCTURE. Only populated on the
  // streamEnvelopes path (bodyStructure:true is fetched there). Undefined on
  // the 4 other fetch paths (listEmails, getEmail, findSenders, searchEmails).
  attachments?: ParsedAttachment[];
  size: number;
}

// getEmail's full-message shape. It carries its OWN attachments representation —
// derived from simpleParser (filename/contentType/size) on the full-body path —
// which is deliberately distinct from EmailHeader's BODYSTRUCTURE ParsedAttachment[]
// (mimeType/partId/md5, index path). Omit the inherited field so the two
// representations don't collide (TS2430).
export interface EmailMessage extends Omit<EmailHeader, 'attachments'> {
  textBody?: string;
  htmlBody?: string;
  attachments: { filename: string; contentType: string; size: number }[];
  truncated: boolean;
}

export interface Folder {
  path: string;
  name: string;
  specialUse?: string;
  flags: string[];
}

// ── IMAP client factory ────────────────────────────────────

function makeClient(creds: Credentials): ImapFlow {
  return new ImapFlow({
    host: creds.imapHost ?? IMAP_HOST,
    port: IMAP_PORT,
    secure: true,
    auth: creds.password
      ? { user: creds.email, pass: creds.password }
      : { user: creds.email, accessToken: creds.oauthToken! },
    logger: false,
  });
}

// ── Hook 4: ConnectionManager (see ARCHITECTURE-NOTES.md §Hook 4) ──
//
// Wraps the per-call connect/logout pattern in a class so future layers can
// add long-lived (L7 IDLE) and pooled (L2/L3 batch) variants without touching
// any of the call sites in this file or in tools.ts.

export class ConnectionManager {
  constructor(private creds: Credentials) {}

  async withClient<T>(fn: (c: ImapFlow) => Promise<T>): Promise<T> {
    const c = makeClient(this.creds);
    try {
      await c.connect();
      return await fn(c);
    } finally {
      await c.logout().catch(() => {});
    }
  }

  // future hooks (NOT in Phase 1):
  //   withIdleClient<T>(...)   — long-lived connection for L7 wait_for_email
  //   withPooledClient<T>(...) — pooled re-use for L2/L3 batch (index build, manifest)
}

let _connectionManager: ConnectionManager | null = null;
export function getConnectionManager(): ConnectionManager {
  if (!_connectionManager) {
    _connectionManager = new ConnectionManager(loadCredentials());
  }
  return _connectionManager;
}

// Legacy top-level shim — delegates to singleton.
// Signature changed: was (creds, fn), now (fn). No external caller uses this
// directly (tools.ts goes through public exports listFolders/getEmail/etc.).
export async function withClient<T>(fn: (c: ImapFlow) => Promise<T>): Promise<T> {
  return getConnectionManager().withClient(fn);
}

// ── Helpers ────────────────────────────────────────────────

// Yandex uses Russian folder names on Russian-locale accounts (e.g. "Удалённые").
// The only reliable way to find special folders is via IMAP LIST specialUse flags.
const FALLBACK_FOLDERS: Record<string, string> = {
  '\\Trash':  'Trash',
  '\\Sent':   'Sent',
  '\\Drafts': 'Drafts',
  '\\Junk':   'Spam',
};

type SpecialUseFlag = '\\Trash' | '\\Sent' | '\\Drafts' | '\\Junk';

function pickSpecialFolder(list: ListResponse[], flag: SpecialUseFlag): string {
  return list.find(f => f.specialUse === flag)?.path ?? FALLBACK_FOLDERS[flag];
}

async function resolveSpecialFolder(c: ImapFlow, flag: SpecialUseFlag): Promise<string> {
  return pickSpecialFolder(await c.list(), flag);
}

function toAddrs(list?: Array<{ name?: string; address?: string }>): EmailAddress[] {
  return (list ?? []).map(a => ({ name: a.name ?? undefined, address: a.address ?? '' })).filter(a => a.address);
}

function parseHeader(msg: FetchMessageObject): EmailHeader {
  const e = msg.envelope;
  const { attachments } = extractAttachments(msg);
  return {
    uid: msg.uid,
    messageId: e?.messageId ?? '',
    inReplyTo: e?.inReplyTo ?? '',
    from: toAddrs(e?.from),
    to: toAddrs(e?.to),
    cc: toAddrs(e?.cc),
    subject: e?.subject ?? '(no subject)',
    date: e?.date?.toISOString() ?? '',
    seen: msg.flags?.has('\\Seen') ?? false,
    flagged: msg.flags?.has('\\Flagged') ?? false,
    hasAttachments: attachments.length > 0,
    attachments,
    size: msg.size ?? 0,
  };
}

// ── Public API ─────────────────────────────────────────────
// Creds are no longer threaded as args — every handler routes through the
// ConnectionManager singleton which holds the resolved Credentials. Tools.ts
// calls these directly without per-invocation token.json re-reads (WR-02).

export async function listFolders(): Promise<Folder[]> {
  return getConnectionManager().withClient(async c => {
    const list = await c.list();
    return list.map((item: { path: string; name: string; specialUse?: string; flags?: Set<string> }) => ({
      path: item.path,
      name: item.name,
      specialUse: item.specialUse,
      flags: Array.from(item.flags ?? []),
    }));
  });
}

export async function folderStatus(folder: string) {
  return getConnectionManager().withClient(async c => {
    const s = await c.status(folder, { messages: true, unseen: true });
    return { folder, messageCount: s.messages ?? 0, unseenCount: s.unseen ?? 0 };
  });
}

// countEmails -- returns the count of messages matching an IMAP search query.
// Cheaper than searchEmails: no fetch, just the UID list length.
export async function countEmails(
  folder: string,
  query: Record<string, unknown>,
): Promise<number> {
  return getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder, { readOnly: true });
    const uids = await c.search(query, { uid: true });
    return Array.isArray(uids) ? uids.length : 0;
  });
}

export interface FolderPeekResult {
  folder: string;
  total?: number;
  unseen?: number;
  error?: string;
}

// folderPeek -- batch c.status() across multiple folders in a single connection.
// Cheaper than N separate folderStatus() calls (one connect vs N).
export async function folderPeek(folders: string[]): Promise<FolderPeekResult[]> {
  return getConnectionManager().withClient(async c => {
    const results: FolderPeekResult[] = [];
    for (const folder of folders) {
      try {
        const s = await c.status(folder, { messages: true, unseen: true });
        results.push({ folder, total: s.messages ?? 0, unseen: s.unseen ?? 0 });
      } catch (e) {
        results.push({ folder, error: e instanceof Error ? e.message : String(e) });
      }
    }
    return results;
  });
}

export async function listEmails(
  folder: string, page: number, pageSize: number
) {
  return getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder, { readOnly: true });

    // BUG-01 (T-02-05): UID-based pagination — стабильно при удалении писем
    // между страницами. Пустой SearchObject == ALL (verified в imap-flow.d.ts).
    const searchResult = await c.search({}, { uid: true });
    const uids: number[] = Array.isArray(searchResult) ? searchResult : [];
    const total = uids.length;
    if (!total) {
      return { folder, total: 0, page, pageSize, hasMore: false, emails: [] as EmailHeader[] };
    }
    if ((page - 1) * pageSize >= total) {
      return { folder, total, page, pageSize, hasMore: false, emails: [] as EmailHeader[] };
    }

    // UIDs приходят отсортированы по возрастанию; нам нужны свежие первыми.
    const sortedDesc = uids.slice().sort((a, b) => b - a);
    const start = (page - 1) * pageSize;
    const end = Math.min(start + pageSize, total);
    const pageUids = sortedDesc.slice(start, end);

    const emails: EmailHeader[] = [];
    for await (const msg of c.fetch(pageUids, { uid: true, flags: true, envelope: true, size: true }, { uid: true })) {
      emails.push(parseHeader(msg));
    }
    // ImapFlow не гарантирует порядок итерации внутри fetch — досортировать.
    emails.sort((a, b) => b.uid - a.uid);
    return { folder, total, page, pageSize, hasMore: end < total, emails };
  });
}

export async function getEmail(folder: string, uid: number): Promise<EmailMessage | null> {
  return getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder, { readOnly: true });
    let raw: Buffer | null = null;
    let hdr: EmailHeader | null = null;
    for await (const msg of c.fetch(String(uid), { uid: true, flags: true, envelope: true, size: true, source: true }, { uid: true })) {
      hdr = parseHeader(msg);
      raw = msg.source ?? null;
    }
    if (!raw || !hdr) return null;

    const parsed = await simpleParser(raw);
    const attachments = (parsed.attachments ?? []).map(
      (a: { filename?: string; contentType?: string; size?: number }) => ({
        filename: a.filename ?? 'attachment',
        contentType: a.contentType ?? 'application/octet-stream',
        size: a.size ?? 0,
      }),
    );

    // SEC-04 (T-02-02): text-first body extraction. mailparser автоматически
    // конвертирует HTML→text (strip tags, drop scripts, collapse hidden CSS).
    // По умолчанию HTML НЕ возвращается в MCP output — opt-in через env.
    const stripHtml = process.env.YANDEX_STRIP_HTML !== 'false';
    let textBody: string | undefined = parsed.text ?? undefined;
    let htmlBody: string | undefined = undefined;
    let truncated = false;

    if (!stripHtml) {
      htmlBody = (parsed.html === false ? undefined : parsed.html) ?? undefined;
      if (htmlBody && htmlBody.length > MAX_BODY_CHARS) {
        htmlBody = htmlBody.slice(0, MAX_BODY_CHARS) + '<!-- truncated -->';
        truncated = true;
      }
    }

    // HTML-only письмо без текстовой части и при включённом strip:
    // показать explicit placeholder вместо пустого body (UX guard).
    if (!textBody && stripHtml && parsed.html) {
      textBody = '(HTML-only message; HTML body stripped — set YANDEX_STRIP_HTML=false to opt in)';
    }

    if (textBody && textBody.length > MAX_BODY_CHARS) {
      textBody = textBody.slice(0, MAX_BODY_CHARS) + '\n[обрезано]';
      truncated = true;
    }

    return { ...hdr, hasAttachments: attachments.length > 0, textBody, htmlBody, attachments, truncated };
  });
}

// getAttachmentBytes -- fetch one attachment from a message by UID.
//
// Reuses getEmail's exact fetch pattern (source:true + simpleParser) but only
// retrieves the single uid needed and does NOT modify getEmail. Returns the
// raw bytes of ONE attachment or null when the message / attachment is absent.
//
// Selector:
//   index    — 0-based index into parsed.attachments (matches yandex_get_email order).
//   filename — match by exact filename first, then case-insensitive substring.
//   If both are provided, index takes precedence.
//
// Returns null (not throws) when the message is absent or the attachment does
// not exist so callers can produce a friendly not-found result.
export async function getAttachmentBytes(
  folder: string,
  uid: number,
  selector: { index?: number; filename?: string },
): Promise<{ content: Buffer; filename: string | null; contentType: string; size: number } | null> {
  return getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder, { readOnly: true });
    let raw: Buffer | null = null;
    for await (const msg of c.fetch(String(uid), { uid: true, source: true }, { uid: true })) {
      raw = (msg as { source?: Buffer }).source ?? null;
    }
    if (!raw) return null;

    const parsed = await simpleParser(raw);
    const attachments: Array<{ content?: Buffer; filename?: string; contentType?: string; size?: number }> =
      (parsed.attachments ?? []) as Array<{ content?: Buffer; filename?: string; contentType?: string; size?: number }>;

    if (attachments.length === 0) return null;

    let att: { content?: Buffer; filename?: string; contentType?: string; size?: number } | undefined;

    if (typeof selector.index === 'number') {
      att = attachments[selector.index];
    } else if (selector.filename) {
      const needle = selector.filename;
      // Exact match first, then case-insensitive substring.
      att = attachments.find(a => a.filename === needle)
        ?? attachments.find(a => typeof a.filename === 'string' && a.filename.toLowerCase().includes(needle.toLowerCase()));
    } else {
      // Default to first attachment if no selector given.
      att = attachments[0];
    }

    if (!att) return null;
    const content = att.content;
    if (!content) return null;

    return {
      content,
      filename: att.filename ?? null,
      contentType: att.contentType ?? 'application/octet-stream',
      size: content.length,
    };
  });
}

// streamEnvelopes -- bounded-memory async generator over a folder's envelopes.
// Yields per envelope (not per batch) so the consumer can short-circuit. UIDs
// are fetched in chunks of CHUNK_SIZE to bound the imapflow internal buffer;
// each chunk's envelopes are emitted as they parse, then the chunk is dropped.
//
// since/until are inclusive ISO dates; the filter runs per-envelope after the
// fetch because IMAP UID order is not date-sorted (we'd have to fetch envelope
// before we know whether to keep it). For mailboxes that need a cheaper filter
// the caller can use c.search({since, before}) -- but that's a different
// trade-off (extra round trip vs. extra parse) and v2.3.0 ships the simpler
// per-envelope filter.
//
// BODYSTRUCTURE is captured on this fetch (one BODYSTRUCTURE atom in the same
// FETCH command, zero extra round-trips, zero body bytes). hasAttachments is
// therefore real on this path -- derived by extractAttachments() in parseHeader.
export async function* streamEnvelopes(
  folder: string,
  since?: string,
  until?: string,
  opts?: { minUid?: number },
): AsyncGenerator<EmailHeader, void, void> {
  const CHUNK_SIZE = 1000;
  const sinceMs = since ? new Date(since).getTime() : null;
  const untilMs = until ? new Date(until).getTime() : null;
  if (sinceMs !== null && isNaN(sinceMs)) throw new Error('invalid since date: ' + since);
  if (untilMs !== null && isNaN(untilMs)) throw new Error('invalid until date: ' + until);
  // Layer 2 index incremental sync: when minUid is given, fetch only UIDs >=
  // minUid via an IMAP UID-range search instead of scanning the whole folder.
  const minUid = opts?.minUid;

  // We need the connection open for the lifetime of the iteration, so we
  // can't use ConnectionManager.withClient (which logs out on Promise
  // resolution). Reuse the same makeClient + try/finally pattern manually so
  // the connection is opened lazily on first iteration and closed on
  // generator return/throw. Memory cost: O(CHUNK_SIZE) envelopes in flight,
  // not O(folder size).
  const c = makeClient(loadCredentials());
  await c.connect();
  try {
    await c.mailboxOpen(folder, { readOnly: true });
    const searchQuery = minUid && minUid > 1 ? { uid: `${minUid}:*` } : {};
    const searchResult = await c.search(searchQuery, { uid: true });
    const uids: number[] = Array.isArray(searchResult) ? searchResult : [];
    for (let i = 0; i < uids.length; i += CHUNK_SIZE) {
      const chunk = uids.slice(i, i + CHUNK_SIZE);
      if (chunk.length === 0) continue;
      for await (const msg of c.fetch(chunk, { uid: true, envelope: true, flags: true, size: true, bodyStructure: true }, { uid: true })) {
        const hdr = parseHeader(msg);
        // Per-envelope date filter: IMAP UID order is not date-sorted, so we
        // must check each envelope. Envelopes with no date pass through and
        // are bucketed as <unknown> downstream when the aggregator runs a
        // date-based group_by.
        const ts = hdr.date ? new Date(hdr.date).getTime() : NaN;
        if (sinceMs !== null && !isNaN(ts) && ts < sinceMs) continue;
        if (untilMs !== null && !isNaN(ts) && ts > untilMs) continue;
        yield hdr;
      }
    }
  } finally {
    await c.logout().catch(() => {});
  }
}

// getMailboxCursor -- cheap read of a folder's sync cursor for the Layer 2
// index. uidValidity changes when the server renumbers UIDs (rare); when it
// changes the index for this folder must be rebuilt from scratch. uidNext is
// the UID the next delivered message will get, so it is the high-water mark:
// the next incremental sync fetches `${storedUidNext}:*`.
export async function getMailboxCursor(
  folder: string,
): Promise<{ uidValidity: number; uidNext: number; exists: number }> {
  return getConnectionManager().withClient(async c => {
    const mbox = await c.mailboxOpen(folder, { readOnly: true });
    return {
      uidValidity: Number(mbox.uidValidity),
      uidNext: Number(mbox.uidNext),
      exists: Number(mbox.exists),
    };
  });
}

export interface SenderCandidate {
  email: string;
  displayName: string;   // last seen display name for this address
  count: number;
  lastDate: string;      // ISO date of the most recent matching message
}

// findSenders -- disambiguates a name/partial address before a deep search.
//
// Uses IMAP SEARCH FROM to pre-filter at the server (substring match across
// both display name and address parts, e.g. "Катя" hits "Катя Иванова"
// <k.ivanova@co.ru> without knowing the address). Returns unique senders
// sorted by message count desc, capped at maxSenders. Typical result is a
// handful of rows (~100 bytes) -- never floods the agent context.
export async function findSenders(
  folder: string,
  query: string,
  maxSenders: number,
): Promise<SenderCandidate[]> {
  return getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder, { readOnly: true });
    // imapflow's search() returns `false` (not []) on no-match or a transient
    // condition. The old `!uids.length` "worked" only by JS coercion luck
    // (false.length === undefined); normalize to an array so the type is honest
    // and the fetch below can never receive `false`.
    const uids = (await c.search({ from: query }, { uid: true })) || [];
    if (uids.length === 0) return [];

    const map = new Map<string, SenderCandidate>();
    for await (const msg of c.fetch(uids, { uid: true, envelope: true }, { uid: true })) {
      const hdr = parseHeader(msg);
      const addr = hdr.from[0];
      if (!addr) continue;
      const key = addr.address.toLowerCase();
      const existing = map.get(key);
      if (existing) {
        existing.count++;
        if (hdr.date && hdr.date > existing.lastDate) {
          existing.lastDate = hdr.date;
          if (addr.name) existing.displayName = addr.name;
        }
      } else {
        map.set(key, {
          email: addr.address,
          displayName: addr.name ?? '',
          count: 1,
          lastDate: hdr.date ?? '',
        });
      }
    }

    return [...map.values()]
      .sort((a, b) => b.count - a.count || a.email.localeCompare(b.email))
      .slice(0, maxSenders);
  });
}

export async function searchEmails(
  folder: string,
  query: Record<string, unknown>,
  maxResults: number
): Promise<EmailHeader[]> {
  return getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder, { readOnly: true });
    // See findSenders: search() may return `false`; normalize to an array.
    const uids = (await c.search(query, { uid: true })) || [];
    if (uids.length === 0) return [];
    const slice = uids.slice(-maxResults).reverse();
    const emails: EmailHeader[] = [];
    for await (const msg of c.fetch(slice.join(','), { uid: true, flags: true, envelope: true, size: true }, { uid: true })) {
      emails.push(parseHeader(msg));
    }
    return emails.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  });
}

export async function moveEmail(folder: string, uid: number, target: string) {
  await getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder);
    await c.messageMove(String(uid), target, { uid: true });
  });
}

export async function deleteEmail(folder: string, uid: number, permanent: boolean) {
  await getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder);
    if (permanent) {
      await c.messageDelete(String(uid), { uid: true });
    } else {
      const trash = await resolveSpecialFolder(c, '\\Trash');
      await c.messageMove(String(uid), trash, { uid: true });
    }
  });
}

export async function markEmail(folder: string, uid: number, seen?: boolean, flagged?: boolean) {
  await getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder);
    if (seen === true)    await c.messageFlagsAdd   (String(uid), ['\\Seen'],    { uid: true });
    if (seen === false)   await c.messageFlagsRemove(String(uid), ['\\Seen'],    { uid: true });
    if (flagged === true) await c.messageFlagsAdd   (String(uid), ['\\Flagged'], { uid: true });
    if (flagged === false)await c.messageFlagsRemove(String(uid), ['\\Flagged'], { uid: true });
  });
}

// findByMessageId — used by Phase 5 in_reply_to auto-trust flow in tools.ts.
// Bounded to INBOX + Sent so we don't fan out across every folder (T-05-13).
// Returns the FROM address of the matching message (lowercased) — that is who
// gets the auto-trust on the reply path, NOT the new recipient (T-05-06).
//
// H-1 fix: also returns a canonical `source` discriminant ('INBOX' | 'Sent')
// so the caller can gate trust elevation on Sent-folder evidence ONLY.
// `folder` keeps the literal mailbox path (cyrillic-safe on RU locales);
// `source` is the policy-level enum the auto-trust block reads.
export type FindByMessageIdSource = 'INBOX' | 'Sent';
export interface FindByMessageIdResult {
  from: string;
  folder: string;
  source: FindByMessageIdSource;
  uid: number;
}
export async function findByMessageId(messageId: string): Promise<FindByMessageIdResult | null> {
  if (!messageId) return null;
  return getConnectionManager().withClient(async c => {
    const list = await c.list();
    const sentPath = pickSpecialFolder(list, '\\Sent');
    // INBOX first, Sent second. Order matters because a message-id is unique
    // per RFC 5322 -- if it shows in both, INBOX wins (sender sent us back
    // our own thread). source is derived from WHICH folder matched.
    const folders: Array<{ path: string; source: FindByMessageIdSource }> = [
      { path: 'INBOX',   source: 'INBOX' },
      { path: sentPath,  source: 'Sent'  },
    ];
    for (const { path: folder, source } of folders) {
      try {
        await c.mailboxOpen(folder, { readOnly: true });
        const uids = await c.search({ header: { 'message-id': messageId } } as Record<string, unknown>, { uid: true });
        if (!Array.isArray(uids) || uids.length === 0) continue;
        const uid = uids[0] as number;
        for await (const msg of c.fetch(String(uid), { uid: true, envelope: true }, { uid: true })) {
          const fromAddr = msg.envelope?.from?.[0]?.address;
          if (fromAddr && typeof fromAddr === 'string') {
            return { from: fromAddr.toLowerCase(), folder, source, uid };
          }
        }
      } catch {
        // Continue to next folder on per-folder errors (eg mailbox absent).
      }
    }
    return null;
  });
}

// Hook-2 helper (Phase 6): fetch only the message-id of a single message
// without pulling source/flags/size. Used by tools.ts move/delete/mark
// handlers BEFORE the mutating IMAP call so audit records carry message_id.
// Returns null if the message is absent or the envelope has no message-id.
// Callers MUST treat failure as non-fatal (the mutation is the user's intent;
// missing message_id only degrades the audit trail to a sentinel value).
export async function getMessageId(folder: string, uid: number): Promise<string | null> {
  return getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder, { readOnly: true });
    const it = c.fetch(String(uid), { uid: true, envelope: true }, { uid: true });
    for await (const msg of it) {
      const mid = msg.envelope?.messageId;
      return (typeof mid === 'string' && mid.length > 0) ? mid : null;
    }
    return null;
  });
}

export async function getSpecialFolders(): Promise<{
  inbox: string; sent: string; drafts: string; trash: string; spam: string;
}> {
  return getConnectionManager().withClient(async c => {
    const list = await c.list();
    return {
      inbox:  'INBOX',
      sent:   pickSpecialFolder(list, '\\Sent'),
      drafts: pickSpecialFolder(list, '\\Drafts'),
      trash:  pickSpecialFolder(list, '\\Trash'),
      spam:   pickSpecialFolder(list, '\\Junk'),
    };
  });
}
