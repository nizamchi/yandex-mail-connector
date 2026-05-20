import { ImapFlow, type FetchMessageObject, type ListResponse } from 'imapflow';
import { simpleParser } from 'mailparser';
import { loadCredentials, type Credentials } from './token.js';

// ── Constants ──────────────────────────────────────────────
const IMAP_HOST = 'imap.yandex.com';
const IMAP_PORT = 993;
const MAX_BODY_CHARS = 8000;

// ── Types ──────────────────────────────────────────────────

export interface EmailAddress { name?: string; address: string; }

export interface EmailHeader {
  uid: number;
  messageId: string;
  from: EmailAddress[];
  to: EmailAddress[];
  cc: EmailAddress[];
  subject: string;
  date: string;
  seen: boolean;
  flagged: boolean;
  hasAttachments: boolean;
  size: number;
}

export interface EmailMessage extends EmailHeader {
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
    auth: { user: creds.email, accessToken: creds.oauthToken },
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
  return {
    uid: msg.uid,
    messageId: e?.messageId ?? '',
    from: toAddrs(e?.from),
    to: toAddrs(e?.to),
    cc: toAddrs(e?.cc),
    subject: e?.subject ?? '(no subject)',
    date: e?.date?.toISOString() ?? '',
    seen: msg.flags?.has('\\Seen') ?? false,
    flagged: msg.flags?.has('\\Flagged') ?? false,
    hasAttachments: false,
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
    const attachments = (parsed.attachments ?? []).map(a => ({
      filename: a.filename ?? 'attachment',
      contentType: a.contentType,
      size: a.size,
    }));

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
    if (!textBody && stripHtml && parsed.html && parsed.html !== false) {
      textBody = '(HTML-only message; HTML body stripped — set YANDEX_STRIP_HTML=false to opt in)';
    }

    if (textBody && textBody.length > MAX_BODY_CHARS) {
      textBody = textBody.slice(0, MAX_BODY_CHARS) + '\n[обрезано]';
      truncated = true;
    }

    return { ...hdr, hasAttachments: attachments.length > 0, textBody, htmlBody, attachments, truncated };
  });
}

export async function searchEmails(
  folder: string,
  query: Record<string, unknown>,
  maxResults: number
): Promise<EmailHeader[]> {
  return getConnectionManager().withClient(async c => {
    await c.mailboxOpen(folder, { readOnly: true });
    const uids = await c.search(query, { uid: true });
    if (!uids.length) return [];
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
