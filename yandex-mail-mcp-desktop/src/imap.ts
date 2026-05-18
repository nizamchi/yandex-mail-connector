import { ImapFlow, type FetchMessageObject, type MailboxObject, type ListResponse } from 'imapflow';
import { simpleParser } from 'mailparser';
import type { Credentials } from './token.js';

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

async function withClient<T>(creds: Credentials, fn: (c: ImapFlow) => Promise<T>): Promise<T> {
  const c = makeClient(creds);
  try {
    await c.connect();
    return await fn(c);
  } finally {
    await c.logout().catch(() => {});
  }
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

export async function listFolders(creds: Credentials): Promise<Folder[]> {
  return withClient(creds, async c => {
    const list = await c.list();
    return list.map((item: { path: string; name: string; specialUse?: string; flags?: Set<string> }) => ({
      path: item.path,
      name: item.name,
      specialUse: item.specialUse,
      flags: Array.from(item.flags ?? []),
    }));
  });
}

export async function folderStatus(creds: Credentials, folder: string) {
  return withClient(creds, async c => {
    const s = await c.status(folder, { messages: true, unseen: true });
    return { folder, messageCount: s.messages ?? 0, unseenCount: s.unseen ?? 0 };
  });
}

export async function listEmails(
  creds: Credentials, folder: string, page: number, pageSize: number
) {
  return withClient(creds, async c => {
    const mbox: MailboxObject = await c.mailboxOpen(folder, { readOnly: true });
    const total = mbox.exists ?? 0;
    if (!total) return { folder, total: 0, page, pageSize, hasMore: false, emails: [] as EmailHeader[] };

    // Guard: requested page is beyond the available messages
    if ((page - 1) * pageSize >= total) {
      return { folder, total, page, pageSize, hasMore: false, emails: [] as EmailHeader[] };
    }

    const lastSeq = total;
    const lastInPage  = Math.max(1, lastSeq - (page - 1) * pageSize);
    const firstInPage = Math.max(1, lastInPage - pageSize + 1);
    if (firstInPage > lastInPage) return { folder, total, page, pageSize, hasMore: false, emails: [] as EmailHeader[] };

    const emails: EmailHeader[] = [];
    for await (const msg of c.fetch(`${firstInPage}:${lastInPage}`, { uid: true, flags: true, envelope: true, size: true })) {
      emails.push(parseHeader(msg));
    }
    emails.reverse();
    return { folder, total, page, pageSize, hasMore: firstInPage > 1, emails };
  });
}

export async function getEmail(creds: Credentials, folder: string, uid: number): Promise<EmailMessage | null> {
  return withClient(creds, async c => {
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

    let textBody = parsed.text ?? undefined;
    let htmlBody  = (parsed.html === false ? undefined : parsed.html) ?? undefined;
    let truncated = false;
    if (textBody && textBody.length > MAX_BODY_CHARS) { textBody = textBody.slice(0, MAX_BODY_CHARS) + '\n[обрезано]'; truncated = true; }
    if (htmlBody  && htmlBody.length  > MAX_BODY_CHARS) { htmlBody  = htmlBody.slice(0, MAX_BODY_CHARS)  + '<!-- truncated -->'; truncated = true; }

    return { ...hdr, hasAttachments: attachments.length > 0, textBody, htmlBody, attachments, truncated };
  });
}

export async function searchEmails(
  creds: Credentials,
  folder: string,
  query: Record<string, unknown>,
  maxResults: number
): Promise<EmailHeader[]> {
  return withClient(creds, async c => {
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

export async function moveEmail(creds: Credentials, folder: string, uid: number, target: string) {
  await withClient(creds, async c => {
    await c.mailboxOpen(folder);
    await c.messageMove(String(uid), target, { uid: true });
  });
}

export async function deleteEmail(creds: Credentials, folder: string, uid: number, permanent: boolean) {
  await withClient(creds, async c => {
    await c.mailboxOpen(folder);
    if (permanent) {
      await c.messageDelete(String(uid), { uid: true });
    } else {
      const trash = await resolveSpecialFolder(c, '\\Trash');
      await c.messageMove(String(uid), trash, { uid: true });
    }
  });
}

export async function markEmail(creds: Credentials, folder: string, uid: number, seen?: boolean, flagged?: boolean) {
  await withClient(creds, async c => {
    await c.mailboxOpen(folder);
    if (seen === true)    await c.messageFlagsAdd   (String(uid), ['\\Seen'],    { uid: true });
    if (seen === false)   await c.messageFlagsRemove(String(uid), ['\\Seen'],    { uid: true });
    if (flagged === true) await c.messageFlagsAdd   (String(uid), ['\\Flagged'], { uid: true });
    if (flagged === false)await c.messageFlagsRemove(String(uid), ['\\Flagged'], { uid: true });
  });
}

export async function getSpecialFolders(creds: Credentials): Promise<{
  inbox: string; sent: string; drafts: string; trash: string; spam: string;
}> {
  return withClient(creds, async c => {
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
