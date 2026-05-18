"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var imap_exports = {};
__export(imap_exports, {
  deleteEmail: () => deleteEmail,
  folderStatus: () => folderStatus,
  getEmail: () => getEmail,
  getSpecialFolders: () => getSpecialFolders,
  listEmails: () => listEmails,
  listFolders: () => listFolders,
  markEmail: () => markEmail,
  moveEmail: () => moveEmail,
  searchEmails: () => searchEmails
});
module.exports = __toCommonJS(imap_exports);
var import_imapflow = require("imapflow");
var import_mailparser = require("mailparser");
const IMAP_HOST = "imap.yandex.com";
const IMAP_PORT = 993;
const MAX_BODY_CHARS = 8e3;
function makeClient(creds) {
  return new import_imapflow.ImapFlow({
    host: creds.imapHost ?? IMAP_HOST,
    port: IMAP_PORT,
    secure: true,
    auth: { user: creds.email, accessToken: creds.oauthToken },
    logger: false
  });
}
async function withClient(creds, fn) {
  const c = makeClient(creds);
  try {
    await c.connect();
    return await fn(c);
  } finally {
    await c.logout().catch(() => {
    });
  }
}
const FALLBACK_FOLDERS = {
  "\\Trash": "Trash",
  "\\Sent": "Sent",
  "\\Drafts": "Drafts",
  "\\Junk": "Spam"
};
function pickSpecialFolder(list, flag) {
  return list.find((f) => f.specialUse === flag)?.path ?? FALLBACK_FOLDERS[flag];
}
async function resolveSpecialFolder(c, flag) {
  return pickSpecialFolder(await c.list(), flag);
}
function toAddrs(list) {
  return (list ?? []).map((a) => ({ name: a.name ?? void 0, address: a.address ?? "" })).filter((a) => a.address);
}
function parseHeader(msg) {
  const e = msg.envelope;
  return {
    uid: msg.uid,
    messageId: e?.messageId ?? "",
    from: toAddrs(e?.from),
    to: toAddrs(e?.to),
    cc: toAddrs(e?.cc),
    subject: e?.subject ?? "(no subject)",
    date: e?.date?.toISOString() ?? "",
    seen: msg.flags?.has("\\Seen") ?? false,
    flagged: msg.flags?.has("\\Flagged") ?? false,
    hasAttachments: false,
    size: msg.size ?? 0
  };
}
async function listFolders(creds) {
  return withClient(creds, async (c) => {
    const list = await c.list();
    return list.map((item) => ({
      path: item.path,
      name: item.name,
      specialUse: item.specialUse,
      flags: Array.from(item.flags ?? [])
    }));
  });
}
async function folderStatus(creds, folder) {
  return withClient(creds, async (c) => {
    const s = await c.status(folder, { messages: true, unseen: true });
    return { folder, messageCount: s.messages ?? 0, unseenCount: s.unseen ?? 0 };
  });
}
async function listEmails(creds, folder, page, pageSize) {
  return withClient(creds, async (c) => {
    const mbox = await c.mailboxOpen(folder, { readOnly: true });
    const total = mbox.exists ?? 0;
    if (!total) return { folder, total: 0, page, pageSize, hasMore: false, emails: [] };
    if ((page - 1) * pageSize >= total) {
      return { folder, total, page, pageSize, hasMore: false, emails: [] };
    }
    const lastSeq = total;
    const lastInPage = Math.max(1, lastSeq - (page - 1) * pageSize);
    const firstInPage = Math.max(1, lastInPage - pageSize + 1);
    if (firstInPage > lastInPage) return { folder, total, page, pageSize, hasMore: false, emails: [] };
    const emails = [];
    for await (const msg of c.fetch(`${firstInPage}:${lastInPage}`, { uid: true, flags: true, envelope: true, size: true })) {
      emails.push(parseHeader(msg));
    }
    emails.reverse();
    return { folder, total, page, pageSize, hasMore: firstInPage > 1, emails };
  });
}
async function getEmail(creds, folder, uid) {
  return withClient(creds, async (c) => {
    await c.mailboxOpen(folder, { readOnly: true });
    let raw = null;
    let hdr = null;
    for await (const msg of c.fetch(String(uid), { uid: true, flags: true, envelope: true, size: true, source: true }, { uid: true })) {
      hdr = parseHeader(msg);
      raw = msg.source ?? null;
    }
    if (!raw || !hdr) return null;
    const parsed = await (0, import_mailparser.simpleParser)(raw);
    const attachments = (parsed.attachments ?? []).map((a) => ({
      filename: a.filename ?? "attachment",
      contentType: a.contentType,
      size: a.size
    }));
    let textBody = parsed.text ?? void 0;
    let htmlBody = (parsed.html === false ? void 0 : parsed.html) ?? void 0;
    let truncated = false;
    if (textBody && textBody.length > MAX_BODY_CHARS) {
      textBody = textBody.slice(0, MAX_BODY_CHARS) + "\n[\u043E\u0431\u0440\u0435\u0437\u0430\u043D\u043E]";
      truncated = true;
    }
    if (htmlBody && htmlBody.length > MAX_BODY_CHARS) {
      htmlBody = htmlBody.slice(0, MAX_BODY_CHARS) + "<!-- truncated -->";
      truncated = true;
    }
    return { ...hdr, hasAttachments: attachments.length > 0, textBody, htmlBody, attachments, truncated };
  });
}
async function searchEmails(creds, folder, query, maxResults) {
  return withClient(creds, async (c) => {
    await c.mailboxOpen(folder, { readOnly: true });
    const uids = await c.search(query, { uid: true });
    if (!uids.length) return [];
    const slice = uids.slice(-maxResults).reverse();
    const emails = [];
    for await (const msg of c.fetch(slice.join(","), { uid: true, flags: true, envelope: true, size: true }, { uid: true })) {
      emails.push(parseHeader(msg));
    }
    return emails.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  });
}
async function moveEmail(creds, folder, uid, target) {
  await withClient(creds, async (c) => {
    await c.mailboxOpen(folder);
    await c.messageMove(String(uid), target, { uid: true });
  });
}
async function deleteEmail(creds, folder, uid, permanent) {
  await withClient(creds, async (c) => {
    await c.mailboxOpen(folder);
    if (permanent) {
      await c.messageDelete(String(uid), { uid: true });
    } else {
      const trash = await resolveSpecialFolder(c, "\\Trash");
      await c.messageMove(String(uid), trash, { uid: true });
    }
  });
}
async function markEmail(creds, folder, uid, seen, flagged) {
  await withClient(creds, async (c) => {
    await c.mailboxOpen(folder);
    if (seen === true) await c.messageFlagsAdd(String(uid), ["\\Seen"], { uid: true });
    if (seen === false) await c.messageFlagsRemove(String(uid), ["\\Seen"], { uid: true });
    if (flagged === true) await c.messageFlagsAdd(String(uid), ["\\Flagged"], { uid: true });
    if (flagged === false) await c.messageFlagsRemove(String(uid), ["\\Flagged"], { uid: true });
  });
}
async function getSpecialFolders(creds) {
  return withClient(creds, async (c) => {
    const list = await c.list();
    return {
      inbox: "INBOX",
      sent: pickSpecialFolder(list, "\\Sent"),
      drafts: pickSpecialFolder(list, "\\Drafts"),
      trash: pickSpecialFolder(list, "\\Trash"),
      spam: pickSpecialFolder(list, "\\Junk")
    };
  });
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  deleteEmail,
  folderStatus,
  getEmail,
  getSpecialFolders,
  listEmails,
  listFolders,
  markEmail,
  moveEmail,
  searchEmails
});
