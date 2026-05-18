"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
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
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var tools_exports = {};
__export(tools_exports, {
  registerTools: () => registerTools
});
module.exports = __toCommonJS(tools_exports);
var import_zod = require("zod");
var import_token = require("./token.js");
var imap = __toESM(require("./imap.js"));
var import_smtp = require("./smtp.js");
function fmtHeaders(emails) {
  if (!emails.length) return "\u041F\u0438\u0441\u0435\u043C \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E.";
  return emails.map((e) => [
    `UID: ${e.uid}  |  ${e.seen ? "\u2713\u043F\u0440\u043E\u0447\u0438\u0442." : "\u25CF\u043D\u0435\u043F\u0440\u043E\u0447\u0438\u0442."}${e.flagged ? "  \u2605" : ""}`,
    `\u041E\u0442: ${e.from.map((a) => a.name ? `${a.name} <${a.address}>` : a.address).join(", ")}`,
    `\u0422\u0435\u043C\u0430: ${e.subject}`,
    `\u0414\u0430\u0442\u0430: ${e.date}  |  ${(e.size / 1024).toFixed(1)} KB${e.hasAttachments ? "  \u{1F4CE}" : ""}`
  ].join("\n")).join("\n\n\u2500\u2500\n\n");
}
function parseSearchDate(s, field) {
  const d = new Date(s);
  if (isNaN(d.getTime())) throw new Error(`\u041D\u0435\u0432\u0435\u0440\u043D\u0430\u044F \u0434\u0430\u0442\u0430 \u0434\u043B\u044F \u043F\u043E\u043B\u044F ${field}: "${s}"`);
  return d;
}
function registerTools(server) {
  const creds = () => (0, import_token.loadCredentials)();
  server.registerTool("yandex_list_folders", {
    title: "\u0421\u043F\u0438\u0441\u043E\u043A \u043F\u0430\u043F\u043E\u043A",
    description: "\u0412\u043E\u0437\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u0432\u0441\u0435 IMAP-\u043F\u0430\u043F\u043A\u0438 \u042F\u043D\u0434\u0435\u043A\u0441.\u041F\u043E\u0447\u0442\u044B: \u043F\u0443\u0442\u044C, \u0438\u043C\u044F, \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u043E\u0435 \u043D\u0430\u0437\u043D\u0430\u0447\u0435\u043D\u0438\u0435 (\u041E\u0442\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u043D\u044B\u0435, \u041A\u043E\u0440\u0437\u0438\u043D\u0430 \u0438 \u0442.\u0434.).",
    inputSchema: import_zod.z.object({}).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async () => {
    try {
      const folders = await imap.listFolders(creds());
      return { content: [{ type: "text", text: JSON.stringify(folders, null, 2) }], structuredContent: { folders } };
    } catch (e) {
      return {
        content: [{ type: "text", text: `\u041E\u0448\u0438\u0431\u043A\u0430: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true
      };
    }
  });
  server.registerTool("yandex_folder_status", {
    title: "\u0421\u0442\u0430\u0442\u0443\u0441 \u043F\u0430\u043F\u043A\u0438",
    description: '\u041A\u043E\u043B\u0438\u0447\u0435\u0441\u0442\u0432\u043E \u0432\u0441\u0435\u0445 \u043F\u0438\u0441\u0435\u043C \u0438 \u043D\u0435\u043F\u0440\u043E\u0447\u0438\u0442\u0430\u043D\u043D\u044B\u0445 \u0432 \u043F\u0430\u043F\u043A\u0435. Args: folder (string) \u2014 IMAP \u043F\u0443\u0442\u044C, \u043D\u0430\u043F\u0440. "INBOX".',
    inputSchema: import_zod.z.object({ folder: import_zod.z.string().describe('IMAP \u043F\u0443\u0442\u044C \u043F\u0430\u043F\u043A\u0438, \u043D\u0430\u043F\u0440. "INBOX", "Sent"') }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async ({ folder }) => {
    try {
      const s = await imap.folderStatus(creds(), folder);
      return { content: [{ type: "text", text: JSON.stringify(s, null, 2) }], structuredContent: s };
    } catch (e) {
      return {
        content: [{ type: "text", text: `\u041E\u0448\u0438\u0431\u043A\u0430: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true
      };
    }
  });
  server.registerTool("yandex_list_emails", {
    title: "\u0421\u043F\u0438\u0441\u043E\u043A \u043F\u0438\u0441\u0435\u043C",
    description: `\u041F\u0438\u0441\u044C\u043C\u0430 \u0432 \u043F\u0430\u043F\u043A\u0435 \u0441 \u043F\u0430\u0433\u0438\u043D\u0430\u0446\u0438\u0435\u0439, \u0441\u0432\u0435\u0436\u0438\u0435 \u043F\u0435\u0440\u0432\u044B\u0435. \u0412\u043E\u0437\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u0437\u0430\u0433\u043E\u043B\u043E\u0432\u043A\u0438 \u0431\u0435\u0437 \u0442\u0435\u043B\u0430.
Args: folder (default "INBOX"), page (default 1), page_size (1-100, default 20).
\u0414\u043B\u044F \u0447\u0442\u0435\u043D\u0438\u044F \u0442\u0435\u043B\u0430 \u2014 yandex_get_email \u043F\u043E UID.`,
    inputSchema: import_zod.z.object({
      folder: import_zod.z.string().default("INBOX").describe("IMAP \u043F\u0430\u043F\u043A\u0430"),
      page: import_zod.z.number().int().min(1).default(1).describe("\u0421\u0442\u0440\u0430\u043D\u0438\u0446\u0430 (1-based)"),
      page_size: import_zod.z.number().int().min(1).max(100).default(20).describe("\u041F\u0438\u0441\u0435\u043C \u043D\u0430 \u0441\u0442\u0440\u0430\u043D\u0438\u0446\u0435")
    }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false }
  }, async ({ folder, page, page_size }) => {
    try {
      const r = await imap.listEmails(creds(), folder, page, page_size);
      const text = `${r.folder}  |  \u0432\u0441\u0435\u0433\u043E: ${r.total}  |  \u0441\u0442\u0440. ${r.page}  |  \u0435\u0449\u0451 \u0435\u0441\u0442\u044C: ${r.hasMore}

${fmtHeaders(r.emails)}`;
      return { content: [{ type: "text", text }], structuredContent: r };
    } catch (e) {
      return {
        content: [{ type: "text", text: `\u041E\u0448\u0438\u0431\u043A\u0430: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true
      };
    }
  });
  server.registerTool("yandex_get_email", {
    title: "\u041F\u0440\u043E\u0447\u0438\u0442\u0430\u0442\u044C \u043F\u0438\u0441\u044C\u043C\u043E",
    description: `\u041F\u043E\u043B\u043D\u043E\u0435 \u0441\u043E\u0434\u0435\u0440\u0436\u0438\u043C\u043E\u0435 \u043F\u0438\u0441\u044C\u043C\u0430 \u043F\u043E IMAP UID (\u0438\u0437 yandex_list_emails \u0438\u043B\u0438 yandex_search_emails).
Args: folder (default "INBOX"), uid (integer UID \u043F\u0438\u0441\u044C\u043C\u0430).
\u0422\u0435\u043B\u043E \u043E\u0431\u0440\u0435\u0437\u0430\u0435\u0442\u0441\u044F \u043D\u0430 8000 \u0441\u0438\u043C\u0432\u043E\u043B\u0430\u0445; \u0444\u043B\u0430\u0433 truncated=true \u0435\u0441\u043B\u0438 \u043E\u0431\u0440\u0435\u0437\u0430\u043D\u043E.`,
    inputSchema: import_zod.z.object({
      folder: import_zod.z.string().default("INBOX"),
      uid: import_zod.z.number().int().positive().describe("IMAP UID \u043F\u0438\u0441\u044C\u043C\u0430")
    }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async ({ folder, uid }) => {
    try {
      const email = await imap.getEmail(creds(), folder, uid);
      if (!email) return { content: [{ type: "text", text: `\u041F\u0438\u0441\u044C\u043C\u043E UID ${uid} \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E \u0432 ${folder}.` }] };
      const lines = [
        `\u041E\u0442: ${email.from.map((a) => a.name ? `${a.name} <${a.address}>` : a.address).join(", ")}`,
        `\u041A\u043E\u043C\u0443: ${email.to.map((a) => a.address).join(", ")}`,
        email.cc.length ? `CC: ${email.cc.map((a) => a.address).join(", ")}` : "",
        `\u0422\u0435\u043C\u0430: ${email.subject}`,
        `\u0414\u0430\u0442\u0430: ${email.date}`,
        `\u0421\u0442\u0430\u0442\u0443\u0441: ${email.seen ? "\u041F\u0440\u043E\u0447\u0438\u0442\u0430\u043D\u043E" : "\u041D\u0435\u043F\u0440\u043E\u0447\u0438\u0442\u0430\u043D\u043E"}${email.flagged ? "  \u2605" : ""}`,
        email.attachments.length ? `\u0412\u043B\u043E\u0436\u0435\u043D\u0438\u044F: ${email.attachments.map((a) => `${a.filename} (${(a.size / 1024).toFixed(1)} KB)`).join(", ")}` : "",
        email.truncated ? "\n\u26A0 \u0422\u0435\u043B\u043E \u043E\u0431\u0440\u0435\u0437\u0430\u043D\u043E \u0434\u043E 8000 \u0441\u0438\u043C\u0432\u043E\u043B\u043E\u0432." : "",
        "",
        "\u2500\u2500\u2500 \u0422\u0435\u043B\u043E \u2500\u2500\u2500",
        email.textBody ?? email.htmlBody ?? "(\u043F\u0443\u0441\u0442\u043E)"
      ].filter(Boolean).join("\n");
      return { content: [{ type: "text", text: lines }], structuredContent: email };
    } catch (e) {
      return {
        content: [{ type: "text", text: `\u041E\u0448\u0438\u0431\u043A\u0430: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true
      };
    }
  });
  server.registerTool("yandex_search_emails", {
    title: "\u041F\u043E\u0438\u0441\u043A \u043F\u0438\u0441\u0435\u043C",
    description: `\u0421\u0435\u0440\u0432\u0435\u0440\u043D\u044B\u0439 \u043F\u043E\u0438\u0441\u043A \u043F\u0438\u0441\u0435\u043C \u043F\u043E \u043A\u0440\u0438\u0442\u0435\u0440\u0438\u044F\u043C IMAP.
Args:
  folder (default "INBOX")
  from   (string?) \u2014 \u0444\u0440\u0430\u0433\u043C\u0435\u043D\u0442 \u0430\u0434\u0440\u0435\u0441\u0430/\u0438\u043C\u0435\u043D\u0438 \u043E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u0435\u043B\u044F
  to     (string?) \u2014 \u0444\u0440\u0430\u0433\u043C\u0435\u043D\u0442 \u0430\u0434\u0440\u0435\u0441\u0430 \u043F\u043E\u043B\u0443\u0447\u0430\u0442\u0435\u043B\u044F
  subject(string?) \u2014 \u0444\u0440\u0430\u0433\u043C\u0435\u043D\u0442 \u0442\u0435\u043C\u044B
  text   (string?) \u2014 \u043F\u043E\u043B\u043D\u043E\u0442\u0435\u043A\u0441\u0442\u043E\u0432\u044B\u0439 \u043F\u043E\u0438\u0441\u043A \u0432 \u0442\u0435\u043B\u0435
  since  (string?) \u2014 ISO \u0434\u0430\u0442\u0430, \u043D\u0430\u043F\u0440. "2025-01-01"
  before (string?) \u2014 ISO \u0434\u0430\u0442\u0430
  seen   (boolean?) \u2014 true=\u0442\u043E\u043B\u044C\u043A\u043E \u043F\u0440\u043E\u0447\u0438\u0442\u0430\u043D\u043D\u044B\u0435, false=\u0442\u043E\u043B\u044C\u043A\u043E \u043D\u0435\u043F\u0440\u043E\u0447\u0438\u0442\u0430\u043D\u043D\u044B\u0435
  flagged(boolean?) \u2014 true=\u0441\u043E \u0437\u0432\u0451\u0437\u0434\u043E\u0447\u043A\u043E\u0439
  max_results (1-100, default 20)`,
    inputSchema: import_zod.z.object({
      folder: import_zod.z.string().default("INBOX"),
      from: import_zod.z.string().optional(),
      to: import_zod.z.string().optional(),
      subject: import_zod.z.string().optional(),
      text: import_zod.z.string().optional(),
      since: import_zod.z.string().optional().describe('ISO \u0434\u0430\u0442\u0430 "2025-01-01"'),
      before: import_zod.z.string().optional().describe("ISO \u0434\u0430\u0442\u0430"),
      seen: import_zod.z.boolean().optional(),
      flagged: import_zod.z.boolean().optional(),
      max_results: import_zod.z.number().int().min(1).max(100).default(20)
    }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false }
  }, async ({ folder, max_results, since, before, seen, flagged, ...rest }) => {
    try {
      const query = {};
      if (rest.from) query.from = rest.from;
      if (rest.to) query.to = rest.to;
      if (rest.subject) query.subject = rest.subject;
      if (rest.text) query.text = rest.text;
      if (since) query["since"] = parseSearchDate(since, "since");
      if (before) query["before"] = parseSearchDate(before, "before");
      if (seen === true) query["seen"] = true;
      if (seen === false) query["unseen"] = true;
      if (flagged === true) query["flagged"] = true;
      if (flagged === false) query["unflagged"] = true;
      const emails = await imap.searchEmails(creds(), folder, query, max_results);
      const text = emails.length ? `\u041D\u0430\u0439\u0434\u0435\u043D\u043E: ${emails.length}

${fmtHeaders(emails)}` : "\u041D\u0438\u0447\u0435\u0433\u043E \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E.";
      return { content: [{ type: "text", text }], structuredContent: { count: emails.length, emails } };
    } catch (e) {
      return {
        content: [{ type: "text", text: `\u041E\u0448\u0438\u0431\u043A\u0430: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true
      };
    }
  });
  server.registerTool("yandex_send_email", {
    title: "\u041E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u044C \u043F\u0438\u0441\u044C\u043C\u043E",
    description: `\u041E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u044C \u043F\u0438\u0441\u044C\u043C\u043E \u0447\u0435\u0440\u0435\u0437 SMTP \u042F\u043D\u0434\u0435\u043A\u0441\u0430 (OAuth2).
Args:
  to       (string[]) \u2014 \u043F\u043E\u043B\u0443\u0447\u0430\u0442\u0435\u043B\u0438, \u043D\u0430\u043F\u0440. ["user@example.com", "Name <other@example.com>"]
  cc, bcc  (string[]?) \u2014 \u043A\u043E\u043F\u0438\u044F, \u0441\u043A\u0440\u044B\u0442\u0430\u044F \u043A\u043E\u043F\u0438\u044F
  subject  (string) \u2014 \u0442\u0435\u043C\u0430
  text     (string?) \u2014 \u0442\u0435\u043B\u043E plain text
  html     (string?) \u2014 \u0442\u0435\u043B\u043E HTML
  reply_to (string?) \u2014 Reply-To \u0430\u0434\u0440\u0435\u0441
  in_reply_to (string?) \u2014 Message-ID \u043F\u0438\u0441\u044C\u043C\u0430, \u043D\u0430 \u043A\u043E\u0442\u043E\u0440\u043E\u0435 \u043E\u0442\u0432\u0435\u0447\u0430\u0435\u043C
  references  (string[]?) \u2014 \u0446\u0435\u043F\u043E\u0447\u043A\u0430 Message-ID \u0434\u043B\u044F \u0442\u0440\u0435\u0434\u0430`,
    inputSchema: import_zod.z.object({
      to: import_zod.z.array(import_zod.z.string()).min(1),
      cc: import_zod.z.array(import_zod.z.string()).optional(),
      bcc: import_zod.z.array(import_zod.z.string()).optional(),
      subject: import_zod.z.string().min(1),
      text: import_zod.z.string().optional(),
      html: import_zod.z.string().optional(),
      reply_to: import_zod.z.string().optional(),
      in_reply_to: import_zod.z.string().optional(),
      references: import_zod.z.array(import_zod.z.string()).optional()
    }).strict().refine((d) => d.text !== void 0 || d.html !== void 0, {
      message: "\u0423\u043A\u0430\u0436\u0438\u0442\u0435 \u0445\u043E\u0442\u044F \u0431\u044B \u043E\u0434\u043D\u043E \u0438\u0437 \u043F\u043E\u043B\u0435\u0439: text \u0438\u043B\u0438 html"
    }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async (params) => {
    try {
      const r = await (0, import_smtp.sendEmail)(creds(), {
        to: params.to,
        cc: params.cc,
        bcc: params.bcc,
        subject: params.subject,
        text: params.text,
        html: params.html,
        replyTo: params.reply_to,
        inReplyTo: params.in_reply_to,
        references: params.references
      });
      const text = r.success ? `\u041F\u0438\u0441\u044C\u043C\u043E \u043E\u0442\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u043E. Message-ID: ${r.messageId ?? "n/a"}` : `\u041E\u0448\u0438\u0431\u043A\u0430 \u043E\u0442\u043F\u0440\u0430\u0432\u043A\u0438: ${r.error}`;
      return { content: [{ type: "text", text }], structuredContent: r };
    } catch (e) {
      return {
        content: [{ type: "text", text: `\u041E\u0448\u0438\u0431\u043A\u0430: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true
      };
    }
  });
  server.registerTool("yandex_move_email", {
    title: "\u041F\u0435\u0440\u0435\u043C\u0435\u0441\u0442\u0438\u0442\u044C \u043F\u0438\u0441\u044C\u043C\u043E",
    description: `\u041F\u0435\u0440\u0435\u043C\u0435\u0441\u0442\u0438\u0442\u044C \u043F\u0438\u0441\u044C\u043C\u043E \u0432 \u0434\u0440\u0443\u0433\u0443\u044E \u043F\u0430\u043F\u043A\u0443.
Args: folder (\u043E\u0442\u043A\u0443\u0434\u0430), uid (UID \u043F\u0438\u0441\u044C\u043C\u0430), target_folder (\u043A\u0443\u0434\u0430, \u043D\u0430\u043F\u0440. "Spam", "Archive").`,
    inputSchema: import_zod.z.object({
      folder: import_zod.z.string(),
      uid: import_zod.z.number().int().positive(),
      target_folder: import_zod.z.string()
    }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }
  }, async ({ folder, uid, target_folder }) => {
    try {
      await imap.moveEmail(creds(), folder, uid, target_folder);
      const text = `UID ${uid}: \u043F\u0435\u0440\u0435\u043C\u0435\u0449\u0435\u043D\u043E \u0438\u0437 ${folder} \u0432 ${target_folder}.`;
      return { content: [{ type: "text", text }], structuredContent: { success: true } };
    } catch (e) {
      return {
        content: [{ type: "text", text: `\u041E\u0448\u0438\u0431\u043A\u0430: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true
      };
    }
  });
  server.registerTool("yandex_delete_email", {
    title: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u043F\u0438\u0441\u044C\u043C\u043E",
    description: `\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u043F\u0438\u0441\u044C\u043C\u043E. \u041F\u043E \u0443\u043C\u043E\u043B\u0447\u0430\u043D\u0438\u044E \u2014 \u0432 \u043A\u043E\u0440\u0437\u0438\u043D\u0443 (\u0432\u043E\u0441\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u043C\u043E).
Args: folder, uid, permanent (bool, default false). permanent=true \u2014 \u0431\u0435\u0437\u0432\u043E\u0437\u0432\u0440\u0430\u0442\u043D\u043E.`,
    inputSchema: import_zod.z.object({
      folder: import_zod.z.string().default("INBOX"),
      uid: import_zod.z.number().int().positive(),
      permanent: import_zod.z.boolean().default(false)
    }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false }
  }, async ({ folder, uid, permanent }) => {
    try {
      await imap.deleteEmail(creds(), folder, uid, permanent);
      const text = permanent ? `UID ${uid} \u0431\u0435\u0437\u0432\u043E\u0437\u0432\u0440\u0430\u0442\u043D\u043E \u0443\u0434\u0430\u043B\u0435\u043D\u043E.` : `UID ${uid} \u043F\u0435\u0440\u0435\u043C\u0435\u0449\u0435\u043D\u043E \u0432 \u041A\u043E\u0440\u0437\u0438\u043D\u0443.`;
      return { content: [{ type: "text", text }], structuredContent: { success: true, permanent } };
    } catch (e) {
      return {
        content: [{ type: "text", text: `\u041E\u0448\u0438\u0431\u043A\u0430: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true
      };
    }
  });
  server.registerTool("yandex_mark_email", {
    title: "\u041F\u043E\u043C\u0435\u0442\u0438\u0442\u044C \u043F\u0438\u0441\u044C\u043C\u043E",
    description: `\u0418\u0437\u043C\u0435\u043D\u0438\u0442\u044C \u0441\u0442\u0430\u0442\u0443\u0441 \u043F\u0440\u043E\u0447\u0438\u0442\u0430\u043D\u043D\u043E\u0441\u0442\u0438 \u0438\u043B\u0438 \u0437\u0432\u0451\u0437\u0434\u043E\u0447\u043A\u0438.
Args: folder, uid, seen (bool?), flagged (bool?). \u0425\u043E\u0442\u044F \u0431\u044B \u043E\u0434\u0438\u043D \u0438\u0437 seen/flagged \u043E\u0431\u044F\u0437\u0430\u0442\u0435\u043B\u0435\u043D.`,
    inputSchema: import_zod.z.object({
      folder: import_zod.z.string().default("INBOX"),
      uid: import_zod.z.number().int().positive(),
      seen: import_zod.z.boolean().optional(),
      flagged: import_zod.z.boolean().optional()
    }).strict().refine((d) => d.seen !== void 0 || d.flagged !== void 0, {
      message: "\u0423\u043A\u0430\u0436\u0438\u0442\u0435 \u0445\u043E\u0442\u044F \u0431\u044B \u043E\u0434\u043D\u043E \u0438\u0437 \u043F\u043E\u043B\u0435\u0439: seen \u0438\u043B\u0438 flagged"
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async ({ folder, uid, seen, flagged }) => {
    try {
      await imap.markEmail(creds(), folder, uid, seen, flagged);
      const changes = [
        seen !== void 0 ? seen ? "\u043F\u0440\u043E\u0447\u0438\u0442\u0430\u043D\u043E" : "\u043D\u0435\u043F\u0440\u043E\u0447\u0438\u0442\u0430\u043D\u043E" : "",
        flagged !== void 0 ? flagged ? "\u043E\u0442\u043C\u0435\u0447\u0435\u043D\u043E \u2605" : "\u0441\u043D\u044F\u0442\u0430 \u0437\u0432\u0451\u0437\u0434\u043E\u0447\u043A\u0430" : ""
      ].filter(Boolean).join(", ");
      return { content: [{ type: "text", text: `UID ${uid}: ${changes}.` }], structuredContent: { success: true } };
    } catch (e) {
      return {
        content: [{ type: "text", text: `\u041E\u0448\u0438\u0431\u043A\u0430: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true
      };
    }
  });
  server.registerTool("yandex_get_special_folders", {
    title: "\u0421\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u044B\u0435 \u043F\u0430\u043F\u043A\u0438",
    description: '\u0412\u043E\u0437\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u0440\u0435\u0430\u043B\u044C\u043D\u044B\u0435 IMAP-\u043F\u0443\u0442\u0438 \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u044B\u0445 \u043F\u0430\u043F\u043E\u043A (\u0412\u0445\u043E\u0434\u044F\u0449\u0438\u0435, \u041E\u0442\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u043D\u044B\u0435, \u0427\u0435\u0440\u043D\u043E\u0432\u0438\u043A\u0438, \u041A\u043E\u0440\u0437\u0438\u043D\u0430, \u0421\u043F\u0430\u043C). \u041D\u0430 \u0440\u0443\u0441\u0441\u043A\u043E\u044F\u0437\u044B\u0447\u043D\u044B\u0445 \u0430\u043A\u043A\u0430\u0443\u043D\u0442\u0430\u0445 \u042F\u043D\u0434\u0435\u043A\u0441\u0430 \u043F\u0430\u043F\u043A\u0438 \u043C\u043E\u0433\u0443\u0442 \u043D\u0430\u0437\u044B\u0432\u0430\u0442\u044C\u0441\u044F "\u0423\u0434\u0430\u043B\u0451\u043D\u043D\u044B\u0435", "\u041E\u0442\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u043D\u044B\u0435" \u0438 \u0442.\u0434. \u2014 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0439\u0442\u0435 \u044D\u0442\u043E\u0442 \u0438\u043D\u0441\u0442\u0440\u0443\u043C\u0435\u043D\u0442, \u0447\u0442\u043E\u0431\u044B \u0443\u0437\u043D\u0430\u0442\u044C \u043F\u0440\u0430\u0432\u0438\u043B\u044C\u043D\u044B\u0435 \u0438\u043C\u0435\u043D\u0430 \u043F\u0435\u0440\u0435\u0434 \u043E\u043F\u0435\u0440\u0430\u0446\u0438\u044F\u043C\u0438 \u0441 \u043F\u0430\u043F\u043A\u0430\u043C\u0438.',
    inputSchema: import_zod.z.object({}).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false }
  }, async () => {
    try {
      const folders = await imap.getSpecialFolders(creds());
      const text = [
        `\u0412\u0445\u043E\u0434\u044F\u0449\u0438\u0435:    ${folders.inbox}`,
        `\u041E\u0442\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u043D\u044B\u0435: ${folders.sent}`,
        `\u0427\u0435\u0440\u043D\u043E\u0432\u0438\u043A\u0438:   ${folders.drafts}`,
        `\u041A\u043E\u0440\u0437\u0438\u043D\u0430:     ${folders.trash}`,
        `\u0421\u043F\u0430\u043C:        ${folders.spam}`
      ].join("\n");
      return { content: [{ type: "text", text }], structuredContent: folders };
    } catch (e) {
      return {
        content: [{ type: "text", text: `\u041E\u0448\u0438\u0431\u043A\u0430: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true
      };
    }
  });
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  registerTools
});
