// Declarative tool registry (Hook 3, AUTH-02).
//
// Why this shape:
//   In v1 each tool was inlined as a direct SDK registration call inside
//   registerTools(). That worked for 10 tools, but every new tool in L2-L7
//   would have grown an if-else lattice tied to auth level and (future)
//   capabilities. The declarative `TOOLS[]` array makes adding a tool a one-line
//   change: append an entry whose `requires.authLevel` / `requires.capabilities`
//   gates discovery. registerTools() is now a pure iterator and never needs
//   to change as long as the contract (authLevel, capabilities) stays stable.
//
//   Layer 1 fact: ctx.capabilities is always an empty Set (see auth.ts:detectCapabilities).
//   So any tool listing required capabilities will be skipped — by design — until
//   Layer 2 wires real capability detection. No L1 tool requires a capability.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { loadCredentials } from './token.js';
import * as imap from './imap.js';
import { sendEmail } from './smtp.js';
import { sanitizeForDisplay, wrapUntrusted } from './sanitize.js';
import type { AuthLevel, Capability } from './auth.js';

// ── Formatters ─────────────────────────────────────────────

// Address part из IMAP envelope считаем syntactically valid и НЕ sanitize-уем
// (это сломает legitimate '+' / '.' / '@'). Display-name — untrusted, sanitize.
function fmtAddr(a: imap.EmailAddress): string {
  if (a.name) return `${sanitizeForDisplay(a.name)} <${a.address}>`;
  return a.address;
}

function fmtHeaders(emails: imap.EmailHeader[]): string {
  if (!emails.length) return 'Писем не найдено.';
  return emails.map(e => [
    `UID: ${e.uid}  |  ${e.seen ? '[read]' : '[unread]'}${e.flagged ? '  [*]' : ''}`,
    `От: ${e.from.map(fmtAddr).join(', ')}`,
    `Тема: ${sanitizeForDisplay(e.subject)}`,
    `Дата: ${e.date}  |  ${(e.size/1024).toFixed(1)} KB${e.hasAttachments ? '  [attach]' : ''}`,
  ].join('\n')).join('\n\n──\n\n');
}

function parseSearchDate(s: string, field: string): Date {
  const d = new Date(s);
  if (isNaN(d.getTime())) throw new Error(`Неверная дата для поля ${field}: "${s}"`);
  return d;
}

// ── Public types (consumed by index.ts and tools-registry.test.ts) ─────────

export interface ToolCtx {
  authLevel: AuthLevel;
  capabilities: Set<Capability>;
}

export interface ToolDef {
  name: string;
  title: string;
  description: string;
  inputSchema: z.AnyZodObject;
  annotations: {
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
  };
  requires: { authLevel: AuthLevel; capabilities?: Capability[] };
  handler: (
    params: unknown,
    ctx: ToolCtx,
  ) => Promise<{
    content: Array<{ type: 'text'; text: string }>;
    structuredContent?: unknown;
    isError?: boolean;
  }>;
}

// creds() is a lazy loader — used by every handler. Module scope is safe because
// loadCredentials() itself is side-effect-free until invoked (it reads token.json
// at call time, not at import time). Putting it here removes per-call closure
// overhead and avoids re-creating the lambda inside registerTools.
const creds = (): ReturnType<typeof loadCredentials> => loadCredentials();

// Narrow helper to format the error path consistently across handlers.
function errorResult(e: unknown): { content: Array<{ type: 'text'; text: string }>; isError: true } {
  return {
    content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
    isError: true,
  };
}

// ── Tool definitions ───────────────────────────────────────

// Input schemas are declared once and reused — both as the SDK-facing inputSchema
// and to type the handler's params via z.infer. This is the only safe way to
// avoid `any` in handler params without losing the runtime validation that the
// SDK performs against inputSchema before invoking the handler.

const listFoldersSchema = z.object({}).strict();
const folderStatusSchema = z.object({
  folder: z.string().describe('IMAP путь папки, напр. "INBOX", "Sent"'),
}).strict();
const listEmailsSchema = z.object({
  folder:    z.string().default('INBOX').describe('IMAP папка'),
  page:      z.number().int().min(1).default(1).describe('Страница (1-based)'),
  page_size: z.number().int().min(1).max(100).default(20).describe('Писем на странице'),
}).strict();
const getEmailSchema = z.object({
  folder: z.string().default('INBOX'),
  uid:    z.number().int().positive().describe('IMAP UID письма'),
}).strict();
const searchEmailsSchema = z.object({
  folder:      z.string().default('INBOX'),
  from:        z.string().optional(),
  to:          z.string().optional(),
  subject:     z.string().optional(),
  text:        z.string().optional(),
  since:       z.string().optional().describe('ISO дата "2025-01-01"'),
  before:      z.string().optional().describe('ISO дата'),
  seen:        z.boolean().optional(),
  flagged:     z.boolean().optional(),
  max_results: z.number().int().min(1).max(100).default(20),
}).strict();
const sendEmailSchema = z.object({
  to:          z.array(z.string()).min(1),
  cc:          z.array(z.string()).optional(),
  bcc:         z.array(z.string()).optional(),
  subject:     z.string().min(1),
  text:        z.string().optional(),
  html:        z.string().optional(),
  reply_to:    z.string().optional(),
  in_reply_to: z.string().optional(),
  references:  z.array(z.string()).optional(),
}).strict().refine(d => d.text !== undefined || d.html !== undefined, {
  message: 'Укажите хотя бы одно из полей: text или html',
});
const moveEmailSchema = z.object({
  folder:        z.string(),
  uid:           z.number().int().positive(),
  target_folder: z.string(),
}).strict();
const deleteEmailSchema = z.object({
  folder:    z.string().default('INBOX'),
  uid:       z.number().int().positive(),
  permanent: z.boolean().default(false),
}).strict();
const markEmailSchema = z.object({
  folder:  z.string().default('INBOX'),
  uid:     z.number().int().positive(),
  seen:    z.boolean().optional(),
  flagged: z.boolean().optional(),
}).strict().refine(d => d.seen !== undefined || d.flagged !== undefined, {
  message: 'Укажите хотя бы одно из полей: seen или flagged',
});
const getSpecialFoldersSchema = z.object({}).strict();

// Note: send_email schema uses .refine() which returns ZodEffects, not ZodObject.
// SDK requires the inputSchema field be a ZodObject (or its plain shape). We pass
// the underlying object schema to the SDK and re-run .refine() inside the handler
// to preserve the cross-field validation message.
const sendEmailBaseSchema = z.object({
  to:          z.array(z.string()).min(1),
  cc:          z.array(z.string()).optional(),
  bcc:         z.array(z.string()).optional(),
  subject:     z.string().min(1),
  text:        z.string().optional(),
  html:        z.string().optional(),
  reply_to:    z.string().optional(),
  in_reply_to: z.string().optional(),
  references:  z.array(z.string()).optional(),
}).strict();
const markEmailBaseSchema = z.object({
  folder:  z.string().default('INBOX'),
  uid:     z.number().int().positive(),
  seen:    z.boolean().optional(),
  flagged: z.boolean().optional(),
}).strict();

// Silence unused-binding for the alias schemas (they document intent and could
// be promoted later when SDK accepts ZodEffects).
void sendEmailSchema; void markEmailSchema;

// readonly array + Object.freeze at module bottom keeps the declarative
// invariant enforceable: runtime mutation of TOOLS would throw in strict
// mode (which esbuild emits by default). Defence-in-depth against any
// future code that might try to push extra entries after import.
export const TOOLS: readonly ToolDef[] = [
  // 1. List folders (L0)
  {
    name: 'yandex_list_folders',
    title: 'Список папок',
    description: 'Возвращает все IMAP-папки Яндекс.Почты: путь, имя, специальное назначение (Отправленные, Корзина и т.д.).',
    inputSchema: listFoldersSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    requires: { authLevel: 0 },
    handler: async (_params, _ctx) => {
      try {
        const folders = await imap.listFolders();
        return { content: [{ type: 'text', text: JSON.stringify(folders, null, 2) }], structuredContent: { folders } };
      } catch (e) { return errorResult(e); }
    },
  },

  // 2. Folder status (L0)
  {
    name: 'yandex_folder_status',
    title: 'Статус папки',
    description: 'Количество всех писем и непрочитанных в папке. Args: folder (string) — IMAP путь, напр. "INBOX".',
    inputSchema: folderStatusSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { folder } = folderStatusSchema.parse(params);
        const s = await imap.folderStatus(folder);
        return { content: [{ type: 'text', text: JSON.stringify(s, null, 2) }], structuredContent: s };
      } catch (e) { return errorResult(e); }
    },
  },

  // 3. List emails (L0) — UID pagination (Phase 2 BUG-01)
  {
    name: 'yandex_list_emails',
    title: 'Список писем',
    description: `Письма в папке с пагинацией, свежие первые. Возвращает заголовки без тела.
Args: folder (default "INBOX"), page (default 1), page_size (1-100, default 20).
Для чтения тела — yandex_get_email по UID.`,
    inputSchema: listEmailsSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { folder, page, page_size } = listEmailsSchema.parse(params);
        const r = await imap.listEmails(folder, page, page_size);
        const text = `${r.folder}  |  всего: ${r.total}  |  стр. ${r.page}  |  ещё есть: ${r.hasMore}\n\n${fmtHeaders(r.emails)}`;
        return { content: [{ type: 'text', text }], structuredContent: r };
      } catch (e) { return errorResult(e); }
    },
  },

  // 4. Get email (L0) — Phase 2 wrapUntrusted + sanitizeForDisplay
  {
    name: 'yandex_get_email',
    title: 'Прочитать письмо',
    description: `Полное содержимое письма по IMAP UID (из yandex_list_emails или yandex_search_emails).
Args: folder (default "INBOX"), uid (integer UID письма).
Тело обрезается на 8000 символах; флаг truncated=true если обрезано.`,
    inputSchema: getEmailSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { folder, uid } = getEmailSchema.parse(params);
        const email = await imap.getEmail(folder, uid);
        if (!email) return { content: [{ type: 'text', text: `Письмо UID ${uid} не найдено в ${folder}.` }] };
        const body = email.textBody ?? email.htmlBody ?? '(пусто)';
        const attachLine = email.attachments.length
          ? `Вложения: ${email.attachments.map(a => `${sanitizeForDisplay(a.filename)} (${(a.size/1024).toFixed(1)} KB)`).join(', ')}`
          : '';
        const lines = [
          `От: ${email.from.map(fmtAddr).join(', ')}`,
          `Кому: ${email.to.map(fmtAddr).join(', ')}`,
          email.cc.length ? `CC: ${email.cc.map(fmtAddr).join(', ')}` : '',
          `Тема: ${sanitizeForDisplay(email.subject)}`,
          `Дата: ${email.date}`,
          `Статус: ${email.seen ? 'Прочитано' : 'Непрочитано'}${email.flagged ? '  [*]' : ''}`,
          attachLine,
          email.truncated ? '\n[Body truncated at 8000 chars]' : '',
          '',
          wrapUntrusted(body),
        ].filter(Boolean).join('\n');
        // SEC-06: text channel получает explicit BEGIN/END markers (LLM).
        // structuredContent — для programmatic клиентов (не подвержены
        // prompt injection); body отдаётся raw без markers сознательно.
        return { content: [{ type: 'text', text: lines }], structuredContent: email };
      } catch (e) { return errorResult(e); }
    },
  },

  // 5. Search emails (L0)
  {
    name: 'yandex_search_emails',
    title: 'Поиск писем',
    description: `Серверный поиск писем по критериям IMAP.
Args:
  folder (default "INBOX")
  from   (string?) — фрагмент адреса/имени отправителя
  to     (string?) — фрагмент адреса получателя
  subject(string?) — фрагмент темы
  text   (string?) — полнотекстовый поиск в теле
  since  (string?) — ISO дата, напр. "2025-01-01"
  before (string?) — ISO дата
  seen   (boolean?) — true=только прочитанные, false=только непрочитанные
  flagged(boolean?) — true=со звёздочкой
  max_results (1-100, default 20)`,
    inputSchema: searchEmailsSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const parsed = searchEmailsSchema.parse(params);
        const { folder, max_results, since, before, seen, flagged, ...rest } = parsed;
        const query: Record<string, unknown> = {};
        if (rest.from)    query.from    = rest.from;
        if (rest.to)      query.to      = rest.to;
        if (rest.subject) query.subject = rest.subject;
        if (rest.text)    query.text    = rest.text;
        if (since)          query['since']     = parseSearchDate(since, 'since');
        if (before)         query['before']    = parseSearchDate(before, 'before');
        if (seen === true)  query['seen']      = true;
        if (seen === false) query['unseen']    = true;
        if (flagged === true)  query['flagged']   = true;
        if (flagged === false) query['unflagged'] = true;
        const emails = await imap.searchEmails(folder, query, max_results);
        const text = emails.length
          ? `Найдено: ${emails.length}\n\n${fmtHeaders(emails)}`
          : 'Ничего не найдено.';
        return { content: [{ type: 'text', text }], structuredContent: { count: emails.length, emails } };
      } catch (e) { return errorResult(e); }
    },
  },

  // 6. Get special folders (L0)
  {
    name: 'yandex_get_special_folders',
    title: 'Специальные папки',
    description: 'Возвращает реальные IMAP-пути специальных папок (Входящие, Отправленные, Черновики, Корзина, Спам). На русскоязычных аккаунтах Яндекса папки могут называться "Удалённые", "Отправленные" и т.д. — используйте этот инструмент, чтобы узнать правильные имена перед операциями с папками.',
    inputSchema: getSpecialFoldersSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    requires: { authLevel: 0 },
    handler: async (_params, _ctx) => {
      try {
        const folders = await imap.getSpecialFolders();
        const text = [
          `Входящие:    ${folders.inbox}`,
          `Отправленные: ${folders.sent}`,
          `Черновики:   ${folders.drafts}`,
          `Корзина:     ${folders.trash}`,
          `Спам:        ${folders.spam}`,
        ].join('\n');
        return { content: [{ type: 'text', text }], structuredContent: folders };
      } catch (e) { return errorResult(e); }
    },
  },

  // 7. Mark email (L1) — fully reversible
  {
    name: 'yandex_mark_email',
    title: 'Пометить письмо',
    description: `Изменить статус прочитанности или звёздочки.
Args: folder, uid, seen (bool?), flagged (bool?). Хотя бы один из seen/flagged обязателен.`,
    inputSchema: markEmailBaseSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    requires: { authLevel: 1 },
    handler: async (params, _ctx) => {
      try {
        const p = markEmailBaseSchema.parse(params);
        if (p.seen === undefined && p.flagged === undefined) {
          throw new Error('Укажите хотя бы одно из полей: seen или flagged');
        }
        const { folder, uid, seen, flagged } = p;
        await imap.markEmail(folder, uid, seen, flagged);
        const changes = [
          seen !== undefined ? (seen ? 'прочитано' : 'непрочитано') : '',
          flagged !== undefined ? (flagged ? 'отмечено ★' : 'снята звёздочка') : '',
        ].filter(Boolean).join(', ');
        return { content: [{ type: 'text', text: `UID ${uid}: ${changes}.` }], structuredContent: { success: true } };
      } catch (e) { return errorResult(e); }
    },
  },

  // 8. Move email (L1) — soft (protected-folder enforcement → Phase 7)
  {
    name: 'yandex_move_email',
    title: 'Переместить письмо',
    description: `Переместить письмо в другую папку.
Args: folder (откуда), uid (UID письма), target_folder (куда, напр. "Spam", "Archive").`,
    inputSchema: moveEmailSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    requires: { authLevel: 1 },
    handler: async (params, _ctx) => {
      try {
        const { folder, uid, target_folder } = moveEmailSchema.parse(params);
        await imap.moveEmail(folder, uid, target_folder);
        const text = `UID ${uid}: перемещено из ${folder} в ${target_folder}.`;
        return { content: [{ type: 'text', text }], structuredContent: { success: true } };
      } catch (e) { return errorResult(e); }
    },
  },

  // 9. Delete email (L1; permanent=true is gated by Phase 4 confirmation flow)
  {
    name: 'yandex_delete_email',
    title: 'Удалить письмо',
    description: `Удалить письмо. По умолчанию — в корзину (восстановимо).
Args: folder, uid, permanent (bool, default false). permanent=true — безвозвратно.`,
    inputSchema: deleteEmailSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    // TODO(phase-4): permanent=true must require a confirmation_token. In Phase 3
    // the entire delete tool is gated at L1; Phase 4 will split the permanent flag
    // into an explicit confirmation-required pathway.
    requires: { authLevel: 1 },
    handler: async (params, _ctx) => {
      try {
        const { folder, uid, permanent } = deleteEmailSchema.parse(params);
        await imap.deleteEmail(folder, uid, permanent);
        const text = permanent ? `UID ${uid} безвозвратно удалено.` : `UID ${uid} перемещено в Корзину.`;
        return { content: [{ type: 'text', text }], structuredContent: { success: true, permanent } };
      } catch (e) { return errorResult(e); }
    },
  },

  // 10. Send email (L2) — destructive; Phase 4 will add confirmation_token / dry_run
  {
    name: 'yandex_send_email',
    title: 'Отправить письмо',
    description: `Отправить письмо через SMTP Яндекса (OAuth2).
Args:
  to       (string[]) — получатели, напр. ["user@example.com", "Name <other@example.com>"]
  cc, bcc  (string[]?) — копия, скрытая копия
  subject  (string) — тема
  text     (string?) — тело plain text
  html     (string?) — тело HTML
  reply_to (string?) — Reply-To адрес
  in_reply_to (string?) — Message-ID письма, на которое отвечаем
  references  (string[]?) — цепочка Message-ID для треда`,
    inputSchema: sendEmailBaseSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    requires: { authLevel: 2 },
    handler: async (params, _ctx) => {
      try {
        const p = sendEmailBaseSchema.parse(params);
        if (p.text === undefined && p.html === undefined) {
          throw new Error('Укажите хотя бы одно из полей: text или html');
        }
        const r = await sendEmail(creds(), {
          to: p.to, cc: p.cc, bcc: p.bcc,
          subject: p.subject, text: p.text, html: p.html,
          replyTo: p.reply_to, inReplyTo: p.in_reply_to, references: p.references,
        });
        const text = r.success
          ? `Письмо отправлено. Message-ID: ${r.messageId ?? 'n/a'}`
          : `Ошибка отправки: ${r.error}`;
        return { content: [{ type: 'text', text }], structuredContent: r };
      } catch (e) { return errorResult(e); }
    },
  },
];

Object.freeze(TOOLS);

// ── Registration ───────────────────────────────────────────

export function registerTools(server: McpServer, ctx: ToolCtx): void {
  for (const def of TOOLS) {
    if (ctx.authLevel < def.requires.authLevel) continue;
    // Capability gate — when a tool lists required capabilities, every one of
    // them must be in ctx.capabilities. In Layer 1 ctx.capabilities is always
    // empty, so any tool that requires capabilities will be skipped. No L1
    // tool sets `requires.capabilities`, so this branch is dormant for now.
    if (def.requires.capabilities && def.requires.capabilities.length > 0) {
      const have = ctx.capabilities;
      const missing = def.requires.capabilities.some(c => !have.has(c));
      if (missing) continue;
    }
    server.registerTool(
      def.name,
      {
        title: def.title,
        description: def.description,
        inputSchema: def.inputSchema.shape,
        annotations: def.annotations,
      },
      (input: unknown) => def.handler(input, ctx),
    );
  }
}
