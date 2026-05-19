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
import * as fs from 'node:fs';
import * as path from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { loadCredentials } from './token.js';
import * as imap from './imap.js';
import { sendEmail } from './smtp.js';
import { sanitizeForDisplay, wrapUntrusted } from './sanitize.js';
import { generateCode, verifyCode, actionFingerprint, type VerifyResult } from './confirm.js';
import type { AuthLevel, Capability } from './auth.js';
import * as allowlist from './allowlist.js';
import { getStateDir } from './state-dir.js';

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

// Shape of the elicit dispatcher exposed to handlers. Inlined here (rather than
// imported from @modelcontextprotocol/sdk/types.js) so tools.ts stays loosely
// coupled to the SDK. The actual SDK signature is verified at integration
// point in src/index.ts where the closure is wired.
export interface ElicitFn {
  (params: {
    message: string;
    requestedSchema: {
      type: 'object';
      properties: Record<string, { type: 'boolean' | 'string' | 'number'; title?: string; description?: string }>;
      required?: string[];
    };
  }): Promise<{
    action: 'accept' | 'cancel' | 'decline';
    content?: Record<string, unknown>;
  }>;
}

export interface ToolCtx {
  authLevel: AuthLevel;
  capabilities: Set<Capability>;
  // serverContext.canElicit is set ASYNCHRONOUSLY by the SDK's
  // `notifications/initialized` handler (server.server.oninitialized hook in
  // src/index.ts). Handlers MUST NOT read it at registration time — only at
  // tool-call time, which is guaranteed to follow `notifications/initialized`
  // per MCP protocol. The bag is mutated in place; the reference is shared.
  serverContext: {
    canElicit: boolean;
    elicit?: ElicitFn;
  };
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
const trustAddressSchema = z.object({
  address:     z.string().min(3),
  scope:       z.enum(['permanent', 'session']).default('permanent'),
  trust_token: z.string().length(64),
}).strict();

// Note: send_email schema uses .refine() which returns ZodEffects, not ZodObject.
// SDK requires the inputSchema field be a ZodObject (or its plain shape). We pass
// the underlying object schema to the SDK and re-run .refine() inside the handler
// to preserve the cross-field validation message.
const sendEmailBaseSchema = z.object({
  to:                 z.array(z.string()).min(1),
  cc:                 z.array(z.string()).optional(),
  bcc:                z.array(z.string()).optional(),
  subject:            z.string().min(1),
  text:               z.string().optional(),
  html:               z.string().optional(),
  reply_to:           z.string().optional(),
  in_reply_to:        z.string().optional(),
  references:         z.array(z.string()).optional(),
  // Phase 4: confirmation gate. confirmation_token is the 6-digit code the user
  // saw out-of-band (elicit dialog, stderr, or OS toast). dry_run returns a
  // SendPlan without touching SMTP.
  confirmation_token: z.string().regex(/^\d{6}$/).optional(),
  dry_run:            z.boolean().optional().default(false),
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

// ── Phase 4: SendPlan / confirmation helpers ───────────────────────────
// Note: node-notifier is intentionally NOT a declared dependency — see
// package.json. Keeps the bundle <3MB and avoids forcing a native Windows
// toast peer on every user. We dynamically import it; absence is non-fatal.

type ParsedSendParams = z.infer<typeof sendEmailBaseSchema>;

interface SendPlan {
  dry_run: true;
  action: 'send';
  action_fingerprint: string;
  preview: {
    to: string[];
    cc?: string[];
    bcc?: string[];
    subject: string;
    body_first_chars: string;
    body_length_chars: number;
    attachments: never[];
  };
  checks: {
    in_allowlist: string;
    rate_limit_ok: string;
    dedup: string;
  };
  next_step: string;
}

function stripHtmlToText(html: string): string {
  return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

function previewBody(p: ParsedSendParams): { first: string; length: number } {
  const raw = p.text ?? (p.html ? stripHtmlToText(p.html) : '');
  return { first: raw.slice(0, 200), length: (p.text ?? p.html ?? '').length };
}

function buildSendPlan(p: ParsedSendParams, fp: string): SendPlan {
  const body = previewBody(p);
  const plan: SendPlan = {
    dry_run: true,
    action: 'send',
    action_fingerprint: fp,
    preview: {
      to: p.to.map(x => sanitizeForDisplay(x)),
      subject: sanitizeForDisplay(p.subject),
      body_first_chars: wrapUntrusted(sanitizeForDisplay(body.first)),
      body_length_chars: body.length,
      attachments: [],
    },
    checks: {
      in_allowlist: 'pass (allowlist gate runs before dry_run preview)',
      rate_limit_ok: 'deferred to phase 7',
      dedup: 'deferred to phase 7',
    },
    next_step:
      'Call yandex_send_email again WITHOUT dry_run to trigger confirmation. ' +
      'You will receive a 6-digit code via elicit dialog or stderr/OS toast; ' +
      'then call yandex_send_email a third time with confirmation_token=<code>. Code expires in 300s.',
  };
  if (p.cc) plan.preview.cc = p.cc.map(x => sanitizeForDisplay(x));
  if (p.bcc) plan.preview.bcc = p.bcc.map(x => sanitizeForDisplay(x));
  return plan;
}

function buildStderrBlock(p: ParsedSendParams, code: string): string {
  const body = previewBody(p);
  const banner = '═══════════════ CONFIRMATION REQUIRED ═══════════════';
  const footer = '═════════════════════════════════════════════════════';
  const primary = p.to.map(x => sanitizeForDisplay(x)).join(', ');
  return [
    banner,
    'Action: SEND EMAIL',
    `To: ${primary}`,
    `Subject: ${sanitizeForDisplay(p.subject)}`,
    `Body preview: ${wrapUntrusted(sanitizeForDisplay(body.first.slice(0, 80)))}`,
    `Code: ${code} (expires in 5 min)`,
    'Reply with confirmation_token=<code> to proceed.',
    footer,
    '',
  ].join('\n');
}

function verifyResultToError(r: Exclude<VerifyResult, true>): string {
  switch (r) {
    case 'expired': return 'confirmation code expired, request a new one with dry_run:true';
    case 'used':    return 'code already used';
    case 'locked':  return 'locked, retry after 5min';
    case 'wrong':   return 'invalid confirmation code';
  }
}

async function tryNotify(title: string, message: string): Promise<void> {
  try {
    const mod = await import('node-notifier').catch(() => null) as
      | { default?: { notify?: (opts: { title: string; message: string }) => void } }
      | null;
    if (mod && mod.default && typeof mod.default.notify === 'function') {
      mod.default.notify({ title, message });
    }
  } catch { /* opportunistic — never block on absence */ }
}

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
        let body = email.textBody ?? email.htmlBody ?? '(пусто)';
        // Phase 5: prepend untrusted-sender marker INSIDE the wrapUntrusted
        // boundary (per ROADMAP SC #9). ASCII per D-EMOJI-MARKER — no glyph.
        const fromAddr = email.from[0]?.address?.toLowerCase();
        if (fromAddr && !allowlist.isAllowed(fromAddr)) {
          body = `[!UNTRUSTED SENDER: ${sanitizeForDisplay(fromAddr)}]\n` + body;
        }
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

  // 10. Send email (L2) — destructive; Phase 4 confirmation gate active.
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
  references  (string[]?) — цепочка Message-ID для треда
  dry_run  (boolean?) — если true, возвращает SendPlan и НЕ отправляет
  confirmation_token (string?) — 6-цифр код, полученный пользователем
    out-of-band (elicit / stderr / OS toast). Без него send блокируется.`,
    inputSchema: sendEmailBaseSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    requires: { authLevel: 2 },
    handler: async (params, ctx) => {
      try {
        const p = sendEmailBaseSchema.parse(params);
        if (p.text === undefined && p.html === undefined) {
          throw new Error('Укажите хотя бы одно из полей: text или html');
        }

        // ── Phase 5: Allowlist gate ──────────────────────────────────
        // Runs BEFORE the dry_run / confirmation_token / SMTP path so that
        // an untrusted recipient blocks the action immediately — including
        // BCC, which is the primary exfil vector (T-INT-03 / T-05-05).
        // Only enforced at L1+; L0 cannot reach this tool (not registered).
        if (ctx.authLevel >= 1) {
          // Strip optional "Name <addr>" wrapping → pull just the address.
          const extractAddr = (s: string): string => {
            const m = s.match(/<([^>]+)>/);
            return (m?.[1] ?? s).trim().toLowerCase();
          };
          const recipients = [
            ...p.to,
            ...(p.cc ?? []),
            ...(p.bcc ?? []),
          ].map(extractAddr).filter(a => a.length > 0);

          // in_reply_to auto-trust: the SENDER of the looked-up message
          // (envelope.from) is the one auto-trusted — NOT the new recipients
          // (T-05-06). This means in_reply_to does NOT bypass the recipient
          // gate; it only seeds trust for future replies in the same thread.
          if (p.in_reply_to) {
            try {
              const found = await imap.findByMessageId(p.in_reply_to);
              if (found && found.from) {
                allowlist.addTrusted(found.from, 'auto', 'auto_trust_reply');
              }
            } catch {
              // Best-effort — failure to look up the original message must
              // not crash the send; recipient gate below is the real check.
            }
          }

          const untrusted = recipients.filter(a => !allowlist.isAllowed(a));
          if (untrusted.length > 0) {
            const trusted = recipients.filter(a => allowlist.isAllowed(a));
            const trustedStr   = trusted.length   ? trusted.map(sanitizeForDisplay).join(', ')   : '(none)';
            const untrustedStr = untrusted.map(sanitizeForDisplay).join(', ');
            allowlist.auditEmit({
              action: 'untrusted_block',
              untrusted,
              trusted,
              level: ctx.authLevel,
            });
            return {
              content: [{
                type: 'text',
                text:
                  `Send blocked — untrusted recipient(s).\n` +
                  `Trusted (allowed): ${trustedStr}\n` +
                  `Untrusted (blocked): ${untrustedStr}\n` +
                  `To trust: npx yandex-mail-mcp-trust <addr>, then call yandex_trust_address.\n` +
                  `Or send with in_reply_to=<message-id> if replying to existing thread.`,
              }],
              isError: true,
            };
          }
        }

        // Fingerprint over the SEND payload only — not over dry_run /
        // confirmation_token, which are control-plane fields. Strip them
        // before canonicalization so the same logical send maps to the same fp
        // whether the agent is in dry_run / token / direct mode.
        const {
          dry_run: _dr,
          confirmation_token: token,
          ...payload
        } = p;
        const fp = actionFingerprint('send', payload as unknown as Record<string, unknown>);

        // (1) dry_run — return SendPlan, NEVER send.
        if (p.dry_run === true) {
          const plan = buildSendPlan(p, fp);
          return {
            content: [{ type: 'text', text: JSON.stringify(plan, null, 2) }],
            structuredContent: plan as unknown as Record<string, unknown>,
            isError: false,
          };
        }

        // (2) confirmation_token provided — verify and proceed on match.
        if (token !== undefined) {
          const v = verifyCode(fp, token);
          if (v !== true) {
            return errorResult(new Error(verifyResultToError(v)));
          }
          // fall through to send path
        } else {
          // (3) Neither dry_run nor token. Gate by elicitation capability.
          if (ctx.serverContext.canElicit && ctx.serverContext.elicit) {
            // Pre-issue a fallback code so the agent can retry via token path
            // if the elicit times out or the dialog is dismissed.
            const { code, expiresAt } = generateCode(fp);
            const sanitizedTo = p.to.map(x => sanitizeForDisplay(x)).join(', ');
            const bodyPrev = previewBody(p);
            const elicitMessage =
              `Send email?\n` +
              `To: ${sanitizedTo}\n` +
              `Subject: ${sanitizeForDisplay(p.subject)}\n` +
              `Body preview: ${wrapUntrusted(sanitizeForDisplay(bodyPrev.first.slice(0, 200)))}`;
            // Belt-and-braces: also drop the code into stderr in case the
            // client renders elicit but the user prefers the token path. Code
            // is never echoed into MCP content[].
            process.stderr.write(buildStderrBlock(p, code));
            void expiresAt; // expiresAt is informational; not surfaced via elicit
            const result = await ctx.serverContext.elicit({
              message: elicitMessage,
              requestedSchema: {
                type: 'object',
                properties: {
                  confirmed: { type: 'boolean', title: 'Send this email?' },
                },
                required: ['confirmed'],
              },
            });
            if (result.action === 'accept' && result.content?.confirmed === true) {
              // M-1 fix: verifyCode return value MUST gate the send. If the elicit
              // dialog hung past the 5-min TTL the code is 'expired'; if some race
              // burned it elsewhere it is 'used'; we must not silently fall through
              // to send under those conditions. Only proceed on `true`.
              const v = verifyCode(fp, code);
              if (v !== true) {
                return errorResult(new Error(`send blocked: confirmation code ${v} (elicit accepted but code no longer valid)`));
              }
            } else {
              return errorResult(new Error(`send cancelled (elicit action=${result.action})`));
            }
          } else {
            // Path B: no elicitation. Issue code, write stderr block, attempt
            // OS toast, return isError:false with requires_confirmation marker.
            const { code, expiresAt } = generateCode(fp);
            process.stderr.write(buildStderrBlock(p, code));
            const primary = p.to[0] ? sanitizeForDisplay(p.to[0]) : '(unknown)';
            await tryNotify('yandex-mail-mcp', `Confirm send to ${primary}: ${code}`);
            return {
              content: [{
                type: 'text',
                text:
                  'Confirmation required. Verify the action plan in stderr/notification ' +
                  'and re-call yandex_send_email with confirmation_token=<6-digit code>. ' +
                  'Code expires in 300s.',
              }],
              structuredContent: {
                requires_confirmation: true,
                action_fingerprint: fp,
                expires_at: expiresAt,
              },
              isError: false,
            };
          }
        }

        // ── Send path ────────────────────────────────────────
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
,

  // 11. Trust address (L1) — Phase 5 TOFU allowlist write path.
  // Validates a single-use trust_token issued out-of-band by the CLI
  // (`npx yandex-mail-mcp-trust <addr>`). The CLI writes pending-trust.json
  // mode 0600 in getStateDir(); this handler reads it, timing-safe compares,
  // appends to allowlist, then deletes (single-use). 5-min TTL enforced.
  {
    name: 'yandex_trust_address',
    title: 'Доверять адресу для отправки',
    description: `Добавить адрес в allowlist для отправки писем. Требует trust_token,
полученный из терминала через 'npx yandex-mail-mcp-trust <адрес>' (TTL 5 минут).
Args:
  address     (string) — email-адрес для добавления (точное совпадение)
  scope       ('permanent' | 'session', default 'permanent')
  trust_token (string) — 64-hex token из CLI, single-use`,
    inputSchema: trustAddressSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    requires: { authLevel: 1 },
    handler: async (params, _ctx) => {
      try {
        const { address, scope, trust_token } = trustAddressSchema.parse(params);
        const pendingPath = path.join(getStateDir(), 'pending-trust.json');
        if (!fs.existsSync(pendingPath)) {
          return errorResult(new Error(
            'No pending trust request. Run `npx yandex-mail-mcp-trust <addr>` in a terminal first.',
          ));
        }
        let pending: { address: string; scope: string; trust_token: string; expires_at_ms: number };
        try {
          pending = JSON.parse(fs.readFileSync(pendingPath, 'utf-8')) as typeof pending;
        } catch (e) {
          try { fs.unlinkSync(pendingPath); } catch { /* ignore */ }
          return errorResult(new Error(`pending-trust.json is corrupt; deleted. Re-run CLI. (${e instanceof Error ? e.message : String(e)})`));
        }
        if (typeof pending.expires_at_ms !== 'number' || pending.expires_at_ms <= Date.now()) {
          try { fs.unlinkSync(pendingPath); } catch { /* ignore */ }
          return errorResult(new Error('Trust token expired (TTL 5 min). Re-run `npx yandex-mail-mcp-trust <addr>`.'));
        }
        if (pending.address.toLowerCase() !== address.toLowerCase()) {
          // Do NOT echo pending.trust_token — only the address mismatch.
          return errorResult(new Error(`Address mismatch — pending request is for ${sanitizeForDisplay(pending.address)}.`));
        }
        // Length already enforced by schema (.length(64)). Decode both.
        let pBuf: Buffer;
        let aBuf: Buffer;
        try {
          pBuf = Buffer.from(pending.trust_token, 'hex');
          aBuf = Buffer.from(trust_token, 'hex');
        } catch {
          return errorResult(new Error('Invalid trust token (not hex).'));
        }
        if (pBuf.length !== 32 || aBuf.length !== 32 || pBuf.length !== aBuf.length) {
          return errorResult(new Error('Invalid trust token.'));
        }
        if (!timingSafeEqual(pBuf, aBuf)) {
          // Wrong-token attempts do NOT burn the pending slot — TTL bounds replay.
          return errorResult(new Error('Invalid trust token.'));
        }
        allowlist.addTrusted(address, scope, 'user_trust_token');
        try { fs.unlinkSync(pendingPath); } catch { /* ignore */ }
        return {
          content: [{ type: 'text', text: `Адрес ${sanitizeForDisplay(address)} добавлен в allowlist (scope=${scope}).` }],
          structuredContent: { success: true, address: address.toLowerCase(), scope },
        };
      } catch (e) {
        return errorResult(e);
      }
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
