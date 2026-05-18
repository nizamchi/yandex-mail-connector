import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { loadCredentials } from './token.js';
import * as imap from './imap.js';
import { sendEmail } from './smtp.js';

// ── Formatters ─────────────────────────────────────────────

function fmtHeaders(emails: imap.EmailHeader[]): string {
  if (!emails.length) return 'Писем не найдено.';
  return emails.map(e => [
    `UID: ${e.uid}  |  ${e.seen ? '✓прочит.' : '●непрочит.'}${e.flagged ? '  ★' : ''}`,
    `От: ${e.from.map(a => a.name ? `${a.name} <${a.address}>` : a.address).join(', ')}`,
    `Тема: ${e.subject}`,
    `Дата: ${e.date}  |  ${(e.size/1024).toFixed(1)} KB${e.hasAttachments ? '  📎' : ''}`,
  ].join('\n')).join('\n\n──\n\n');
}

function parseSearchDate(s: string, field: string): Date {
  const d = new Date(s);
  if (isNaN(d.getTime())) throw new Error(`Неверная дата для поля ${field}: "${s}"`);
  return d;
}

// ── Tool registration ──────────────────────────────────────

export function registerTools(server: McpServer): void {
  const creds = () => loadCredentials(); // lazy — no crash at startup if token missing

  // 1. List folders
  server.registerTool('yandex_list_folders', {
    title: 'Список папок',
    description: 'Возвращает все IMAP-папки Яндекс.Почты: путь, имя, специальное назначение (Отправленные, Корзина и т.д.).',
    inputSchema: z.object({}).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async () => {
    try {
      const folders = await imap.listFolders(creds());
      return { content: [{ type: 'text', text: JSON.stringify(folders, null, 2) }], structuredContent: { folders } };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true,
      };
    }
  });

  // 2. Folder status
  server.registerTool('yandex_folder_status', {
    title: 'Статус папки',
    description: 'Количество всех писем и непрочитанных в папке. Args: folder (string) — IMAP путь, напр. "INBOX".',
    inputSchema: z.object({ folder: z.string().describe('IMAP путь папки, напр. "INBOX", "Sent"') }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ folder }) => {
    try {
      const s = await imap.folderStatus(creds(), folder);
      return { content: [{ type: 'text', text: JSON.stringify(s, null, 2) }], structuredContent: s };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true,
      };
    }
  });

  // 3. List emails
  server.registerTool('yandex_list_emails', {
    title: 'Список писем',
    description: `Письма в папке с пагинацией, свежие первые. Возвращает заголовки без тела.
Args: folder (default "INBOX"), page (default 1), page_size (1-100, default 20).
Для чтения тела — yandex_get_email по UID.`,
    inputSchema: z.object({
      folder:    z.string().default('INBOX').describe('IMAP папка'),
      page:      z.number().int().min(1).default(1).describe('Страница (1-based)'),
      page_size: z.number().int().min(1).max(100).default(20).describe('Писем на странице'),
    }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async ({ folder, page, page_size }) => {
    try {
      const r = await imap.listEmails(creds(), folder, page, page_size);
      const text = `${r.folder}  |  всего: ${r.total}  |  стр. ${r.page}  |  ещё есть: ${r.hasMore}\n\n${fmtHeaders(r.emails)}`;
      return { content: [{ type: 'text', text }], structuredContent: r };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true,
      };
    }
  });

  // 4. Get email
  server.registerTool('yandex_get_email', {
    title: 'Прочитать письмо',
    description: `Полное содержимое письма по IMAP UID (из yandex_list_emails или yandex_search_emails).
Args: folder (default "INBOX"), uid (integer UID письма).
Тело обрезается на 8000 символах; флаг truncated=true если обрезано.`,
    inputSchema: z.object({
      folder: z.string().default('INBOX'),
      uid:    z.number().int().positive().describe('IMAP UID письма'),
    }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ folder, uid }) => {
    try {
      const email = await imap.getEmail(creds(), folder, uid);
      if (!email) return { content: [{ type: 'text', text: `Письмо UID ${uid} не найдено в ${folder}.` }] };
      const lines = [
        `От: ${email.from.map(a => a.name ? `${a.name} <${a.address}>` : a.address).join(', ')}`,
        `Кому: ${email.to.map(a => a.address).join(', ')}`,
        email.cc.length ? `CC: ${email.cc.map(a => a.address).join(', ')}` : '',
        `Тема: ${email.subject}`,
        `Дата: ${email.date}`,
        `Статус: ${email.seen ? 'Прочитано' : 'Непрочитано'}${email.flagged ? '  ★' : ''}`,
        email.attachments.length ? `Вложения: ${email.attachments.map(a => `${a.filename} (${(a.size/1024).toFixed(1)} KB)`).join(', ')}` : '',
        email.truncated ? '\n⚠ Тело обрезано до 8000 символов.' : '',
        '',
        '─── Тело ───',
        email.textBody ?? email.htmlBody ?? '(пусто)',
      ].filter(Boolean).join('\n');
      return { content: [{ type: 'text', text: lines }], structuredContent: email };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true,
      };
    }
  });

  // 5. Search emails
  server.registerTool('yandex_search_emails', {
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
    inputSchema: z.object({
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
    }).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async ({ folder, max_results, since, before, seen, flagged, ...rest }) => {
    try {
      // Explicit allowlist — avoid passing unknown fields to the IMAP search engine
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

      const emails = await imap.searchEmails(creds(), folder, query, max_results);
      const text = emails.length
        ? `Найдено: ${emails.length}\n\n${fmtHeaders(emails)}`
        : 'Ничего не найдено.';
      return { content: [{ type: 'text', text }], structuredContent: { count: emails.length, emails } };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true,
      };
    }
  });

  // 6. Send email
  server.registerTool('yandex_send_email', {
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
    inputSchema: z.object({
      to:          z.array(z.string()).min(1),
      cc:          z.array(z.string()).optional(),
      bcc:         z.array(z.string()).optional(),
      subject:     z.string().min(1),
      text:        z.string().optional(),
      html:        z.string().optional(),
      reply_to:    z.string().optional(),
      in_reply_to: z.string().optional(),
      references:  z.array(z.string()).optional(),
    }).strict()
      .refine(d => d.text !== undefined || d.html !== undefined, {
        message: 'Укажите хотя бы одно из полей: text или html',
      }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, async (params) => {
    try {
      const r = await sendEmail(creds(), {
        to: params.to, cc: params.cc, bcc: params.bcc,
        subject: params.subject, text: params.text, html: params.html,
        replyTo: params.reply_to, inReplyTo: params.in_reply_to, references: params.references,
      });
      const text = r.success
        ? `Письмо отправлено. Message-ID: ${r.messageId ?? 'n/a'}`
        : `Ошибка отправки: ${r.error}`;
      return { content: [{ type: 'text', text }], structuredContent: r };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true,
      };
    }
  });

  // 7. Move email
  server.registerTool('yandex_move_email', {
    title: 'Переместить письмо',
    description: `Переместить письмо в другую папку.
Args: folder (откуда), uid (UID письма), target_folder (куда, напр. "Spam", "Archive").`,
    inputSchema: z.object({
      folder:        z.string(),
      uid:           z.number().int().positive(),
      target_folder: z.string(),
    }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async ({ folder, uid, target_folder }) => {
    try {
      await imap.moveEmail(creds(), folder, uid, target_folder);
      const text = `UID ${uid}: перемещено из ${folder} в ${target_folder}.`;
      return { content: [{ type: 'text', text }], structuredContent: { success: true } };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true,
      };
    }
  });

  // 8. Delete email
  server.registerTool('yandex_delete_email', {
    title: 'Удалить письмо',
    description: `Удалить письмо. По умолчанию — в корзину (восстановимо).
Args: folder, uid, permanent (bool, default false). permanent=true — безвозвратно.`,
    inputSchema: z.object({
      folder:    z.string().default('INBOX'),
      uid:       z.number().int().positive(),
      permanent: z.boolean().default(false),
    }).strict(),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  }, async ({ folder, uid, permanent }) => {
    try {
      await imap.deleteEmail(creds(), folder, uid, permanent);
      const text = permanent ? `UID ${uid} безвозвратно удалено.` : `UID ${uid} перемещено в Корзину.`;
      return { content: [{ type: 'text', text }], structuredContent: { success: true, permanent } };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true,
      };
    }
  });

  // 9. Mark email
  server.registerTool('yandex_mark_email', {
    title: 'Пометить письмо',
    description: `Изменить статус прочитанности или звёздочки.
Args: folder, uid, seen (bool?), flagged (bool?). Хотя бы один из seen/flagged обязателен.`,
    inputSchema: z.object({
      folder:  z.string().default('INBOX'),
      uid:     z.number().int().positive(),
      seen:    z.boolean().optional(),
      flagged: z.boolean().optional(),
    }).strict().refine(d => d.seen !== undefined || d.flagged !== undefined, {
      message: 'Укажите хотя бы одно из полей: seen или flagged',
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ folder, uid, seen, flagged }) => {
    try {
      await imap.markEmail(creds(), folder, uid, seen, flagged);
      const changes = [
        seen !== undefined ? (seen ? 'прочитано' : 'непрочитано') : '',
        flagged !== undefined ? (flagged ? 'отмечено ★' : 'снята звёздочка') : '',
      ].filter(Boolean).join(', ');
      return { content: [{ type: 'text', text: `UID ${uid}: ${changes}.` }], structuredContent: { success: true } };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true,
      };
    }
  });

  // 10. Get special folders
  server.registerTool('yandex_get_special_folders', {
    title: 'Специальные папки',
    description: 'Возвращает реальные IMAP-пути специальных папок (Входящие, Отправленные, Черновики, Корзина, Спам). На русскоязычных аккаунтах Яндекса папки могут называться "Удалённые", "Отправленные" и т.д. — используйте этот инструмент, чтобы узнать правильные имена перед операциями с папками.',
    inputSchema: z.object({}).strict(),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async () => {
    try {
      const folders = await imap.getSpecialFolders(creds());
      const text = [
        `Входящие:    ${folders.inbox}`,
        `Отправленные: ${folders.sent}`,
        `Черновики:   ${folders.drafts}`,
        `Корзина:     ${folders.trash}`,
        `Спам:        ${folders.spam}`,
      ].join('\n');
      return { content: [{ type: 'text', text }], structuredContent: folders };
    } catch (e) {
      return {
        content: [{ type: 'text', text: `Ошибка: ${e instanceof Error ? e.message : String(e)}` }],
        isError: true,
      };
    }
  });
}
