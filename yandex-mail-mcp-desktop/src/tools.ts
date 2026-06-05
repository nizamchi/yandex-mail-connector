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
//   So any tool listing required capabilities will be skipped -- by design -- until
//   Layer 2 wires real capability detection. No L1 tool requires a capability.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { loadCredentials } from './token.js';
import * as imap from './imap.js';
import { aggregate, type GroupByField, type EnvelopeRow } from './stats.js';
import * as mailIndex from './mail-index.js';
import { sendEmail } from './smtp.js';
import { sanitizeForDisplay, wrapUntrusted, sanitizeError } from './sanitize.js';
import { generateCode, verifyCode, actionFingerprint, type VerifyResult } from './confirm.js';
import type { AuthLevel, Capability } from './auth.js';
import * as allowlist from './allowlist.js';
import { getStateDir } from './state-dir.js';
import * as policy from './policy.js';
import { auditLog, auditLogAction, EMAIL_ACTIONS, subjectHash } from './audit.js';
import { enforceSendGuards, recordSend, isAdvisory, is2FASender, isProtectedFolder, type GuardResult } from './guards.js';
import { normalizeRecipients, validateNoSmuggling } from './recipients.js';
import * as provenance from './provenance.js';
import { sendEmailBaseSchema } from './send-schemas.js';
import {
  runPipeline,
  type SendContext,
  type PipelineResult,
} from './send-pipeline.js';

// Domain extraction helper used by guard audit records (D-RECIP-DOMAINS: never
// log raw recipient addresses; domains-only for forensics correlation).
function domainOnly(addr: string): string {
  const trimmed = addr.trim();
  const m = trimmed.match(/<([^>]+)>/);
  const bare = (m?.[1] ?? trimmed).toLowerCase();
  const at = bare.lastIndexOf('@');
  return at >= 0 ? bare.slice(at + 1) : '(unknown)';
}

// Human-readable error message for the guard violation reasons. Exhaustive
// switch with never assertion: if a new GuardResult variant ships in Layer 2+
// the compile-time-ish reminder fires here (esbuild won't catch it, but the
// pattern documents the contract for the next maintainer).
function errorTextFor(g: Extract<GuardResult, { ok: false }>): string {
  switch (g.reason) {
    case 'daily_send_limit_exceeded':
      return 'daily_send_limit_exceeded: limit=' + g.limit + ', remaining=' + g.remaining +
        '. Wait ~24h or raise YANDEX_DAILY_SEND_LIMIT.';
    case 'per_recipient_rate_limit':
      return 'per_recipient_rate_limit: recipient=' + g.recipient + ', limit=' + g.limit +
        '/hour, retry_after=' + g.retryAfter.toISOString() + '.';
    case 'duplicate_send_within_window':
      return 'duplicate_send_within_window: window=' + g.windowSec +
        's. The same send was already submitted recently. Adjust subject/body or wait the window out.';
    default: {
      const _exhaustive: never = g;
      return 'guard_violation_unknown: ' + String(_exhaustive);
    }
  }
}

// Helper for protected-folder gate (used by move_email and delete_email).
// Returns the canonical entry from the set (preserves operator casing) so the
// audit + error message echo the configured path verbatim.
function checkProtectedFolder(folder: string, protectedSet: ReadonlySet<string>): { blocked: boolean; matched: string | null } {
  if (!isProtectedFolder(folder, protectedSet)) return { blocked: false, matched: null };
  const target = folder.toLowerCase();
  for (const entry of protectedSet) {
    if (entry.toLowerCase() === target) return { blocked: true, matched: entry };
  }
  return { blocked: true, matched: folder };
}

// ── Formatters ─────────────────────────────────────────────

// Address part из IMAP envelope считаем syntactically valid и НЕ sanitize-уем
// (это сломает legitimate '+' / '.' / '@'). Display-name -- untrusted, sanitize.
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
  // src/index.ts). Handlers MUST NOT read it at registration time -- only at
  // tool-call time, which is guaranteed to follow `notifications/initialized`
  // per MCP protocol. The bag is mutated in place; the reference is shared.
  serverContext: {
    canElicit: boolean;
    elicit?: ElicitFn;
  };
  // Phase 7: protected-folder set resolved ONCE at startup
  // (resolveProtectedFolders in guards.ts) and threaded through here. Empty
  // Set is acceptable for L0 callers; gate firing happens only at L1+ inside
  // the move/delete handlers.
  protectedFolders: ReadonlySet<string>;
}

// Internal handler return shape -- extends the SDK-visible shape with an
// _audit channel used by wrapWithAudit (Phase 6 Hook-2). The wrapper strips
// _audit BEFORE returning to the SDK so the channel never reaches MCP clients.
export interface HandlerAuditExtras {
  message_id?: string;
  folder?: string;
  uid?: number;
  recipients?: string[];
  subject_hash?: string;
  body_length?: number;
  from_domain?: string;
}

export interface HandlerResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: unknown;
  isError?: boolean;
  _audit?: HandlerAuditExtras;
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
  /** Optional MCP _meta passed through to registerTool. Used to raise the
   *  per-tool result-size cap for tools that legitimately return large outputs
   *  (e.g. `anthropic/maxResultSizeChars` on list/search/get-email). */
  meta?: Record<string, unknown>;
  requires: { authLevel: AuthLevel; capabilities?: Capability[] };
  handler: (
    params: unknown,
    ctx: ToolCtx,
  ) => Promise<HandlerResult>;
}

// creds() is a lazy loader -- used by every handler. Module scope is safe because
// loadCredentials() itself is side-effect-free until invoked (it reads token.json
// at call time, not at import time). Putting it here removes per-call closure
// overhead and avoids re-creating the lambda inside registerTools.
const creds = (): ReturnType<typeof loadCredentials> => loadCredentials();

// Narrow helper to format the error path consistently across handlers.
function errorResult(e: unknown): HandlerResult {
  return {
    content: [{ type: 'text', text: `Ошибка: ${sanitizeError(e)}` }],
    isError: true,
  };
}

// wrapWithAudit (Phase 6) -- wraps every handler so each tool call emits an
// 'attempt' audit record on entry and a 'success' | 'denied' | 'error' record
// on exit. Reads handler-returned _audit extras and forwards them (incl. the
// mandatory message_id for EMAIL_ACTIONS -- enforced by audit.ts on the
// receiving side). Strips _audit from the SDK return shape so the channel
// never leaks to MCP clients.
//
// Declarative invariant: wrapping happens at the TOOLS export site
// (TOOLS = [...].map(wrapWithAudit) BEFORE Object.freeze) -- registerTools()
// continues to iterate TOOLS and call exactly ONE server.registerTool per
// visible def. Greppable.
function wrapWithAudit(def: ToolDef): ToolDef {
  return {
    ...def,
    handler: async (params, ctx) => {
      const action = def.name;
      void EMAIL_ACTIONS; // referenced by audit.ts; kept here for readability
      auditLogAction(action, 'attempt', { reason: 'level=' + ctx.authLevel });
      try {
        const r = await def.handler(params, ctx);
        const status: 'success' | 'denied' = r.isError ? 'denied' : 'success';
        const extras = r._audit ?? {};
        auditLogAction(action, status, {
          folder: extras.folder,
          uid: extras.uid,
          message_id: extras.message_id,
          recipients: extras.recipients,
          subject_hash: extras.subject_hash,
          body_length: extras.body_length,
          from_domain: extras.from_domain,
        });
        // Strip _audit before returning to SDK.
        const { _audit: _drop, ...sdkResult } = r;
        void _drop;
        return sdkResult;
      } catch (e) {
        auditLogAction(action, 'error', {
          reason: e instanceof Error ? e.message.slice(0, 200) : String(e).slice(0, 200),
        });
        throw e;
      }
    },
  };
}

// ── Tool definitions ───────────────────────────────────────

// Input schemas are declared once and reused -- both as the SDK-facing inputSchema
// and to type the handler's params via z.infer. This is the only safe way to
// avoid `any` in handler params without losing the runtime validation that the
// SDK performs against inputSchema before invoking the handler.

const listFoldersSchema = z.object({}).strict();
const healthCheckSchema = z.object({}).strict();
const folderStatusSchema = z.object({
  folder: z.string().describe('IMAP путь папки, напр. "INBOX", "Sent"'),
}).strict();
const listEmailsSchema = z.object({
  folder:    z.string().default('INBOX').describe('IMAP папка'),
  page:      z.number().int().min(1).default(1).describe('Страница (1-based)'),
  page_size: z.number().int().min(1).max(100).default(20).describe('Писем на странице'),
  summary_only: z.boolean().default(false).describe(
    'Если true -- возвращает только {uid, from_email, date, subject_first_50} вместо полного заголовка. Снижает вес в токенах ~3-5x.',
  ),
}).strict();
const GROUP_BY_FIELDS = [
  'sender', 'sender_name', 'domain',
  'year', 'month', 'year_month', 'weekday', 'hour', 'date',
  'to_first',
  'subject_prefix', 'subject_normalized',
  'size_bucket', 'has_attachments',
  'flag_seen', 'flag_flagged',
] as const;
const findSenderSchema = z.object({
  query:       z.string().min(1).describe('Имя, часть имени или часть адреса (подстрока). Пример: "Катя", "ivan", "@company.ru"'),
  folder:      z.string().default('INBOX').describe('IMAP папка для поиска'),
  max_senders: z.number().int().min(1).max(100).default(20).describe('Максимум кандидатов в ответе'),
}).strict();
const searchFastSchema = z.object({
  query:  z.string().optional().describe('Слова из темы или имени/адреса отправителя. Кириллица поддерживается. Можно опустить, если задан хотя бы один фильтр.'),
  folder: z.string().optional().describe('Ограничить поиск одной папкой; по умолчанию все проиндексированные'),
  limit:  z.number().int().min(1).max(100).optional().describe('Максимум результатов (default 20)'),
  from:   z.string().optional().describe('Фильтр: фрагмент адреса/имени отправителя'),
  since:  z.string().optional().describe('Фильтр: ISO дата, напр. "2025-03-01" -- письма не раньше этой даты (включительно)'),
  before: z.string().optional().describe('Фильтр: ISO дата -- письма строго раньше этой даты'),
  seen:   z.boolean().optional().describe('Фильтр: true=только прочитанные, false=только непрочитанные'),
  flagged:z.boolean().optional().describe('Фильтр: true=только со звёздочкой, false=только без'),
}).strict();
const getThreadSchema = z.object({
  query:  z.string().min(1).describe('Слова из темы письма, тред которого нужен'),
  folder: z.string().optional(),
  limit:  z.number().int().min(1).max(100).optional(),
}).strict();
const countEmailsSchema = z.object({
  folder:  z.string().default('INBOX'),
  from:    z.string().optional(),
  to:      z.string().optional(),
  subject: z.string().optional(),
  text:    z.string().optional(),
  since:   z.string().optional().describe('ISO дата начала, напр. "2025-01-01"'),
  before:  z.string().optional().describe('ISO дата конца'),
  seen:    z.boolean().optional().describe('true=только прочитанные, false=только непрочитанные'),
  flagged: z.boolean().optional().describe('true=только со звёздочкой'),
}).strict();
const folderPeekSchema = z.object({
  folders: z.array(z.string()).optional().describe('Список папок. Если не задан — все папки ящика.'),
}).strict();
const statsSchema = z.object({
  folder: z.string().default('INBOX').describe('IMAP папка для сканирования'),
  group_by: z.array(z.enum(GROUP_BY_FIELDS)).min(1).max(3)
    .describe('Поля группировки (1-3). См. описание инструмента для списка.'),
  since: z.string().optional().describe('ISO дата начала диапазона (включительно), напр. "2025-01-01"'),
  until: z.string().optional().describe('ISO дата конца диапазона (включительно)'),
  top_n: z.number().int().min(1).max(1000).default(50).describe('Максимум строк в результате'),
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
  // R7 (v2.6.0): permanent (irreversible) delete requires a server-issued
  // one-time code. Recoverable trash-delete (permanent=false) ignores this.
  // Same 6-digit shape as yandex_send_email's confirmation_token.
  confirmation_token: z.string().regex(/^\d{6}$/).optional(),
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

// Note: sendEmailBaseSchema lives in src/send-schemas.ts (Phase 6 B-3/B-7) so
// both tools.ts and send-pipeline.ts can import the canonical schema without
// creating a cycle. The schema includes B-1 per-array refinements + Phase 6
// override_token field. validateNoSmuggling is still imported above for
// handler-internal defense-in-depth, but the schema-side refiner is owned by
// send-schemas.ts.
void validateNoSmuggling;
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
// Note: node-notifier is intentionally NOT a declared dependency -- see
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
  // H-2 FIX: guards-pure status surfaces in dry_run output so the user
  // can see "47/50 daily, 0/5 per-recipient, no dedup hit" BEFORE consuming
  // any confirmation code. When guards.ok=false the field carries the
  // blocking reason and NO confirmation_token is issued (Q1 = yes, Q2 = no).
  guard_status?: { ok: true };
  guard_violation?:
    | { reason: 'daily_send_limit_exceeded'; remaining: number; limit: number }
    | { reason: 'per_recipient_rate_limit'; recipient: string; retry_after: string; limit: number }
    | { reason: 'duplicate_send_within_window'; window_sec: number };
  next_step: string;
}

function stripHtmlToText(html: string): string {
  return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

function previewBody(p: ParsedSendParams): { first: string; length: number } {
  const raw = p.text ?? (p.html ? stripHtmlToText(p.html) : '');
  return { first: raw.slice(0, 200), length: (p.text ?? p.html ?? '').length };
}

function buildSendPlan(p: ParsedSendParams, fp: string, guard?: GuardResult): SendPlan {
  // H-2 FIX SENTINEL v1: when guard is provided, surface it in the plan so
  // dry_run callers see the gate decision BEFORE the confirmation step. ok=true
  // -> guard_status snapshot (Q1 = yes); ok=false -> guard_violation field +
  // NO confirmation_token issued downstream (Q2 = no).
  const body = previewBody(p);
  const rateOk = guard !== undefined && guard.ok === true
    ? 'pass (guards-pure: daily + per-recipient + dedup)'
    : 'not evaluated (guard state unavailable)';
  const dedupOk = guard !== undefined && guard.ok === true
    ? 'pass (no fingerprint hit in dedup window)'
    : 'not evaluated (guard state unavailable)';
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
      rate_limit_ok: rateOk,
      dedup: dedupOk,
    },
    next_step:
      'Call yandex_send_email again WITHOUT dry_run to trigger confirmation. ' +
      'You will receive a 6-digit code via elicit dialog or stderr/OS toast; ' +
      'then call yandex_send_email a third time with confirmation_token=<code>. Code expires in 300s.',
  };
  if (p.cc) plan.preview.cc = p.cc.map(x => sanitizeForDisplay(x));
  if (p.bcc) plan.preview.bcc = p.bcc.map(x => sanitizeForDisplay(x));
  if (guard !== undefined) {
    if (guard.ok) {
      plan.guard_status = { ok: true };
    } else {
      switch (guard.reason) {
        case 'daily_send_limit_exceeded':
          plan.guard_violation = {
            reason: 'daily_send_limit_exceeded',
            remaining: guard.remaining,
            limit: guard.limit,
          };
          plan.next_step =
            'Send blocked by daily limit (' + guard.limit + '/day). Wait ~24h or raise ' +
            'YANDEX_DAILY_SEND_LIMIT, then re-run dry_run to get a fresh confirmation code.';
          break;
        case 'per_recipient_rate_limit':
          plan.guard_violation = {
            reason: 'per_recipient_rate_limit',
            recipient: guard.recipient,
            retry_after: guard.retryAfter.toISOString(),
            limit: guard.limit,
          };
          plan.next_step =
            'Send blocked by per-recipient rate limit (' + guard.limit + '/hour for ' + guard.recipient +
            '). Retry after ' + guard.retryAfter.toISOString() + ', then re-run dry_run.';
          break;
        case 'duplicate_send_within_window':
          plan.guard_violation = {
            reason: 'duplicate_send_within_window',
            window_sec: guard.windowSec,
          };
          plan.next_step =
            'Send blocked: identical fingerprint already submitted within the ' + guard.windowSec +
            's dedup window. Adjust subject/body or wait the window out, then re-run dry_run.';
          break;
      }
    }
  }
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
  } catch { /* opportunistic -- never block on absence */ }
}

// ── Phase 6 driver helpers (D4) -- keep handler body <= 60 LOC ────────

function renderDryRunPlan(p: ParsedSendParams, _ctx: ToolCtx): HandlerResult {
  const toNorm  = normalizeRecipients(p.to);
  const ccNorm  = normalizeRecipients(p.cc);
  const bccNorm = normalizeRecipients(p.bcc);
  const payload: Record<string, unknown> = {
    to: toNorm.normalized,
    subject: p.subject,
  };
  if (ccNorm.normalized.length > 0)  payload.cc  = ccNorm.normalized;
  if (bccNorm.normalized.length > 0) payload.bcc = bccNorm.normalized;
  if (p.text !== undefined)        payload.text        = p.text;
  if (p.html !== undefined)        payload.html        = p.html;
  if (p.reply_to !== undefined)    payload.reply_to    = p.reply_to;
  if (p.in_reply_to !== undefined) payload.in_reply_to = p.in_reply_to;
  if (p.references !== undefined)  payload.references  = p.references;
  const fp = actionFingerprint('send', payload);
  const guardPayload = {
    to: toNorm.normalized,
    cc:  ccNorm.normalized.length  > 0 ? ccNorm.normalized  : undefined,
    bcc: bccNorm.normalized.length > 0 ? bccNorm.normalized : undefined,
  };
  const guardVerdict = enforceSendGuards(guardPayload, _ctx.authLevel, fp);
  const plan = buildSendPlan(p, fp, guardVerdict);
  return {
    content: [{ type: 'text', text: JSON.stringify(plan, null, 2) }],
    structuredContent: plan as unknown as Record<string, unknown>,
    isError: false,
    _audit: {
      recipients: p.to.map(a => a.split('@')[1] ?? a),
      subject_hash: subjectHash(p.subject),
      body_length: (p.text ?? p.html ?? '').length,
      message_id: '<dry-run-no-message-id>',
    },
  };
}

async function renderPipelineResult(
  result: PipelineResult,
  ctx: ToolCtx,
  rawParams: unknown,
): Promise<HandlerResult> {
  if (result.kind === 'success') {
    const r = result.ctx.sendResult!;
    const inp = result.ctx.input!;
    const text = r.success
      ? `Письмо отправлено. Message-ID: ${r.messageId ?? 'n/a'}`
      : `Ошибка отправки: ${r.error}`;
    return {
      content: [{ type: 'text', text }],
      structuredContent: r,
      _audit: {
        recipients: inp.to.map(a => a.split('@')[1] ?? a),
        subject_hash: subjectHash(inp.subject),
        body_length: (inp.text ?? inp.html ?? '').length,
        message_id: r.messageId && r.messageId.length > 0
          ? r.messageId
          : '<send-failed-no-message-id>',
      },
    };
  }
  if (result.kind === 'block') {
    const inp = result.ctx.input;
    const reasonText = result.audit.reason ?? result.reason;
    return {
      content: [{ type: 'text', text: 'Send blocked: ' + reasonText }],
      isError: true,
      _audit: {
        recipients: inp?.to.map(a => a.split('@')[1] ?? a) ?? [],
        subject_hash: inp ? subjectHash(inp.subject) : '',
        body_length: inp ? (inp.text ?? inp.html ?? '').length : 0,
        message_id: '<blocked-no-message-id>',
      },
    };
  }
  // kind === 'pending' -- only confirmation_code is emitted today.
  if (result.requires.kind !== 'confirmation_code') {
    return { content: [{ type: 'text', text: 'Pending requirement unsupported' }], isError: true };
  }
  const inp = result.ctx.input!;
  const fp = result.requires.actionFingerprint;
  const expiresAt = result.requires.expiresAt;
  if (ctx.serverContext.canElicit && ctx.serverContext.elicit) {
    // Mint a fresh code (rotates the prior pipeline-minted code for the same fp).
    const gen = generateCode(fp);
    process.stderr.write(buildStderrBlock(inp, gen.code ?? '<no-code>'));
    const sanitizedTo = inp.to.map(x => sanitizeForDisplay(x)).join(', ');
    const elicitResult = await ctx.serverContext.elicit({
      message:
        `Send email?\n` +
        `To: ${sanitizedTo}\n` +
        `Subject: ${sanitizeForDisplay(inp.subject)}\n` +
        `Body preview: ${wrapUntrusted(sanitizeForDisplay(previewBody(inp).first.slice(0, 200)))}`,
      requestedSchema: {
        type: 'object',
        properties: { confirmed: { type: 'boolean', title: 'Send this email?' } },
        required: ['confirmed'],
      },
    });
    if (elicitResult.action === 'accept' && elicitResult.content?.confirmed === true) {
      const replayParams = { ...(rawParams as Record<string, unknown>), confirmation_token: gen.code };
      const replayCtx: SendContext = {
        rawParams: replayParams,
        authLevel: ctx.authLevel,
        nowMs: Date.now(),
      };
      const replay = await runPipeline(replayCtx);
      return renderPipelineResult(replay, ctx, replayParams);
    }
    return {
      ...errorResult(new Error(`send cancelled (elicit action=${elicitResult.action})`)),
      _audit: {
        recipients: inp.to.map(a => a.split('@')[1] ?? a),
        subject_hash: subjectHash(inp.subject),
        body_length: (inp.text ?? inp.html ?? '').length,
        message_id: '<blocked-no-message-id>',
      },
    };
  }
  // Path B: no elicit support. Mint a fresh code, write stderr, OS toast.
  const gen = generateCode(fp);
  process.stderr.write(buildStderrBlock(inp, gen.code ?? '<no-code>'));
  const primary = inp.to[0] ? sanitizeForDisplay(inp.to[0]) : '(unknown)';
  await tryNotify('yandex-mail-mcp', `Confirm send to ${primary}: ${gen.code ?? ''}`);
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
    _audit: {
      recipients: inp.to.map(a => a.split('@')[1] ?? a),
      subject_hash: subjectHash(inp.subject),
      body_length: (inp.text ?? inp.html ?? '').length,
      message_id: '<blocked-no-message-id>',
    },
  };
}

// readonly array + Object.freeze at module bottom keeps the declarative
// invariant enforceable: runtime mutation of TOOLS would throw in strict
// mode (which esbuild emits by default). Defence-in-depth against any
// future code that might try to push extra entries after import.
const TOOLS_RAW: ToolDef[] = [
  // 0. Health check (L0) — server-side self-diagnostic. v2.1.4. Does NOT touch
  // IMAP/SMTP. Returns the same set of facts that `node bundle --check` prints
  // to stderr at startup, but accessible from inside an MCP session. Useful
  // for an agent verifying the connector is healthy before doing actual work.
  {
    name: 'yandex_health_check',
    title: 'Состояние коннектора',
    description: 'Self-diagnostic: версия, auth level, state-dir, token.json (тип учётных данных), allowlist signature, policy file. НЕ обращается к IMAP/SMTP — для сетевой проверки запусти `node dist/yandex-mail-mcp.js --check`. Используй когда нужно понять что не работает или что используется по умолчанию.',
    inputSchema: healthCheckSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    requires: { authLevel: 0 },
    handler: async (_params, ctx) => {
      const report: Record<string, unknown> = {
        server_version: '2.7.1',
        auth_level: ctx.authLevel,
        capabilities: Array.from(ctx.capabilities),
        platform: process.platform,
        node: process.version,
      };

      // state-dir
      try { report.state_dir = getStateDir(); }
      catch (e) { report.state_dir = { error: e instanceof Error ? e.message : String(e) }; }

      // token shape (does NOT call loadCredentials — that throws on missing;
      // here we want to report state, not gate on it)
      try {
        const stateDir = getStateDir();
        const tokenPath = (process.env.YANDEX_TOKEN_FILE && process.env.YANDEX_TOKEN_FILE.length > 0)
          ? process.env.YANDEX_TOKEN_FILE
          : `${stateDir}/token.json`;
        if (fs.existsSync(tokenPath)) {
          const raw = JSON.parse(fs.readFileSync(tokenPath, 'utf8')) as Record<string, unknown>;
          let kind: string;
          if (raw.password || raw.pass) kind = 'app_password (explicit field)';
          else if (typeof raw.access_token === 'string' && raw.access_token.startsWith('y0_')) kind = 'oauth';
          else if (typeof raw.access_token === 'string' && /^[a-z]{16}$/.test(raw.access_token)) kind = 'app_password (legacy field, heuristic)';
          else kind = 'unknown';
          report.token = { found: true, path: tokenPath, kind, email: raw.email ?? null };
        } else {
          // fallback to env vars
          if (process.env.YANDEX_APP_PASSWORD && process.env.YANDEX_EMAIL) {
            report.token = { found: true, source: 'env', kind: 'app_password', email: process.env.YANDEX_EMAIL };
          } else if (process.env.YANDEX_OAUTH_TOKEN && process.env.YANDEX_EMAIL) {
            report.token = { found: true, source: 'env', kind: 'oauth', email: process.env.YANDEX_EMAIL };
          } else {
            report.token = { found: false, hint: 'no token.json and no YANDEX_APP_PASSWORD/YANDEX_OAUTH_TOKEN env' };
          }
        }
      } catch (e) {
        report.token = { error: e instanceof Error ? e.message : String(e) };
      }

      // allowlist
      try {
        const apath = allowlist.getAllowlistPath();
        if (fs.existsSync(apath)) {
          const valid = allowlist.verifySignature();
          let count = 0;
          try {
            const raw = JSON.parse(fs.readFileSync(apath, 'utf8')) as { entries?: unknown[] };
            if (Array.isArray(raw.entries)) count = raw.entries.length;
          } catch { /* ignore — keep count=0 */ }
          report.allowlist = { path: apath, signature_valid: valid, trusted_count: count };
        } else {
          report.allowlist = { path: apath, exists: false, hint: 'created on first L1+ start' };
        }
      } catch (e) {
        report.allowlist = { error: e instanceof Error ? e.message : String(e) };
      }

      // policy
      try {
        const ppath = policy.getPolicyPath();
        if (fs.existsSync(ppath)) {
          // Parse JSON only; signature check at this layer would require
          // a new public API in policy.ts. Report exists+JSON-parseable.
          JSON.parse(fs.readFileSync(ppath, 'utf8'));
          report.policy = { path: ppath, exists: true, parseable: true };
        } else {
          report.policy = { path: ppath, exists: false, hint: 'bootstrapped on first startup' };
        }
      } catch (e) {
        report.policy = { error: e instanceof Error ? e.message : String(e) };
      }

      const text = JSON.stringify(report, null, 2);
      return { content: [{ type: 'text', text }], structuredContent: report };
    },
  },

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
    description: 'Количество всех писем и непрочитанных в папке. Args: folder (string) -- IMAP путь, напр. "INBOX".',
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

  // 3. List emails (L0) -- UID pagination (Phase 2 BUG-01)
  {
    name: 'yandex_list_emails',
    title: 'Список писем',
    description: `Письма в папке с пагинацией, свежие первые. Возвращает заголовки без тела.
Args: folder (default "INBOX"), page (default 1), page_size (1-100, default 20), summary_only (bool, default false).
Для чтения тела -- yandex_get_email по UID.
НЕ используй чтобы найти письма по критерию (отправитель/тема/дата) -- используй yandex_search_emails.
НЕ используй чтобы посчитать письма -- используй yandex_count или yandex_stats.
НЕ загружай много страниц подряд чтобы проанализировать ящик -- используй yandex_stats.`,
    inputSchema: listEmailsSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    // v2.1.3: raise per-tool output cap. Default Claude Code limit is ~25k tokens
    // (~100k chars). A 20-email page with full envelopes/subjects easily exceeds
    // that on chatty mailboxes — raise to 200k chars so headers aren't truncated.
    meta: { 'anthropic/maxResultSizeChars': 200_000 },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { folder, page, page_size, summary_only } = listEmailsSchema.parse(params);
        const r = await imap.listEmails(folder, page, page_size);
        if (summary_only) {
          const slim = r.emails.map(e => ({
            uid: e.uid,
            from_email: e.from[0]?.address ?? '',
            date: e.date,
            subject_first_50: (e.subject ?? '').slice(0, 50),
          }));
          const text = `${r.folder}  |  всего: ${r.total}  |  стр. ${r.page}  |  ещё есть: ${r.hasMore}  |  summary_only\n\n` +
            (slim.length
              ? slim.map(s => `UID ${s.uid}  ${s.date}  ${sanitizeForDisplay(s.from_email)}  | ${sanitizeForDisplay(s.subject_first_50)}`).join('\n')
              : 'Писем не найдено.');
          return {
            content: [{ type: 'text', text }],
            structuredContent: { folder: r.folder, total: r.total, page: r.page, pageSize: r.pageSize, hasMore: r.hasMore, summary_only: true, emails: slim },
          };
        }
        const text = `${r.folder}  |  всего: ${r.total}  |  стр. ${r.page}  |  ещё есть: ${r.hasMore}\n\n${fmtHeaders(r.emails)}`;
        return { content: [{ type: 'text', text }], structuredContent: r };
      } catch (e) { return errorResult(e); }
    },
  },

  // 4. Get email (L0) -- Phase 2 wrapUntrusted + sanitizeForDisplay
  {
    name: 'yandex_get_email',
    title: 'Прочитать письмо',
    description: `Полное содержимое письма по IMAP UID (из yandex_list_emails или yandex_search_emails).
Args: folder (default "INBOX"), uid (integer UID письма).
Тело обрезается на 8000 символах; флаг truncated=true если обрезано.
НЕ вызывай в цикле по многим письмам -- сначала сузь список через yandex_search_emails или yandex_stats.
НЕ вызывай чтобы узнать тему/отправителя -- эти данные уже есть в yandex_list_emails / yandex_search_emails.`,
    inputSchema: getEmailSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    // v2.1.3: same rationale as list_emails — single full email body + headers
    // can hit ~50k chars on rich messages. Cap raised to 200k to be safe.
    meta: { 'anthropic/maxResultSizeChars': 200_000 },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { folder, uid } = getEmailSchema.parse(params);
        const email = await imap.getEmail(folder, uid);
        if (!email) {
          // No email → Hook-2 sentinel so the audit layer doesn't fire a
          // schema-violation on a benign not-found.
          return {
            content: [{ type: 'text', text: `Письмо UID ${uid} не найдено в ${folder}.` }],
            _audit: { folder, uid, message_id: '<not-found-no-message-id>' },
          };
        }
        // PMLF-PROV-04: record read provenance (RAM-only, never persisted).
        // SINGLE call site -- placed BEFORE the is2FASender branch diverges so
        // both the 2FA-redacted return and the standard return inherit the
        // same record-before-return guarantee. DO NOT place recordRead inside
        // catch blocks, after auditLog (which can throw on disk-full / EROFS),
        // or after side-effect-ful sync ops -- read-record discipline must be
        // exception-safe (B-1 fix).
        provenance.recordRead(
          email.messageId && email.messageId.length > 0
            ? email.messageId
            : '<no-message-id-uid-' + uid + '>',
          { folder, uid }
        );
        // Phase 7: 2FA-sender redaction. PRIORITY: this short-circuit fires
        // BEFORE the Phase 5 untrusted-sender marker logic (information
        // disclosure is the higher-severity threat -- a 2FA code in LLM
        // context = third-party account takeover). The stub body is wrapped
        // in wrapUntrusted to preserve the Phase 2 boundary marker invariant
        // (even REDACTED placeholders flow through the consistent envelope so
        // the consuming LLM never sees a bare instruction-shaped payload).
        // body_length and subject_hash are deliberately omitted from _audit
        // -- those length/hash signals would leak side-channel info (a
        // 6-digit code has a known body_length signature). T-07-10.
        // NOTE (T-07-14): redaction is leak-PREVENTION, not authenticity. An
        // attacker who controls the From header could forge a 2FA-sender
        // domain to deliberately trigger redaction and hide phishing payload.
        // SPF/DKIM verification is out of scope for Layer 1.
        const fromAddrRaw = email.from[0]?.address ?? null;
        if (is2FASender(fromAddrRaw)) {
          const fromDomain = domainOnly(fromAddrRaw ?? '');
          auditLog({
            action: 'yandex_get_email',
            status: 'denied',
            level: 'warn',
            ts: new Date().toISOString(),
            reason: '2fa_sender_redacted',
            folder,
            uid,
            message_id: email.messageId && email.messageId.length > 0 ? email.messageId : '<not-found-no-message-id>',
            from_domain: fromDomain,
            redacted: ['body', 'subject_hash', 'body_length'],
          });
          // Stub body string: exactly '[REDACTED - 2FA sender]' with ASCII
          // hyphen-minus (U+002D). NOT em-dash U+2014. CLAUDE.md ASCII rule;
          // Task 7 grep gate enforces. subject is sanitizeForDisplay'd even
          // here -- defence-in-depth against control-char smuggling.
          return {
            content: [{
              type: 'text',
              text:
                `От: ${sanitizeForDisplay(fromAddrRaw ?? '(unknown)')}\n` +
                `Тема: ${sanitizeForDisplay(email.subject ?? '')}\n` +
                `Дата: ${email.date ?? ''}\n` +
                wrapUntrusted('[REDACTED - 2FA sender]'),
            }],
            _audit: {
              folder,
              uid,
              message_id: email.messageId && email.messageId.length > 0 ? email.messageId : '<not-found-no-message-id>',
              from_domain: fromDomain,
              // body_length + subject_hash deliberately omitted (side-channel).
            },
          };
        }
        let body = email.textBody ?? email.htmlBody ?? '(пусто)';
        // Phase 5: prepend untrusted-sender marker INSIDE the wrapUntrusted
        // boundary (per ROADMAP SC #9). ASCII per D-EMOJI-MARKER -- no glyph.
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
        // structuredContent -- для programmatic клиентов (не подвержены
        // prompt injection); body отдаётся raw без markers сознательно.
        const _bodyLen = (email.textBody ?? email.htmlBody ?? '').length;
        const _fromDomain = (email.from[0]?.address ?? '').split('@')[1] ?? '(unknown)';
        return {
          content: [{ type: 'text', text: lines }],
          structuredContent: email,
          _audit: {
            folder,
            uid,
            message_id: email.messageId && email.messageId.length > 0 ? email.messageId : '<not-found-no-message-id>',
            subject_hash: subjectHash(email.subject),
            body_length: _bodyLen,
            from_domain: _fromDomain,
          },
        };
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
  from   (string?) -- фрагмент адреса/имени отправителя
  to     (string?) -- фрагмент адреса получателя
  subject(string?) -- фрагмент темы
  text   (string?) -- полнотекстовый поиск в теле
  since  (string?) -- ISO дата, напр. "2025-01-01"
  before (string?) -- ISO дата
  seen   (boolean?) -- true=только прочитанные, false=только непрочитанные
  flagged(boolean?) -- true=со звёздочкой
  max_results (1-100, default 20)
НЕ передавай имя без @ в поле from -- сначала вызови yandex_find_sender чтобы узнать адрес.
НЕ используй чтобы только посчитать письма -- используй yandex_count.`,
    inputSchema: searchEmailsSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    // v2.1.3: same rationale as list_emails — search can return up to 100 headers.
    meta: { 'anthropic/maxResultSizeChars': 200_000 },
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
        // PMLF-PROV-04: record each search result as a read (RAM-only).
        // Synthetic msgid format encodes uid (richer than audit.ts Hook-2
        // sentinel <not-found-no-message-id>) for Phase 4 disambiguation.
        // Provenance.ts is intentionally not coupled to audit.ts exact
        // format (D6 negative coupling). Per-iteration getPolicy() inside
        // recordRead returns a cached frozen reference (O(1)), so 100
        // search results = 100 O(1) lookups, not 100 fresh parses.
        for (const e of emails) {
          const msgid = e.messageId && e.messageId.length > 0
            ? e.messageId
            : '<search-no-message-id-uid-' + (e.uid ?? 'unknown') + '>';
          provenance.recordRead(msgid, { folder, uid: e.uid });
        }
        // C-alt: if from looks like a name (no @) and search returned nothing,
        // add a structured hint so the agent knows to try yandex_find_sender.
        const fromLooksLikeName = typeof rest.from === 'string' && !rest.from.includes('@');
        const hint = (!emails.length && fromLooksLikeName && !rest.text && !rest.subject)
          ? 'Подсказка: поле from не содержит @, возможно передано имя вместо адреса. Вызови yandex_find_sender чтобы найти точный адрес.'
          : undefined;
        const text = emails.length
          ? `Найдено: ${emails.length}\n\n${fmtHeaders(emails)}`
          : hint ?? 'Ничего не найдено.';
        return { content: [{ type: 'text', text }], structuredContent: { count: emails.length, emails, hint } };
      } catch (e) { return errorResult(e); }
    },
  },

  // 6. Get special folders (L0)
  {
    name: 'yandex_get_special_folders',
    title: 'Специальные папки',
    description: 'Возвращает реальные IMAP-пути специальных папок (Входящие, Отправленные, Черновики, Корзина, Спам). На русскоязычных аккаунтах Яндекса папки могут называться "Удалённые", "Отправленные" и т.д. -- используйте этот инструмент, чтобы узнать правильные имена перед операциями с папками.',
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

  // 6b. Find sender (L0) -- disambiguates a name before a deep search; v2.4.0.
  //
  // When the user says "find emails from Катя" without specifying an address,
  // use this tool first to resolve which Катя they mean. IMAP SEARCH FROM
  // matches against the full FROM header (display name + address), so "Катя"
  // hits "Катя Иванова" <k.ivanova@co.ru> even though "katya" isn't in the
  // address. Returns deduped candidates sorted by message count; the agent
  // can ask the user to pick one and then pass the exact email to
  // yandex_search_emails or yandex_stats.
  {
    name: 'yandex_find_sender',
    title: 'Найти отправителя',
    description: `Используй ПЕРЕД поиском писем, если пользователь назвал человека по имени без email-адреса.
Принимает часть имени или адреса, возвращает список уникальных отправителей с числом писем.
Агент должен показать список пользователю и спросить кого именно искать, затем передать точный email в yandex_search_emails.
Поиск нечёткий: "Катя" найдёт "Катя Иванова <k.ivanova@co.ru>" и "katya@mail.ru".
Args:
  query        -- часть имени или адреса (обязательно)
  folder       -- папка (default "INBOX")
  max_senders  -- максимум кандидатов (default 20)
Output: { candidates: [{ email, displayName, count, lastDate }], total_found, folder }`,
    inputSchema: findSenderSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    meta: { 'anthropic/maxResultSizeChars': 20_000 },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { query, folder, max_senders } = findSenderSchema.parse(params);
        const candidates = await imap.findSenders(folder, query, max_senders);
        const out = { folder, query, candidates, total_found: candidates.length };
        if (!candidates.length) {
          return { content: [{ type: 'text', text: `Отправители по запросу "${query}" не найдены в папке ${folder}.` }], structuredContent: out };
        }
        const lines = candidates.map((c, i) =>
          `${i + 1}. ${c.displayName ? c.displayName + ' ' : ''}<${c.email}> — ${c.count} писем, последнее ${c.lastDate.slice(0, 10)}`
        );
        const text = `Найдено ${candidates.length} отправителей по "${query}":\n\n${lines.join('\n')}`;
        return { content: [{ type: 'text', text }], structuredContent: out };
      } catch (e) { return errorResult(e); }
    },
  },

  // 6c. Count emails (L0) -- v2.5.0. Just a number, no envelopes.
  {
    name: 'yandex_count',
    title: 'Подсчёт писем',
    description: `Считает письма по критериям без загрузки содержимого. Возвращает одно число.
ВСЕГДА используй вместо yandex_list_emails / yandex_search_emails когда нужно только количество.
Args: folder (default "INBOX"), from?, to?, subject?, text?, since?, before?, seen?, flagged?
Примеры: "сколько непрочитанных?" → seen=false. "сколько писем от boss@co.ru?" → from="boss@co.ru".`,
    inputSchema: countEmailsSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    meta: { 'anthropic/maxResultSizeChars': 1_000 },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { folder, since, before, seen, flagged, ...rest } = countEmailsSchema.parse(params);
        const query: Record<string, unknown> = {};
        if (rest.from)    query.from    = rest.from;
        if (rest.to)      query.to      = rest.to;
        if (rest.subject) query.subject = rest.subject;
        if (rest.text)    query.text    = rest.text;
        if (since)           query['since']     = parseSearchDate(since, 'since');
        if (before)          query['before']    = parseSearchDate(before, 'before');
        if (seen === true)   query['seen']      = true;
        if (seen === false)  query['unseen']    = true;
        if (flagged === true)  query['flagged']   = true;
        if (flagged === false) query['unflagged'] = true;
        const count = await imap.countEmails(folder, query);
        const out = { folder, count, query_echo: params };
        return { content: [{ type: 'text', text: `${folder}: ${count} писем по заданным критериям.` }], structuredContent: out };
      } catch (e) { return errorResult(e); }
    },
  },

  // 6d. Folder peek (L0) -- v2.5.0. Batch status, one connection.
  {
    name: 'yandex_folder_peek',
    title: 'Обзор папок',
    description: `Возвращает total и unseen для нескольких папок за один запрос.
Используй в начале сессии чтобы понять что есть в ящике, или когда нужен статус нескольких папок сразу.
НЕ используй для одной папки -- yandex_folder_status дешевле.
Args: folders (string[]?) -- список папок; если не задан, берёт все папки ящика.
Папки с ошибкой возвращают {folder, error} вместо счётчиков -- не падает целиком.`,
    inputSchema: folderPeekSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    meta: { 'anthropic/maxResultSizeChars': 20_000 },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { folders: requestedFolders } = folderPeekSchema.parse(params);
        const targetFolders = requestedFolders && requestedFolders.length > 0
          ? requestedFolders
          : (await imap.listFolders()).map(f => f.path);
        const results = await imap.folderPeek(targetFolders);
        const lines = results.map(r =>
          r.error
            ? `${r.folder}: ошибка (${r.error})`
            : `${r.folder}: всего ${r.total}, непрочитанных ${r.unseen}`
        );
        const out = { folders: results, total_folders: results.length };
        return { content: [{ type: 'text', text: lines.join('\n') }], structuredContent: out };
      } catch (e) { return errorResult(e); }
    },
  },

  // 6e. Stats (L0) -- server-side aggregation; v2.3.0.
  {
    name: 'yandex_stats',
    title: 'Статистика писем',
    description: `ВСЕГДА используй этот инструмент когда нужна агрегация по получателям/датам/размерам --
НЕ загружай список писем через yandex_list_emails чтобы подсчитать вручную (сожжёт контекст на тысячах писем).
Серверная агрегация: возвращает счётчики (~КБ) вместо envelopes (~сотни КБ).
Args:
  folder    (default "INBOX") -- IMAP папка
  group_by  (string[], 1-3 полей) -- композитный ключ группировки
  since     (ISO date?, включительно)
  until     (ISO date?, включительно)
  top_n     (1-1000, default 50)
Доступные поля group_by:
  sender / sender_name / domain
  year / month / year_month / weekday / hour / date
  to_first / subject_prefix / subject_normalized
  size_bucket (<10KB / 10-100KB / 100KB-1MB / >1MB)
  has_attachments (best-effort: envelope-only, всегда "no" в v2.3.0 -- bodyStructure слишком тяжёл для streaming)
  flag_seen / flag_flagged
Примеры:
  group_by=["sender"]              -- топ отправителей
  group_by=["year","domain"]       -- по годам и доменам
  group_by=["weekday","hour"]      -- распределение по дню недели + часу
Output: { rows: [{ key:[...], count, total_size_bytes, earliest, latest }], total_scanned, scan_time_ms, truncated }
Сортировка: count desc, ключ asc.`,
    inputSchema: statsSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    meta: { 'anthropic/maxResultSizeChars': 200_000 },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { folder, group_by, since, until, top_n } = statsSchema.parse(params);
        // Adapter: imap.streamEnvelopes yields EmailHeader; stats.aggregate
        // accepts the EnvelopeRow subset. Shape is structurally compatible,
        // but the cast keeps type-narrowing honest and survives future
        // EmailHeader-only field additions.
        const src = imap.streamEnvelopes(folder, since, until) as AsyncGenerator<EnvelopeRow>;
        const result = await aggregate(src, {
          groupBy: group_by as GroupByField[],
          since,
          until,
          topN: top_n,
        });
        const out = {
          folder,
          group_by,
          total_scanned: result.total_scanned,
          date_range: result.date_range,
          rows: result.rows,
          scan_time_ms: result.scan_time_ms,
          truncated: result.truncated,
        };
        return {
          content: [{ type: 'text', text: JSON.stringify(out, null, 2) }],
          structuredContent: out,
        };
      } catch (e) { return errorResult(e); }
    },
  },

  // 6f. Fast search over the local index (L0) -- v2.6.0 Layer 2 foundation.
  // Always registered; the handler degrades gracefully when no index is built
  // (the index may be built by the CLI after the server started, so gating
  // registration on indexExists() at startup would hide a usable tool).
  {
    name: 'yandex_search_fast',
    title: 'Быстрый поиск (локальный индекс)',
    description: `Мгновенный поиск по локальному индексу писем -- единицы мс вместо ~1 с живого IMAP.
Ищет по теме и отправителю, ранжирует по релевантности, поддерживает кириллицу.
Поддерживает фильтры: from / since / before / seen / flagged. Можно искать ТОЛЬКО по фильтрам без query (напр. «непрочитанные за март»: seen=false, since="2025-03-01").
Требует построенного индекса: в терминале \`yandex-mail-mcp index build\` (и \`index update\` для досинхронизации).
Если индекс не построен -- вернёт подсказку; тогда используй yandex_search_emails (живой поиск).
Args: query? (опционально, если задан фильтр), folder?, limit (default 20, max 100), from?, since?, before?, seen?, flagged?.
Output: { index_built, total, hits: [{ uid, folder, from, subject, date, score, match_reasons }] }`,
    inputSchema: searchFastSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    meta: { 'anthropic/maxResultSizeChars': 50_000 },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { query, folder, limit, from, since, before, seen, flagged } = searchFastSchema.parse(params);
        const q = (query ?? '').trim();
        const filters: mailIndex.SearchFilters = {};
        if (from) filters.from = from;
        if (since) filters.since = parseSearchDate(since, 'since').getTime();
        if (before) filters.before = parseSearchDate(before, 'before').getTime();
        if (seen !== undefined) filters.seen = seen;
        if (flagged !== undefined) filters.flagged = flagged;
        const hasFilter = Object.keys(filters).length > 0;
        if (q.length === 0 && !hasFilter) {
          throw new Error('Укажите query или хотя бы один фильтр (from/since/before/seen/flagged).');
        }
        if (!mailIndex.indexExists()) {
          return {
            content: [{ type: 'text', text: 'Локальный индекс не построен. Запусти `yandex-mail-mcp index build` в терминале, либо используй yandex_search_emails для живого поиска по IMAP.' }],
            structuredContent: { index_built: false, total: 0, hits: [] },
          };
        }
        const hits = mailIndex.searchFast(q, { folder, limit, filters });
        const rows = hits.map(h => ({
          uid: h.record.uid,
          folder: h.record.folder,
          from: h.record.fromName ? `${h.record.fromName} <${h.record.fromEmail}>` : h.record.fromEmail,
          subject: h.record.subject,
          date: h.record.date,
          score: h.score,
          match_reasons: h.matchReasons,
        }));
        const label = q.length > 0 ? `"${q}"` : 'заданным фильтрам';
        const out = { index_built: true, query: q, total: rows.length, hits: rows };
        if (rows.length === 0) {
          return { content: [{ type: 'text', text: `По ${label} в индексе ничего не найдено.` }], structuredContent: out };
        }
        const lines = rows.map((r, i) =>
          `${i + 1}. [${r.folder}#${r.uid}] ${sanitizeForDisplay(r.subject) || '(без темы)'} — ${sanitizeForDisplay(r.from)}, ${r.date.slice(0, 10)} (релевантность ${r.score})`,
        );
        return { content: [{ type: 'text', text: `Найдено ${rows.length} (локальный индекс):\n\n${lines.join('\n')}` }], structuredContent: out };
      } catch (e) { return errorResult(e); }
    },
  },

  // 6g. Thread reconstruction over the local index (L0) -- v2.6.0.
  {
    name: 'yandex_get_thread',
    title: 'Цепочка письма (тред)',
    description: `Собирает цепочку (тред) по локальному индексу: находит лучшее совпадение и связывает письма
по графу Message-ID (In-Reply-To) — ловит ответы с изменённой темой и треды, разбитые между
папками (Входящие/Отправленные), — плюс по нормализованной теме (Re:/Fwd:/Вс: отбрасываются)
в пределах папки совпадения. Возвращает письма в хронологическом порядке. Требует индекса
(см. yandex_search_fast; для связей по In-Reply-To нужен \`index build\`, не только update).
Args: query (слова из темы), folder?, limit (default 20, max 100).
Output: { index_built, total, thread: [{ uid, folder, from, subject, date }] }`,
    inputSchema: getThreadSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    meta: { 'anthropic/maxResultSizeChars': 50_000 },
    requires: { authLevel: 0 },
    handler: async (params, _ctx) => {
      try {
        const { query, folder, limit } = getThreadSchema.parse(params);
        if (!mailIndex.indexExists()) {
          return {
            content: [{ type: 'text', text: 'Локальный индекс не построен. Запусти `yandex-mail-mcp index build` в терминале.' }],
            structuredContent: { index_built: false, total: 0, thread: [] },
          };
        }
        const hits = mailIndex.getThread(query, { folder, limit });
        const thread = hits.map(h => ({
          uid: h.record.uid,
          folder: h.record.folder,
          from: h.record.fromName ? `${h.record.fromName} <${h.record.fromEmail}>` : h.record.fromEmail,
          subject: h.record.subject,
          date: h.record.date,
        }));
        const out = { index_built: true, query, total: thread.length, thread };
        if (thread.length === 0) {
          return { content: [{ type: 'text', text: `Тред по запросу "${query}" в индексе не найден.` }], structuredContent: out };
        }
        const lines = thread.map((r, i) =>
          `${i + 1}. ${r.date.slice(0, 10)} — ${sanitizeForDisplay(r.from)}: ${sanitizeForDisplay(r.subject) || '(без темы)'} [${r.folder}#${r.uid}]`,
        );
        return { content: [{ type: 'text', text: `Тред из ${thread.length} писем:\n\n${lines.join('\n')}` }], structuredContent: out };
      } catch (e) { return errorResult(e); }
    },
  },

  // 7. Mark email (L1) -- fully reversible
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
        // Hook-2: fetch message_id BEFORE the mutating call. Failure to fetch
        // MUST NOT block the mutation -- the audit field degrades to a sentinel.
        const messageId = await imap.getMessageId(folder, uid).catch(() => null);
        await imap.markEmail(folder, uid, seen, flagged);
        const changes = [
          seen !== undefined ? (seen ? 'прочитано' : 'непрочитано') : '',
          flagged !== undefined ? (flagged ? 'отмечено ★' : 'снята звёздочка') : '',
        ].filter(Boolean).join(', ');
        return {
          content: [{ type: 'text', text: `UID ${uid}: ${changes}.` }],
          structuredContent: { success: true },
          _audit: { folder, uid, message_id: messageId ?? '<not-found-no-message-id>' },
        };
      } catch (e) { return errorResult(e); }
    },
  },

  // 8. Move email (L1) -- soft (protected-folder enforcement → Phase 7)
  {
    name: 'yandex_move_email',
    title: 'Переместить письмо',
    description: `Переместить письмо в другую папку.
Args: folder (откуда), uid (UID письма), target_folder (куда, напр. "Spam", "Archive").`,
    inputSchema: moveEmailSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    requires: { authLevel: 1 },
    handler: async (params, ctx) => {
      try {
        const { folder, uid, target_folder } = moveEmailSchema.parse(params);
        // Phase 7: protected-folder gate -- fail-fast BEFORE any IMAP call.
        // Check BOTH source and destination: source mutation is the obvious
        // destruction risk (move INBOX -> Trash en masse); destination
        // mutation can clobber a protected folder via filter side effects
        // (move spam INTO Inbox). L1/L2 deny; L3 advisory.
        for (const candidate of [folder, target_folder]) {
          const gate = checkProtectedFolder(candidate, ctx.protectedFolders);
          if (!gate.blocked) continue;
          if (isAdvisory(ctx.authLevel)) {
            auditLog({
              action: 'yandex_move_email',
              status: 'denied',
              level: 'warn',
              ts: new Date().toISOString(),
              reason: 'protected_folder_L3_advisory',
              folder: gate.matched ?? candidate,
              uid,
            });
            // L3: proceed.
            continue;
          }
          auditLog({
            action: 'yandex_move_email',
            status: 'denied',
            level: 'warn',
            ts: new Date().toISOString(),
            reason: 'protected_folder',
            folder: gate.matched ?? candidate,
            uid,
          });
          return {
            content: [{
              type: 'text',
              text: 'protected_folder: ' + (gate.matched ?? candidate) +
                ' is in YANDEX_PROTECTED_FOLDERS. To allow, set YANDEX_PROTECTED_FOLDERS to exclude this folder (set to empty string to disable entirely).',
            }],
            isError: true,
            _audit: { folder: gate.matched ?? candidate, uid, message_id: '<blocked-no-message-id>' },
          };
        }
        // Hook-2: fetch message_id BEFORE the mutating call.
        const messageId = await imap.getMessageId(folder, uid).catch(() => null);
        await imap.moveEmail(folder, uid, target_folder);
        const text = `UID ${uid}: перемещено из ${folder} в ${target_folder}.`;
        return {
          content: [{ type: 'text', text }],
          structuredContent: { success: true },
          _audit: { folder, uid, message_id: messageId ?? '<not-found-no-message-id>' },
        };
      } catch (e) { return errorResult(e); }
    },
  },

  // 9. Delete email (L1). permanent=true is gated by a server-issued
  // confirmation code (R7, v2.6.0) — see the handler's confirmation block.
  {
    name: 'yandex_delete_email',
    title: 'Удалить письмо',
    description: `Удалить письмо. По умолчанию -- в корзину (восстановимо).
Args: folder, uid, permanent (bool, default false), confirmation_token (string?).
permanent=true -- безвозвратно; требует двух шагов: первый вызов без
confirmation_token возвращает 6-значный код, второй вызов с тем же folder/uid и
confirmation_token=<код> выполняет удаление. Код истекает через 300с.`,
    inputSchema: deleteEmailSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    requires: { authLevel: 1 },
    handler: async (params, ctx) => {
      try {
        const { folder, uid, permanent, confirmation_token } = deleteEmailSchema.parse(params);
        // Phase 7: protected-folder gate -- fail-fast BEFORE any IMAP call.
        // delete has no destination; gate only the source folder.
        {
          const gate = checkProtectedFolder(folder, ctx.protectedFolders);
          if (gate.blocked) {
            if (isAdvisory(ctx.authLevel)) {
              auditLog({
                action: 'yandex_delete_email',
                status: 'denied',
                level: 'warn',
                ts: new Date().toISOString(),
                reason: 'protected_folder_L3_advisory',
                folder: gate.matched ?? folder,
                uid,
              });
              // L3: proceed.
            } else {
              auditLog({
                action: 'yandex_delete_email',
                status: 'denied',
                level: 'warn',
                ts: new Date().toISOString(),
                reason: 'protected_folder',
                folder: gate.matched ?? folder,
                uid,
              });
              return {
                content: [{
                  type: 'text',
                  text: 'protected_folder: ' + (gate.matched ?? folder) +
                    ' is in YANDEX_PROTECTED_FOLDERS. To allow, set YANDEX_PROTECTED_FOLDERS to exclude this folder (set to empty string to disable entirely).',
                }],
                isError: true,
                _audit: { folder: gate.matched ?? folder, uid, message_id: '<blocked-no-message-id>' },
              };
            }
          }
        }
        // R7 (v2.6.0): permanent delete is irreversible — gate it behind a
        // server-issued confirmation code, mirroring the send flow. The
        // destructiveHint annotation is only a client-side hint; enforcement
        // must live server-side (project security rule). Trash-delete
        // (permanent=false) stays a single L1 call.
        if (permanent) {
          const fp = actionFingerprint('yandex_delete_email_permanent', { folder, uid });
          if (confirmation_token === undefined) {
            const gen = generateCode(fp);
            auditLog({
              action: 'yandex_delete_email',
              status: 'pending',
              level: 'info',
              ts: new Date().toISOString(),
              reason: 'permanent_confirmation_required',
              folder, uid,
            });
            return {
              content: [{
                type: 'text',
                text: `Безвозвратное удаление UID ${uid} из «${folder}» требует подтверждения. ` +
                  `Код подтверждения: ${gen.code}. Повторите вызов yandex_delete_email с теми же ` +
                  `folder и uid, permanent=true и confirmation_token=${gen.code}. Код истекает через 300 секунд.`,
              }],
              structuredContent: { requires_confirmation: true, action_fingerprint: fp },
              _audit: { folder, uid, message_id: '<pending-confirmation>' },
            };
          }
          const verdict = verifyCode(fp, confirmation_token);
          if (verdict !== true) {
            const why = verdict === 'expired'
              ? 'код истёк — повторите вызов без confirmation_token, чтобы получить новый'
              : verifyResultToError(verdict);
            auditLog({
              action: 'yandex_delete_email',
              status: 'denied',
              level: 'warn',
              ts: new Date().toISOString(),
              reason: 'permanent_confirmation_' + verdict,
              folder, uid,
            });
            return {
              content: [{ type: 'text', text: 'Безвозвратное удаление отклонено: ' + why + '.' }],
              isError: true,
              _audit: { folder, uid, message_id: '<denied-confirmation>' },
            };
          }
        }
        // Hook-2: fetch message_id BEFORE the (potentially permanent) mutation.
        const messageId = await imap.getMessageId(folder, uid).catch(() => null);
        await imap.deleteEmail(folder, uid, permanent);
        const text = permanent ? `UID ${uid} безвозвратно удалено.` : `UID ${uid} перемещено в Корзину.`;
        return {
          content: [{ type: 'text', text }],
          structuredContent: { success: true, permanent },
          _audit: { folder, uid, message_id: messageId ?? '<not-found-no-message-id>' },
        };
      } catch (e) { return errorResult(e); }
    },
  },

  // 10. Send email (L2) -- destructive; Phase 4 confirmation gate active.
  {
    name: 'yandex_send_email',
    title: 'Отправить письмо',
    description: `Отправить письмо через SMTP Яндекса (OAuth2).
Args:
  to       (string[]) -- получатели, напр. ["user@example.com", "Name <other@example.com>"]
  cc, bcc  (string[]?) -- копия, скрытая копия
  subject  (string) -- тема
  text     (string?) -- тело plain text
  html     (string?) -- тело HTML
  reply_to (string?) -- Reply-To адрес
  in_reply_to (string?) -- Message-ID письма, на которое отвечаем
  references  (string[]?) -- цепочка Message-ID для треда
  dry_run  (boolean?) -- если true, возвращает SendPlan и НЕ отправляет
  confirmation_token (string?) -- 6-цифр код, полученный пользователем
    out-of-band (elicit / stderr / OS toast). Без него send блокируется.`,
    inputSchema: sendEmailBaseSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    requires: { authLevel: 2 },
    handler: async (params, ctx) => {
      try {
        // Phase 6 (D4): driver shrunk to <=60 LOC. All pipeline logic lives
        // in send-pipeline.ts (10 stages, FROZEN D3 order). The handler does
        // exactly four things:
        //   1. Fork on dry_run -- skip the mutating pipeline, return a SendPlan
        //      with the guards-pure verdict (Q1/Q2 contract).
        //   2. Build the initial SendContext frame.
        //   3. Call runPipeline.
        //   4. Render the PipelineResult via renderPipelineResult (handles
        //      elicit dialog re-runs, block / pending / success formatting).
        // T-PIPE-H2-REORDER-01 (Task 8) is the runtime spy-based assertion of
        // the H-2 invariant; source-grep tests in send-pipeline-ordering.test.ts
        // are migrated to the pipeline (see 06-DEVIATIONS.md DEV-01).
        const peek = sendEmailBaseSchema.safeParse(params);
        if (peek.success && peek.data.dry_run === true) {
          if (peek.data.text === undefined && peek.data.html === undefined) {
            throw new Error('Укажите хотя бы одно из полей: text или html');
          }
          return renderDryRunPlan(peek.data, ctx);
        }
        const initCtx: SendContext = {
          rawParams: params,
          authLevel: ctx.authLevel,
          nowMs: Date.now(),
        };
        const result = await runPipeline(initCtx);
        return await renderPipelineResult(result, ctx, params);
      } catch (e) { return errorResult(e); }
    },
  },

  // 11. Trust address (L1) -- Phase 5 TOFU allowlist write path.
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
  address     (string) -- email-адрес для добавления (точное совпадение)
  scope       ('permanent' | 'session', default 'permanent')
  trust_token (string) -- 64-hex token из CLI, single-use`,
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
          // Do NOT echo pending.trust_token -- only the address mismatch.
          return errorResult(new Error(`Address mismatch -- pending request is for ${sanitizeForDisplay(pending.address)}.`));
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
          // Wrong-token attempts do NOT burn the pending slot -- TTL bounds replay.
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

// Apply wrapWithAudit to every entry BEFORE Object.freeze -- preserves the
// declarative invariant (registerTools still iterates a single readonly array
// and emits exactly one server.registerTool per visible def).
export const TOOLS: readonly ToolDef[] = TOOLS_RAW.map(wrapWithAudit);
Object.freeze(TOOLS);

// ── Registration ───────────────────────────────────────────

export function registerTools(server: McpServer, ctx: ToolCtx): void {
  for (const def of TOOLS) {
    if (ctx.authLevel < def.requires.authLevel) continue;
    // Capability gate -- when a tool lists required capabilities, every one of
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
        ...(def.meta ? { _meta: def.meta } : {}),
      },
      // Our handlers validate input via zod and return a CallToolResult-shaped
      // value; the SDK's registerTool callback generic is narrower than our
      // runtime contract. Cast to the SDK's own callback type rather than
      // loosening every handler signature.
      ((input: unknown) => def.handler(input, ctx)) as Parameters<typeof server.registerTool>[2],
    );
  }
}
