// audit.ts -- append-only JSON Lines forensics log (Phase 6, OPS-01 + Hook-2).
//
// Hook-2 enforcement contract:
//   For any action in EMAIL_ACTIONS (yandex_get_email, yandex_send_email,
//   yandex_move_email, yandex_delete_email, yandex_mark_email) the record MUST
//   carry a non-empty message_id. If a caller forgets to pass one, this module
//   writes a stderr 'schema-violation' line AND still appends the record with
//   level forced to 'warn' and 'hook2_missing_message_id' added to redacted[].
//   We NEVER throw out of auditLog -- a forensics-log failure must never crash
//   the handler that emitted it.
//
// D-RECIP-DOMAINS: the recipients[] field carries DOMAINS, NOT full addresses
//   (we map 'user@example.com' -> 'example.com' at the call site). Rationale:
//   - sufficient for forensics correlation ("who keeps sending to gmail?")
//   - avoids logging exfil targets verbatim
//   - operator-readable (vs SHA-256 of address, which is opaque at L1)
//   SHA-256(addr) was considered and deferred to L2 where the index will need
//   a stable join key across forensics + dedup.
//
// FORBIDDEN_KEYS (defence-in-depth redaction):
//   Zod schema is .strict() -- unknown keys are dropped at parse time. On top
//   of that we strip a hard-coded list of forbidden key names (case-insensitive)
//   BEFORE parse, and record the stripped names in redacted[]. This gives a
//   greppable guarantee in the codebase: a single FORBIDDEN_KEYS array names
//   every secret type we never want to see in the log.
//
// Rotation policy:
//   Single prior file: audit.jsonl + audit.jsonl.1. Checked ONCE per process
//   per target path (module-local rotationChecked flag). At first auditLog
//   call we statSync the target; if size > maxBytes() we rename to .1
//   (overwriting any prior .1) and start fresh. Atomic on POSIX via rename();
//   on Windows we unlinkSync(.1) before renameSync to avoid EEXIST.
//
// Async write queue invariant:
//   All appendFile calls chain through writeChain (single Promise). This means:
//   - records appear in the file in the same order auditLog() was called
//   - no record is lost under concurrent tool invocations
//   - errors are caught and reported to stderr -- writeChain never rejects
//   - the chain is non-blocking: auditLog returns synchronously after enqueue
//
// No `any`. ESM `.js` import suffix.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { z } from 'zod';

import { getStateDir } from './state-dir.js';

// -- Constants ----------------------------------------------

// The five tool names that constitute an "email action" per Hook 2. Anything
// outside this set MUST NOT carry message_id (non-email tools like list_folders
// have no email to correlate to). Exported for tests + tools.ts wrapper.
export const EMAIL_ACTIONS: ReadonlySet<string> = new Set<string>([
  'yandex_get_email',
  'yandex_send_email',
  'yandex_move_email',
  'yandex_delete_email',
  'yandex_mark_email',
]);

const MB = 1024 * 1024;
const DEFAULT_MAX_MB = 10;

// Forbidden top-level keys -- stripped at input layer (defence-in-depth).
// Order is irrelevant; matching is case-insensitive on the key name.
const FORBIDDEN_KEYS: readonly string[] = [
  'body',
  'subject',
  'oauth_token',
  'access_token',
  'app_password',
  'confirmation_token',
  'trust_token',
  'code',
  'password',
  'secret',
  'token',
  'refresh_token',
  'raw_body',
  'raw_subject',
];

// -- Zod schema ---------------------------------------------

export const AuditRecord = z.object({
  ts: z.string().datetime(),
  action: z.string().min(1),
  level: z.enum(['info', 'warn', 'error']),
  status: z.enum(['attempt', 'success', 'denied', 'error']),
  folder: z.string().optional(),
  message_id: z.string().min(1).optional(),
  from_domain: z.string().optional(),
  reason: z.string().optional(),
  uid: z.number().int().nonnegative().optional(),
  recipients: z.array(z.string()).optional(),
  subject_hash: z.string().length(16).optional(),
  body_length: z.number().int().nonnegative().optional(),
  redacted: z.array(z.string()).optional(),
  // Phase 2 outbound-scan REDACTED-MATCH payload (D15 / L2 of 02-01-PLAN.md).
  // Content-free by construction: category name + byte range + hash of the
  // first-4-chars (NEVER the raw 4 chars; that stays behind YANDEX_SCAN_DEBUG=1
  // on stderr only). These fields ONLY accompany action='outbound_scan_match'
  // and action='outbound_scan_oversize' (oversize uses none of them).
  category: z.string().optional(),
  subCategory: z.string().optional(),
  byteStart: z.number().int().nonnegative().optional(),
  byteEnd: z.number().int().nonnegative().optional(),
  prefix4_hash: z.string().regex(/^[0-9a-f]{8}$/).optional(),
  // Phase 5 risk fields. ALL THREE optional() -- forward-compat with
  // Phase 1/2/3/4 audit emissions that omit them. risk_reasons[] is the
  // array of canonical signal IDs (NOT the human-readable .detail
  // strings; those contain recipient addresses). Phase 5 confirm.ts
  // strips .detail at the audit boundary.
  risk_score: z.number().int().nonnegative().max(100).optional(),
  risk_reasons: z.array(z.string()).optional(),
  risk_tier: z.enum(['low','medium','high','block']).optional(),
  // REV 3 WR-02 (STRIDE Repudiation closure). Privacy-safe identifiers on
  // override-token denied-consume audit records. SHA-256 prefix (16 hex)
  // of the supplied token and the bound fingerprint so forensics can
  // correlate attempts without revealing raw values. .optional() so
  // existing emissions are unaffected (Phase 1/2/3/4/5 forward-compat).
  token_id_hash: z.string().regex(/^[0-9a-f]{16}$/).optional(),
  fingerprint_hash: z.string().regex(/^[0-9a-f]{16}$/).optional(),
}).strict();

export type AuditRecord = z.infer<typeof AuditRecord>;

// -- Path + size resolution (read env at call time, not at module load) -----

function logPath(): string | null {
  const v = process.env.YANDEX_AUDIT_LOG;
  if (v === 'off') return null;
  if (v === undefined || v.length === 0) {
    return path.join(getStateDir(), 'audit.jsonl');
  }
  return path.resolve(v);
}

function maxBytes(): number {
  const raw = process.env.YANDEX_AUDIT_LOG_MAX_MB;
  const n = raw === undefined ? DEFAULT_MAX_MB : Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_MAX_MB * MB;
  return n * MB;
}

// -- Rotation (single-prior-file, checked once per process per target path) --

let rotationChecked: string | null = null;

function maybeRotate(target: string): void {
  if (rotationChecked === target) return;
  try {
    const st = fs.statSync(target);
    if (st.size > maxBytes()) {
      const prior = target + '.1';
      try { fs.unlinkSync(prior); } catch { /* ignore ENOENT */ }
      fs.renameSync(target, prior);
    }
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code !== 'ENOENT') {
      process.stderr.write('[yandex-mail-audit] rotation check failed: ' + (err.message ?? String(e)) + '\n');
    }
  }
  rotationChecked = target;
}

// -- Async write queue -------------------------------------

let writeChain: Promise<void> = Promise.resolve();

function enqueue(line: string, target: string): Promise<void> {
  writeChain = writeChain
    .then(() => fs.promises.appendFile(target, line + '\n', { mode: 0o600 }))
    .catch(err => {
      process.stderr.write(
        '[yandex-mail-audit] write failed: ' +
        (err instanceof Error ? err.message : String(err)) + '\n',
      );
    });
  return writeChain;
}

// -- Redaction ---------------------------------------------

interface StripResult {
  clean: Record<string, unknown>;
  redacted: string[];
}

function stripForbidden(obj: Record<string, unknown>): StripResult {
  const forbiddenSet = new Set(FORBIDDEN_KEYS.map(k => k.toLowerCase()));
  const clean: Record<string, unknown> = {};
  const redacted: string[] = [];
  for (const [key, value] of Object.entries(obj)) {
    if (forbiddenSet.has(key.toLowerCase())) {
      redacted.push(key.toLowerCase());
      continue;
    }
    clean[key] = value;
  }
  return { clean, redacted };
}

// -- Public API --------------------------------------------

export function auditLog(input: unknown): void {
  const target = logPath();
  if (target === null) return; // env=off no-op

  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    process.stderr.write('[yandex-mail-audit] schema-invalid: input is not a plain object\n');
    return;
  }

  // Strip forbidden keys BEFORE Zod parse. Merge any pre-existing redacted[]
  // from caller with the keys we stripped.
  const inputObj = input as Record<string, unknown>;
  const { clean, redacted: strippedNames } = stripForbidden(inputObj);
  const priorRedacted = Array.isArray(clean.redacted) ? (clean.redacted as unknown[]).filter((x): x is string => typeof x === 'string') : [];
  if (strippedNames.length > 0 || priorRedacted.length > 0) {
    clean.redacted = Array.from(new Set([...priorRedacted, ...strippedNames]));
  }

  const parsed = AuditRecord.safeParse(clean);
  if (!parsed.success) {
    process.stderr.write(
      '[yandex-mail-audit] schema-invalid: ' +
      JSON.stringify(parsed.error.issues) + '\n',
    );
    return;
  }

  // Hook 2 enforcement -- applied AFTER successful schema parse.
  const record: AuditRecord = { ...parsed.data };
  if (EMAIL_ACTIONS.has(record.action)) {
    if (record.message_id === undefined || record.message_id.length === 0) {
      process.stderr.write(
        '[yandex-mail-audit] schema-violation: ' + record.action + ' missing message_id\n',
      );
      record.level = 'warn';
      const merged = new Set([...(record.redacted ?? []), 'hook2_missing_message_id']);
      record.redacted = Array.from(merged);
    }
  }

  maybeRotate(target);
  enqueue(JSON.stringify(record), target);
}

// Convenience helper used by the tools.ts wrapper. Synthesizes ts + maps
// status -> level so call sites stay terse.
export function auditLogAction(
  action: string,
  status: 'attempt' | 'success' | 'denied' | 'error',
  extras?: Record<string, unknown>,
): void {
  const level: 'info' | 'warn' | 'error' =
    status === 'error' ? 'error' :
    status === 'denied' ? 'warn' :
    'info';
  const ts = new Date().toISOString();
  // Drop undefined-valued extras so they don't fail Zod 'optional' checks
  // (z.string().optional() rejects an explicit undefined under strict()).
  const filtered: Record<string, unknown> = {};
  if (extras !== undefined) {
    for (const [k, v] of Object.entries(extras)) {
      if (v !== undefined) filtered[k] = v;
    }
  }
  auditLog({ action, status, level, ts, ...filtered });
}

/**
 * Drain the audit writeChain. Awaits all queued appendFile operations so
 * callers can guarantee on-disk durability before exiting the process.
 *
 * Public surface for the CLI (Phase 7). MUST be awaited after any
 * auditLog()/auditLogAction() call followed by process.exit(...).
 *
 * Idempotent and safe to call at any time. Not a test seam -- this is a
 * production API.
 */
export async function flushAudit(): Promise<void> {
  await writeChain;
}

// -- Test seams (NOT for production callers) ---------------

export async function _drainForTests(): Promise<void> {
  await flushAudit();
}

export function _resetForTests(): void {
  writeChain = Promise.resolve();
  rotationChecked = null;
}

// subject_hash helper -- sha256 of subject, first 16 hex (non-reversible).
// Header comment: this is a non-reversible fingerprint, NOT a cipher. It lets
// forensics correlate "same subject across N records" without ever logging
// the subject itself.
export function subjectHash(subject: string): string {
  return crypto.createHash('sha256').update(subject ?? '').digest('hex').slice(0, 16);
}
