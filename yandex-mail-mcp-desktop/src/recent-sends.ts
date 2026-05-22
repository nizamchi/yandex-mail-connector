// recent-sends.ts -- operator-readable forensics buffer for the last N
// successful sends (Phase 7 PMLF-CLI-02). Read by
// `yandex-mail-mcp-trust --recent`. Written by stage-10 recordSend in the
// send pipeline (one append per successful send).
//
// Design contract:
//   * 50-record cap. On every append, file is truncated to the last 50
//     records (read-modify-rewrite atomic-rename). Worst-case file size
//     ~ 15 KB. NOT signed (forensics-only; T-07-08 acceptance).
//   * Never crashes a send. appendRecentSend catches every internal error
//     and falls back to a single stderr warn. Caller (send-pipeline.ts:
//     recordSend) additionally wraps in try/catch.
//   * `version` field (Rev-2 W1): currently 1. Bump on ANY field add /
//     rename / type-change. readRecentSends drops version-mismatched lines
//     with a stderr warn -- forward / backward incompat does not corrupt
//     the file or crash the reader.
//   * risk_score clamp (Rev-2 M2): the schema enforces .max(100) as a
//     defence-in-depth gate against hand-edits. The pipeline call site in
//     send-pipeline.ts clamps via Math.min(score, 100) so future risk-tier
//     changes that push scores above 100 are capped, not lost.
//   * Privacy boundary (T-07-04): domains-only recipients (mirror
//     audit.ts D-RECIP-DOMAINS), subject_hash NOT subject, no body. Strict
//     Zod schema rejects accidental extra fields at append-time.
//   * count >= unique-domains invariant (Rev-2 M1): refine on the schema.
//
// File: <state-dir>/recent-sends.jsonl, mode 0o600 on POSIX.
// No `any`. ESM `.js` import suffix.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { z } from 'zod';

import { getStateDir } from './state-dir.js';

// -- Schema --------------------------------------------------

export const RecentSendSchema = z.object({
  version: z.literal(1),
  ts: z.string().datetime(),
  message_id: z.string().min(1),
  recipients_count: z.number().int().nonnegative(),
  recipients_domains: z.array(z.string()),
  subject_hash: z.string().length(16),
  body_length: z.number().int().nonnegative(),
  risk_tier: z.enum(['low', 'medium', 'high', 'block']),
  risk_score: z.number().int().nonnegative().max(100),
  action_fingerprint: z.string(),
}).strict().refine(
  r => r.recipients_count >= r.recipients_domains.length,
  { message: 'recipients_count must be >= recipients_domains.length' },
);

export type RecentSendRecord = z.infer<typeof RecentSendSchema>;

// -- Module config -------------------------------------------

const MAX_RECORDS = 50;

// Rev-2 H2: test seam for rotation-fail injection. Production default null.
// Pass a function that throws (or returns) to inject behaviour into the
// atomic-rename step; pass null to clear.
let rotationFailHook: (() => void) | null = null;

export function _setRotationFailHookForTests(fn: (() => void) | null): void {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('_setRotationFailHookForTests is test-only');
  }
  rotationFailHook = fn;
}

// -- Paths ---------------------------------------------------

function bufferPath(): string {
  return path.join(getStateDir(), 'recent-sends.jsonl');
}

// -- Append --------------------------------------------------

// Best-effort. Caller (stage-10 recordSend) also wraps in try/catch. This
// function MUST NOT throw to its caller under any circumstances.
export function appendRecentSend(rec: RecentSendRecord): void {
  // 1. Validate. Strict schema rejects extra fields; refine enforces
  //    count >= unique-domains.
  const parsed = RecentSendSchema.safeParse(rec);
  if (!parsed.success) {
    try {
      process.stderr.write(
        '[yandex-mail-recent] schema-invalid: ' + parsed.error.message + '\n',
      );
    } catch { /* stderr best-effort */ }
    return;
  }

  try {
    const target = bufferPath();
    // 2. Read existing buffer (ENOENT -> []).
    let existing: RecentSendRecord[] = [];
    if (fs.existsSync(target)) {
      const raw = fs.readFileSync(target, 'utf8');
      for (const line of raw.split('\n')) {
        if (line.length === 0) continue;
        let obj: unknown;
        try { obj = JSON.parse(line); } catch { continue; }
        if (typeof obj !== 'object' || obj === null) continue;
        // Drop version-mismatched lines silently on the write path
        // (readRecentSends warns; we don't spam on the hot path).
        if ((obj as { version?: unknown }).version !== 1) continue;
        const ok = RecentSendSchema.safeParse(obj);
        if (ok.success) existing.push(ok.data);
      }
    }

    // 3. Append and trim to MAX_RECORDS (oldest dropped).
    existing.push(parsed.data);
    if (existing.length > MAX_RECORDS) {
      existing = existing.slice(-MAX_RECORDS);
    }

    // 4. Serialize.
    const serialized = existing.map(r => JSON.stringify(r)).join('\n') + '\n';

    // 5. Atomic write (tmp + rename), mode 0o600.
    const tmp = target + '.tmp';
    try {
      fs.writeFileSync(tmp, serialized, { mode: 0o600 });
      // Hook fires IMMEDIATELY BEFORE rename (Rev-2 H2 seam).
      if (rotationFailHook !== null) {
        rotationFailHook();
      }
      fs.renameSync(tmp, target);
    } catch (e) {
      try { fs.unlinkSync(tmp); } catch { /* best-effort cleanup */ }
      throw e;
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    try {
      process.stderr.write('[yandex-mail-recent] write-error: ' + msg + '\n');
    } catch { /* stderr best-effort */ }
    return;
  }
}

// -- Read ----------------------------------------------------

export function readRecentSends(): RecentSendRecord[] {
  const target = bufferPath();
  if (!fs.existsSync(target)) return [];

  let raw: string;
  try {
    raw = fs.readFileSync(target, 'utf8');
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    try {
      process.stderr.write('[yandex-mail-recent] read-error: ' + msg + '\n');
    } catch { /* stderr best-effort */ }
    return [];
  }

  const out: RecentSendRecord[] = [];
  let dropped = 0;
  for (const line of raw.split('\n')) {
    if (line.length === 0) continue;
    let obj: unknown;
    try { obj = JSON.parse(line); } catch { dropped++; continue; }
    if (typeof obj !== 'object' || obj === null) { dropped++; continue; }
    if ((obj as { version?: unknown }).version !== 1) { dropped++; continue; }
    const parsed = RecentSendSchema.safeParse(obj);
    if (parsed.success) {
      out.push(parsed.data);
    } else {
      dropped++;
    }
  }
  if (dropped > 0) {
    try {
      process.stderr.write(
        '[yandex-mail-recent] dropped ' + dropped + ' corrupt/version-mismatched lines\n',
      );
    } catch { /* stderr best-effort */ }
  }
  return out;
}

// -- Test seam ------------------------------------------------

export function _resetForTests(): void {
  rotationFailHook = null;
}
