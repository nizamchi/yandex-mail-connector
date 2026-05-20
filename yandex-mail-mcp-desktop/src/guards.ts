// guards.ts -- Phase 7 Operational Guards (OPS-02..05).
//
// Four runtime defences gated on auth level:
//   1. DailyCounter           -- sliding 24h send cap (default 50; Yandex ~500 cap, 10x safety).
//   2. PerRecipientCounter    -- sliding 1h per-address send cap (default 5).
//   3. SendDedup              -- 60s window keyed by actionFingerprint (anti retry-loop).
//   4. ProtectedFolder + 2FA  -- destruction gate (move/delete) + body redaction (get_email).
//
// Invariants (DO NOT REGRESS without phase plan):
//   - In-memory state, per-process. Counters reset on restart -- ACCEPTED
//     (Yandex itself resets daily; persistence is Layer 2+). T-07-08 / T-07-12.
//   - L1/L2: failing guard returns { ok:false, reason, ... } to the handler.
//     Handler emits isError + auditLog denied record.
//   - L3 (auto): the GuardResult is STILL { ok:false, ... }. The handler chooses
//     to bypass+audit-warn instead of blocking (isAdvisory helper exposes the
//     rule). Counters are mutated by recordSend on EVERY successful send
//     regardless of level so the prior-call state is always visible.
//   - Dedup key contract: caller MUST pass the same actionFingerprint that the
//     Phase 4 confirmation step used. No parallel hash. (T-07-04.)
//   - Protected folder set is captured ONCE at server startup via
//     resolveProtectedFolders() and threaded as ReadonlySet<string> into
//     ToolCtx. Env changes after startup are NOT reflected until restart --
//     matches the rest of the env-loading pattern.
//   - ASCII only: REDACTED_STUB uses hyphen-minus U+002D, NOT em-dash U+2014.
//     CLAUDE.md ASCII rule; Task 7 grep gate enforces. See D-ASCII-REDACTED-MARKER.
//   - enforceSendGuards is PURE (no state mutation). recordSend is the SOLE
//     state-mutation site. Lets the L3 path observe the would-be violation
//     without poisoning counter state on the bypass.
//   - 2FA redaction is UNCONDITIONAL (no L3 advisory bypass) -- leak risk is
//     severity-independent. T-07-02.

import { getSpecialFolders } from './imap.js';
import type { AuthLevel } from './auth.js';

// -- Constants (read env at call time, not at module-load) ----------------

const DEFAULT_DAILY_LIMIT = 50;
const DEFAULT_PER_RECIPIENT_HOURLY = 5;
const DEFAULT_DEDUP_WINDOW_SEC = 60;
const DEFAULT_PROTECTED_FOLDERS: readonly string[] = ['INBOX', 'Sent', 'Drafts', 'Important'];

// REQUIREMENTS.md OPS-04 default 2FA-sender domain list. Operator override via
// YANDEX_BLOCK_2FA_SENDERS is TOTAL REPLACEMENT (not additive). T-07-11.
const DEFAULT_2FA_PATTERNS: readonly string[] = [
  'sberbank.ru',
  'tinkoff.ru',
  'gosuslugi.ru',
  'vtb.ru',
  'alfabank.ru',
  'mos.ru',
  'nalog.ru',
  'yandex.ru',
  'steampowered.com',
  'github.com',
  'google.com',
  'microsoft.com',
  'apple.com',
];

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

// ASCII-only stub body. Hyphen-minus U+002D. NOT em-dash U+2014. CLAUDE.md.
export const REDACTED_STUB = '[REDACTED - 2FA sender]';

// -- Env readers --------------------------------------------------------

function clampPositiveInt(raw: string | undefined, fallback: number): number {
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.floor(n);
}

function dailyLimit(): number {
  return clampPositiveInt(process.env.YANDEX_DAILY_SEND_LIMIT, DEFAULT_DAILY_LIMIT);
}

function perRecipientLimit(): number {
  return clampPositiveInt(process.env.YANDEX_PER_RECIPIENT_HOURLY, DEFAULT_PER_RECIPIENT_HOURLY);
}

function dedupWindowMs(): number {
  const raw = process.env.YANDEX_DEDUP_WINDOW_SEC;
  if (raw === undefined) return DEFAULT_DEDUP_WINDOW_SEC * 1000;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_DEDUP_WINDOW_SEC * 1000;
  return Math.max(1000, Math.floor(n * 1000));
}

function protectedFolderLiterals(): readonly string[] {
  const raw = process.env.YANDEX_PROTECTED_FOLDERS;
  if (raw === undefined) return DEFAULT_PROTECTED_FOLDERS;
  if (raw === '') return []; // operator opt-out (documented).
  return raw.split(',').map(s => s.trim()).filter(s => s.length > 0);
}

function twoFaPatterns(): readonly string[] {
  const raw = process.env.YANDEX_BLOCK_2FA_SENDERS;
  if (raw === undefined) return DEFAULT_2FA_PATTERNS;
  // Total replacement -- even '' yields empty list (operator opt-out).
  return raw.split(',').map(s => s.trim()).filter(s => s.length > 0);
}

// -- GuardResult discriminated union --------------------------------------

export type GuardResult =
  | { ok: true }
  | { ok: false; reason: 'daily_send_limit_exceeded'; remaining: number; limit: number }
  | { ok: false; reason: 'per_recipient_rate_limit'; recipient: string; retryAfter: Date; limit: number }
  | { ok: false; reason: 'duplicate_send_within_window'; windowSec: number };

// -- Address normalization (shared by PerRecipientCounter + tests) -------

function normalizeAddr(addr: string | null | undefined): string | null {
  if (!addr) return null;
  const trimmed = addr.trim();
  if (!trimmed) return null;
  // Strip optional "Name <addr>" wrapping; identical pattern to allowlist gate.
  const m = trimmed.match(/<([^>]+)>/);
  const bare = (m?.[1] ?? trimmed).trim().toLowerCase();
  return bare.length > 0 ? bare : null;
}

// -- DailyCounter ---------------------------------------------------------

export class DailyCounter {
  private timestamps: number[] = [];

  private prune(now: number): void {
    const cutoff = now - DAY_MS;
    let idx = 0;
    while (idx < this.timestamps.length && this.timestamps[idx] < cutoff) idx++;
    if (idx > 0) this.timestamps = this.timestamps.slice(idx);
  }

  check(now: number = Date.now()): GuardResult {
    this.prune(now);
    const limit = dailyLimit();
    if (this.timestamps.length >= limit) {
      return { ok: false, reason: 'daily_send_limit_exceeded', remaining: 0, limit };
    }
    return { ok: true };
  }

  record(now: number = Date.now()): void {
    this.timestamps.push(now);
  }

  count(now: number = Date.now()): number {
    this.prune(now);
    return this.timestamps.length;
  }
}

// -- PerRecipientCounter --------------------------------------------------

export class PerRecipientCounter {
  private buckets: Map<string, number[]> = new Map();

  private prune(addr: string, now: number): number[] {
    const cutoff = now - HOUR_MS;
    const cur = this.buckets.get(addr);
    if (!cur) return [];
    const next = cur.filter(t => t >= cutoff);
    if (next.length === 0) {
      this.buckets.delete(addr);
      return [];
    }
    this.buckets.set(addr, next);
    return next;
  }

  check(recipients: readonly string[], now: number = Date.now()): GuardResult {
    const limit = perRecipientLimit();
    for (const raw of recipients) {
      const addr = normalizeAddr(raw);
      if (addr === null) continue;
      const bucket = this.prune(addr, now);
      if (bucket.length >= limit) {
        return {
          ok: false,
          reason: 'per_recipient_rate_limit',
          recipient: addr,
          retryAfter: new Date((bucket[0] ?? now) + HOUR_MS),
          limit,
        };
      }
    }
    return { ok: true };
  }

  record(recipients: readonly string[], now: number = Date.now()): void {
    const seen = new Set<string>();
    for (const raw of recipients) {
      const addr = normalizeAddr(raw);
      if (addr === null || seen.has(addr)) continue;
      seen.add(addr);
      const cur = this.buckets.get(addr) ?? [];
      cur.push(now);
      this.buckets.set(addr, cur);
    }
  }
}

// -- SendDedup ------------------------------------------------------------

export class SendDedup {
  private seen: Map<string, number> = new Map();

  private fullPrune(now: number): void {
    const windowMs = dedupWindowMs();
    for (const [fp, ts] of this.seen) {
      if (now - ts > windowMs) this.seen.delete(fp);
    }
  }

  check(fingerprint: string, now: number = Date.now()): GuardResult {
    const windowMs = dedupWindowMs();
    const ts = this.seen.get(fingerprint);
    if (ts !== undefined) {
      if (now - ts <= windowMs) {
        return {
          ok: false,
          reason: 'duplicate_send_within_window',
          windowSec: Math.floor(windowMs / 1000),
        };
      }
      // Lazy single-key prune on access.
      this.seen.delete(fingerprint);
    }
    return { ok: true };
  }

  record(fingerprint: string, now: number = Date.now()): void {
    this.fullPrune(now);
    this.seen.set(fingerprint, now);
  }
}

// -- Module-level singletons (mirror ConnectionManager pattern) -----------

let _daily: DailyCounter | null = null;
let _perRecip: PerRecipientCounter | null = null;
let _dedup: SendDedup | null = null;

export function getDailyCounter(): DailyCounter {
  return _daily ?? (_daily = new DailyCounter());
}
export function getPerRecipientCounter(): PerRecipientCounter {
  return _perRecip ?? (_perRecip = new PerRecipientCounter());
}
export function getSendDedup(): SendDedup {
  return _dedup ?? (_dedup = new SendDedup());
}

// -- Send-pipeline helpers ------------------------------------------------

export interface SendGuardPayload {
  to: readonly string[];
  cc?: readonly string[];
  bcc?: readonly string[];
}

// Pure: NO state mutation. Order: dedup -> daily -> per-recipient.
// Rationale: dedup is cheapest (single Map lookup) and catches retry loops
// first; daily is a single counter; per-recipient walks a Map.
export function enforceSendGuards(
  payload: SendGuardPayload,
  _level: AuthLevel,
  fingerprint: string,
): GuardResult {
  void _level; // level is consumed by handler (advisory mode decision), not here.
  const dedup = getSendDedup().check(fingerprint);
  if (!dedup.ok) return dedup;
  const daily = getDailyCounter().check();
  if (!daily.ok) return daily;
  const allRecipients: string[] = [
    ...payload.to,
    ...(payload.cc ?? []),
    ...(payload.bcc ?? []),
  ];
  const perRecip = getPerRecipientCounter().check(allRecipients);
  if (!perRecip.ok) return perRecip;
  return { ok: true };
}

// Called from the handler ONLY after sendEmail() resolved successfully (no
// error thrown). Mutates ALL three state-tracking singletons. Phase 6
// wrapWithAudit fires the success record around the handler return separately.
export function recordSend(payload: SendGuardPayload, fingerprint: string): void {
  const now = Date.now();
  getDailyCounter().record(now);
  const allRecipients: string[] = [
    ...payload.to,
    ...(payload.cc ?? []),
    ...(payload.bcc ?? []),
  ];
  getPerRecipientCounter().record(allRecipients, now);
  getSendDedup().record(fingerprint, now);
}

// L3 (auto) advisory rule. Helper kept here so the L3 semantics are owned by
// guards.ts (single source of truth) rather than scattered through tools.ts.
export function isAdvisory(level: AuthLevel): boolean {
  return level >= 3;
}

// -- 2FA matcher ----------------------------------------------------------

export function is2FASender(fromAddr: string | null | undefined): boolean {
  if (!fromAddr) return false;
  const addr = fromAddr.trim().toLowerCase();
  if (!addr) return false;
  for (const raw of twoFaPatterns()) {
    const pattern = raw.trim().toLowerCase();
    if (!pattern) continue;
    if (pattern.includes('@')) {
      // Exact-address match (e.g. 'security@example.org').
      if (addr === pattern) return true;
      continue;
    }
    // Bare domain (e.g. 'github.com') -- match any address at that domain or
    // its subdomains. L-4 fix: 'noreply@security.yandex.ru' must match the
    // 'yandex.ru' pattern (it didn't before because endsWith('@yandex.ru')
    // checks an exact domain anchor and excludes subdomains).
    //
    // Lookalike safety: 'user@evilyandex.ru' does NOT match 'yandex.ru' because
    // the host 'evilyandex.ru' is not equal to 'yandex.ru' and does not end
    // with '.yandex.ru' (no leading dot). Subdomain match requires the dot
    // boundary explicitly.
    //
    // Wildcard patterns ('security@*', '*@domain') are deferred to Layer 2+.
    const domain = pattern.startsWith('@') ? pattern.slice(1) : pattern;
    const atIdx = addr.lastIndexOf('@');
    if (atIdx < 0) continue;
    const host = addr.slice(atIdx + 1);
    if (host === domain || host.endsWith('.' + domain)) return true;
  }
  return false;
}

// -- Protected-folder helpers --------------------------------------------

// Case-insensitive lookup. The set is small (<= ~10 entries) so linear scan
// is fine and avoids forcing all-lowercase semantics on the caller.
export function isProtectedFolder(path: string, protectedSet: ReadonlySet<string>): boolean {
  const target = path.toLowerCase();
  for (const entry of protectedSet) {
    if (entry.toLowerCase() === target) return true;
  }
  return false;
}

// Resolved ONCE at server startup. Combines env-literal defaults with the
// cyrillic-aware special-use IMAP paths from getSpecialFolders. IMAP failure
// degrades gracefully to literals-only (logged to stderr). The literal
// INBOX/Sent/Drafts/Important defaults catch the English-locale common case
// even when the IMAP probe is unreachable.
export async function resolveProtectedFolders(): Promise<ReadonlySet<string>> {
  const set = new Set<string>();
  for (const lit of protectedFolderLiterals()) set.add(lit);
  try {
    const sf = await getSpecialFolders();
    for (const v of Object.values(sf)) {
      if (v && typeof v === 'string') set.add(v);
    }
  } catch (e) {
    process.stderr.write(
      '[yandex-mail-guards] resolveProtectedFolders: IMAP unreachable, using literal defaults only: ' +
      (e instanceof Error ? e.message : String(e)) + '\n',
    );
  }
  return set;
}

// -- Test seam (NOT for production callers) ------------------------------

export function _resetForTests(): void {
  _daily = null;
  _perRecip = null;
  _dedup = null;
}
