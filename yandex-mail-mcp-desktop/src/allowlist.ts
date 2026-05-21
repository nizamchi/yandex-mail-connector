// allowlist.ts — TOFU (trust-on-first-use) recipient allowlist with HMAC signing.
//
// Phase 6 (D9-D13): AllowlistEntry now carries trust metadata fields
//   { added: number; lastUsed: number; useCount: number }
// HMAC over canonicalStringify covers them automatically (no signing-code
// change needed). Migration of legacy files (entries without the 3 numeric
// fields) happens on loadAllowlist() -- one-shot, idempotent on subsequent
// loads. Session-scope entries are NOT mutated by bumpUseCount* (D13); they
// always surface useCount=0 via getTrustEntry (CONTEXT amendment H-2).
//
// Closes T-INT-03 (BCC exfil via prompt injection) and T-PI exfil routes by
// gating every outbound recipient against a permanent file-backed allowlist.
// The file is HMAC-SHA256 signed against a per-install secret (secret.bin in
// getStateDir()) so a file-system-only attacker cannot extend it without
// also stealing the key. Both files are written mode 0o600 on POSIX.
//
// On first L1+ start index.ts calls bootstrap() which walks the user's Sent
// folder, pulls the last 500 unique recipient addresses (to + cc), and treats
// those as the initial trust set ("you've emailed them before — they're real").
// Subsequent additions happen ONLY via:
//   - autoTrustOnReply() called from the in_reply_to auto-trust flow in
//     tools.ts. Per H-1 fix this runs ONLY when imap.findByMessageId resolved
//     the message-id in the Sent folder (prior-correspondence evidence), and
//     the entry is added with scope='session' -- in-memory only, NOT
//     persisted to allowlist.json. The blast radius of any unforeseen
//     escalation is one process lifetime.
//   - addTrusted() called from the yandex_trust_address MCP tool after the
//     CLI hands over a single-use trust_token via pending-trust.json
//     (scope='permanent', persisted + signed).
//   - bootstrap() (scope='permanent', source='sent_history').
//
// Phase 6 (06-01) replaced auditEmit() with audit.ts:auditLog().
//
// Per D-HMAC-SECRET-SOURCE: secret is auto-generated, persisted to secret.bin
// (NOT reused from YANDEX_CONFIRMATION_PASSWORD — that env is L2-only).
//
// No `any`. ESM `.js` suffix on internal imports.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { ImapFlow } from 'imapflow';

import { getStateDir } from './state-dir.js';
import { auditLog } from './audit.js';

// ── Types ──────────────────────────────────────────────────

export type AllowlistScope = 'permanent' | 'session' | 'auto';
export type AllowlistSource =
  | 'sent_history'
  | 'user_trust_token'
  | 'auto_trust_reply'
  | 'legacy_migration';

export interface AllowlistEntry {
  address: string;
  scope: AllowlistScope;
  source: AllowlistSource;
  added_at: string;
  // -- Phase 6 (PMLF-TRUST-META-01): trust metadata fields. --
  // added/lastUsed are ms epoch (consistency with risk-score.ts:trustAddedAtMs).
  // useCount increments on successful sends via bumpUseCountBatch (D13 + H-1).
  // canonicalStringify sorts keys -- HMAC covers these automatically.
  added: number;
  lastUsed: number;
  useCount: number;
}

interface AllowlistFile {
  version: 1;
  schema: 'yandex-mail-mcp-allowlist/v1';
  bootstrap_completed_at: string | null;
  entries: AllowlistEntry[];
  signature: string;
}

// ── Paths ──────────────────────────────────────────────────

function allowlistPath(): string {
  return process.env.YANDEX_ALLOWLIST_PATH ?? path.join(getStateDir(), 'allowlist.json');
}

function secretPath(): string {
  return path.join(getStateDir(), 'secret.bin');
}

function pendingTrustPath(): string {
  return path.join(getStateDir(), 'pending-trust.json');
}

export function getAllowlistPath(): string { return allowlistPath(); }
export function getSecretPath(): string { return secretPath(); }
export function getPendingTrustPath(): string { return pendingTrustPath(); }

// ── Secret management ──────────────────────────────────────

// In-process cache of the resolved secret. Cleared by _resetForTests().
let secretCache: Buffer | null = null;

// ── H-1: In-memory session-scope store ─────────────────────
// scope='session' entries live ONLY here -- never written to allowlist.json,
// never HMAC-signed. isAllowed() consults this set alongside the persisted
// file. Cleared by _resetForTests() (which restores deterministic state for
// tests and would also wipe the set on a process restart).
//
// Map keeps the metadata (source + added_at) so _listTrusted() can surface
// session grants to the user with a clear ephemerality marker (H-1 §Q1).
interface SessionEntry {
  source: AllowlistSource;
  added_at: string;
}
const sessionEntries: Map<string, SessionEntry> = new Map();

function loadSecret(): Buffer {
  if (secretCache !== null) return secretCache;
  const p = secretPath();
  if (fs.existsSync(p)) {
    const buf = fs.readFileSync(p);
    if (buf.length !== 32) {
      // Corrupt secret — fail closed. Caller (verifySignature) returns false.
      throw new Error(`allowlist secret at ${p} has unexpected length ${buf.length} (expected 32). Delete the file to regenerate (this wipes all trust).`);
    }
    secretCache = buf;
    return buf;
  }
  const buf = randomBytes(32);
  atomicWrite(p, buf, 0o600);
  secretCache = buf;
  return buf;
}

// ── Canonicalization + signing ────────────────────────────

// Recursive deterministic JSON serializer with sorted keys at every object
// level. Used as HMAC input. Excludes the 'signature' field — caller passes
// the file object with signature stripped or set to ''.
function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalStringify).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
}

function canonicalize(file: AllowlistFile): string {
  const { signature: _sig, ...rest } = file;
  void _sig;
  return canonicalStringify(rest);
}

function computeSignature(file: AllowlistFile, secret: Buffer): string {
  return createHmac('sha256', secret).update(canonicalize(file)).digest('hex');
}

// ── Atomic write helper ────────────────────────────────────

function atomicWrite(target: string, data: Buffer | string, mode: number): void {
  const tmp = target + '.tmp';
  try {
    fs.writeFileSync(tmp, data, { mode });
    fs.renameSync(tmp, target);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    // Best-effort cleanup of half-written tmpfile.
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    throw new Error(`atomicWrite to ${target} failed: ${err.message ?? String(e)}`);
  }
}

// ── Address normalisation ─────────────────────────────────

function norm(address: string): string {
  return address.trim().toLowerCase();
}

// ── Load / persist ────────────────────────────────────────

function emptyFile(): AllowlistFile {
  return {
    version: 1,
    schema: 'yandex-mail-mcp-allowlist/v1',
    bootstrap_completed_at: null,
    entries: [],
    signature: '',
  };
}

// Phase 6 (D10) migration discipline:
//
//   loadAllowlist() detects legacy entries (any entry missing one of the 3
//   numeric metadata fields) and rewrites the file in place with a fresh
//   HMAC signature. Migration is ONE-SHOT per file -- a second loadAllowlist
//   sees fully-populated entries and skips migrateInPlace, producing a
//   byte-equal file on subsequent reads (idempotency contract T-MIG-IDEMP).
//
//   Migration is fail-closed: if persist throws (disk error / corrupt
//   secret), in-memory state is NOT cached. The next call retries from
//   disk. Surface failure via the existing verifySignature startup gate.

function isLegacyEntry(e: unknown): boolean {
  if (typeof e !== 'object' || e === null) return true;
  const o = e as Record<string, unknown>;
  return !Number.isFinite(o['added'])
      || !Number.isFinite(o['lastUsed'])
      || !Number.isFinite(o['useCount']);
}

function migrateInPlace(file: AllowlistFile): { migratedCount: number; mutated: boolean } {
  let migratedCount = 0;
  for (const entry of file.entries) {
    if (!isLegacyEntry(entry)) continue;
    // entry has SOME pre-Phase-6 fields populated (address/scope/source/added_at)
    // but is missing one or more of {added, lastUsed, useCount}.
    const e = entry as unknown as Record<string, unknown>;
    const parsed = typeof e['added_at'] === 'string' ? Date.parse(e['added_at'] as string) : NaN;
    const ts = Number.isFinite(parsed) ? parsed : Date.now();
    if (!Number.isFinite(e['added']))    e['added']    = ts;
    if (!Number.isFinite(e['lastUsed'])) e['lastUsed'] = ts;
    if (!Number.isFinite(e['useCount'])) e['useCount'] = 0;
    if (e['source'] === undefined || e['source'] === null) e['source'] = 'legacy_migration';
    migratedCount++;
  }
  return { migratedCount, mutated: migratedCount > 0 };
}

function loadAllowlistRaw(): AllowlistFile {
  const p = allowlistPath();
  if (!fs.existsSync(p)) return emptyFile();
  try {
    const raw = fs.readFileSync(p, 'utf-8');
    const parsed = JSON.parse(raw) as unknown;
    if (
      typeof parsed !== 'object' || parsed === null ||
      (parsed as { version?: unknown }).version !== 1 ||
      (parsed as { schema?: unknown }).schema !== 'yandex-mail-mcp-allowlist/v1' ||
      !Array.isArray((parsed as { entries?: unknown }).entries)
    ) {
      // Corrupt — return fresh-empty so caller's verifySignature() can return
      // false and trigger the startup gate.
      return { ...emptyFile(), signature: 'corrupt' };
    }
    return parsed as AllowlistFile;
  } catch {
    return { ...emptyFile(), signature: 'corrupt' };
  }
}

// Re-entrancy guard: migrateInPlace -> persist -> (future caller) loadAllowlist
// must not retrigger migration on the same call stack. Per-process flag.
let _migrationInProgress = false;

export function loadAllowlist(): AllowlistFile {
  const file = loadAllowlistRaw();
  if (file.signature === 'corrupt') return file;
  if (_migrationInProgress) return file;
  // Phase 6 (D10): one-shot legacy migration on first load.
  const { migratedCount, mutated } = migrateInPlace(file);
  if (!mutated) return file;
  _migrationInProgress = true;
  try {
    const secret = loadSecret();
    file.signature = computeSignature(file, secret);
    persist(file);
    auditLog({
      action: 'allowlist_migrated',
      status: 'success',
      level: 'info',
      ts: new Date(Date.now()).toISOString(),
      reason: 'count=' + migratedCount + ',source=phase6',
    });
  } catch {
    // Fail-closed: leave on-disk file unchanged; next load retries.
    // No in-memory cache to invalidate (loadAllowlist reads disk every call).
  } finally {
    _migrationInProgress = false;
  }
  return file;
}

function persist(file: AllowlistFile): void {
  atomicWrite(allowlistPath(), JSON.stringify(file, null, 2), 0o600);
}

// ── Public API ────────────────────────────────────────────

// verifySignature: NEVER throws on bad input. Returns:
//   true  — fresh state (empty + never bootstrapped) OR signature matches.
//   false — file exists but signature missing/wrong/corrupt; caller exits.
//
// IMPORTANT (Phase 6 D10 + tamper invariant): verifySignature reads the file
// RAW -- it must NOT trigger migrateInPlace. Migration recomputes the
// signature; if verify went through loadAllowlist, a tampered file with
// legacy-shaped entries would be silently re-signed and pass verification.
// Tamper detection therefore runs on the disk bytes, not on the migrated
// shape. Migration only runs through loadAllowlist (called by isAllowed,
// getTrustEntry, bumpUseCountBatch, etc.) AFTER startup verification.
export function verifySignature(): boolean {
  const file = loadAllowlistRaw();
  if (file.signature === 'corrupt') return false;
  // Fresh state: never bootstrapped, no entries, empty signature → OK.
  if (file.bootstrap_completed_at === null && file.entries.length === 0 && file.signature === '') {
    return true;
  }
  let secret: Buffer;
  try { secret = loadSecret(); } catch { return false; }
  const expected = computeSignature(file, secret);
  const expectedBuf = Buffer.from(expected, 'hex');
  const actualBuf = Buffer.from(file.signature, 'hex');
  if (expectedBuf.length !== actualBuf.length || expectedBuf.length === 0) return false;
  try {
    return timingSafeEqual(expectedBuf, actualBuf);
  } catch {
    return false;
  }
}

// resign(): re-sign current allowlist file. With newSecret arg → rotate the
// stored secret AND re-sign with the new one (single-call rotation). Without
// arg → recompute signature with the current secret. Atomic write.
export function resign(newSecret?: Buffer): void {
  if (newSecret !== undefined) {
    if (newSecret.length !== 32) {
      throw new Error(`resign: new secret must be 32 bytes (got ${newSecret.length})`);
    }
    atomicWrite(secretPath(), newSecret, 0o600);
    secretCache = newSecret;
  }
  const secret = loadSecret();
  const file = loadAllowlist();
  if (file.signature === 'corrupt') {
    throw new Error('resign: allowlist file is corrupt — cannot resign. Delete it to regenerate.');
  }
  file.signature = computeSignature(file, secret);
  persist(file);
}

export function isAllowed(address: string): boolean {
  const target = norm(address);
  if (!target) return false;
  // H-1: session-scope entries are consulted alongside the persisted file.
  // Either source grants trust; neither alone is sufficient to escalate
  // (the file is HMAC-gated; the session set is process-local).
  if (sessionEntries.has(target)) return true;
  const file = loadAllowlist();
  return file.entries.some(e => e.address === target);
}

// addTrusted(address, scope, source):
//
//   scope='session' (H-1) -> in-memory only. No file I/O, no HMAC mutation.
//     Survives only until the process exits or _resetForTests() runs. Used
//     by the auto_trust_reply flow when a Sent-folder lookup demonstrates
//     prior correspondence with the sender.
//
//   scope='permanent' or scope='auto' -> persisted to allowlist.json with a
//     fresh HMAC signature. Survives process restart. Used by the explicit
//     user-trust CLI flow (permanent) and the legacy bootstrap path.
//
// Dedupe is case-insensitive and cross-scope: if an address is already in
// either the persisted file or the session set, the call is a no-op. We do
// NOT "upgrade" a session entry to permanent here -- that would require the
// caller to pass a distinct scope, and the dedupe-then-skip behavior keeps
// the function's contract simple.
export function addTrusted(address: string, scope: AllowlistScope, source: AllowlistSource): void {
  const target = norm(address);
  if (!target) return;

  // H-1: session scope is process-local; never touch disk.
  if (scope === 'session') {
    if (sessionEntries.has(target)) return;
    // Dedupe against the persisted file too -- no value in tracking a
    // session entry for an already-permanent address.
    const persisted = loadAllowlist();
    if (persisted.signature !== 'corrupt' && persisted.entries.some(e => e.address === target)) return;
    sessionEntries.set(target, {
      source,
      added_at: new Date().toISOString(),
    });
    auditLog({
      action: 'allowlist_add',
      status: 'success',
      level: 'info',
      ts: new Date().toISOString(),
      from_domain: target.split('@')[1] ?? '(none)',
      reason: 'scope=session,source=' + source,
    });
    return;
  }

  // Persisted scopes ('permanent', 'auto') -- legacy path. Note: the H-1
  // fix routes auto_trust_reply through scope='session' so 'auto' should
  // no longer reach this branch in normal flow. We keep the type union
  // open in case a future caller has a legitimate persisted-auto need.
  const file = loadAllowlist();
  if (file.signature === 'corrupt') {
    throw new Error('addTrusted: allowlist file is corrupt — refusing to mutate.');
  }
  const existing = file.entries.find(e => e.address === target);
  if (existing) return;
  const nowMs = Date.now();
  file.entries.push({
    address: target,
    scope,
    source,
    added_at: new Date(nowMs).toISOString(),
    added: nowMs,
    lastUsed: nowMs,
    useCount: 0,
  });
  const secret = loadSecret();
  file.signature = computeSignature(file, secret);
  persist(file);
  auditLog({
    action: 'allowlist_add',
    status: 'success',
    level: 'info',
    ts: new Date().toISOString(),
    from_domain: target.split('@')[1] ?? '(none)',
    reason: 'scope=' + scope + ',source=' + source,
  });
}

// autoTrustOnReply (H-1): policy helper for the yandex_send_email auto-trust
// block. Consolidates three guards in one place so tools.ts holds no policy:
//   1. Env opt-out:  YANDEX_AUTO_TRUST_REPLY=off -> hard no-op.
//   2. Sent-only:    only Sent-folder findByMessageId results elevate trust.
//                    INBOX hits emit allowlist_skip (forensics) and onSkip().
//   3. Session-only: elevation goes through addTrusted(..., 'session', ...)
//                    so the entry never persists. Process-restart wipes it.
//
// `opts.onSkip(reason)` lets the caller log a per-tool audit alongside the
// allowlist module's own forensics record. Both fire on the INBOX path.
//
// This function NEVER throws -- a forensics failure must not crash a send.
// Input shape accepted by autoTrustOnReply. Mirrors imap.findByMessageId
// (which returns source + folder + uid + from). We accept either field as
// the policy discriminant -- source preferred (canonical enum), folder
// falls back to literal-string compare against {INBOX, Sent}. This keeps
// the test seam simple (callers can pass folder=Sent without knowing the
// internal source/folder split) while preserving the imap.ts contract.
export interface AutoTrustOnReplyInput {
  from: string;
  source?: 'INBOX' | 'Sent';
  folder?: 'INBOX' | 'Sent' | string;
  uid?: number;
}
export interface AutoTrustOnReplyOpts {
  onSkip?: (reason: string) => void;
}
export function autoTrustOnReply(
  found: AutoTrustOnReplyInput | null,
  opts: AutoTrustOnReplyOpts = {},
): void {
  // 1. Env opt-out. Silent -- this is a global policy, not a per-call event.
  if (process.env.YANDEX_AUTO_TRUST_REPLY === 'off') return;

  if (!found || !found.from) return;

  const target = norm(found.from);
  if (!target) return;

  // 2. Sent-only gate. The H-1 invariant: INBOX-source resolutions are NOT
  // trust evidence; they're attacker-controllable metadata. Emit forensics.
  const isSent = found.source === 'Sent' || found.folder === 'Sent';
  if (!isSent) {
    try {
      auditLog({
        action: 'allowlist_skip',
        status: 'denied',
        level: 'warn',
        ts: new Date().toISOString(),
        from_domain: target.split('@')[1] ?? '(none)',
        reason: 'inbox_source',
      });
    } catch { /* forensics best-effort */ }
    try { opts.onSkip?.('inbox_source'); } catch { /* caller best-effort */ }
    return;
  }

  // 3. Sent path -> session-scope elevation. addTrusted handles dedupe and
  // its own audit emit (allowlist_add, scope=session).
  try {
    addTrusted(target, 'session', 'auto_trust_reply');
  } catch { /* must not crash a send */ }
}

// _listTrusted (H-1 §Q1): returns every trusted entry across BOTH the
// persisted file and the in-memory session set, with a clear scope marker so
// a future UX (yandex_trust_address --list, or a tool that surfaces trust
// state) can warn users that scope='session' grants evaporate on restart.
// Test seam: also used by auto-trust-reply.test.ts T-H1-04 to verify
// visibility of session entries.
export function _listTrusted(): Array<{ address: string; scope: AllowlistScope; source: AllowlistSource; added_at: string }> {
  const out: Array<{ address: string; scope: AllowlistScope; source: AllowlistSource; added_at: string }> = [];
  const file = loadAllowlist();
  if (file.signature !== 'corrupt') {
    for (const e of file.entries) {
      out.push({ address: e.address, scope: e.scope, source: e.source, added_at: e.added_at });
    }
  }
  for (const [address, meta] of sessionEntries) {
    out.push({ address, scope: 'session', source: meta.source, added_at: meta.added_at });
  }
  return out;
}

// bootstrap(client, limit, sentPath): one-shot Sent-folder mining of the
// initial trust set. Guarded by bootstrap_completed_at — returns 0 if already
// bootstrapped. sentPath is taken as a parameter (DI) so callers resolve it
// via imap.getSpecialFolders() — this avoids hardcoding 'Sent' (CLAUDE.md
// requires cyrillic-safe handling) and makes the function easy to unit-test
// with a mock client.
export async function bootstrap(
  client: ImapFlow,
  limit: number,
  sentPath: string,
): Promise<number> {
  const file = loadAllowlist();
  if (file.signature === 'corrupt') {
    throw new Error('bootstrap: allowlist file is corrupt — refusing to mutate.');
  }
  if (file.bootstrap_completed_at !== null) return 0;
  if (!Number.isFinite(limit) || limit <= 0) limit = 500;

  await client.mailboxOpen(sentPath, { readOnly: true });
  const searchResult = await client.search({ all: true }, { uid: true });
  const uids: number[] = Array.isArray(searchResult) ? searchResult : [];
  if (uids.length === 0) {
    // Empty Sent — mark bootstrap complete with zero entries so we don't retry
    // on every restart. User will accrue trust via in_reply_to + CLI.
    file.bootstrap_completed_at = new Date().toISOString();
    const secret = loadSecret();
    file.signature = computeSignature(file, secret);
    persist(file);
    auditLog({
      action: 'allowlist_bootstrap',
      status: 'success',
      level: 'info',
      ts: new Date().toISOString(),
      reason: 'count=0,source=sent_history',
    });
    return 0;
  }

  // Take last `limit` UIDs (highest = most recent in Yandex's UID assignment).
  const slice = uids.slice(-limit);

  const addrs = new Set<string>();
  const MAX_RAW = limit * 10;
  for await (const msg of client.fetch(slice, { uid: true, envelope: true }, { uid: true })) {
    const env = msg.envelope;
    if (!env) continue;
    const collect = (list?: Array<{ address?: string | null }>): void => {
      if (!list) return;
      for (const a of list) {
        if (a.address && typeof a.address === 'string') {
          const n = norm(a.address);
          if (n) addrs.add(n);
        }
      }
    };
    // Plan-check fix W-4: read BOTH to AND cc (ALLOW-01).
    collect(env.to);
    collect(env.cc);
    if (addrs.size > MAX_RAW) break;
  }

  const nowMs = Date.now();
  const now = new Date(nowMs).toISOString();
  const existingSet = new Set(file.entries.map(e => e.address));
  let added = 0;
  for (const a of addrs) {
    if (existingSet.has(a)) continue;
    file.entries.push({
      address: a,
      scope: 'permanent',
      source: 'sent_history',
      added_at: now,
      added: nowMs,
      lastUsed: nowMs,
      useCount: 0,
    });
    added++;
  }

  file.bootstrap_completed_at = now;
  const secret = loadSecret();
  file.signature = computeSignature(file, secret);
  persist(file);
  auditLog({
    action: 'allowlist_bootstrap',
    status: 'success',
    level: 'info',
    ts: new Date().toISOString(),
    reason: 'count=' + added + ',source=sent_history',
  });
  return added;
}

// ── Phase 6 trust metadata API (D11/D13 + H-1/H-5) ────────────

// getTrustEntry(address): returns the full AllowlistEntry for a trusted
// address. Case-insensitive. Consults the session map first (H-1) so
// auto-trusted session entries surface with scope='session' + useCount=0
// (CONTEXT amendment H-2: session entries ALWAYS report useCount=0; the
// "just auto-trusted" signal is timestamp-based, not count-based). Returns
// undefined for untrusted addresses.
export function getTrustEntry(address: string): AllowlistEntry | undefined {
  const target = norm(address);
  if (!target) return undefined;
  // 1. Session map first (matches isAllowed's lookup order).
  const session = sessionEntries.get(target);
  if (session !== undefined) {
    const parsed = Date.parse(session.added_at);
    const ts = Number.isFinite(parsed) ? parsed : Date.now();
    return {
      address: target,
      scope: 'session',
      source: session.source,
      added_at: session.added_at,
      added: ts,
      lastUsed: ts,
      useCount: 0,
    };
  }
  // 2. Persisted file (triggers migration if legacy).
  const file = loadAllowlist();
  if (file.signature === 'corrupt') return undefined;
  return file.entries.find(e => e.address === target);
}

// bumpUseCount(address, nowMs): single-recipient convenience wrapper.
// Persisted-scope: increments useCount + sets lastUsed, atomic re-sign+persist.
// Session-scope: no-op (D13). Unknown addresses: no-op.
// Multi-recipient sends MUST use bumpUseCountBatch (single atomic write).
export function bumpUseCount(address: string, nowMs: number): void {
  bumpUseCountBatch([address], nowMs);
}

// bumpUseCountBatch(addresses, nowMs) -- H-1 atomic mutation:
//   Single load+sign+write cycle for all addresses. Session-scope entries
//   are skipped (no disk mutation; D13 + H-2 amendment). Unknown addresses
//   are silently no-op. Emits ONE summary audit per call (domain-only,
//   CLAUDE.md privacy). On the all-unknown / all-session path, no audit
//   fires (no signal worth recording).
export function bumpUseCountBatch(addresses: readonly string[], nowMs: number): void {
  if (!addresses || addresses.length === 0) return;
  const seen = new Set<string>();
  const normed: string[] = [];
  for (const a of addresses) {
    const n = norm(a);
    if (!n || seen.has(n)) continue;
    seen.add(n);
    normed.push(n);
  }
  if (normed.length === 0) return;

  const sessionAddrs: string[] = [];
  const persistedAddrs: string[] = [];
  for (const n of normed) {
    if (sessionEntries.has(n)) sessionAddrs.push(n);
    else persistedAddrs.push(n);
  }

  if (persistedAddrs.length === 0) return; // pure-session call: no-op, no audit.

  const file = loadAllowlist();
  if (file.signature === 'corrupt') {
    throw new Error('bumpUseCountBatch: allowlist file is corrupt -- refusing to mutate.');
  }
  const bumpedDomains: string[] = [];
  let bumped = 0;
  for (const addr of persistedAddrs) {
    const entry = file.entries.find(e => e.address === addr);
    if (!entry) continue; // unknown -- no-op.
    entry.useCount = (Number.isFinite(entry.useCount) ? entry.useCount : 0) + 1;
    entry.lastUsed = nowMs;
    bumped++;
    const at = addr.indexOf('@');
    bumpedDomains.push(at >= 0 ? addr.slice(at + 1) : '(none)');
  }
  if (bumped === 0) return; // all unknown.

  const secret = loadSecret();
  file.signature = computeSignature(file, secret);
  persist(file);

  auditLog({
    action: 'allowlist_used',
    status: 'success',
    level: 'info',
    ts: new Date(nowMs).toISOString(),
    from_domain: bumpedDomains[0] ?? '(none)',
    reason: 'recipients=' + bumped + ',session=' + sessionAddrs.length,
  });
}

// _setEntryAddedForTests (H-5 test seam): backdates entry.added for an
// existing persisted-scope address. Used by allowlist-fixture.ts to drive
// 'new_trust' risk-signal assertions deterministically. PRODUCTION GUARD:
// throws if NODE_ENV === 'production'. Throws if entry not found (test bug).
export function _setEntryAddedForTests(address: string, addedMs: number): void {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('_setEntryAddedForTests called in production');
  }
  const target = norm(address);
  if (!target) throw new Error('_setEntryAddedForTests: empty address');
  const file = loadAllowlist();
  if (file.signature === 'corrupt') {
    throw new Error('_setEntryAddedForTests: allowlist file is corrupt');
  }
  const entry = file.entries.find(e => e.address === target);
  if (!entry) {
    throw new Error('_setEntryAddedForTests: entry not found: ' + target);
  }
  entry.added = addedMs;
  const secret = loadSecret();
  file.signature = computeSignature(file, secret);
  persist(file);
}

// sweepPendingTrust: orphan-sweep called from index.ts startup. Removes a
// pending-trust.json older than the TTL (5 minutes). Plan-check fix W-3.
// Returns true iff a sweep happened (for stderr quiet-log gate).
const PENDING_TTL_MS = 5 * 60 * 1000;
export function sweepPendingTrust(): boolean {
  const p = pendingTrustPath();
  if (!fs.existsSync(p)) return false;
  try {
    const st = fs.statSync(p);
    const ageMs = Date.now() - st.mtimeMs;
    if (ageMs > PENDING_TTL_MS) {
      fs.unlinkSync(p);
      auditLog({
        action: 'pending_trust_swept',
        status: 'success',
        level: 'info',
        ts: new Date().toISOString(),
        reason: 'age_ms=' + Math.round(ageMs),
      });
      return true;
    }
  } catch { /* ignore — best-effort */ }
  return false;
}

// Test-only: flush in-process caches (secret + session-scope entries).
// H-1: also wipes the session set so tests cannot bleed trust across cases.
export function _resetForTests(): void {
  secretCache = null;
  sessionEntries.clear();
}
