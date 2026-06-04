// mail-index.ts -- bundle-safe local envelope index (Layer 2 foundation).
//
// Turns 800-1500ms live IMAP scans into <5ms local lookups by caching folder
// envelopes on disk as JSON Lines. ZERO native deps: pure node:fs + node:path +
// node:crypto. No sqlite, no better-sqlite3 -- a native module would break both
// the single esbuild bundle and the `npx -y github:` install path.
//
// Storage (under getStateDir()/index/):
//   meta.json       -- { version, account, folders: { [f]: cursor+count } }
//   envelopes.jsonl -- one IndexRecord per line (JSON).
//
// Sync model:
//   buildIndex(folders)  -- full rebuild of the given folders.
//   updateIndex(folders) -- incremental: fetch UIDs >= stored uidNext; a
//                           uidValidity change rebuilds that folder.
//
// Search (in-memory, lazy-loaded, mtime-invalidated):
//   searchFast(query)    -- inverted-index FTS over subject + sender, ranked.
//   getThread(query)     -- groups Re:/Fwd: variants by normalized subject.
//
// Multi-account hook: every record carries `account` (= getConfiguredAccount()).
// For now there is a single account; the dimension is reserved so a future
// layer can index several mailboxes side by side without a schema migration.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';

import { getStateDir } from './state-dir.js';
import type { EmailHeader } from './imap.js';

// ── Public types ──────────────────────────────────────────────────────

export interface IndexRecord {
  account: string;
  folder: string;
  uid: number;
  messageId: string;
  fromEmail: string;
  fromName: string;
  subject: string;
  date: string;
  seen: boolean;
  flagged: boolean;
  size: number;
}

export interface SearchHit {
  record: IndexRecord;
  score: number;
  matchReasons: string[];
}

export interface FolderStatus {
  folder: string;
  count: number;
  uidValidity: number;
  uidNext: number;
  lastSyncMs: number;
}

export interface IndexStatus {
  exists: boolean;
  account: string;
  folders: FolderStatus[];
  totalCount: number;
  indexPath: string;
}

// Dependency injection so tests do not need a live IMAP server. The default
// source (defaultSource()) wraps imap.getMailboxCursor + imap.streamEnvelopes.
export interface EnvelopeSource {
  getCursor(folder: string): Promise<{ uidValidity: number; uidNext: number; exists: number }>;
  stream(folder: string, opts?: { minUid?: number }): AsyncGenerator<EmailHeader, void, void>;
}

// ── Storage shapes ────────────────────────────────────────────────────

interface FolderMeta {
  uidValidity: number;
  uidNext: number;
  count: number;
  lastSyncMs: number;
}

interface MetaFile {
  version: 1;
  account: string;
  folders: Record<string, FolderMeta>;
}

// ── Constants ─────────────────────────────────────────────────────────

const META_VERSION = 1 as const;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MIN_TOKEN_LEN = 2;
const RECENCY_TOP_FRACTION = 0.2;   // newest 20% by date get the recency boost.
// Strip leading reply/forward prefixes: English re/fwd/fw + Russian "Вс:".
const SUBJECT_PREFIX_RE = /^\s*(re|fwd?|fw|вс)\s*:\s*/iu;
// Unicode tokenizer split: anything that is not a letter or a number (handles
// Cyrillic via \p{L}). Requires the /u flag.
const TOKEN_SPLIT_RE = /[^\p{L}\p{N}]+/u;

// ── Paths ─────────────────────────────────────────────────────────────

function indexDir(): string {
  return path.join(getStateDir(), 'index');
}

function metaPath(): string {
  return path.join(indexDir(), 'meta.json');
}

function envelopesPath(): string {
  return path.join(indexDir(), 'envelopes.jsonl');
}

export function getIndexDir(): string { return indexDir(); }

// ── Account resolution ────────────────────────────────────────────────

// getConfiguredAccount: the account id stamped on every record. Lazy + guarded
// so a missing token file never throws (which would break tool registration).
function getConfiguredAccount(): string {
  try {
    // Lazy require keeps token.ts off the module-load critical path -- importing
    // it does not run loadCredentials, but we centralise the catch here anyway.
    const { loadCredentials } = require('./token.js') as typeof import('./token.js');
    const email = loadCredentials().email;
    return email && email.length > 0 ? email.toLowerCase() : 'default';
  } catch {
    return 'default';
  }
}

// ── Default IMAP-backed source ────────────────────────────────────────

// defaultSource: wraps imap.getMailboxCursor + imap.streamEnvelopes. Lazily
// required so importing this module never opens an IMAP connection and never
// forces a credential load.
function defaultSource(): EnvelopeSource {
  const imap = require('./imap.js') as typeof import('./imap.js');
  return {
    getCursor(folder: string) {
      return imap.getMailboxCursor(folder);
    },
    stream(folder: string, opts?: { minUid?: number }) {
      return imap.streamEnvelopes(folder, undefined, undefined, opts);
    },
  };
}

// ── Atomic write helper (mirrors allowlist.ts:atomicWrite) ────────────

function ensureIndexDir(): void {
  fs.mkdirSync(indexDir(), { recursive: true, mode: 0o700 });
}

function atomicWrite(target: string, data: string, mode: number): void {
  ensureIndexDir();
  const tmp = target + '.tmp.' + process.pid + '.' + randomBytes(3).toString('hex');
  try {
    fs.writeFileSync(tmp, data, { mode });
    fs.renameSync(tmp, target);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    throw new Error(`atomicWrite to ${target} failed: ${err.message ?? String(e)}`);
  }
}

// ── Meta load / persist ───────────────────────────────────────────────

function emptyMeta(): MetaFile {
  return { version: META_VERSION, account: getConfiguredAccount(), folders: {} };
}

function loadMeta(): MetaFile {
  const p = metaPath();
  if (!fs.existsSync(p)) return emptyMeta();
  try {
    const parsed = JSON.parse(fs.readFileSync(p, 'utf-8')) as unknown;
    if (
      typeof parsed !== 'object' || parsed === null ||
      (parsed as { version?: unknown }).version !== META_VERSION ||
      typeof (parsed as { folders?: unknown }).folders !== 'object' ||
      (parsed as { folders?: unknown }).folders === null
    ) {
      return emptyMeta();
    }
    const obj = parsed as { account?: unknown; folders: Record<string, unknown> };
    const folders: Record<string, FolderMeta> = {};
    for (const [folder, raw] of Object.entries(obj.folders)) {
      if (typeof raw !== 'object' || raw === null) continue;
      const r = raw as Record<string, unknown>;
      folders[folder] = {
        uidValidity: Number(r['uidValidity']) || 0,
        uidNext: Number(r['uidNext']) || 0,
        count: Number(r['count']) || 0,
        lastSyncMs: Number(r['lastSyncMs']) || 0,
      };
    }
    return {
      version: META_VERSION,
      account: typeof obj.account === 'string' ? obj.account : getConfiguredAccount(),
      folders,
    };
  } catch {
    return emptyMeta();
  }
}

function persistMeta(meta: MetaFile): void {
  atomicWrite(metaPath(), JSON.stringify(meta, null, 2), 0o600);
}

// ── Envelope record helpers ───────────────────────────────────────────

function toRecord(account: string, folder: string, h: EmailHeader): IndexRecord {
  return {
    account,
    folder,
    uid: h.uid,
    messageId: h.messageId,
    fromEmail: h.from[0]?.address?.toLowerCase() ?? '',
    fromName: h.from[0]?.name ?? '',
    subject: h.subject ?? '',
    date: h.date ?? '',
    seen: h.seen,
    flagged: h.flagged,
    size: h.size,
  };
}

function loadAllRecords(): IndexRecord[] {
  const p = envelopesPath();
  if (!fs.existsSync(p)) return [];
  const raw = fs.readFileSync(p, 'utf-8');
  const out: IndexRecord[] = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as IndexRecord);
    } catch {
      // Skip a corrupt line rather than abort the whole load -- a partially
      // written JSONL (crash mid-append) must not brick the index.
    }
  }
  return out;
}

function serializeRecords(records: IndexRecord[]): string {
  return records.length === 0 ? '' : records.map(r => JSON.stringify(r)).join('\n') + '\n';
}

function rewriteEnvelopes(records: IndexRecord[]): void {
  atomicWrite(envelopesPath(), serializeRecords(records), 0o600);
}

// ── Public: status / existence ────────────────────────────────────────

export function indexExists(): boolean {
  if (!fs.existsSync(metaPath())) return false;
  const meta = loadMeta();
  return Object.keys(meta.folders).length >= 1;
}

export function getIndexStatus(): IndexStatus {
  const exists = fs.existsSync(metaPath());
  const meta = loadMeta();
  const folders: FolderStatus[] = Object.entries(meta.folders).map(([folder, m]) => ({
    folder,
    count: m.count,
    uidValidity: m.uidValidity,
    uidNext: m.uidNext,
    lastSyncMs: m.lastSyncMs,
  }));
  const totalCount = folders.reduce((sum, f) => sum + f.count, 0);
  return {
    exists: exists && folders.length >= 1,
    account: meta.account,
    folders,
    totalCount,
    indexPath: indexDir(),
  };
}

// ── Public: build / update ────────────────────────────────────────────

// buildIndex: full rebuild of the given folders. Records for any OTHER folder
// are preserved. For each rebuilt folder: read the cursor, stream every
// envelope, replace that folder's records, and stamp meta with the cursor.
export async function buildIndex(
  folders: string[],
  source?: EnvelopeSource,
): Promise<{ folders: FolderStatus[]; added: number }> {
  const src = source ?? defaultSource();
  const account = getConfiguredAccount();
  const meta = loadMeta();
  meta.account = account;

  // Keep records for folders we are NOT rebuilding.
  const rebuildSet = new Set(folders);
  const records: IndexRecord[] = loadAllRecords().filter(r => !rebuildSet.has(r.folder));

  let added = 0;
  const result: FolderStatus[] = [];
  for (const folder of folders) {
    const cursor = await src.getCursor(folder);
    let count = 0;
    for await (const h of src.stream(folder)) {
      records.push(toRecord(account, folder, h));
      count++;
      added++;
    }
    const m: FolderMeta = {
      uidValidity: cursor.uidValidity,
      uidNext: cursor.uidNext,
      count,
      lastSyncMs: Date.now(),
    };
    meta.folders[folder] = m;
    result.push({ folder, count, uidValidity: m.uidValidity, uidNext: m.uidNext, lastSyncMs: m.lastSyncMs });
  }

  rewriteEnvelopes(records);
  persistMeta(meta);
  return { folders: result, added };
}

// updateIndex: incremental sync. Per folder:
//   - no stored meta OR uidValidity changed -> full rebuild of that folder.
//   - else stream UIDs >= stored.uidNext, keep only uid >= stored.uidNext
//     (the IMAP "N:*" range can echo the last existing message), dedup against
//     existing (folder, uid) pairs, append, and advance the cursor.
export async function updateIndex(
  folders: string[],
  source?: EnvelopeSource,
): Promise<{ folders: FolderStatus[]; added: number }> {
  const src = source ?? defaultSource();
  const account = getConfiguredAccount();
  const meta = loadMeta();
  meta.account = account;

  // Determine which folders need a full rebuild vs an incremental append.
  const toRebuild: string[] = [];
  const toAppend: string[] = [];
  const cursors = new Map<string, { uidValidity: number; uidNext: number; exists: number }>();
  for (const folder of folders) {
    const cursor = await src.getCursor(folder);
    cursors.set(folder, cursor);
    const stored = meta.folders[folder];
    if (!stored || stored.uidValidity !== cursor.uidValidity) {
      toRebuild.push(folder);
    } else {
      toAppend.push(folder);
    }
  }

  let added = 0;
  const result: FolderStatus[] = [];

  // Rebuild path delegates to buildIndex semantics for the affected folders.
  if (toRebuild.length > 0) {
    const rebuilt = await buildIndex(toRebuild, src);
    added += rebuilt.added;
    for (const fs0 of rebuilt.folders) result.push(fs0);
    // buildIndex rewrote files + meta; re-read so the append path below sees
    // the post-rebuild state.
    Object.assign(meta.folders, loadMeta().folders);
  }

  if (toAppend.length > 0) {
    const records = loadAllRecords();
    // Existing (folder, uid) keys for dedup.
    const existing = new Set<string>();
    for (const r of records) existing.add(r.folder + '\x00' + r.uid);

    for (const folder of toAppend) {
      const stored = meta.folders[folder];
      const cursor = cursors.get(folder)!;
      const minUid = stored.uidNext;
      let newCount = 0;
      for await (const h of src.stream(folder, { minUid })) {
        // The IMAP "minUid:*" range can echo the last existing message; drop
        // anything below the high-water mark.
        if (h.uid < minUid) continue;
        const key = folder + '\x00' + h.uid;
        if (existing.has(key)) continue;
        existing.add(key);
        records.push(toRecord(account, folder, h));
        newCount++;
        added++;
      }
      const m: FolderMeta = {
        uidValidity: cursor.uidValidity,
        uidNext: cursor.uidNext,
        count: stored.count + newCount,
        lastSyncMs: Date.now(),
      };
      meta.folders[folder] = m;
      result.push({ folder, count: m.count, uidValidity: m.uidValidity, uidNext: m.uidNext, lastSyncMs: m.lastSyncMs });
    }

    rewriteEnvelopes(records);
    persistMeta(meta);
  } else if (toRebuild.length > 0) {
    // Only rebuilds happened; buildIndex already persisted. Still persist meta
    // to capture the merged account field (cheap, idempotent).
    persistMeta(meta);
  }

  return { folders: result, added };
}

// dropIndex: delete the entire index directory. Idempotent.
export function dropIndex(): void {
  const dir = indexDir();
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // Best-effort: a stale handle on Windows can refuse the unlink. Fall back
    // to truncating the two known files so indexExists() returns false.
    try { fs.writeFileSync(metaPath(), JSON.stringify(emptyMeta(), null, 2)); } catch { /* ignore */ }
    try { fs.unlinkSync(envelopesPath()); } catch { /* ignore */ }
  }
  invalidateCache();
}

// ── In-memory FTS cache (lazy, mtime-invalidated) ─────────────────────

interface IndexCache {
  key: string;                         // mtimeMs + ':' + size of envelopes.jsonl
  records: IndexRecord[];
  // token -> set of record indices. Built over subject + fromName +
  // fromEmail local-part.
  inverted: Map<string, Set<number>>;
  // Per-record token sets, split so subject hits score higher than sender.
  subjectTokens: Set<string>[];
  senderTokens: Set<string>[];
  // Date (ms) per record; NaN when missing/invalid.
  dateMs: number[];
  // Recency threshold: records with dateMs >= this get the recency boost.
  recencyThresholdMs: number;
}

let cache: IndexCache | null = null;

function invalidateCache(): void {
  cache = null;
}

function tokenize(text: string): string[] {
  if (!text) return [];
  const out: string[] = [];
  for (const part of text.toLowerCase().split(TOKEN_SPLIT_RE)) {
    if (part.length >= MIN_TOKEN_LEN) out.push(part);
  }
  return out;
}

function localPart(email: string): string {
  const at = email.indexOf('@');
  return at > 0 ? email.slice(0, at) : email;
}

function cacheKeyFor(): string | null {
  const p = envelopesPath();
  try {
    const st = fs.statSync(p);
    return st.mtimeMs + ':' + st.size;
  } catch {
    return null; // no file yet.
  }
}

function buildCache(): IndexCache {
  const records = loadAllRecords();
  const inverted = new Map<string, Set<number>>();
  const subjectTokens: Set<string>[] = [];
  const senderTokens: Set<string>[] = [];
  const dateMs: number[] = [];
  const validDates: number[] = [];

  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    const sTok = new Set<string>(tokenize(r.subject));
    const fromTok = new Set<string>([
      ...tokenize(r.fromName),
      ...tokenize(localPart(r.fromEmail)),
    ]);
    subjectTokens.push(sTok);
    senderTokens.push(fromTok);

    for (const t of sTok) addToInverted(inverted, t, i);
    for (const t of fromTok) addToInverted(inverted, t, i);

    const ms = r.date ? new Date(r.date).getTime() : NaN;
    dateMs.push(ms);
    if (!isNaN(ms)) validDates.push(ms);
  }

  // Recency threshold: the cutoff above which a record is in the newest
  // RECENCY_TOP_FRACTION by date. Records without a valid date never qualify.
  let recencyThresholdMs = Number.POSITIVE_INFINITY;
  if (validDates.length > 0) {
    const sorted = validDates.slice().sort((a, b) => a - b);
    const idx = Math.floor(sorted.length * (1 - RECENCY_TOP_FRACTION));
    recencyThresholdMs = sorted[Math.min(idx, sorted.length - 1)];
  }

  return {
    key: cacheKeyFor() ?? '',
    records,
    inverted,
    subjectTokens,
    senderTokens,
    dateMs,
    recencyThresholdMs,
  };
}

function addToInverted(inverted: Map<string, Set<number>>, token: string, idx: number): void {
  let set = inverted.get(token);
  if (!set) { set = new Set<number>(); inverted.set(token, set); }
  set.add(idx);
}

// getCache: lazy-load + mtime-invalidated. A rebuild by a separate CLI process
// changes the file mtime/size, so the next search re-reads from disk.
function getCache(): IndexCache {
  const key = cacheKeyFor();
  if (key === null) {
    // No envelopes file -> empty cache (but keep a sentinel so we don't rebuild
    // every call). Use an empty key.
    if (cache && cache.key === '' && cache.records.length === 0) return cache;
    cache = {
      key: '',
      records: [],
      inverted: new Map(),
      subjectTokens: [],
      senderTokens: [],
      dateMs: [],
      recencyThresholdMs: Number.POSITIVE_INFINITY,
    };
    return cache;
  }
  if (cache && cache.key === key) return cache;
  cache = buildCache();
  return cache;
}

// ── Subject normalization (thread grouping) ───────────────────────────

function normalizeSubject(subject: string): string {
  let s = subject ?? '';
  for (let i = 0; i < 32; i++) {
    const next = s.replace(SUBJECT_PREFIX_RE, '');
    if (next === s) break;
    s = next;
  }
  return s.trim().toLowerCase();
}

// ── Public: search ────────────────────────────────────────────────────

function clampLimit(limit?: number): number {
  if (limit === undefined || !Number.isFinite(limit)) return DEFAULT_LIMIT;
  return Math.min(Math.max(Math.floor(limit), 1), MAX_LIMIT);
}

export function searchFast(query: string, opts?: { folder?: string; limit?: number }): SearchHit[] {
  const c = getCache();
  if (c.records.length === 0) return [];

  const qLower = query.toLowerCase().trim();
  const qTokens = tokenize(query);
  const limit = clampLimit(opts?.limit);
  const folderFilter = opts?.folder;

  // Candidate set: union of records matching any query token. With no usable
  // tokens we cannot rank by token -- fall back to a substring scan.
  const candidates = new Set<number>();
  for (const t of qTokens) {
    const set = c.inverted.get(t);
    if (set) for (const idx of set) candidates.add(idx);
  }
  // Substring fallback so a single short query token (or a phrase) still finds
  // subject-substring matches even when token indexing missed it.
  if (qLower.length > 0) {
    for (let i = 0; i < c.records.length; i++) {
      if (c.records[i].subject.toLowerCase().includes(qLower)) candidates.add(i);
    }
  }

  const hits: SearchHit[] = [];
  for (const idx of candidates) {
    const r = c.records[idx];
    if (folderFilter !== undefined && r.folder !== folderFilter) continue;

    let score = 0;
    const reasons: string[] = [];
    const sTok = c.subjectTokens[idx];
    const fromTok = c.senderTokens[idx];

    let subjectMatched = false;
    let senderMatched = false;
    for (const t of qTokens) {
      if (sTok.has(t)) { score += 3; subjectMatched = true; }
      if (fromTok.has(t)) { score += 2; senderMatched = true; }
    }
    if (subjectMatched) reasons.push('subject');
    if (senderMatched) reasons.push('sender');

    if (qLower.length > 0 && r.subject.toLowerCase().includes(qLower)) {
      score += 5;
      reasons.push('subject-substring');
    }

    // Recency boost: newest RECENCY_TOP_FRACTION by date.
    const ms = c.dateMs[idx];
    if (!isNaN(ms) && ms >= c.recencyThresholdMs) {
      score += 1;
      reasons.push('recent');
    }

    if (score <= 0) continue;
    hits.push({ record: r, score, matchReasons: reasons });
  }

  hits.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return dateCompareDesc(a.record.date, b.record.date);
  });
  return hits.slice(0, limit);
}

function dateCompareDesc(a: string, b: string): number {
  const ma = a ? new Date(a).getTime() : NaN;
  const mb = b ? new Date(b).getTime() : NaN;
  const va = isNaN(ma) ? -Infinity : ma;
  const vb = isNaN(mb) ? -Infinity : mb;
  return vb - va;
}

// getThread: pick the best searchFast hit, compute its normalized subject, and
// return every record in the SAME folder whose normalized subject matches,
// sorted by date ascending (chronological thread order). Score is a recency
// rank so the caller can still surface the newest message. Empty if no hit.
export function getThread(query: string, opts?: { folder?: string; limit?: number }): SearchHit[] {
  const top = searchFast(query, { folder: opts?.folder, limit: 1 });
  if (top.length === 0) return [];
  const seed = top[0].record;
  const target = normalizeSubject(seed.subject);
  const limit = clampLimit(opts?.limit);

  const c = getCache();
  const members: IndexRecord[] = [];
  for (const r of c.records) {
    if (r.folder !== seed.folder) continue;
    if (normalizeSubject(r.subject) !== target) continue;
    members.push(r);
  }

  members.sort((a, b) => -dateCompareDesc(a.date, b.date)); // ascending by date.

  // When a thread is longer than the limit, keep the NEWEST messages (the tail
  // of the ascending list) rather than the oldest -- a thread view wants the
  // most recent replies. Order stays chronological (ascending).
  const kept = members.length > limit ? members.slice(members.length - limit) : members;

  // Score by recency rank: newest message gets the highest score so a caller
  // sorting by score still lands on the latest reply.
  return kept.map((r, i) => ({
    record: r,
    score: i + 1, // chronological position; later = newer = higher.
    matchReasons: ['thread'],
  }));
}

// ── Test-only ─────────────────────────────────────────────────────────

// _resetForTests: flush the in-memory FTS cache so a fresh state dir (or a
// rebuild within the same process) is picked up on the next search.
export function _resetForTests(): void {
  invalidateCache();
}
