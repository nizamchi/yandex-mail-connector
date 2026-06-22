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
import type { ParsedAttachment } from './attachment-parser.js';
import { sanitizeForDisplay } from './sanitize.js';

// ── Public types ──────────────────────────────────────────────────────

export interface IndexRecord {
  account: string;
  folder: string;
  uid: number;
  messageId: string;
  // In-Reply-To message-id (parent in the thread graph). Optional: records
  // written before v2.7.0-p3 lack it -- getThread falls back to subject grouping.
  inReplyTo?: string;
  fromEmail: string;
  fromName: string;
  subject: string;
  date: string;
  seen: boolean;
  flagged: boolean;
  size: number;
  // Whether the message carries attachments, derived from BODYSTRUCTURE. Added
  // in schema 3 (v3.0.0). Pre-schema-3 records read from disk have this as
  // undefined until auto-migrated; the ?? false default handles forward-compat.
  has_attachments: boolean;
}

// AttachmentRecord: durable per-attachment manifest row (one per attachment leaf).
// One email with N attachment leaves → N AttachmentRecord rows, all co-located in
// attachments.jsonl alongside envelopes.jsonl.
//
// Field ordering:
//   identity prefix — mirrors IndexRecord :35-38 so reviewers read both the same way.
//   denormalized envelope fields — snapshotted from EmailHeader at build/append time;
//     refreshed only on rebuild. Phase-3 since/before/from filters scan the manifest
//     alone (no cross-cache join needed).
//   attachment payload — mirrors ParsedAttachment field order.
//
// Key invariants:
//   - md5 key is ALWAYS present (null when absent from BODYSTRUCTURE — Yandex sends null).
//   - filename may be null (sanitized-to-empty filename is stored null, row NOT dropped).
//   - sha256 is ABSENT entirely (populated values require a body download; Yandex IMAP
//     sends none — metadata-only per Phase 2 contract).
export interface AttachmentRecord {
  // Identity prefix — mirrors IndexRecord :35-38
  account: string;
  folder: string;
  uid: number;
  messageId: string;
  // Denormalized envelope fields (MR-2) — from EmailHeader, snapshot at build/append time,
  // refreshed only on rebuild. Phase-3 since/before/from filters scan the manifest alone.
  date: string;
  fromEmail: string;
  fromName: string;
  subject: string;
  // Attachment payload — mirrors ParsedAttachment :13-26
  // filename: sanitizeForDisplay(raw ?? '', {maxLen:200}) || null  (LD-6/LD-7)
  filename: string | null;
  mimeType: string;
  // RFC 3501 §7.4.2 BODYSTRUCTURE transfer-encoded octets; base64 parts ~33% over
  // decoded bytes; NO correction factor. Number.isFinite(a.size) ? a.size : 0 backstop.
  size: number;
  partId: string;
  // a.md5 ?? null — Yandex sends null (verified live 2026-06-22); key always present.
  md5: string | null;
}

export interface SearchHit {
  record: IndexRecord;
  score: number;
  matchReasons: string[];
}

// Structured filters applied on top of (or instead of) the free-text query.
// Every field maps to a column already present on IndexRecord, so filtering
// needs no schema change. `since`/`before` are epoch ms; `since` is inclusive,
// `before` is exclusive (mirrors IMAP SINCE/BEFORE semantics in tools.ts).
export interface SearchFilters {
  from?: string;       // substring of fromEmail or fromName (case-insensitive)
  since?: number;      // ms, inclusive lower bound on date
  before?: number;     // ms, exclusive upper bound on date
  seen?: boolean;
  flagged?: boolean;
  // True/false = only emails that do / don't carry attachments (derived from
  // BODYSTRUCTURE, schema 3). Counts named-inline parts (logos) by spec; see the
  // tool description + yandex_find_attachments for the mime escape hatch.
  has_attachments?: boolean;
}

export interface FolderStatus {
  folder: string;
  count: number;
  uidValidity: number;
  uidNext: number;
  lastSyncMs: number;
  schema: number;
}

export interface IndexStatus {
  exists: boolean;
  account: string;
  folders: FolderStatus[];
  totalCount: number;
  indexPath: string;
  // True once every indexed folder carries In-Reply-To links (schema >= 2).
  // False on a pre-threading index -> getThread falls back to subject grouping
  // until the next `index update` auto-rebuilds.
  threadingReady: boolean;
}

// Dependency injection so tests do not need a live IMAP server. The default
// source (defaultSource()) wraps imap.getMailboxCursor + imap.streamEnvelopes.
export interface EnvelopeSource {
  getCursor(folder: string): Promise<{ uidValidity: number; uidNext: number; exists: number }>;
  stream(folder: string, opts?: { minUid?: number }): AsyncGenerator<EmailHeader, void, void>;
}

// Per-folder failure surfaced by build/update instead of aborting the whole
// run. A folder that throws (network drop, missing mailbox, UID reset mid-sync)
// is reported here and the other folders still sync. The CLI turns a non-empty
// list into a non-zero exit so a cron job can detect a partial sync.
export interface IndexError {
  folder: string;
  error: string;
}

export interface IndexResult {
  folders: FolderStatus[];
  added: number;
  errors: IndexError[];
}

// ── Storage shapes ────────────────────────────────────────────────────

interface FolderMeta {
  uidValidity: number;
  uidNext: number;
  count: number;
  lastSyncMs: number;
  // Index schema the folder's records were written under. See INDEX_SCHEMA for
  // the full history (1 = pre-threading; 2 = inReplyTo; 3 = has_attachments).
  // A folder below the current schema is auto-rebuilt on the next `index update`.
  schema: number;
}

interface MetaFile {
  version: 1;
  account: string;
  folders: Record<string, FolderMeta>;
}

// ── Constants ─────────────────────────────────────────────────────────

const META_VERSION = 1 as const;
// Index content schema (distinct from META_VERSION, the file format). Bumped
// when a build captures new per-record fields:
//   1 = pre-threading (no inReplyTo)
//   2 = inReplyTo present (v2.7.0-p3)
//   3 = has_attachments (v3.0.0, derived from BODYSTRUCTURE on streamEnvelopes)
// Folders stamped below INDEX_SCHEMA are re-streamed on the next incremental
// update (auto-migration gate at updateIndex -- no manual `index build` needed).
const INDEX_SCHEMA = 3;
// Threading-readiness floor (independent of INDEX_SCHEMA). threadingReady is
// true when every indexed folder is at or above this schema. Threading depends
// on inReplyTo = schema 2, NOT attachments = schema 3. Decoupled so future
// INDEX_SCHEMA bumps do not silently regress the threadingReady flag.
const THREADING_SCHEMA = 2;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MIN_TOKEN_LEN = 2;
const RECENCY_TOP_FRACTION = 0.2;   // newest 20% by date get the recency boost.
// idf weighting: a matched token's base weight is scaled by how distinctive it
// is across the corpus. idf is capped+normalised into [0.5, 1.5] so magnitudes
// stay comparable to the legacy flat scores (substring=5, recency=1) regardless
// of corpus size -- a token in every message counts ~half, a rare one ~1.5x.
const IDF_CAP = 6;
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

function attachmentsPath(): string {
  return path.join(indexDir(), 'attachments.jsonl');
}

export function getIndexDir(): string { return indexDir(); }

// ── Account resolution ────────────────────────────────────────────────

// Test seam: override the resolved account without a token file. null = resolve
// normally. Set/cleared only by _setAccountForTests.
let accountOverrideForTests: string | null = null;

// getConfiguredAccount: the account id stamped on every record. Lazy + guarded
// so a missing token file never throws (which would break tool registration).
function getConfiguredAccount(): string {
  if (accountOverrideForTests !== null) return accountOverrideForTests;
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

// enforceAccount: the account that reads must be restricted to, or null to
// serve every record. When a concrete account is configured we never return
// another mailbox's records -- this is the defence against a shared/misconfigured
// state dir leaking account A's mail into account B's session. 'default' (no
// credentials resolved) disables the filter so the unconfigured single-account
// case and a transient credential hiccup still return results (fail-open only
// when there is no account identity to enforce).
function enforceAccount(): string | null {
  const acct = getConfiguredAccount();
  return acct !== 'default' ? acct : null;
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

// errMessage: extract a short, credential-free message from an unknown throw.
// IMAP/network errors carry no password (auth failures read "Authentication
// failed"), so the raw message is safe to surface to the CLI; we still avoid
// stringifying the whole error object.
function errMessage(e: unknown): string {
  const m = (e as { message?: unknown } | null)?.message;
  return typeof m === 'string' && m.length > 0 ? m : String(e);
}

// dedupKey: primary key of a record. Includes account so a future multi-account
// index (or a misconfigured shared state dir) never collides two mailboxes'
// (folder, uid) pairs onto one slot.
function dedupKey(account: string, folder: string, uid: number): string {
  return account + '\x00' + folder + '\x00' + uid;
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
        // Absent on indexes built before schema tracking -> treat as schema 1
        // (pre-threading) so the next update re-streams to capture inReplyTo.
        schema: Number(r['schema']) || 1,
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
    inReplyTo: h.inReplyTo ?? '',
    fromEmail: h.from[0]?.address?.toLowerCase() ?? '',
    fromName: h.from[0]?.name ?? '',
    subject: h.subject ?? '',
    date: h.date ?? '',
    seen: h.seen,
    flagged: h.flagged,
    size: h.size,
    has_attachments: h.hasAttachments ?? false,
  };
}

// toAttachmentRecord: sibling of toRecord for the attachment manifest.
// METADATA-ONLY: reads only h.attachments (already-parsed metadata from BODYSTRUCTURE).
// No c.download, no simpleParser, no msg.source, no sha256 computation.
function toAttachmentRecord(
  account: string,
  folder: string,
  h: EmailHeader,
  a: ParsedAttachment,
): AttachmentRecord {
  return {
    account,
    folder,
    uid: h.uid,
    messageId: h.messageId,
    // Denormalized envelope fields — snapshotted from the same EmailHeader that produced toRecord.
    date: h.date ?? '',
    fromEmail: h.from[0]?.address?.toLowerCase() ?? '',
    fromName: h.from[0]?.name ?? '',
    subject: h.subject ?? '',
    // Store boundary: sanitize the raw filename to strip bidi/control/format chars (LD-6/LD-7).
    // sanitized-to-empty filename → null (row not dropped; preserves the attachment's existence).
    filename: sanitizeForDisplay(a.filename ?? '', { maxLen: 200 }) || null,
    mimeType: a.mimeType,
    // RFC 3501 §7.4.2 BODYSTRUCTURE octets backstop: non-finite (undefined/NaN/Infinity) → 0.
    size: Number.isFinite(a.size) ? a.size : 0,
    partId: a.partId ?? '',
    // md5 key always present; Yandex sends null from BODYSTRUCTURE (verified live 2026-06-22).
    md5: a.md5 ?? null,
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

// ── Attachment manifest helpers (mirrors of the envelope helpers above) ────────

// loadAllAttachments: verbatim mirror of loadAllRecords. Returns [] when the
// manifest does not exist; skips a corrupt line rather than aborting.
export function loadAllAttachments(): AttachmentRecord[] {
  const p = attachmentsPath();
  if (!fs.existsSync(p)) return [];
  const raw = fs.readFileSync(p, 'utf-8');
  const out: AttachmentRecord[] = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      out.push(JSON.parse(trimmed) as AttachmentRecord);
    } catch {
      // Skip a corrupt line rather than abort the whole load -- a partially
      // written JSONL (crash mid-append) must not brick the manifest.
    }
  }
  return out;
}

// serializeAttachments: verbatim mirror of serializeRecords.
function serializeAttachments(records: AttachmentRecord[]): string {
  return records.length === 0 ? '' : records.map(r => JSON.stringify(r)).join('\n') + '\n';
}

// rewriteAttachments: verbatim mirror of rewriteEnvelopes at mode 0o600.
// Filenames + sender metadata are sensitive — same secret hygiene as envelopes.
function rewriteAttachments(records: AttachmentRecord[]): void {
  atomicWrite(attachmentsPath(), serializeAttachments(records), 0o600);
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
    schema: m.schema,
  }));
  const totalCount = folders.reduce((sum, f) => sum + f.count, 0);
  return {
    exists: exists && folders.length >= 1,
    account: meta.account,
    folders,
    totalCount,
    indexPath: indexDir(),
    threadingReady: folders.length >= 1 && folders.every(f => f.schema >= THREADING_SCHEMA),
  };
}

// ── Public: build / update ────────────────────────────────────────────

// buildIndex: full rebuild of the given folders. Records for any OTHER folder
// (or the same folder under a different account) are preserved. For each
// folder: read the cursor, stream every envelope into a scratch list, and only
// on success replace that folder's records + stamp meta. A folder that throws
// mid-stream leaves its prior records and meta untouched and is reported in
// `errors` -- a partial failure never corrupts the folders that did sync.
export async function buildIndex(
  folders: string[],
  source?: EnvelopeSource,
): Promise<IndexResult> {
  const src = source ?? defaultSource();
  const account = getConfiguredAccount();
  const meta = loadMeta();
  meta.account = account;

  let added = 0;
  const result: FolderStatus[] = [];
  const errors: IndexError[] = [];
  const succeeded = new Set<string>();
  const freshByFolder = new Map<string, IndexRecord[]>();
  // Parallel attachment scratch lists — collected in the SAME stream loop as
  // freshByFolder so there is zero extra IMAP cost (h.attachments is already
  // on the yielded EmailHeader from streamEnvelopes).
  const freshAttachmentsByFolder = new Map<string, AttachmentRecord[]>();

  for (const folder of folders) {
    try {
      const cursor = await src.getCursor(folder);
      // Stream into a scratch list so a mid-stream throw discards the partial
      // folder rather than committing half of it.
      const fresh: IndexRecord[] = [];
      const freshAttachments: AttachmentRecord[] = [];
      for await (const h of src.stream(folder)) {
        fresh.push(toRecord(account, folder, h));
        // Collect attachment rows from the same header. Treat undefined as zero
        // rows (the T-bit fixture confirms boolean-only headers carry no array).
        for (const a of h.attachments ?? []) {
          freshAttachments.push(toAttachmentRecord(account, folder, h, a));
        }
      }
      const streamed = fresh.length;
      freshByFolder.set(folder, fresh);
      freshAttachmentsByFolder.set(folder, freshAttachments);
      succeeded.add(folder);
      added += streamed;
      // count := the server's EXISTS, the SAME authoritative number updateIndex's
      // reconcile compares against -- this guarantees convergence. Stamping the
      // streamed length instead would let a folder reconcile-rebuild on EVERY run
      // whenever EXISTS exceeds what SEARCH ALL streamed (an in-flight delivery
      // between the cursor and stream IMAP sessions, or a non-standard server).
      // Normally EXISTS == streamed, so this is the measured count; in the rare
      // divergent case it tracks the server and the folder still converges.
      const m: FolderMeta = {
        uidValidity: cursor.uidValidity,
        uidNext: cursor.uidNext,
        count: cursor.exists,
        lastSyncMs: Date.now(),
        schema: INDEX_SCHEMA,
      };
      meta.folders[folder] = m;
      result.push({ folder, count: m.count, uidValidity: m.uidValidity, uidNext: m.uidNext, lastSyncMs: m.lastSyncMs, schema: m.schema });
    } catch (e) {
      errors.push({ folder, error: errMessage(e) });
    }
  }

  // Drop only THIS account's records for folders we successfully rebuilt; keep
  // everything else (other folders, other accounts, and folders that errored).
  const records: IndexRecord[] = loadAllRecords()
    .filter(r => !(r.account === account && succeeded.has(r.folder)));
  for (const fresh of freshByFolder.values()) {
    for (const r of fresh) records.push(r);
  }

  // MR-4 write order: manifest FIRST, envelopes LAST.
  // A crash between the two non-transactional atomicWrites leaves at worst
  // orphan manifest rows (Phase-3 join degrades to skip — harmless) rather
  // than a visible email silently showing no attachments in the manifest.
  //
  // Mirror the envelope merge: use the SAME `succeeded` set (NOT the input
  // `folders` arg) so a mid-stream-failed folder keeps its prior attachment rows.
  const attachments: AttachmentRecord[] = loadAllAttachments()
    .filter(a => !(a.account === account && succeeded.has(a.folder)));
  for (const freshSlice of freshAttachmentsByFolder.values()) {
    for (const a of freshSlice) attachments.push(a);
  }
  rewriteAttachments(attachments); // manifest first (MR-4)
  rewriteEnvelopes(records);       // envelopes last (MR-4)
  persistMeta(meta);
  return { folders: result, added, errors };
}

// updateIndex: incremental sync. Per folder:
//   - no stored meta, uidValidity changed, stale schema, or a corrupt cursor
//     (uidNext <= 0) -> full rebuild of that folder.
//   - else stream UIDs >= stored.uidNext, keep only uid >= stored.uidNext (the
//     IMAP "N:*" range can echo the last existing message), dedup, append, then
//     RECONCILE: if stored.count + newCount != cursor.exists the folder lost
//     messages (expunge/move) the append path cannot observe -> fall back to a
//     full rebuild so the record set and count match the server exactly.
export async function updateIndex(
  folders: string[],
  source?: EnvelopeSource,
): Promise<IndexResult> {
  const src = source ?? defaultSource();
  const account = getConfiguredAccount();
  const meta = loadMeta();
  meta.account = account;

  // Determine which folders need a full rebuild vs an incremental append.
  const toRebuild: string[] = [];
  const toAppend: string[] = [];
  const cursors = new Map<string, { uidValidity: number; uidNext: number; exists: number }>();
  const errors: IndexError[] = [];
  for (const folder of folders) {
    try {
      const cursor = await src.getCursor(folder);
      cursors.set(folder, cursor);
      const stored = meta.folders[folder];
      // Rebuild on: never indexed, server renumbered (uidValidity), stale schema
      // (auto-migration -- e.g. capturing inReplyTo for threading without a
      // manual `index build`), or a corrupt/zero cursor that can't anchor an
      // incremental fetch.
      if (
        !stored || stored.uidValidity !== cursor.uidValidity ||
        stored.schema < INDEX_SCHEMA || stored.uidNext <= 0
      ) {
        toRebuild.push(folder);
      } else {
        toAppend.push(folder);
      }
    } catch (e) {
      errors.push({ folder, error: errMessage(e) });
    }
  }

  let added = 0;
  const result: FolderStatus[] = [];
  // Folders whose append revealed deletions -> rebuilt below alongside toRebuild.
  const reconcile: string[] = [];

  if (toAppend.length > 0) {
    const records = loadAllRecords();
    // Load the manifest once at the top (paralleling loadAllRecords() above).
    // Attachment rows are pushed alongside records.push() after BOTH guards below.
    const attachments = loadAllAttachments();
    const existing = new Set<string>();
    for (const r of records) existing.add(dedupKey(r.account, r.folder, r.uid));
    // Manifest-side dedup so the append path is self-healing like buildIndex. If a
    // prior run crashed AFTER rewriteAttachments but BEFORE rewriteEnvelopes/persistMeta
    // (MR-4 manifest-first order), the orphan attachment row already sits in
    // `attachments`; the envelope existing-Set cannot catch it (the envelope was never
    // written, so the message is re-streamed), and without this Set the re-stream would
    // push a DUPLICATE manifest row that survives until a full rebuild. Key on
    // (account, folder, uid, partId) -- one row per attachment part.
    const existingAtt = new Set<string>();
    for (const a of attachments) existingAtt.add(a.account + '|' + a.folder + '|' + a.uid + '|' + a.partId);

    for (const folder of toAppend) {
      try {
        const stored = meta.folders[folder];
        const cursor = cursors.get(folder)!;
        const minUid = stored.uidNext;
        let newCount = 0;
        for await (const h of src.stream(folder, { minUid })) {
          // The IMAP "minUid:*" range can echo the last existing message; drop
          // anything below the high-water mark.
          if (h.uid < minUid) continue;
          const key = dedupKey(account, folder, h.uid);
          if (existing.has(key)) continue;
          existing.add(key);
          records.push(toRecord(account, folder, h));
          // Push attachment rows ONLY after BOTH the minUid guard and the
          // existing-dedup guard pass — alongside records.push() above (LD-2).
          // This closes the Pitfall-7 silent-staleness bug: without this,
          // a new attachment-carrying email would appear in the envelope index
          // but be invisible in the manifest until a full rebuild.
          for (const a of h.attachments ?? []) {
            const ak = account + '|' + folder + '|' + h.uid + '|' + a.partId;
            if (existingAtt.has(ak)) continue; // self-heal a crashed-run orphan (no dup row)
            existingAtt.add(ak);
            attachments.push(toAttachmentRecord(account, folder, h, a));
          }
          newCount++;
        }
        // Reconcile: cursor.exists is the server's authoritative message count.
        // If our (stored.count + appended) disagrees, messages were deleted or
        // the stored count had drifted -- the append path can only add, so hand
        // the folder to a full rebuild that measures the true count.
        // Known limitation: if exactly as many messages are expunged as arrive in
        // the same interval, EXISTS is unchanged and the stale (expunged) record
        // is not detected until the next count-changing event or a uidValidity
        // bump. Perfect detection would require diffing the full UID list every
        // run (expensive); the count heuristic covers the common cases.
        const expected = stored.count + newCount;
        if (expected !== cursor.exists) {
          reconcile.push(folder);
        } else {
          added += newCount;
          const m: FolderMeta = {
            uidValidity: cursor.uidValidity,
            uidNext: cursor.uidNext,
            count: cursor.exists, // measured, not fabricated.
            lastSyncMs: Date.now(),
            schema: INDEX_SCHEMA,
          };
          meta.folders[folder] = m;
          result.push({ folder, count: m.count, uidValidity: m.uidValidity, uidNext: m.uidNext, lastSyncMs: m.lastSyncMs, schema: m.schema });
        }
      } catch (e) {
        errors.push({ folder, error: errMessage(e) });
      }
    }

    // MR-4 write order: manifest first, envelopes last (mirrors buildIndex).
    rewriteAttachments(attachments); // manifest first (MR-4)
    rewriteEnvelopes(records);       // envelopes last (MR-4)
    persistMeta(meta);
  }

  // Full-rebuild folders: the originally-stale ones plus any the append found to
  // have lost messages. buildIndex re-streams and persists records + meta.
  // LD-3: NO manifest code here — this branch delegates entirely to buildIndex.
  // buildIndex's account+succeeded filter (:448-449 equivalent) supersedes the
  // appended rows written above, making the buildIndex copy authoritative/final.
  // A crash between the append rewrite and the buildIndex rewrite leaves the
  // folder un-stamped in meta so the next update re-rebuilds and converges
  // (the same guarantee the envelope path already relies on).
  const rebuildAll = [...toRebuild, ...reconcile];
  if (rebuildAll.length > 0) {
    const rebuilt = await buildIndex(rebuildAll, src);
    added += rebuilt.added;
    for (const fs0 of rebuilt.folders) result.push(fs0);
    for (const e of rebuilt.errors) errors.push(e);
    // Re-read so meta reflects the post-rebuild cursors, then persist to keep
    // the merged account field (cheap, idempotent).
    Object.assign(meta.folders, loadMeta().folders);
    persistMeta(meta);
  }

  return { folders: result, added, errors };
}

// dropIndex: delete the entire index directory. Idempotent.
export function dropIndex(): void {
  const dir = indexDir();
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // Best-effort: a stale handle on Windows can refuse the directory unlink.
    // Fall back to TRUNCATING both files (write empty), not unlinking: a delete
    // is what the open handle blocks, whereas truncation usually succeeds. This
    // matters -- if envelopes.jsonl survived with content, searchFast would keep
    // serving the "dropped" records (indexExists() reads meta, but the FTS cache
    // reads envelopes.jsonl). Emptying it guarantees no stale/orphan reads.
    try { fs.writeFileSync(metaPath(), JSON.stringify(emptyMeta(), null, 2)); } catch { /* ignore */ }
    try { fs.writeFileSync(envelopesPath(), ''); } catch { /* ignore */ }
    // Truncate the attachment manifest too — without this, Phase-3 findAttachments
    // would serve orphan rows after a drop (the same failure the comment above
    // warns about for envelopes.jsonl).
    try { fs.writeFileSync(attachmentsPath(), ''); } catch { /* ignore */ }
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
  // Normalized subject per record (Re:/Fwd:/Вс: stripped), precomputed so
  // getThread's same-folder fallback does not re-run the regex loop per call.
  normalizedSubjects: string[];
  // Recency threshold: records with dateMs >= this get the recency boost.
  recencyThresholdMs: number;
  // Thread graph (v2.7.0-p3): messageId -> record index, and parent-messageId ->
  // child record indices (from inReplyTo). Empty strings are never keyed.
  byMessageId: Map<string, number>;
  childrenOf: Map<string, number[]>;
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
  const normalizedSubjects: string[] = [];
  const validDates: number[] = [];
  const byMessageId = new Map<string, number>();
  const childrenOf = new Map<string, number[]>();

  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    normalizedSubjects.push(normalizeSubject(r.subject));
    const sTok = new Set<string>(tokenize(r.subject));
    const fromTok = new Set<string>([
      ...tokenize(r.fromName),
      ...tokenize(localPart(r.fromEmail)),
    ]);
    subjectTokens.push(sTok);
    senderTokens.push(fromTok);

    for (const t of sTok) addToInverted(inverted, t, i);
    for (const t of fromTok) addToInverted(inverted, t, i);

    if (r.messageId) byMessageId.set(r.messageId, i);
    const irt = r.inReplyTo;
    if (irt) {
      const kids = childrenOf.get(irt);
      if (kids) kids.push(i); else childrenOf.set(irt, [i]);
    }

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
    normalizedSubjects,
    recencyThresholdMs,
    byMessageId,
    childrenOf,
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
      normalizedSubjects: [],
      recencyThresholdMs: Number.POSITIVE_INFINITY,
      byMessageId: new Map(),
      childrenOf: new Map(),
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

// sameRecord / findRecordIndex: locate a record in the cache by its stable
// primary key (account, folder, uid) rather than by object identity. getThread
// gets its seed from a separate searchFast call; if the cache were rebuilt
// between the two calls an identity (indexOf) lookup would silently fail and
// drop the Message-ID thread graph. byMessageId gives an O(1) first guess,
// verified against the key because duplicate Message-IDs exist in the wild.
function sameRecord(a: IndexRecord, b: IndexRecord): boolean {
  return a.account === b.account && a.folder === b.folder && a.uid === b.uid;
}

function findRecordIndex(c: IndexCache, seed: IndexRecord): number {
  if (seed.messageId) {
    const i = c.byMessageId.get(seed.messageId);
    if (i !== undefined && sameRecord(c.records[i], seed)) return i;
  }
  for (let i = 0; i < c.records.length; i++) {
    if (sameRecord(c.records[i], seed)) return i;
  }
  return -1;
}

// ── Public: search ────────────────────────────────────────────────────

function clampLimit(limit?: number): number {
  if (limit === undefined || !Number.isFinite(limit)) return DEFAULT_LIMIT;
  return Math.min(Math.max(Math.floor(limit), 1), MAX_LIMIT);
}

// rangeIndices: 0..n-1 without materialising an array/Set. Used by the
// pure-filter scan so it does not allocate one Set entry per record.
function* rangeIndices(n: number): Generator<number> {
  for (let i = 0; i < n; i++) yield i;
}

function hasAnyFilter(f?: SearchFilters): boolean {
  return !!f && (
    (f.from !== undefined && f.from.length > 0) ||
    f.since !== undefined || f.before !== undefined ||
    f.seen !== undefined || f.flagged !== undefined ||
    f.has_attachments !== undefined
  );
}

// passesFilters: does a record satisfy every set structured filter? `ms` is the
// pre-parsed date (c.dateMs[idx]); a record with no valid date fails any
// since/before bound rather than silently passing.
function passesFilters(r: IndexRecord, ms: number, f?: SearchFilters): boolean {
  if (!f) return true;
  if (f.seen !== undefined && r.seen !== f.seen) return false;
  if (f.flagged !== undefined && r.flagged !== f.flagged) return false;
  // `?? false`, NOT strict ===: loadAllRecords raw-casts JSON, so a pre-schema-3
  // (pre-v3.0.0) index carries has_attachments:undefined at read time. The ?? false
  // coercion treats those as "no attachments" rather than silently dropping them
  // from a has_attachments:false query; they self-heal on the next auto-migration.
  if (f.has_attachments !== undefined && (r.has_attachments ?? false) !== f.has_attachments) return false;
  if (f.from !== undefined && f.from.length > 0) {
    const needle = f.from.toLowerCase();
    if (!r.fromEmail.includes(needle) && !r.fromName.toLowerCase().includes(needle)) return false;
  }
  if (f.since !== undefined && (isNaN(ms) || ms < f.since)) return false;
  if (f.before !== undefined && (isNaN(ms) || ms >= f.before)) return false;
  return true;
}

// idfWeight: how much a matched token contributes, scaled by its rarity. df is
// the number of records containing the token (= inverted posting-list size).
// Returns [0.5, 1.5]; an unindexed token (substring-only candidate) is neutral.
function idfWeight(c: IndexCache, token: string): number {
  const df = c.inverted.get(token)?.size ?? 0;
  if (df <= 0) return 1;
  const n = c.records.length;
  const idf = Math.log(1 + (n - df + 0.5) / (df + 0.5));
  return 0.5 + Math.min(idf, IDF_CAP) / IDF_CAP;
}

// searchFastResult: free-text query (subject + sender, ranked) AND/OR
// structured filters (from/since/before/seen/flagged), returning a page of hits
// plus the TOTAL number of matches -- so a caller can distinguish "20 hits"
// from "20 of thousands" and paginate via offset. A query with content ranks by
// token/substring/recency; a query that is ONLY filters ("all unread since
// March") scans every record and orders by recency.
export interface SearchPage {
  hits: SearchHit[];
  total: number;
}

export function searchFastResult(
  query: string,
  opts?: { folder?: string; limit?: number; offset?: number; filters?: SearchFilters },
): SearchPage {
  const c = getCache();
  if (c.records.length === 0) return { hits: [], total: 0 };

  const qLower = query.toLowerCase().trim();
  const qTokens = tokenize(query);
  const limit = clampLimit(opts?.limit);
  const offset = Math.max(0, Math.floor(opts?.offset ?? 0));
  const folderFilter = opts?.folder;
  const filters = opts?.filters;
  const hasContent = qTokens.length > 0 || qLower.length > 0;
  const hasFilters = hasAnyFilter(filters);

  // Nothing to match on at all.
  if (!hasContent && !hasFilters) return { hits: [], total: 0 };

  // Candidate record indices: a content query unions token postings + subject
  // substrings into a Set; a pure-filter query iterates all indices directly
  // (no Set-of-every-index allocation).
  let candidateIdx: Iterable<number>;
  if (hasContent) {
    const set = new Set<number>();
    for (const t of qTokens) {
      const posting = c.inverted.get(t);
      if (posting) for (const idx of posting) set.add(idx);
    }
    if (qLower.length > 0) {
      for (let i = 0; i < c.records.length; i++) {
        if (c.records[i].subject.toLowerCase().includes(qLower)) set.add(i);
      }
    }
    candidateIdx = set;
  } else {
    candidateIdx = rangeIndices(c.records.length);
  }

  const acct = enforceAccount();
  const hits: SearchHit[] = [];
  for (const idx of candidateIdx) {
    const r = c.records[idx];
    if (acct !== null && r.account !== acct) continue;
    if (folderFilter !== undefined && r.folder !== folderFilter) continue;
    const ms = c.dateMs[idx];
    if (!passesFilters(r, ms, filters)) continue;

    let score = 0;
    const reasons: string[] = [];

    if (hasContent) {
      const sTok = c.subjectTokens[idx];
      const fromTok = c.senderTokens[idx];
      let subjectMatched = false;
      let senderMatched = false;
      for (const t of qTokens) {
        // Distinct query tokens; a rarer token (higher idf) contributes more.
        const w = idfWeight(c, t);
        if (sTok.has(t)) { score += 3 * w; subjectMatched = true; }
        if (fromTok.has(t)) { score += 2 * w; senderMatched = true; }
      }
      if (subjectMatched) reasons.push('subject');
      if (senderMatched) reasons.push('sender');

      if (qLower.length > 0 && r.subject.toLowerCase().includes(qLower)) {
        score += 5;
        reasons.push('subject-substring');
      }
    } else {
      // The match reason IS the filter; ranking is recency-only.
      reasons.push('filter');
    }

    // Recency boost: newest RECENCY_TOP_FRACTION by date.
    if (!isNaN(ms) && ms >= c.recencyThresholdMs) {
      score += 1;
      reasons.push('recent');
    }

    // Content queries: a zero score means no real token/substring match -> drop.
    // Pure-filter queries: every record that passed the filters is a valid hit
    // (its score may be 0 when it is not in the recency top fraction).
    if (hasContent && score <= 0) continue;
    hits.push({ record: r, score, matchReasons: reasons });
  }

  hits.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return dateCompareDesc(a.record.date, b.record.date);
  });
  return { hits: hits.slice(offset, offset + limit), total: hits.length };
}

// searchFast: page-less convenience wrapper (existing callers + tests). Returns
// only the hits for the first `limit` (post-offset) matches.
export function searchFast(
  query: string,
  opts?: { folder?: string; limit?: number; offset?: number; filters?: SearchFilters },
): SearchHit[] {
  return searchFastResult(query, opts).hits;
}

function dateCompareDesc(a: string, b: string): number {
  const ma = a ? new Date(a).getTime() : NaN;
  const mb = b ? new Date(b).getTime() : NaN;
  const va = isNaN(ma) ? -Infinity : ma;
  const vb = isNaN(mb) ? -Infinity : mb;
  return vb - va;
}

// getThread: assemble the thread containing the best searchFast hit. Two
// complementary signals are UNION-ed:
//   1. Message-ID graph (cross-folder, precise) -- BFS over In-Reply-To links,
//      walking both to the parent (this.inReplyTo -> a messageId) and to
//      children (records whose inReplyTo == this.messageId). This catches
//      renamed-subject replies and threads split across INBOX/Sent.
//   2. Normalized-subject grouping IN THE SEED'S FOLDER (the prior behaviour) --
//      catches same-folder Re:/Fwd: variants that carry no In-Reply-To and
//      keeps working on indexes built before inReplyTo was captured.
// Result is sorted ascending by date (chronological). On overflow the NEWEST
// `limit` messages are kept. Score is the chronological rank (newest highest).
export function getThread(query: string, opts?: { folder?: string; limit?: number }): SearchHit[] {
  const c = getCache();
  const top = searchFast(query, { folder: opts?.folder, limit: 1 });
  if (top.length === 0) return [];
  const seed = top[0].record;
  const limit = clampLimit(opts?.limit);
  const acct = enforceAccount();

  const memberIdx = new Set<number>();
  // 1. Message-ID graph BFS over actual In-Reply-To EDGES only: a node links to
  //    its parent (the record whose messageId == this.inReplyTo) and to its
  //    children (records whose inReplyTo == this.messageId). We deliberately do
  //    NOT treat a shared messageId as a link -- malformed/duplicate Message-IDs
  //    must not collapse unrelated mail into one thread. Cross-account records
  //    are never admitted (the graph could otherwise bridge two mailboxes).
  const stack: number[] = [];
  const seedIdx = findRecordIndex(c, seed);
  if (seedIdx >= 0) { memberIdx.add(seedIdx); stack.push(seedIdx); }
  const visit = (i: number | undefined): void => {
    if (i === undefined || i < 0 || memberIdx.has(i)) return;
    if (acct !== null && c.records[i].account !== acct) return;
    memberIdx.add(i);
    stack.push(i);
  };
  while (stack.length > 0) {
    const r = c.records[stack.pop()!];
    if (r.inReplyTo) visit(c.byMessageId.get(r.inReplyTo));   // parent edge
    if (r.messageId) {                                         // child edges
      const kids = c.childrenOf.get(r.messageId);
      if (kids) for (const k of kids) visit(k);
    }
  }

  // 2. Same-folder normalized-subject fallback. Skipped when the seed has no
  //    real subject (an empty/placeholder normalized subject would otherwise
  //    collapse every subjectless message in the folder into one bogus thread);
  //    such seeds rely on the Message-ID graph above.
  const target = normalizeSubject(seed.subject);
  if (target.length > 0) {
    for (let i = 0; i < c.records.length; i++) {
      const r = c.records[i];
      if (acct !== null && r.account !== acct) continue;
      if (r.folder === seed.folder && c.normalizedSubjects[i] === target) memberIdx.add(i);
    }
  }

  const members: IndexRecord[] = [...memberIdx].map(i => c.records[i]);
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

// ── Public: unanswered threads ────────────────────────────────────────

// Local-parts that almost always indicate automated/no-reply senders. A tiny
// HARDCODED set keeps this Layer 2 (a user-editable list would be Layer 4).
// Matched against the local-part of latest.fromEmail (before '@'), lowercased.
const NO_REPLY_LOCALPARTS = new Set([
  'noreply', 'no-reply', 'no_reply',
  'donotreply', 'do-not-reply',
  'notifications', 'notification',
  'mailer-daemon', 'mailer',
  'newsletter', 'newsletters',
  'digest', 'bounce', 'postmaster',
]);

function looksAutomated(fromEmail: string): boolean {
  const at = fromEmail.indexOf('@');
  const local = (at >= 0 ? fromEmail.slice(0, at) : fromEmail).toLowerCase();
  if (NO_REPLY_LOCALPARTS.has(local)) return true;
  if (local.startsWith('noreply') || local.startsWith('no-reply') || local.startsWith('donotreply')) return true;
  if (local.includes('notification') || local.includes('newsletter')) return true;
  return false;
}

export interface UnansweredHit {
  record: IndexRecord;
  daysWaiting: number;
  tier: 'reply_likely' | 'normal' | 'fyi_likely';
  reasons: string[];
  priority: number;
}

export interface UnansweredPage {
  hits: UnansweredHit[];
  total: number;
  ownerKnown: boolean;
}

// unansweredThreads: find received threads the owner has NOT replied to that
// have been sitting longer than olderThanDays.
//
// Thread grouping uses the SAME graph getThread uses (Message-ID edges +
// normalized-subject bucket) but runs a SINGLE pass over all account records
// rather than calling getThread per message -- that would re-invoke searchFast
// N times and be O(N^2).
//
// Sender-identity classification (CLAUDE.md: never hardcode folder names):
// A message whose fromEmail === owner is one the owner authored regardless of
// what folder it lives in (Sent/Drafts/Отправленные/etc.). Condition (a) below
// (latest.fromEmail !== owner) therefore covers Sent and Drafts without ever
// naming a folder.
//
// Known acceptable limitation: newsletters/notifications the owner never replies
// to appear as "unanswered" by definition. Document this in the tool description
// and suggest the `from` filter.
export function unansweredThreads(opts?: {
  olderThanDays?: number;
  folder?: string;
  from?: string;
  limit?: number;
  offset?: number;
  nowMs?: number;
}): UnansweredPage {
  // Step 1: resolve owner. Cannot classify "mine" without a known identity.
  const owner = getConfiguredAccount();
  if (owner === 'default') return { hits: [], total: 0, ownerKnown: false };

  const c = getCache();
  const acct = enforceAccount();
  const olderThanDays = Math.max(0, Math.floor(opts?.olderThanDays ?? 7));
  const limit = clampLimit(opts?.limit);
  const offset = Math.max(0, Math.floor(opts?.offset ?? 0));
  const nowMs = opts?.nowMs ?? Date.now();
  const folderFilter = opts?.folder;
  const fromFilter = opts?.from?.toLowerCase();

  // Step 2: collect account record indices.
  const accountIdx: number[] = [];
  for (let i = 0; i < c.records.length; i++) {
    const r = c.records[i];
    if (acct !== null && r.account !== acct) continue;
    accountIdx.push(i);
  }
  if (accountIdx.length === 0) return { hits: [], total: 0, ownerKnown: true };

  // Step 3: thread grouping over account records via union-find.
  // We use a simple union-find (parent array over accountIdx positions).
  // Edges: Message-ID graph (inReplyTo -> byMessageId child edges) PLUS
  // normalized-subject bucket (same non-empty normalized subject = same thread).
  // Cross-account edges are never admitted: byMessageId/childrenOf span ALL
  // records in the cache; we only union indices within accountIdx.

  // Map from cache index -> position in accountIdx for O(1) membership checks.
  const idxPos = new Map<number, number>();
  for (let p = 0; p < accountIdx.length; p++) idxPos.set(accountIdx[p], p);

  // Union-find arrays indexed by position within accountIdx.
  const parent = accountIdx.map((_, p) => p);
  function find(p: number): number {
    while (parent[p] !== p) { parent[p] = parent[parent[p]]; p = parent[p]; }
    return p;
  }
  function union(a: number, b: number): void {
    a = find(a); b = find(b);
    if (a !== b) parent[a] = b;
  }

  // Message-ID graph edges (cross-folder, precise).
  for (const pos of accountIdx.map((_, p) => p)) {
    const cIdx = accountIdx[pos];
    const r = c.records[cIdx];
    // Parent edge: this record's inReplyTo points to a parent messageId.
    if (r.inReplyTo) {
      const parentCIdx = c.byMessageId.get(r.inReplyTo);
      if (parentCIdx !== undefined) {
        const parentPos = idxPos.get(parentCIdx);
        if (parentPos !== undefined) union(pos, parentPos);
      }
    }
    // Child edges: records that replied to this record's messageId.
    if (r.messageId) {
      const kids = c.childrenOf.get(r.messageId);
      if (kids) {
        for (const kidCIdx of kids) {
          const kidPos = idxPos.get(kidCIdx);
          if (kidPos !== undefined) union(pos, kidPos);
        }
      }
    }
  }

  // Normalized-subject bucket: same non-empty normalized subject -> same thread.
  // Empty normalized subject must NOT collapse subjectless mail into one thread
  // (mirrors getThread's `target.length > 0` guard).
  const subjectBucket = new Map<string, number>(); // normalizedSubject -> first pos
  for (let p = 0; p < accountIdx.length; p++) {
    const cIdx = accountIdx[p];
    const ns = c.normalizedSubjects[cIdx];
    if (!ns) continue; // guard: empty subject never groups
    const existing = subjectBucket.get(ns);
    if (existing === undefined) {
      subjectBucket.set(ns, p);
    } else {
      union(p, existing);
    }
  }

  // Step 4 & 5: per thread, pick latest record and apply the unanswered test.
  // Group positions by their root component.
  const components = new Map<number, number[]>(); // root -> [positions]
  for (let p = 0; p < accountIdx.length; p++) {
    const root = find(p);
    const list = components.get(root);
    if (list) list.push(p); else components.set(root, [p]);
  }

  const candidates: UnansweredHit[] = [];

  for (const positions of components.values()) {
    // Find the latest record in the thread by valid date (ties: highest uid).
    let latestPos = -1;
    let latestMs = -Infinity;
    let latestUid = -1;
    for (const p of positions) {
      const cIdx = accountIdx[p];
      const ms = c.dateMs[cIdx];
      if (isNaN(ms)) continue; // skip records with no valid date
      if (ms > latestMs || (ms === latestMs && c.records[cIdx].uid > latestUid)) {
        latestMs = ms;
        latestUid = c.records[cIdx].uid;
        latestPos = p;
      }
    }
    // Skip threads with no valid-date member.
    if (latestPos < 0) continue;

    const latestCIdx = accountIdx[latestPos];
    const latest = c.records[latestCIdx];

    // Unanswered test:
    // (a) latest.fromEmail !== owner: the last word came from someone else, not me.
    // (b) ageDays >= olderThanDays: the thread has been sitting long enough.
    if (latest.fromEmail === owner) continue; // owner sent the last message
    const ageDays = Math.floor((nowMs - latestMs) / 86_400_000);
    if (ageDays < 0) continue; // future-dated: fails the cutoff
    if (ageDays < olderThanDays) continue;

    // Step 6: apply candidate filters to `latest`.
    if (folderFilter !== undefined && latest.folder !== folderFilter) continue;
    if (fromFilter) {
      const emailMatch = latest.fromEmail.includes(fromFilter);
      const nameMatch = latest.fromName.toLowerCase().includes(fromFilter);
      if (!emailMatch && !nameMatch) continue;
    }

    // Step 6b: compute confidence signals from component records and `latest`.
    // All signals use data ALREADY on IndexRecord -- no new IMAP fetch needed.

    // participated: owner authored an earlier message in this thread.
    // (By construction latest.fromEmail !== owner, so an owner record = earlier msg.)
    let participated = false;
    let flaggedInThread = false;
    for (const p of positions) {
      const r = c.records[accountIdx[p]];
      if (r.fromEmail === owner) participated = true;
      if (r.flagged) flaggedInThread = true;
    }
    const readByMe = latest.seen === true;
    const automated = looksAutomated(latest.fromEmail);

    const priority =
      (flaggedInThread ? 3 : 0) +
      (participated    ? 2 : 0) +
      (readByMe        ? 0.5 : 0) +
      (automated       ? -3 : 0);

    const tier: UnansweredHit['tier'] =
      priority >= 2 ? 'reply_likely' :
      priority < 0  ? 'fyi_likely'   :
      'normal';

    const reasons: string[] = [];
    if (flaggedInThread) reasons.push('отмечено флажком');        // 'отмечено флажком'
    if (participated)   reasons.push('вы уже писали в этой переписке'); // 'вы уже писали в этой переписке'
    if (readByMe)       reasons.push('прочитано, но без ответа');                               // 'прочитано, но без ответа'
    if (automated)      reasons.push('похоже на авто-уведомление');             // 'похоже на авто-уведомление'

    candidates.push({ record: latest, daysWaiting: ageDays, tier, reasons, priority });
  }

  // Step 7: PRIMARY priority DESC (highest confidence first),
  // SECONDARY date ASC (most overdue within the same tier first).
  // Nothing is hidden -- every candidate survives; only order changes.
  candidates.sort((a, b) => {
    if (b.priority !== a.priority) return b.priority - a.priority;
    const ma = a.record.date ? new Date(a.record.date).getTime() : -Infinity;
    const mb = b.record.date ? new Date(b.record.date).getTime() : -Infinity;
    return ma - mb;
  });

  // Step 8: paginate.
  const total = candidates.length;
  const hits = candidates.slice(offset, offset + limit);
  return { hits, total, ownerKnown: true };
}

// ── Test-only ─────────────────────────────────────────────────────────

// _resetForTests: flush the in-memory FTS cache so a fresh state dir (or a
// rebuild within the same process) is picked up on the next search.
export function _resetForTests(): void {
  invalidateCache();
}

// _setAccountForTests: override the resolved account (null = resolve normally)
// so account-isolation can be exercised without provisioning a token file.
export function _setAccountForTests(account: string | null): void {
  accountOverrideForTests = account;
}
