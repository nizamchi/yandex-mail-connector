// index-auto.ts -- opt-in, background index lifecycle (first-build + freshness).
//
// Closes the "zero-to-parity" gap: a freshly-installed connector starts with an
// EMPTY index, so yandex_search_fast / find_attachments / unanswered return
// nothing until the user manually runs `index build`. This module auto-builds on
// first start and keeps the index fresh, so a new user gets the owner's
// experience with no manual CLI step.
//
// MISSION lock ("no background daemon features without explicit opt-in"): this is
// OFF by default and only acts when YANDEX_INDEX_AUTO is turned on. It NEVER
// blocks server.connect -- index.ts calls startIndexAutoLifecycle() AFTER connect
// and does NOT await it, so the work runs detached and tool calls are available
// immediately. Every failure is stderr-logged and non-fatal: a degraded index
// must never crash the server.
//
// Decision (pure -- decideAutoAction):
//   off                           -> skip
//   on + no index                 -> build   (first-build: INBOX + Sent)
//   on + index older than maxAge  -> refresh (updateIndex of indexed folders)
//   on + index fresh              -> skip
//
// Heaviness note: an envelope build streams thousands of envelopes and can take
// minutes on a large mailbox -- exactly why it must run detached after connect,
// never inline before it. The refresh path is incremental (UIDs >= uidNext) and
// far cheaper. A periodic re-check (setInterval, unref'd) keeps long-lived server
// sessions fresh; a running-guard prevents overlapping syncs.

import * as mailIndex from './mail-index.js';
import { auditLog } from './audit.js';

export type AutoAction = 'build' | 'refresh' | 'skip';

export interface AutoConfig {
  enabled: boolean;
  maxAgeMinutes: number;
}

const DEFAULT_MAX_AGE_MINUTES = 60;

// parseAutoConfig: the two opt-in knobs. `enabled` defaults to FALSE (MISSION
// opt-in). YANDEX_INDEX_AUTO accepts on/true/1/yes (case-insensitive); anything
// else (off/false/0/unset) stays disabled. YANDEX_INDEX_MAX_AGE_MINUTES sets the
// staleness threshold AND the periodic re-check interval; invalid/<=0 -> 60.
export function parseAutoConfig(env: NodeJS.ProcessEnv = process.env): AutoConfig {
  const raw = (env.YANDEX_INDEX_AUTO ?? '').trim().toLowerCase();
  const enabled = raw === 'on' || raw === 'true' || raw === '1' || raw === 'yes';
  const ageRaw = Number(env.YANDEX_INDEX_MAX_AGE_MINUTES);
  const maxAgeMinutes = Number.isFinite(ageRaw) && ageRaw > 0 ? ageRaw : DEFAULT_MAX_AGE_MINUTES;
  return { enabled, maxAgeMinutes };
}

// decideAutoAction: pure decision. `oldestSyncMs` is the oldest per-folder
// lastSyncMs (null when there is no index or no synced folder). A "fresh" index
// at exactly the threshold is left alone (strictly-older triggers refresh).
export function decideAutoAction(opts: {
  enabled: boolean;
  indexExists: boolean;
  oldestSyncMs: number | null;
  nowMs: number;
  maxAgeMinutes: number;
}): AutoAction {
  if (!opts.enabled) return 'skip';
  if (!opts.indexExists || opts.oldestSyncMs === null) return 'build';
  const ageMinutes = (opts.nowMs - opts.oldestSyncMs) / 60000;
  return ageMinutes > opts.maxAgeMinutes ? 'refresh' : 'skip';
}

// Dependency seam so runIndexAutoLifecycle is unit-testable with no live IMAP
// and no real index on disk.
export interface AutoDeps {
  getStatus: () => mailIndex.IndexStatus;
  build: (folders: string[]) => Promise<mailIndex.IndexResult>;
  update: (folders: string[]) => Promise<mailIndex.IndexResult>;
  resolveBuildFolders: () => Promise<string[]>;
  now: () => number;
  env: NodeJS.ProcessEnv;
}

function defaultDeps(): AutoDeps {
  return {
    getStatus: () => mailIndex.getIndexStatus(),
    build: (folders) => mailIndex.buildIndex(folders),
    update: (folders) => mailIndex.updateIndex(folders),
    resolveBuildFolders: async () => {
      // INBOX + Sent (cyrillic-aware via specialUse). Sent powers cross-folder
      // threads and yandex_unanswered, so a first build without it is half-blind.
      // Lazy require mirrors mail-index.ts: importing imap.js eagerly would pull
      // imapflow onto the module-load critical path.
      const imap = require('./imap.js') as typeof import('./imap.js');
      try {
        const sent = (await imap.getSpecialFolders()).sent;
        return sent && sent !== 'INBOX' ? ['INBOX', sent] : ['INBOX'];
      } catch {
        return ['INBOX'];
      }
    },
    now: () => Date.now(),
    env: process.env,
  };
}

export interface AutoResult {
  action: AutoAction;
  folders?: string[];
  added?: number;
  errors?: mailIndex.IndexError[];
}

function oldestSync(status: mailIndex.IndexStatus): number | null {
  let oldest = Infinity;
  for (const f of status.folders) {
    if (f.lastSyncMs > 0 && f.lastSyncMs < oldest) oldest = f.lastSyncMs;
  }
  return oldest === Infinity ? null : oldest;
}

// runIndexAutoLifecycle: decide + act. All IO routes through injectable deps so
// tests need neither IMAP nor a real index. Throws propagate to the caller
// (startIndexAutoLifecycle catches and logs).
export async function runIndexAutoLifecycle(deps: AutoDeps = defaultDeps()): Promise<AutoResult> {
  const cfg = parseAutoConfig(deps.env);
  const status = deps.getStatus();
  const action = decideAutoAction({
    enabled: cfg.enabled,
    indexExists: status.exists,
    oldestSyncMs: oldestSync(status),
    nowMs: deps.now(),
    maxAgeMinutes: cfg.maxAgeMinutes,
  });

  if (action === 'skip') return { action };

  if (action === 'build') {
    const folders = await deps.resolveBuildFolders();
    const r = await deps.build(folders);
    return { action, folders, added: r.added, errors: r.errors };
  }

  // refresh: incremental update of the folders already in the index.
  const folders = status.folders.map(f => f.folder);
  const r = await deps.update(folders);
  return { action, folders, added: r.added, errors: r.errors };
}

// ── Background runner (production entry, fire-and-forget) ──────────────

// At most one in-process sync at a time: a second tick while one runs would
// double IMAP load and could interleave writes. The periodic timer is created
// once (`started`).
let running = false;
let started = false;

async function tick(): Promise<void> {
  if (running) return;
  running = true;
  try {
    const res = await runIndexAutoLifecycle();
    if (res.action !== 'skip') {
      const errN = res.errors?.length ?? 0;
      const errNote = errN > 0 ? `, ${errN} folder error(s)` : '';
      process.stderr.write(
        `[yandex-mail] index auto-lifecycle: ${res.action} done -- ${res.added ?? 0} message(s) indexed${errNote}.\n`,
      );
      auditLog({
        action: 'index_auto',
        status: 'success',
        level: errN > 0 ? 'warn' : 'info',
        ts: new Date().toISOString(),
        reason: `action=${res.action},added=${res.added ?? 0},errors=${errN}`,
      });
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    process.stderr.write(`[yandex-mail] index auto-lifecycle failed (non-fatal): ${msg}\n`);
    auditLog({
      action: 'index_auto',
      status: 'error',
      level: 'error',
      ts: new Date().toISOString(),
      reason: msg.slice(0, 200),
    });
  } finally {
    running = false;
  }
}

// startIndexAutoLifecycle: called from index.ts AFTER server.connect and NOT
// awaited. No-op (silent) when the opt-in is off, so default users see no extra
// noise or work. When on: one immediate check, then a periodic re-check every
// maxAgeMinutes. The timer is unref'd so it never keeps the process alive by
// itself.
export function startIndexAutoLifecycle(): void {
  if (started) return;
  const cfg = parseAutoConfig();
  if (!cfg.enabled) return;
  started = true;
  process.stderr.write(
    `[yandex-mail] index auto-lifecycle: ON (build-if-empty + refresh older than ${cfg.maxAgeMinutes} min, background).\n`,
  );
  void tick();
  const timer = setInterval(() => { void tick(); }, Math.max(1, cfg.maxAgeMinutes) * 60_000);
  if (typeof timer.unref === 'function') timer.unref();
}

// Test seam: reset the module-level guards (NOT for production callers).
export function _resetForTests(): void {
  running = false;
  started = false;
}
