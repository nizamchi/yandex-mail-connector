// provenance.ts -- Phase 3 (Layer B) RAM-only read-event tracker.
//
// Privacy / structural invariants (load-bearing -- enforced by grep gates
// in 03-01-PLAN.md verify blocks and by T-PROV-PRIVACY-DISK-01):
//
//   (a) RAM-only. NO disk write. NO audit emission. NO network. The Map
//       contents are NEVER serialized (no JSON.stringify of `reads`).
//   (b) Backing store is `Map<msgid, ReadEvent>` (D3) -- NOT WeakMap.
//       WeakMap forbids iteration; we need iteration for prune +
//       recentReads(). Repeated reads of the same msgid overwrite the
//       prior entry (newest read wins, binary signal).
//   (c) Prune-on-access (D4). Every public entry point walks the Map
//       FIRST and drops stale entries. NO background timer of any kind
//       (no set-interval, no set-timeout, no set-immediate, no
//       queue-microtask, no worker, no async).
//   (d) Window source: `getPolicy().provenance_window_sec * 1000` ms (D5).
//       Read per-call (NOT cached at module load) so Phase 7 policy
//       rotation surfaces immediately without restart-of-this-module.
//   (e) `provenance_window_sec === 0` is the explicit DISABLE knob. It
//       does NOT mean "match-all-time". Tracking is OFF:
//         recordRead -> no-op (Map untouched)
//         recentReads -> []
//         postReadFlag -> false (ALWAYS)
//   (f) MUST NOT import './audit.js'. MUST NOT touch fs.* / fsPromises.* /
//       net.* / tls.* / http.* / https.* / dgram.* / child_process.*.
//       Privacy is structural, not policy-based.
//   (g) ESM `.js` suffix on internal imports (NodeNext convention).
//
// Phase 4 input contract: postReadFlag(now) -> boolean. Phase 4's risk
// scorer reads it and applies `policy.weights.post_read_send` on true.
//
// No `any`. ASCII-only. Pure-synchronous module.

import { getPolicy } from './policy.js';

// ── Public types (D2 + D8) ────────────────────────────────────

export interface ReadMeta {
  folder: string;
  uid?: number;
}

export interface ReadEvent {
  msgid: string;     // Message-ID header value (RFC 5322 angle-bracketed form).
  readAtMs: number;  // Date.now() at recordRead invocation.
  folder: string;    // IMAP folder name (e.g., 'INBOX', 'Sent', 'Удалённые').
  uid?: number;      // IMAP UID, optional (search results may lack it).
}

// ── Module-local backing store (D3) ───────────────────────────
// Single-writer Map; MCP transport is sequential per-connection (D10), so
// no mutex / atomic-CAS is needed. T-PROV-RACE-01 documents the
// no-corruption property under 100-entry burst.

const reads = new Map<string, ReadEvent>();

// ── Internal helpers ──────────────────────────────────────────

// Window source -- re-read per public-call (NOT cached at module load) so
// Phase 7 policy rotation surfaces immediately. Cost is one Map lookup
// against the frozen policy snapshot (O(1)).
function windowMs(): number {
  return getPolicy().provenance_window_sec * 1000;
}

// pruneInPlace is O(N) per call where N = current Map size. With
// provenance_window_sec=30 and typical read rates 1-10/min, N stays
// <= ~50 -- acceptable for synchronous call hot path. No background timer.
//
// Boundary discipline (D9 / B-3): drop only entries whose age is
// STRICTLY GREATER than the window. An entry whose age equals windowMs
// EXACTLY survives prune (inclusive lower bound). Off-by-one would
// either leak old reads (false-positive flag) or drop fresh reads
// (false-negative flag) -- both degrade Phase 4's signal.
function pruneInPlace(now: number, w: number): void {
  if (w === 0) {
    // Window=0 means tracking is OFF -- recentReads/postReadFlag/recordRead
    // short-circuit, but if a stale entry remains from a prior non-zero
    // window, clear it on first access under the new (0) policy.
    reads.clear();
    return;
  }
  for (const [msgid, ev] of reads.entries()) {
    if ((now - ev.readAtMs) > w) {
      reads.delete(msgid);
    }
  }
}

// ── Public surface ────────────────────────────────────────────

export function recordRead(msgid: string, meta: ReadMeta): void {
  const w = windowMs();
  if (w === 0) return;  // D5 disable: no-op, Map untouched.
  const now = Date.now();
  pruneInPlace(now, w);
  // Defensive shallow-copy of meta -- caller may mutate their local copy;
  // we own our Map value (W-4 anti-alias guard). The folder string is
  // captured by value via fresh object literal; uid is a primitive.
  reads.set(msgid, { msgid, readAtMs: now, folder: meta.folder, uid: meta.uid });
}

export function recentReads(): ReadEvent[] {
  const w = windowMs();
  if (w === 0) { reads.clear(); return []; }  // D5 disable: empty view.
  const now = Date.now();
  pruneInPlace(now, w);
  // Shallow-copy ARRAY (fresh array). ReadEvent objects are NOT
  // deep-frozen -- callers MUST NOT mutate entries (W-5). Phase 4
  // consumes only via postReadFlag; recentReads is reserved for
  // forward-compat enrichment (D8).
  return [...reads.values()];
}

export function postReadFlag(now?: number): boolean {
  const w = windowMs();
  if (w === 0) return false;  // D5 hard false; not "match-all-time".
  const t = now ?? Date.now();
  pruneInPlace(t, w);
  return reads.size > 0;
}

export function _resetForTests(): void {
  // Clears the Map only; does NOT touch the policy cache (D-CONTEXT note).
  // Window remains whatever getPolicy() reports.
  reads.clear();
}
