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
//       FIRST and drops stale entries. NO setInterval, setTimeout,
//       setImmediate, queueMicrotask, worker, or async.
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

// ── Public surface (stubs -- filled in T-03-01-02) ────────────

export function recordRead(_msgid: string, _meta: ReadMeta): void {
  // Stub: filled in T-03-01-02.
}

export function recentReads(): ReadEvent[] {
  // Stub: filled in T-03-01-02.
  return [];
}

export function postReadFlag(_now?: number): boolean {
  // Stub: filled in T-03-01-02.
  return false;
}

export function _resetForTests(): void {
  // Stub: filled in T-03-01-02. Will clear the Map only; does NOT touch
  // the policy cache (D-CONTEXT note).
}
