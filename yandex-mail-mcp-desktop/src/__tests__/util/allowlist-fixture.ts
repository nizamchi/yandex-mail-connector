// allowlist-fixture.ts -- Phase 6 H-5 test fixture helpers.
//
// Provides mkAllowlistEntryWithMeta(addr, addedMs, useCount?, scope?, source?)
// for tests that need to assert risk-signal evaluators with a controlled
// `entry.added` timestamp (e.g. new_trust which checks (now - added) < 7d).
//
// The helper composes:
//   1. addTrusted(addr, scope, source)            -- persists base entry.
//   2. _setEntryAddedForTests(addr, addedMs)      -- backdates entry.added.
//   3. bumpUseCount(addr, addedMs) * useCount     -- raises useCount.
//
// Returns void (the entry is on disk; callers read via getTrustEntry).

import {
  addTrusted,
  _setEntryAddedForTests,
  bumpUseCount,
  type AllowlistScope,
  type AllowlistSource,
} from '../../allowlist.js';

export function mkAllowlistEntryWithMeta(
  addr: string,
  addedMs: number,
  useCount: number = 0,
  scope: AllowlistScope = 'permanent',
  source: AllowlistSource = 'sent_history',
): void {
  // Session-scope entries don't go through the persisted file; H-5 fixture
  // helper targets persisted entries only. Session-scope is callable for
  // session_useCount=0 invariant tests but bumpUseCount is a no-op for them.
  addTrusted(addr, scope, source);
  if (scope === 'permanent' || scope === 'auto') {
    _setEntryAddedForTests(addr, addedMs);
    for (let i = 0; i < useCount; i++) {
      bumpUseCount(addr, addedMs);
    }
  }
}
