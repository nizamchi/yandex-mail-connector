// Layer 1 auth module — AUTH-01.
//
// Single source of truth for "what authorization level is this process running at?".
// Read once at startup in index.ts, then propagated as ctx into registerTools().
//
// Default-secure: any unknown / empty / out-of-range value collapses to L0 (read-only).
// We do NOT print warnings from this module — that responsibility lives in index.ts
// so there is exactly one place printing the startup banner (single responsibility).

export type AuthLevel = 0 | 1 | 2 | 3;

// Capability stub for L2-L7. In Layer 1 it stays empty — capabilities will be
// activated later (e.g. 'index' when the search index ships, 'sampling' when
// MCP sampling negotiation is wired). Hook 3 forward-compat.
export type Capability = 'index' | 'manifest' | 'sampling' | 'auto';

const LEVEL_MAP: ReadonlyMap<string, AuthLevel> = new Map<string, AuthLevel>([
  ['0', 0],
  ['readonly', 0],
  ['1', 1],
  ['safe', 1],
  ['2', 2],
  ['destructive', 2],
  ['3', 3],
  ['auto', 3],
]);

export function getAuthLevel(env: NodeJS.ProcessEnv = process.env): AuthLevel {
  const raw = env.YANDEX_AUTH_LEVEL;
  if (raw === undefined || raw === null) return 0;
  const normalized = String(raw).trim().toLowerCase();
  if (normalized === '') return 0;
  const level = LEVEL_MAP.get(normalized);
  return level ?? 0;
}

// True if YANDEX_AUTH_LEVEL was set but did not match any known token.
// Lets index.ts distinguish "user typo silently fell back to L0" from
// "user explicitly set L0" — both yield authLevel=0 but the typo case
// deserves a loud stderr warning so it does not become a debug hell.
export function isInvalidAuthLevel(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env.YANDEX_AUTH_LEVEL;
  if (raw === undefined || raw === null) return false;
  const normalized = String(raw).trim().toLowerCase();
  if (normalized === '') return false;
  return !LEVEL_MAP.has(normalized);
}

// Layer 1 stub — returns empty Set regardless of level.
// WHY: Capabilities-based gating is a Hook 3 forward-compat surface. In v2 (Layer 1)
// no tool requires a capability; in L2+ tools like "index_search" will list
// `requires.capabilities: ['index']` and registerTools will skip them when the
// capability is absent. Keeping this stub now means index.ts and registerTools
// don't need to change shape when Layer 2 lands.
export function detectCapabilities(_level: AuthLevel): Set<Capability> {
  return new Set<Capability>();
}

export function describeAuthLevel(level: AuthLevel): string {
  switch (level) {
    case 0: return 'READ-ONLY (L0)';
    case 1: return 'SAFE (L1)';
    case 2: return 'DESTRUCTIVE (L2)';
    case 3: return 'AUTO (L3)';
  }
}
