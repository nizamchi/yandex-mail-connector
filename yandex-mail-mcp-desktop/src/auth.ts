// Layer 1 auth module — AUTH-01.
//
// Single source of truth for "what authorization level is this process running at?".
// Read once at startup in index.ts, then propagated as ctx into registerTools().
//
// Default-secure: any unknown / empty / out-of-range value collapses to L0 (read-only).
// We do NOT print warnings from this module — that responsibility lives in index.ts
// so there is exactly one place printing the startup banner (single responsibility).

export type AuthLevel = 0 | 1 | 2 | 3;

// Capability flags surfaced via yandex_health_check (agent introspection) and,
// forward-compat, usable for tool gating. 'index' = fast local search index
// (Layer 2). 'manifest' = attachment catalog (Layer 3). 'auto' = L3 auto-confirm
// mode. 'sampling' = MCP sampling (not yet wired -- it is client-negotiated at
// runtime, not known at this startup-time call). See detectCapabilities below.
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

// Report the capabilities this build actually has, for agent introspection via
// yandex_health_check. 'index' (Layer 2 local search) and 'manifest' (Layer 3
// attachment catalog) are compiled-in features available at every auth level, so
// they are always present. 'auto' reflects the L3 auto-confirm mode. 'sampling'
// is omitted until MCP sampling negotiation is wired (it is client-negotiated at
// runtime, not known here).
//
// Populating this set is purely informational today: registerTools only SKIPS a
// tool that REQUIRES a capability it lacks, and no tool currently sets
// `requires.capabilities` -- so a non-empty set cannot change which tools register.
export function detectCapabilities(level: AuthLevel): Set<Capability> {
  const caps = new Set<Capability>(['index', 'manifest']);
  if (level >= 3) caps.add('auto');
  return caps;
}

export function describeAuthLevel(level: AuthLevel): string {
  switch (level) {
    case 0: return 'READ-ONLY (L0)';
    case 1: return 'SAFE (L1)';
    case 2: return 'DESTRUCTIVE (L2)';
    case 3: return 'AUTO (L3)';
  }
}
