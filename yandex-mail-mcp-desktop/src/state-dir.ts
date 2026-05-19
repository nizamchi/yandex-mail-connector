// Hook 1 — platform-aware persistent state directory.
//
// THIS MODULE IS THE SINGLE SOURCE OF TRUTH for resolving the path of any
// state file the connector writes between runs: allowlist.json + secret.bin
// (Phase 5), pending-trust.json (Phase 5 CLI handoff), audit.jsonl (Phase 6),
// rate-limit state (Phase 7), index.db (Layer 2), etc. DO NOT inline path
// resolution anywhere else — call getStateDir() instead.
//
// Resolution order (per ROADMAP D-STATE-DIR-PATH):
//   1. process.env.YANDEX_STATE_DIR — explicit override, resolved via
//      path.resolve so relative paths Just Work in tests/dev.
//   2. Windows (process.platform === 'win32'):
//        ${APPDATA ?? %USERPROFILE%/AppData/Roaming}/yandex-mail-mcp
//   3. Unix (linux, darwin, others):
//        ${XDG_CONFIG_HOME ?? $HOME/.config}/yandex-mail-mcp
//
// Side effect: on first call we mkdirSync(dir, { recursive: true, mode: 0o700 })
// so subsequent state writes don't have to. mode 0o700 is honoured on POSIX;
// Windows ignores it (the directory inherits %APPDATA% ACL — see Phase 8 README
// "File Locations" for the documented limitation).
//
// Idempotent: result is cached in a module-local. _resetForTests() flushes the
// cache so platform-branch tests can re-evaluate without spawning a child
// process. The leading underscore signals "test-only" — it is not part of the
// stable public surface.

import * as os from 'node:os';
import * as path from 'node:path';
import * as fs from 'node:fs';

let cached: string | null = null;

function resolve(): string {
  const override = process.env.YANDEX_STATE_DIR;
  if (override && override.length > 0) {
    return path.resolve(override);
  }
  if (process.platform === 'win32') {
    const appdata = process.env.APPDATA ?? path.join(os.homedir(), 'AppData', 'Roaming');
    return path.join(appdata, 'yandex-mail-mcp');
  }
  const xdg = process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), '.config');
  return path.join(xdg, 'yandex-mail-mcp');
}

function ensureDir(dir: string): void {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === 'EEXIST') return;
    throw new Error(`getStateDir: failed to create ${dir}: ${err.message ?? String(e)}`);
  }
}

export function getStateDir(): string {
  if (cached !== null) return cached;
  const dir = resolve();
  ensureDir(dir);
  cached = dir;
  return dir;
}

// Test-only: flush the module cache so a subsequent call re-reads env + platform.
// Underscore-prefix marks the export as non-public; production code MUST NOT call it.
export function _resetForTests(): void {
  cached = null;
}
