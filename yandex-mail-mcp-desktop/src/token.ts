/**
 * Token loader — mirrors yandex_disk client._load_token() pattern.
 *
 * Priority (first wins):
 *   1. YANDEX_TOKEN_FILE env var (explicit path override; power-user escape)
 *   2. <state_dir>/token.json — PREFERRED for `npx -y github:...` installs.
 *      state_dir resolves via getStateDir() (Hook 1): %APPDATA%/yandex-mail-mcp
 *      on Windows, $XDG_CONFIG_HOME/yandex-mail-mcp on Unix, or
 *      $YANDEX_STATE_DIR if set. Lives alongside allowlist.json + secret.bin
 *      + audit.jsonl, so users have one durable place for all state.
 *   3. <project_root>/token.json — legacy: works for `git clone` + `npm start`
 *      dev installs. Fails on `npx` because __dirname points into ~/.npm/_npx
 *      which is wiped on each invocation.
 *   4. <cwd>/token.json — legacy: works when manually invoked from a known cwd.
 *      Unreliable from Claude Desktop / Cursor MCP child processes.
 *   5. YANDEX_APP_PASSWORD or YANDEX_OAUTH_TOKEN + YANDEX_EMAIL env vars —
 *      fallback for ephemeral envs.
 *
 * token.json formats (v2.1.2+):
 *
 *   Yandex app password (RECOMMENDED — created at passport.yandex.ru):
 *     {
 *       "email": "you@yandex.ru",
 *       "password": "abcdefghijklmnop",      // 16 lowercase letters
 *       "imap_host": "imap.yandex.com",      // optional
 *       "smtp_host": "smtp.yandex.com"       // optional
 *     }
 *
 *   OAuth (legacy — only if you have a yandex OAuth app):
 *     {
 *       "email": "you@yandex.ru",
 *       "access_token": "y0_AgAAA..."        // starts with y0_
 *     }
 *
 *   Legacy single-field (v2.0/v2.1 compatibility) — auto-detected:
 *     {
 *       "email": "you@yandex.ru",
 *       "access_token": "abcdefghijklmnop"    // 16 lowercase → routed as app password
 *     }
 *
 * Env var overrides: YANDEX_IMAP_HOST, YANDEX_SMTP_HOST
 */

import fs from 'fs';
import path from 'path';
import { getStateDir } from './state-dir.js';

export interface Credentials {
  email: string;
  /** Yandex app password (SASL PLAIN auth). Exactly one of password|oauthToken must be set. */
  password?: string;
  /** Yandex OAuth access_token (XOAUTH2 auth). Legacy path. Exactly one of password|oauthToken must be set. */
  oauthToken?: string;
  imapHost?: string;
  smtpHost?: string;
}

/**
 * Heuristic: detect whether a token-shaped string is a Yandex app password
 * or an OAuth access token. Used for backward compatibility with users who
 * stored an app password in the legacy "access_token" field per pre-v2.1.2
 * INSTALL.md guidance.
 *
 *   - OAuth token: starts with `y0_` prefix (Yandex convention, ~80 chars)
 *   - App password: exactly 16 lowercase letters (Yandex Passport generator)
 *
 * Default for ambiguous: OAuth (preserves v2.0/v2.1 behavior).
 */
function detectTokenKind(t: string): 'password' | 'oauth' {
  if (t.startsWith('y0_')) return 'oauth';
  if (/^[a-z]{16}$/.test(t)) return 'password';
  return 'oauth';
}

// SEC-03 (T-02-01): host allowlist для защиты от env-poisoning. Оба `.com` и
// `.ru` first-class (CNAME + TLS SAN, см. ARCHITECTURE-NOTES.md Fact 1);
// `imap.ya.ru` — legacy alias, тоже допустим.
const ALLOWED_HOSTS = new Set<string>([
  'imap.yandex.com',
  'imap.yandex.ru',
  'imap.ya.ru',
  'smtp.yandex.com',
  'smtp.yandex.ru',
]);

function validateHost(host: string | undefined, kind: 'imap' | 'smtp'): void {
  if (host == null) return; // defaults в imap.ts / smtp.ts уже в allowlist
  if (process.env.YANDEX_ALLOW_CUSTOM_HOSTS === 'true') return;
  if (!ALLOWED_HOSTS.has(host)) {
    throw new Error(
      `Refused ${kind}Host "${host}" — not in Yandex host allowlist. ` +
      `Set YANDEX_ALLOW_CUSTOM_HOSTS=true to bypass (NOT recommended for production).`,
    );
  }
}

// T-08-02 (OPS-06): on Unix, refuse token.json that is group/other-readable.
// process.platform === 'win32': skip entirely — Windows fs mode is unreliable.
// Otherwise: if mode & 0o077 !== 0 → stderr warning. If
// YANDEX_STRICT_FILE_PERMS=true AND mode !== 0o600 → process.exit(1).
function permCheck(tokenPath: string): void {
  if (process.platform === 'win32') return;
  let mode: number;
  try {
    mode = fs.statSync(tokenPath).mode & 0o777;
  } catch {
    return; // accessSync passed already; treat stat failure as non-blocking
  }
  if ((mode & 0o077) === 0) return; // 0o600 or tighter
  const octal = mode.toString(8).padStart(3, '0');
  process.stderr.write(
    `[yandex-mail-mcp] token.json at ${tokenPath} has mode ${octal}; ` +
    `expected 600. Tighten with: chmod 600 ${tokenPath}\n`,
  );
  if (process.env.YANDEX_STRICT_FILE_PERMS === 'true' && mode !== 0o600) {
    process.stderr.write(
      `[yandex-mail-mcp] YANDEX_STRICT_FILE_PERMS=true; refusing to start.\n`,
    );
    process.exit(1);
  }
}

function findTokenFile(): string | null {
  // M-2 fix (milestone deep-review): resolution order extended to make
  // `npx -y github:...` installs work without manual path archaeology.
  //
  // Order (first wins):
  //   1. YANDEX_TOKEN_FILE env override — power-user escape hatch.
  //   2. <state_dir>/token.json — PREFERRED for npx installs.
  //   3. <project_root>/token.json — legacy: clone + npm start.
  //   4. <cwd>/token.json — legacy: manual invoke from known cwd.

  const explicit = process.env.YANDEX_TOKEN_FILE;
  if (explicit && explicit.length > 0) {
    const resolved = path.resolve(explicit);
    try {
      fs.accessSync(resolved, fs.constants.R_OK);
      return resolved;
    } catch {
      // Explicit override that doesn't exist is a configuration error worth
      // surfacing — don't silently fall through to discovery. Returning null
      // here would mask the typo. Throw with a clear message.
      throw new Error(
        `YANDEX_TOKEN_FILE=${explicit} (resolved: ${resolved}) is not readable. ` +
        `Check the path, or unset YANDEX_TOKEN_FILE to fall back to discovery.`,
      );
    }
  }

  const candidates: string[] = [];
  // Preferred state-dir location. getStateDir() may throw if it cannot create
  // the directory (e.g. parent unwritable); treat that as "no state-dir
  // candidate" and continue with legacy paths.
  try {
    candidates.push(path.join(getStateDir(), 'token.json'));
  } catch { /* state dir unavailable; legacy candidates only */ }
  candidates.push(path.join(__dirname, '..', 'token.json'));   // project root (legacy)
  candidates.push(path.join(process.cwd(), 'token.json'));      // cwd (legacy)

  for (const p of candidates) {
    try {
      fs.accessSync(p, fs.constants.R_OK);
      return p;
    } catch { /* skip */ }
  }
  return null;
}

export function loadCredentials(): Credentials {
  // 1. Try token.json
  const tokenFile = findTokenFile();
  if (tokenFile) {
    permCheck(tokenFile);
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(fs.readFileSync(tokenFile, 'utf8'));
    } catch (e) {
      throw new Error(`Failed to read token.json at ${tokenFile}: ${String(e)}`);
    }
    if (!raw.email) {
      throw new Error('token.json must contain "email"');
    }

    // v2.1.2: support both "password" (Yandex app password, recommended) and
    // "access_token" (OAuth, legacy). Exactly one of the two must be present.
    // For backward compat with pre-v2.1.2 users who put their app password
    // into the "access_token" field (per the misleading old INSTALL.md),
    // detectTokenKind() routes the value to the correct auth path.
    const explicitPwd = (raw.password ?? raw.pass) as string | undefined;
    const legacyTok   = raw.access_token as string | undefined;

    if (explicitPwd && legacyTok) {
      throw new Error(
        'token.json must contain either "password" OR "access_token", not both. ' +
        'Use "password" for Yandex app passwords (recommended) or "access_token" for OAuth tokens.',
      );
    }
    if (!explicitPwd && !legacyTok) {
      throw new Error(
        'token.json must contain one of: "password" (Yandex app password, recommended) | ' +
        '"access_token" (OAuth token, legacy).',
      );
    }

    const creds: Credentials = {
      email:    raw.email as string,
      imapHost: raw.imap_host as string | undefined,
      smtpHost: raw.smtp_host as string | undefined,
    };
    if (explicitPwd) {
      creds.password = explicitPwd;
    } else if (legacyTok) {
      // Heuristic: route based on token shape
      if (detectTokenKind(legacyTok) === 'password') {
        creds.password = legacyTok;
      } else {
        creds.oauthToken = legacyTok;
      }
    }
    validateHost(creds.imapHost, 'imap');
    validateHost(creds.smtpHost, 'smtp');
    return creds;
  }

  // 2. Env var fallback — both YANDEX_APP_PASSWORD (new) and YANDEX_OAUTH_TOKEN
  //    (legacy) are accepted. Exactly one must be set together with YANDEX_EMAIL.
  const envPwd   = process.env.YANDEX_APP_PASSWORD;
  const envToken = process.env.YANDEX_OAUTH_TOKEN;
  const email    = process.env.YANDEX_EMAIL;
  if (email && (envPwd || envToken)) {
    if (envPwd && envToken) {
      throw new Error(
        'Set either YANDEX_APP_PASSWORD or YANDEX_OAUTH_TOKEN, not both.',
      );
    }
    const creds: Credentials = {
      email,
      imapHost: process.env.YANDEX_IMAP_HOST,
      smtpHost: process.env.YANDEX_SMTP_HOST,
    };
    if (envPwd) {
      creds.password = envPwd;
    } else if (envToken) {
      if (detectTokenKind(envToken) === 'password') {
        creds.password = envToken;
      } else {
        creds.oauthToken = envToken;
      }
    }
    validateHost(creds.imapHost, 'imap');
    validateHost(creds.smtpHost, 'smtp');
    return creds;
  }

  // M-2 fix: error message now points users at the durable state-dir location
  // (works for npx installs) instead of "next to the server" which is
  // ~/.npm/_npx/... and gets wiped on every invocation.
  let preferredDir = '';
  try { preferredDir = getStateDir(); } catch { /* unavailable */ }

  const lines = [
    'Yandex Mail credentials not found.',
    '',
    'Option 1 (RECOMMENDED) -- Yandex app password in token.json:',
  ];
  if (preferredDir) {
    lines.push(`  ${path.join(preferredDir, 'token.json')}`);
  } else {
    lines.push('  <state_dir>/token.json  (state_dir unavailable; check $YANDEX_STATE_DIR)');
  }
  lines.push(
    '  { "email": "you@yandex.ru", "password": "abcdefghijklmnop" }',
    '',
    '  Create the 16-letter app password at passport.yandex.ru ->',
    '  "Passwords and authorization" -> "App passwords" -> "Mail".',
    '',
    'Option 2 -- OAuth token (legacy, only if you have a Yandex OAuth app):',
    '  { "email": "you@yandex.ru", "access_token": "y0_AgAAA..." }',
    '',
    'Option 3 -- point to an arbitrary path via env:',
    '  YANDEX_TOKEN_FILE=/path/to/token.json',
    '',
    'Option 4 -- ephemeral env vars (CI / containers):',
    '  YANDEX_APP_PASSWORD=abcdefghijklmnop  YANDEX_EMAIL=you@yandex.ru',
    '  (or YANDEX_OAUTH_TOKEN=y0_AgAAA...  YANDEX_EMAIL=...  for OAuth)',
  );
  throw new Error(lines.join('\n'));
}
