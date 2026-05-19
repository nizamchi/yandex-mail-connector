/**
 * Token loader — mirrors yandex_disk client._load_token() pattern.
 *
 * Priority (first wins):
 *   1. token.json next to this script (sources/yandex_mail/token.json style)
 *   2. YANDEX_OAUTH_TOKEN env var (fallback for power users)
 *
 * token.json format (same as disk):
 *   {
 *     "access_token": "y0_AgAAA...",
 *     "email": "you@yandex.ru",
 *     "imap_host": "imap.yandex.com",   // optional — override IMAP host
 *     "smtp_host": "smtp.yandex.com"    // optional — override SMTP host
 *   }
 *
 * Env var overrides: YANDEX_IMAP_HOST, YANDEX_SMTP_HOST
 */

import fs from 'fs';
import path from 'path';

export interface Credentials {
  email: string;
  oauthToken: string;
  imapHost?: string;
  smtpHost?: string;
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

function findTokenFile(): string | null {
  // Look next to dist/index.js → project root → cwd
  const candidates = [
    path.join(__dirname, '..', 'token.json'),     // project root
    path.join(process.cwd(), 'token.json'),        // cwd fallback
  ];
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
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(fs.readFileSync(tokenFile, 'utf8'));
    } catch (e) {
      throw new Error(`Failed to read token.json at ${tokenFile}: ${String(e)}`);
    }
    // Validate required fields (no try — let it throw naturally with a clear message)
    if (!raw.access_token || !raw.email) {
      throw new Error('token.json must contain "access_token" and "email"');
    }
    const creds: Credentials = {
      email:      raw.email as string,
      oauthToken: raw.access_token as string,
      imapHost:   raw.imap_host as string | undefined,
      smtpHost:   raw.smtp_host as string | undefined,
    };
    validateHost(creds.imapHost, 'imap');
    validateHost(creds.smtpHost, 'smtp');
    return creds;
  }

  // 2. Env var fallback
  const token = process.env.YANDEX_OAUTH_TOKEN;
  const email = process.env.YANDEX_EMAIL;
  if (token && email) {
    const creds: Credentials = {
      email,
      oauthToken: token,
      imapHost:   process.env.YANDEX_IMAP_HOST,
      smtpHost:   process.env.YANDEX_SMTP_HOST,
    };
    validateHost(creds.imapHost, 'imap');
    validateHost(creds.smtpHost, 'smtp');
    return creds;
  }

  throw new Error(
    'Yandex Mail credentials not found.\n' +
    'Create token.json next to the server:\n' +
    '  { "access_token": "y0_AgAAA...", "email": "you@yandex.ru" }\n' +
    'Or set YANDEX_OAUTH_TOKEN + YANDEX_EMAIL env vars.'
  );
}
