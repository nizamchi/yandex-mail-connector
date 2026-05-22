// `--check` health-check mode for the MCP server bundle.
//
// Goal: a 2-3 second sanity pass that surfaces 90% of "у меня не работает"
// issues BEFORE the user wires the bundle into a real MCP client. Runs the
// same path-resolution + signature gates as the normal startup, plus
// a non-authenticating TLS handshake against imap/smtp hosts so DNS and
// network reachability are verified. Never sends LOGIN. Never authenticates.
//
// Exit codes:
//   0 — all checks passed
//   1 — one or more checks failed (any line marked [✗] in output)
//   2 — internal error during the check itself
//
// Output: stderr only (consistent with normal startup banner). No stdout —
// some users may pipe `--check` to a file for sharing; we don't want to
// corrupt that file with any partial MCP framing.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { getStateDir } from './state-dir.js';
import * as allowlist from './allowlist.js';
import * as policy from './policy.js';

interface CheckResult {
  name: string;
  ok: boolean;
  detail: string;
}

function pad(s: string, w: number): string {
  return s.length >= w ? s : s + ' '.repeat(w - s.length);
}

function fmt(r: CheckResult): string {
  // ASCII safe markers — Windows cmd.exe in default codepage chokes on ✓/✗.
  // Boxes/colour skipped for the same reason.
  const mark = r.ok ? '[ok]' : '[FAIL]';
  return `${mark} ${pad(r.name, 22)} ${r.detail}`;
}

function checkBundlePath(): CheckResult {
  // index.ts is at <bundle>/yandex-mail-mcp.js in shipped artifact; in dev
  // it's <project>/src/check-config.ts. Show whatever __filename / cwd say.
  // This is informational; never fails.
  let p = '';
  try {
    p = typeof __filename === 'string' ? __filename : process.argv[1] || '<unknown>';
  } catch {
    p = '<unknown>';
  }
  return { name: 'Bundle path:', ok: true, detail: p };
}

function checkStateDir(): CheckResult {
  try {
    const dir = getStateDir();
    let modeNote = '';
    if (process.platform !== 'win32') {
      try {
        const mode = fs.statSync(dir).mode & 0o777;
        modeNote = `, mode ${mode.toString(8).padStart(3, '0')}`;
      } catch { /* ignore */ }
    }
    return { name: 'State directory:', ok: true, detail: `${dir} (exists${modeNote})` };
  } catch (e) {
    return { name: 'State directory:', ok: false, detail: `unavailable: ${stringifyErr(e)}` };
  }
}

function findExistingTokenFile(): string | null {
  // Mirror token.ts findTokenFile() priority but READ-ONLY — no permCheck
  // exits, no env-var refusal to throw.
  const explicit = process.env.YANDEX_TOKEN_FILE;
  if (explicit && explicit.length > 0) {
    const resolved = path.resolve(explicit);
    if (canRead(resolved)) return resolved;
    return null;
  }
  let stateCandidate: string | null = null;
  try { stateCandidate = path.join(getStateDir(), 'token.json'); }
  catch { /* state dir unavailable */ }
  const candidates: string[] = [];
  if (stateCandidate) candidates.push(stateCandidate);
  candidates.push(path.join(__dirname, '..', 'token.json'));
  candidates.push(path.join(process.cwd(), 'token.json'));
  for (const p of candidates) {
    if (canRead(p)) return p;
  }
  return null;
}

function canRead(p: string): boolean {
  try { fs.accessSync(p, fs.constants.R_OK); return true; }
  catch { return false; }
}

function checkTokenFile(): CheckResult {
  const tokenPath = findExistingTokenFile();
  if (!tokenPath) {
    // Maybe env-var fallback?
    const envPwd = process.env.YANDEX_APP_PASSWORD;
    const envOauth = process.env.YANDEX_OAUTH_TOKEN;
    const envEmail = process.env.YANDEX_EMAIL;
    if (envEmail && (envPwd || envOauth)) {
      const kind = envPwd ? 'app password' : 'OAuth token';
      return { name: 'Credentials:', ok: true, detail: `env-var fallback (${kind}, email=${envEmail})` };
    }
    return {
      name: 'Credentials:',
      ok: false,
      detail: 'NOT FOUND — no token.json in state-dir/project/cwd, no YANDEX_APP_PASSWORD/YANDEX_OAUTH_TOKEN env',
    };
  }
  // Parse the file and surface auth kind
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(fs.readFileSync(tokenPath, 'utf8'));
  } catch (e) {
    return { name: 'token.json:', ok: false, detail: `${tokenPath} unparseable: ${stringifyErr(e)}` };
  }
  if (!raw.email) {
    return { name: 'token.json:', ok: false, detail: `${tokenPath} missing "email" field` };
  }
  const pwd = (raw.password ?? raw.pass) as string | undefined;
  const legacyTok = raw.access_token as string | undefined;
  if (!pwd && !legacyTok) {
    return { name: 'token.json:', ok: false, detail: `${tokenPath} missing "password" / "access_token"` };
  }
  if (pwd && legacyTok) {
    return { name: 'token.json:', ok: false, detail: `${tokenPath} has BOTH "password" and "access_token" — pick one` };
  }
  // Detect token kind for display
  const tok = pwd ?? legacyTok!;
  let kind = 'unknown';
  if (pwd !== undefined) {
    kind = 'app password (explicit "password" field)';
  } else if (tok.startsWith('y0_')) {
    kind = 'OAuth token (y0_ prefix)';
  } else if (/^[a-z]{16}$/.test(tok)) {
    kind = 'app password (16-char heuristic on legacy "access_token" field)';
  } else {
    kind = 'OAuth token (legacy "access_token" field, no shape match)';
  }
  let modeNote = '';
  if (process.platform !== 'win32') {
    try {
      const mode = fs.statSync(tokenPath).mode & 0o777;
      if ((mode & 0o077) === 0) modeNote = `, mode ${mode.toString(8).padStart(3, '0')}`;
      else modeNote = `, mode ${mode.toString(8).padStart(3, '0')} (WARN: world/group readable; chmod 600)`;
    } catch { /* ignore */ }
  }
  return { name: 'token.json:', ok: true, detail: `${tokenPath} (${kind}${modeNote})` };
}

function checkAllowlist(): CheckResult {
  try {
    const allowlistPath = allowlist.getAllowlistPath();
    if (!canRead(allowlistPath)) {
      return { name: 'Allowlist:', ok: true, detail: `${allowlistPath} (not yet bootstrapped — created on first L1+ start)` };
    }
    const verified = allowlist.verifySignature();
    if (!verified) {
      return { name: 'Allowlist:', ok: false, detail: `${allowlistPath} signature INVALID — file or secret.bin was modified outside the connector` };
    }
    // Count entries — read the JSON and look at .entries.length
    try {
      const raw = JSON.parse(fs.readFileSync(allowlistPath, 'utf8'));
      const count = Array.isArray(raw.entries) ? raw.entries.length : 0;
      return { name: 'Allowlist:', ok: true, detail: `${allowlistPath} (signature valid, ${count} trusted addresses)` };
    } catch {
      return { name: 'Allowlist:', ok: true, detail: `${allowlistPath} (signature valid)` };
    }
  } catch (e) {
    return { name: 'Allowlist:', ok: false, detail: `error: ${stringifyErr(e)}` };
  }
}

function checkPolicy(): CheckResult {
  try {
    // policy.loadPolicy() in normal startup will recoverFatal()+exit(1) on
    // invalid signature. Here we want a softer report. We don't have a
    // non-exit-y verify in policy.ts public API, so we mirror the file path
    // and report what we can without crashing.
    const policyPath = policy.getPolicyPath();
    if (!canRead(policyPath)) {
      return { name: 'Risk policy:', ok: true, detail: `${policyPath} (not yet created — bootstrapped on first startup)` };
    }
    // Just verify the file is parseable JSON. Signature verification will
    // happen at real startup (and crash there if bad).
    JSON.parse(fs.readFileSync(policyPath, 'utf8'));
    return { name: 'Risk policy:', ok: true, detail: `${policyPath} (file exists, JSON valid)` };
  } catch (e) {
    return { name: 'Risk policy:', ok: false, detail: `error: ${stringifyErr(e)}` };
  }
}

async function tlsPing(host: string, port: number, timeoutMs: number): Promise<CheckResult> {
  return new Promise<CheckResult>(resolve => {
    const start = Date.now();
    let resolved = false;
    const done = (r: CheckResult): void => { if (!resolved) { resolved = true; resolve(r); } };

    const sock = tls.connect({ host, port, servername: host }, () => {
      const ms = Date.now() - start;
      const cert = sock.getPeerCertificate();
      const cn = cert?.subject?.CN ?? '<unknown>';
      sock.end();
      done({
        name: `${host}:${port}:`,
        ok: true,
        detail: `TLS OK in ${ms}ms (cert CN=${cn})`,
      });
    });

    sock.setTimeout(timeoutMs, () => {
      sock.destroy();
      done({ name: `${host}:${port}:`, ok: false, detail: `timeout after ${timeoutMs}ms` });
    });

    sock.on('error', (e: Error & { code?: string }) => {
      done({ name: `${host}:${port}:`, ok: false, detail: `${e.code ?? 'ERROR'}: ${e.message}` });
    });
  });
}

function stringifyErr(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export async function runHealthCheck(): Promise<number> {
  const lines: string[] = [];
  lines.push('');
  lines.push('yandex-mail-mcp health check');
  lines.push('==========================================');

  const sync: CheckResult[] = [
    checkBundlePath(),
    checkStateDir(),
    checkTokenFile(),
    checkAllowlist(),
    checkPolicy(),
  ];

  const async_: CheckResult[] = await Promise.all([
    tlsPing('imap.yandex.com', 993, 5000),
    tlsPing('smtp.yandex.com', 465, 5000),
  ]);

  const all = [...sync, ...async_];
  for (const r of all) lines.push(fmt(r));

  const failed = all.filter(r => !r.ok).length;
  lines.push('==========================================');
  if (failed === 0) {
    lines.push(`All ${all.length} checks passed.`);
  } else {
    lines.push(`${failed} of ${all.length} checks FAILED — see [FAIL] lines above.`);
  }
  lines.push('');

  process.stderr.write(lines.join('\n'));
  return failed === 0 ? 0 : 1;
}
