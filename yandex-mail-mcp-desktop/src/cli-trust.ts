// cli-trust.ts -- `yandex-mail-mcp-trust` bin entry.
//
// Phase 5 origin: out-of-band trust-token issuer + high-risk-send override
// minter (D-CLI-IPC option a). Phase 7 adds operator subcommands:
//   --policy show|set|reset|edit       (PMLF-CLI-01)
//   --recent [--risk] [--limit N]      (PMLF-CLI-02)
//   --list-trust [--stale Nd] [--source X]   (PMLF-CLI-03)
//   --revoke-trust <address>           (PMLF-CLI-04)
//   --high-risk-send <fp>              (PMLF-CLI-05; existing)
//   --yes                              (PMLF-CLI-06; non-interactive flag)
//
// Why a separate process instead of a chat tool: the MCP server is started by
// Claude Desktop and lives only inside that client. An attacker (LLM-crafted
// email content) can call MCP tools but cannot spawn arbitrary processes on
// the user's machine and cannot read this CLI's stdout. The token is bound to
// the user's terminal until the user copy-pastes it.
//
// Parser determinism (Rev-2 H1): the manual argv parser follows fixed rules
// for flag forms, positional consumption, --yes ordering, multi-value
// rejection, negative-number handling, unknown flags, empty argv, missing
// values. See parseArgs() comments for the verbatim rule list and the
// T-CLI-PARSER-EDGE-01 test case for the assertion harness.
//
// Audit drain (Rev-2 B1): every subcommand that emits an auditLog enqueue
// MUST exit via exitAfterAudit(code) so the audit writeChain drains before
// process termination. Plain process.exit is used ONLY on read-only paths
// (no audit emitted) and on parse-error paths (audit not yet enqueued).
//
// No `any`. ESM `.js` suffix. ASCII only.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { randomBytes } from 'node:crypto';

import { getStateDir } from './state-dir.js';
import { mintOverrideToken } from './override-tokens.js';
import { flushAudit, auditLog } from './audit.js';
import {
  loadPolicy,
  writePolicy,
  getPolicyPath,
  RiskPolicySchema,
} from './policy.js';
import { DEFAULT_POLICY, type RiskPolicy } from './policy-defaults.js';
import {
  revokeTrust,
  _listTrusted,
  type AllowlistSource,
} from './allowlist.js';
import { readRecentSends } from './recent-sends.js';

// -- CliArgs discriminated union (CONTEXT D2) ---------------

type CliArgs =
  | { mode: 'trust'; address: string; scope: 'permanent' | 'session'; yes: boolean }
  | { mode: 'high-risk-send'; fingerprint: string; yes: boolean }
  | { mode: 'help' }
  | { mode: 'policy-show' }
  | { mode: 'policy-set'; key: string; value: string; yes: boolean }
  | { mode: 'policy-reset'; yes: boolean }
  | { mode: 'policy-edit'; yes: boolean }
  | { mode: 'recent'; risk: boolean; limit: number }
  | { mode: 'list-trust'; staleMs?: number; source?: AllowlistSource }
  | { mode: 'revoke-trust'; address: string; yes: boolean };

const TTL_MS = 5 * 60 * 1000;

const VALID_SOURCES: ReadonlyArray<AllowlistSource> = [
  'sent_history',
  'user_trust_token',
  'auto_trust_reply',
  'legacy_migration',
];

// -- Audit-drain helper (Rev-2 B1) --------------------------

/**
 * Drain the audit writeChain, then exit. Use this in any exit path that
 * follows an auditLog(...) enqueue. Internally awaits the audit writeChain
 * so the queued appendFile lands on disk before the process terminates.
 * Plain process.exit(...) is still used on read-only exit paths (no audit
 * emitted) and on parse-error paths (audit not yet enqueued).
 */
async function exitAfterAudit(code: number): Promise<never> {
  await flushAudit();
  process.exit(code);
}

// -- Platform test seam (Rev-2 B2) --------------------------

// effectivePlatform(): returns YANDEX_FORCE_PLATFORM_FOR_TESTS if set to
// 'win32' / 'linux' / 'darwin', else process.platform. Used in --policy
// edit to make win32 / POSIX paths deterministic in tests. Test-only seam
// -- production behaviour is process.platform via the fallback.
function effectivePlatform(): string {
  const forced = process.env.YANDEX_FORCE_PLATFORM_FOR_TESTS;
  if (forced === 'win32' || forced === 'linux' || forced === 'darwin') {
    return forced;
  }
  return process.platform;
}

// -- Email validator (shared by trust + revoke-trust modes) -

function validEmail(s: string): boolean {
  // Cheap syntactic check -- RFC 5322 is intentionally not parsed here.
  // Same as the IMAP envelope: addresses are treated as opaque tokens.
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

// -- Parser ------------------------------------------------

// Parser determinism rules (Rev-2 H1):
//   - Flag form: `--foo bar` is canonical. `--foo=bar` accepted ONLY for
//     legacy --high-risk-send=<hex> + --scope=<scope> (Phase 5 contract).
//   - Boolean flags: --yes, --risk, --help take no value.
//   - Positional consumption: after a mode-defining flag with positional
//     shape, the NEXT non-flag token is the positional unconditionally
//     (handles negative numbers in `--policy set foo -1`).
//   - --yes ordering: may appear ANYWHERE in argv. Pre-scanned once.
//   - Multi-value flags: NOT supported. `--source foo --source bar` ->
//     exit 2 with `<flag>: specified more than once`.
//   - Negative numbers: `--limit -5` parses to -5, fails range check;
//     exit 2 with `--limit: must be 1..50, got -5`. NOT "unknown flag".
//   - Unknown flag: exit 2 with `unknown flag: <token>` + `try --help`.
//   - Empty argv: exit 2 with `no command specified; try --help`.
//   - Missing value: `--limit` at end of argv -> exit 2 with
//     `--limit: expected an integer value`.
//   - Mixed-mode flags: e.g. `--policy show --recent` -> exit 2 with
//     `mixed-mode flags not allowed; got --policy and --recent`.

function die(msg: string, hint?: string): never {
  process.stderr.write(msg + '\n');
  if (hint !== undefined) process.stderr.write(hint + '\n');
  process.exit(2);
}

const MODE_FLAGS = new Set([
  '--help',
  '--policy',
  '--recent',
  '--list-trust',
  '--revoke-trust',
  '--high-risk-send',
]);

function detectMode(argv: string[]): string | null {
  const seen: string[] = [];
  for (const a of argv) {
    if (MODE_FLAGS.has(a)) seen.push(a);
    if (a.startsWith('--high-risk-send=')) seen.push('--high-risk-send');
  }
  // Drop duplicates while preserving first-seen order.
  const uniq = Array.from(new Set(seen));
  if (uniq.length > 1) {
    die(`mixed-mode flags not allowed; got ${uniq[0]} and ${uniq[1]}`);
  }
  if (uniq.length === 1) return uniq[0];
  // Positional-only path: address-trust mode (Phase 5 backward compat).
  for (const a of argv) {
    if (!a.startsWith('-')) return '__positional__';
  }
  return null;
}

function preScanYes(argv: string[]): boolean {
  return argv.includes('--yes');
}

// Strip --yes from argv so per-mode helpers do not have to handle it.
function stripFlags(argv: string[], drop: ReadonlySet<string>): string[] {
  return argv.filter(a => !drop.has(a));
}

function parseArgs(argv: string[]): CliArgs {
  if (argv.length === 0) {
    die('no command specified; try --help');
  }
  const mode = detectMode(argv);
  if (mode === null) {
    // All tokens were unknown flags.
    for (const a of argv) {
      if (a.startsWith('--')) die(`unknown flag: ${a}`, 'try --help');
    }
    die('no command specified; try --help');
  }

  const yes = preScanYes(argv);
  const cleaned = stripFlags(argv, new Set(['--yes']));

  switch (mode) {
    case '--help':
      return { mode: 'help' };
    case '--policy':
      return parsePolicyMode(cleaned, yes);
    case '--recent':
      return parseRecentMode(cleaned);
    case '--list-trust':
      return parseListTrustMode(cleaned);
    case '--revoke-trust':
      return parseRevokeTrustMode(cleaned, yes);
    case '--high-risk-send':
      return parseHighRiskSendMode(cleaned, yes);
    case '__positional__':
      return parseAddressMode(cleaned, yes);
  }
  /* istanbul ignore next */
  die(`internal: unrecognised mode ${mode}`);
}

// --- per-mode parsers ---

function parsePolicyMode(argv: string[], yes: boolean): CliArgs {
  // argv has --policy somewhere; locate index, consume next token as
  // subcmd, then per-subcmd positionals.
  const idx = argv.indexOf('--policy');
  const subcmd = argv[idx + 1];
  const known = subcmd === 'show' || subcmd === 'set'
    || subcmd === 'reset' || subcmd === 'edit';
  if (!known) {
    die(`policy: expected one of show|set|reset|edit, got '${subcmd ?? ''}'`);
  }
  // Reject extra positionals (parser-determinism rule, MD-01).
  // 'set' consumes 2 extra (key, value); others consume 0.
  const consumed = subcmd === 'set' ? idx + 3 : idx + 1;
  for (let i = consumed + 1; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) die(`unknown flag: ${a}`, 'try --help');
    die(`unexpected positional: ${a}`);
  }
  if (subcmd === 'show') return { mode: 'policy-show' };
  if (subcmd === 'reset') return { mode: 'policy-reset', yes };
  if (subcmd === 'edit') return { mode: 'policy-edit', yes };
  // subcmd === 'set'
  const key = argv[idx + 2];
  const value = argv[idx + 3];
  if (key === undefined || key.startsWith('--')) die('policy set: expected <key>');
  if (value === undefined) die('policy set: expected <value>');
  return { mode: 'policy-set', key, value, yes };
}

function parseRecentMode(argv: string[]): CliArgs {
  let risk = false;
  let limit = 20;
  let sawLimit = false;
  // Skip --recent itself; iterate the rest.
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--recent') continue;
    if (a === '--risk') { risk = true; continue; }
    if (a === '--limit') {
      if (sawLimit) die('--limit: specified more than once');
      sawLimit = true;
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) {
        die('--limit: expected an integer value');
      }
      const n = Number(v);
      if (!Number.isInteger(n) || n < 1 || n > 50) {
        die(`--limit: must be 1..50, got ${v}`);
      }
      limit = n;
      i++;
      continue;
    }
    if (a.startsWith('--')) die(`unknown flag: ${a}`, 'try --help');
    die(`unexpected positional: ${a}`);
  }
  return { mode: 'recent', risk, limit };
}

function parseListTrustMode(argv: string[]): CliArgs {
  let staleMs: number | undefined;
  let source: AllowlistSource | undefined;
  let sawStale = false;
  let sawSource = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--list-trust') continue;
    if (a === '--stale') {
      if (sawStale) die('--stale: specified more than once');
      sawStale = true;
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) {
        die('--stale: expected a value like 90d');
      }
      const m = /^([0-9]+)d$/.exec(v);
      if (m === null) die(`--stale: expected Nd format, got '${v}'`);
      const n = Number(m[1]);
      if (!Number.isInteger(n) || n < 0) die(`--stale: invalid number '${v}'`);
      staleMs = n * 86_400_000;
      i++;
      continue;
    }
    if (a === '--source') {
      if (sawSource) die('--source: specified more than once');
      sawSource = true;
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) {
        die('--source: expected a value');
      }
      if (!VALID_SOURCES.includes(v as AllowlistSource)) {
        die(`--source: expected one of ${VALID_SOURCES.join('|')}, got '${v}'`);
      }
      source = v as AllowlistSource;
      i++;
      continue;
    }
    if (a.startsWith('--')) die(`unknown flag: ${a}`, 'try --help');
    die(`unexpected positional: ${a}`);
  }
  return { mode: 'list-trust', staleMs, source };
}

function parseRevokeTrustMode(argv: string[], yes: boolean): CliArgs {
  const idx = argv.indexOf('--revoke-trust');
  const address = argv[idx + 1];
  if (address === undefined || address.startsWith('--')) {
    die('revoke-trust: expected an address');
  }
  if (!validEmail(address)) {
    die(`revoke-trust: invalid address: '${address}'`);
  }
  // Reject extra positionals.
  for (let i = idx + 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) die(`unknown flag: ${a}`, 'try --help');
    die(`unexpected positional: ${a}`);
  }
  return { mode: 'revoke-trust', address: address.toLowerCase(), yes };
}

function parseHighRiskSendMode(argv: string[], yes: boolean): CliArgs {
  // MD-02 parser-determinism: reject duplicate --high-risk-send.
  let fp: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    let v: string | undefined;
    if (a.startsWith('--high-risk-send=')) {
      v = a.slice('--high-risk-send='.length);
    } else if (a === '--high-risk-send') {
      v = argv[++i];
      if (v === undefined || v.startsWith('--')) {
        die('high-risk-send: expected <32-hex-fingerprint>');
      }
    } else {
      continue;
    }
    if (fp !== undefined) die('--high-risk-send: specified more than once');
    fp = v;
  }
  if (fp === undefined) die('high-risk-send: expected <32-hex-fingerprint>');
  if (!/^[0-9a-f]{32}$/.test(fp)) {
    die(`high-risk-send: invalid fingerprint: '${fp}' (expected 32 hex chars)`);
  }
  return { mode: 'high-risk-send', fingerprint: fp, yes };
}

function parseAddressMode(argv: string[], yes: boolean): CliArgs {
  let scope: 'permanent' | 'session' = 'permanent';
  const positional: string[] = [];
  for (const a of argv) {
    if (a.startsWith('--scope=')) {
      const v = a.slice('--scope='.length);
      if (v === 'permanent' || v === 'session') { scope = v; continue; }
      die(`Invalid scope '${v}'. Use --scope=permanent | --scope=session.`);
    }
    if (a.startsWith('-')) {
      die(`unknown flag: ${a}`, 'try --help');
    }
    positional.push(a);
  }
  if (positional.length !== 1) {
    die(
      'Usage: yandex-mail-mcp-trust <address> [--scope=permanent|session]\n' +
      '       yandex-mail-mcp-trust --high-risk-send <32-hex-fingerprint>\n' +
      '       yandex-mail-mcp-trust --help',
    );
  }
  const address = positional[0]!;
  if (!validEmail(address)) {
    die(`Invalid address: '${address}'`);
  }
  return { mode: 'trust', address: address.toLowerCase(), scope, yes };
}

// -- Helpers --------------------------------------------------

function atomicWrite(target: string, data: string, mode: number): void {
  const tmp = target + '.tmp';
  try {
    fs.writeFileSync(tmp, data, { mode });
    fs.renameSync(tmp, target);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    const err = e as NodeJS.ErrnoException;
    throw new Error(`atomicWrite(${target}): ${err.message ?? String(e)}`);
  }
}

async function promptYesNo(question: string): Promise<boolean> {
  // CI / piped-stdin mode: if YANDEX_TRUST_ASSUME_YES is set we skip the prompt.
  if (process.env.YANDEX_TRUST_ASSUME_YES === '1') return true;
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const ans = (await rl.question(question)).trim();
    return ans === 'y' || ans === 'Y';
  } finally {
    rl.close();
  }
}

// -- --help text (CONTEXT D14) -------------------------------

function printHelp(): void {
  const lines: string[] = [
    'yandex-mail-mcp-trust -- operator CLI.',
    '',
    'Usage:',
    '  <address> [--scope=permanent|session]      [W] mint trust_token',
    '  --high-risk-send <32-hex> [--yes]          [W] mint override token',
    '  --policy show                              [R] print risk policy JSON',
    '  --policy set <key> <value> [--yes]         [W] set policy leaf',
    '  --policy reset [--yes]                     [W] reset to defaults',
    '  --policy edit                              [W] $EDITOR + re-sign',
    '  --recent [--risk] [--limit N]              [R] last N sends',
    '  --list-trust [--stale Nd] [--source X]     [R] allowlist filter',
    '  --revoke-trust <address> [--yes]           [W] remove from allowlist',
    '  --help                                     [R] this help',
    '',
    '[R] read-only; [W] mutates. --yes skips prompts.',
    'State dir: ' + getStateDir(),
  ];
  process.stdout.write(lines.join('\n') + '\n');
}

// -- Mode handlers -------------------------------------------

async function handleHighRiskSend(args: { fingerprint: string; yes: boolean }): Promise<void> {
  const skipPrompt = args.yes || process.env.YANDEX_TRUST_ASSUME_YES === '1';
  if (!skipPrompt) {
    const ok = await promptYesNo(
      `Mint a single-use high-risk-send override for fingerprint ${args.fingerprint}? [y/N]: `,
    );
    if (!ok) {
      process.stderr.write('Aborted.\n');
      process.exit(1);
    }
  }
  const { token, expiresAtMs } = mintOverrideToken(args.fingerprint);
  const minLeft = Math.round((expiresAtMs - Date.now()) / 60_000);
  process.stdout.write(`override_token: ${token}\n`);
  process.stderr.write(
    `\n[yandex-mail-mcp-trust] Override expires in ${minLeft} min.\n` +
    `[yandex-mail-mcp-trust] Paste the token when the MCP elicit prompt asks for it,\n` +
    `[yandex-mail-mcp-trust] OR set YANDEX_OVERRIDE_TOKEN=<token> in your MCP server env and retry the send.\n`,
  );
  process.exit(0);
}

async function handleTrust(args: { address: string; scope: 'permanent' | 'session'; yes: boolean }): Promise<void> {
  const skipPrompt = args.yes || process.env.YANDEX_TRUST_ASSUME_YES === '1';
  if (!skipPrompt) {
    const ok = await promptYesNo(`Add '${args.address}' to yandex-mail-mcp allowlist? [y/N]: `);
    if (!ok) {
      process.stderr.write('Aborted.\n');
      process.exit(1);
    }
  }
  const trust_token = randomBytes(32).toString('hex');
  const expires_at_ms = Date.now() + TTL_MS;
  const pending = { address: args.address, scope: args.scope, trust_token, expires_at_ms };
  const target = path.join(getStateDir(), 'pending-trust.json');
  atomicWrite(target, JSON.stringify(pending, null, 2), 0o600);

  process.stdout.write(`trust_token: ${trust_token}\n`);
  process.stderr.write(
    `\n[yandex-mail-mcp-trust] Now call:\n` +
    `  yandex_trust_address({ address: "${args.address}", scope: "${args.scope}", trust_token: "${trust_token}" })\n` +
    `[yandex-mail-mcp-trust] TTL: 5 minutes.\n`,
  );
  process.exit(0);
}

// -- --policy show (read-only) ------------------------------

async function handlePolicyShow(): Promise<void> {
  // loadPolicy triggers first-launch write if missing (Phase 1 D5). We print
  // the resolved policy object (NOT the on-disk wrapper -- T-07-10: never
  // surface the .signature field).
  const policy = loadPolicy();
  process.stdout.write(JSON.stringify(policy, null, 2) + '\n');
  process.exit(0);
}

// -- --policy set <key> <value> (D5) ------------------------

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function navigateDotted(
  obj: Record<string, unknown>,
  segments: string[],
): { container: Record<string, unknown>; leafKey: string } | null {
  if (segments.length === 0) return null;
  let cur: Record<string, unknown> = obj;
  for (let i = 0; i < segments.length - 1; i++) {
    const next = cur[segments[i]!];
    if (!isPlainObject(next)) return null;
    cur = next;
  }
  return { container: cur, leafKey: segments[segments.length - 1]! };
}

async function handlePolicySet(args: { key: string; value: string; yes: boolean }): Promise<void> {
  const skipPrompt = args.yes || process.env.YANDEX_TRUST_ASSUME_YES === '1';
  if (!skipPrompt) {
    const ok = await promptYesNo(
      `Apply set '${args.key}=${args.value}' to risk-policy.json? [y/N]: `,
    );
    if (!ok) {
      process.stderr.write('Aborted.\n');
      process.exit(0);
    }
  }

  // Deep-clone current resolved policy.
  const next = JSON.parse(JSON.stringify(loadPolicy())) as RiskPolicy;
  const segments = args.key.split('.');

  // Navigate in parallel on DEFAULT_POLICY to infer the leaf type.
  // DEFAULT_POLICY is the source of truth for "is this path known?".
  const defaultClone = DEFAULT_POLICY as unknown as Record<string, unknown>;
  const defaultNav = navigateDotted(defaultClone, segments);
  if (defaultNav === null
      || !(defaultNav.leafKey in defaultNav.container)) {
    die(`policy set: unknown key '${args.key}'`);
  }
  const existingDefault = defaultNav.container[defaultNav.leafKey];

  const writeNav = navigateDotted(next as unknown as Record<string, unknown>, segments);
  if (writeNav === null) {
    // Should not happen given the default navigation passed -- defensive.
    die(`policy set: unknown key '${args.key}'`);
  }

  // Coerce based on EXISTING default type.
  let coerced: unknown;
  if (typeof existingDefault === 'number') {
    const n = Number(args.value);
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
      die(`policy set: '${args.key}' expects a non-negative integer, got '${args.value}'`);
    }
    coerced = n;
  } else if (typeof existingDefault === 'boolean') {
    if (args.value === 'true') coerced = true;
    else if (args.value === 'false') coerced = false;
    else die(`policy set: '${args.key}' expects 'true' or 'false', got '${args.value}'`);
  } else if (typeof existingDefault === 'string' || Array.isArray(existingDefault)) {
    die(`policy set: '${args.key}' is a ${Array.isArray(existingDefault) ? 'list' : 'string'}; use --policy edit`);
  } else {
    die(`policy set: '${args.key}' is a nested object; use --policy edit`);
  }

  writeNav.container[writeNav.leafKey] = coerced;

  // Validate the WHOLE clone.
  const parsed = RiskPolicySchema.safeParse(next);
  if (!parsed.success) {
    process.stderr.write('policy set: schema validation failed:\n');
    for (const issue of parsed.error.issues) {
      process.stderr.write('  ' + issue.path.join('.') + ': ' + issue.message + '\n');
    }
    process.exit(2);
  }

  writePolicy(parsed.data);

  process.stdout.write(`policy updated: ${args.key} = ${JSON.stringify(coerced)}\n`);
  process.stderr.write('Restart MCP server to apply (policy is load-once per session).\n');

  auditLog({
    action: 'policy_set',
    status: 'success',
    level: 'info',
    ts: new Date().toISOString(),
    reason: 'key=' + args.key,
  });
  await exitAfterAudit(0);
}

// -- --policy reset (D6) ------------------------------------

async function handlePolicyReset(args: { yes: boolean }): Promise<void> {
  const skipPrompt = args.yes || process.env.YANDEX_TRUST_ASSUME_YES === '1';
  if (!skipPrompt) {
    const ok = await promptYesNo('Reset risk-policy.json to defaults? [y/N]: ');
    if (!ok) {
      process.stderr.write('Aborted.\n');
      process.exit(0);
    }
  }
  writePolicy(DEFAULT_POLICY);
  process.stdout.write('policy reset to defaults.\n');
  process.stderr.write('Restart MCP server to apply (policy is load-once per session).\n');
  auditLog({
    action: 'policy_reset',
    status: 'success',
    level: 'info',
    ts: new Date().toISOString(),
  });
  await exitAfterAudit(0);
}

// -- --policy edit (D7 + Rev-2 B2) --------------------------

function printEditHelpBlock(): void {
  process.stdout.write(
    '--policy edit requires $EDITOR. Set it (e.g. EDITOR=notepad / vi) and re-run,\n' +
    'or edit the file manually: ' + getPolicyPath() + '\n' +
    'then re-run --policy edit to re-validate + re-sign. Or use --policy set.\n',
  );
}

async function handlePolicyEdit(_args: { yes: boolean }): Promise<void> {
  // Rev-2 B2: normalise EDITOR -- empty-string identical to undefined on
  // every platform.
  const isWin32 = effectivePlatform() === 'win32';
  const rawEditor = (process.env.EDITOR ?? '').trim();
  const editor: string | null = rawEditor.length > 0
    ? rawEditor
    : (isWin32 ? null : 'vi');

  // TTY guard BEFORE any spawn. Editor spawns with stdio: 'inherit'; a
  // non-TTY stdin would hang vi forever.
  if (!process.stdin.isTTY) {
    process.stderr.write('--policy edit requires an interactive TTY\n');
    process.exit(2);
  }

  if (editor === null) {
    // Win32 + no editor: print the help-block, exit 0. NO audit (no
    // mutation). T-CLI-08a coverage.
    printEditHelpBlock();
    process.exit(0);
  }

  // Spawn editor synchronously.
  const cp = await import('node:child_process');
  const r = cp.spawnSync(editor, [getPolicyPath()], { stdio: 'inherit' });
  if (r.status !== 0) {
    process.stderr.write('editor exited non-zero\n');
    process.exit(1);
  }

  // Re-read + re-validate. Rev-2 M4: tolerate bare-vs-wrapper.
  let raw: string;
  try {
    raw = fs.readFileSync(getPolicyPath(), 'utf8');
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    process.stderr.write(`policy edit: cannot re-read file: ${msg}\n`);
    process.exit(1);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    process.stderr.write(`policy edit: file is not valid JSON: ${msg}\n`);
    process.stderr.write('file NOT re-signed (left as edited)\n');
    process.exit(1);
  }
  const policyObj = (parsed && typeof parsed === 'object' && 'policy' in parsed)
    ? (parsed as { policy: unknown }).policy
    : parsed;
  const v = RiskPolicySchema.safeParse(policyObj);
  if (!v.success) {
    process.stderr.write('policy edit: schema validation failed:\n');
    for (const issue of v.error.issues) {
      process.stderr.write('  ' + issue.path.join('.') + ': ' + issue.message + '\n');
    }
    process.stderr.write('file NOT re-signed (left as edited)\n');
    process.exit(1);
  }

  writePolicy(v.data);
  process.stdout.write('policy saved + re-signed. Restart MCP server to apply.\n');

  auditLog({
    action: 'policy_edit',
    status: 'success',
    level: 'info',
    ts: new Date().toISOString(),
  });
  await exitAfterAudit(0);
}

// -- --recent (D11; read-only) ------------------------------

function formatTier(t: 'low' | 'medium' | 'high' | 'block'): string {
  // Pad tier marker to fixed-width 9 chars including brackets so the row
  // columns line up. e.g. '[low]    ', '[medium] ', '[high]   ', '[block]  '.
  const s = '[' + t + ']';
  return s + ' '.repeat(Math.max(0, 9 - s.length));
}

function formatDomains(doms: string[]): string {
  if (doms.length === 0) return '()';
  if (doms.length <= 3) return '(' + doms.join(',') + ')';
  return '(' + doms.slice(0, 3).join(',') + '+' + (doms.length - 3) + ')';
}

async function handleRecent(args: { risk: boolean; limit: number }): Promise<void> {
  const all = readRecentSends();
  if (all.length === 0) {
    process.stderr.write('no sends recorded yet.\n');
    process.exit(0);
  }
  let filtered = all;
  if (args.risk) {
    filtered = filtered.filter(r => r.risk_tier !== 'low');
  }
  if (filtered.length === 0) {
    process.stderr.write('no matching sends.\n');
    process.exit(0);
  }
  const sliced = filtered.slice(-args.limit);
  for (const r of sliced) {
    const tier = formatTier(r.risk_tier);
    const msgid = r.message_id.slice(0, 32);
    const doms = formatDomains(r.recipients_domains);
    process.stdout.write(
      `${tier} ${r.ts} msgid=${msgid} rcpts=${r.recipients_count} ${doms} score=${r.risk_score}\n`,
    );
  }
  process.exit(0);
}

// -- --list-trust (D12; read-only) --------------------------

async function handleListTrust(args: { staleMs?: number; source?: AllowlistSource }): Promise<void> {
  const all = _listTrusted();
  const now = Date.now();
  let filtered = all;
  if (args.staleMs !== undefined) {
    const staleMs = args.staleMs;
    filtered = filtered.filter(e => e.scope === 'permanent' && (now - e.lastUsed) > staleMs);
  }
  if (args.source !== undefined) {
    const src = args.source;
    filtered = filtered.filter(e => e.source === src);
  }
  if (filtered.length === 0) {
    process.stderr.write('no matching entries.\n');
    process.exit(0);
  }
  // Column-pad for readability. address up to 40, scope 9, source 17.
  function pad(s: string, n: number): string {
    return s.length >= n ? s : s + ' '.repeat(n - s.length);
  }
  for (const e of filtered) {
    const addr = pad(e.address, 40);
    const scope = pad(e.scope, 9);
    const source = pad(e.source, 17);
    const lastUsedIso = Number.isFinite(e.lastUsed)
      ? new Date(e.lastUsed).toISOString()
      : '(unknown)';
    process.stdout.write(
      `${addr} ${scope} ${source} lastUsed=${lastUsedIso} useCount=${e.useCount}\n`,
    );
  }
  process.exit(0);
}

// -- --revoke-trust (D13) ----------------------------------

async function handleRevokeTrust(args: { address: string; yes: boolean }): Promise<void> {
  const skipPrompt = args.yes || process.env.YANDEX_TRUST_ASSUME_YES === '1';
  if (!skipPrompt) {
    const ok = await promptYesNo(`Revoke '${args.address}' from allowlist? [y/N]: `);
    if (!ok) {
      process.stderr.write('Aborted.\n');
      process.exit(0);
    }
  }
  const removed = revokeTrust(args.address);
  if (removed) {
    process.stdout.write(`revoked: ${args.address}\n`);
    // revokeTrust emitted allowlist_revoke audit; drain before exit.
    await exitAfterAudit(0);
  } else {
    process.stderr.write(`no entry for '${args.address}'\n`);
    process.exit(0);
  }
}

// --- main() ---

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  switch (args.mode) {
    case 'help':
      printHelp();
      process.exit(0);
      break;
    case 'trust':
      await handleTrust(args);
      break;
    case 'high-risk-send':
      await handleHighRiskSend(args);
      break;
    case 'policy-show':
      await handlePolicyShow();
      break;
    case 'policy-set':
      await handlePolicySet(args);
      break;
    case 'policy-reset':
      await handlePolicyReset(args);
      break;
    case 'policy-edit':
      await handlePolicyEdit(args);
      break;
    case 'recent':
      await handleRecent(args);
      break;
    case 'list-trust':
      await handleListTrust(args);
      break;
    case 'revoke-trust':
      await handleRevokeTrust(args);
      break;
  }
}

main().catch((e: unknown) => {
  const err = e as Error;
  process.stderr.write(`[yandex-mail-mcp-trust] error: ${err.message ?? String(e)}\n`);
  process.exit(1);
});

