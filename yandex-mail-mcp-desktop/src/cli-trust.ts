// cli-trust.ts — `yandex-mail-mcp-trust` bin entry.
//
// Out-of-band trust-token issuer (D-CLI-IPC option a). Workflow:
//   1. User runs `npx yandex-mail-mcp-trust bob@x.com [--scope=permanent]`.
//   2. We prompt "Add 'bob@x.com' to yandex-mail-mcp allowlist? [y/N]:" via
//      node:readline/promises. Only 'y'/'Y' proceeds.
//   3. Generate trust_token = crypto.randomBytes(32).toString('hex')   (64 hex chars).
//   4. Write {address, scope, trust_token, expires_at_ms} to
//      `${getStateDir()}/pending-trust.json` (mode 0600, atomic, single slot).
//      TTL = 5 minutes.
//   5. Print the token on stdout (one line) so the user can paste it into
//      chat, then a stderr usage hint.
//
// Why a separate process instead of a chat tool: the MCP server is started by
// Claude Desktop and lives only inside that client. An attacker (LLM-crafted
// email content) can call MCP tools but cannot spawn arbitrary processes on
// the user's machine and cannot read this CLI's stdout. The token is bound to
// the user's terminal until the user copy-pastes it.
//
// pending-trust.json is single-slot by design: a second CLI invocation
// overwrites the first. The previous pending becomes orphaned & expires
// harmlessly (≤5min). The matching MCP tool yandex_trust_address deletes the
// file after successful redemption (single-use).
//
// No `any`. ESM `.js` suffix.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { randomBytes } from 'node:crypto';

import { getStateDir } from './state-dir.js';
import { mintOverrideToken } from './override-tokens.js';

type CliArgs =
  | { mode: 'trust'; address: string; scope: 'permanent' | 'session' }
  | { mode: 'high-risk-send'; fingerprint: string };

const TTL_MS = 5 * 60 * 1000;

function parseArgs(argv: string[]): CliArgs {
  // Phase 5 D13: --high-risk-send=<32-hex> is mutually exclusive with the
  // positional address argument and the --scope flag.
  let highRiskFp: string | undefined;
  const otherArgs: string[] = [];
  for (const a of argv) {
    if (a.startsWith('--high-risk-send=')) {
      const v = a.slice('--high-risk-send='.length);
      if (!/^[0-9a-f]{32}$/.test(v)) {
        process.stderr.write(
          `[yandex-mail-mcp-trust] Invalid fingerprint: expected 32 hex characters, got '${v}'\n`,
        );
        process.exit(2);
      }
      highRiskFp = v;
      continue;
    }
    otherArgs.push(a);
  }
  if (highRiskFp !== undefined) {
    if (otherArgs.length > 0) {
      process.stderr.write(
        `[yandex-mail-mcp-trust] --high-risk-send is mutually exclusive with <address> and --scope\n`,
      );
      process.exit(2);
    }
    return { mode: 'high-risk-send', fingerprint: highRiskFp };
  }

  const positional: string[] = [];
  let scope: 'permanent' | 'session' = 'permanent';
  for (const a of otherArgs) {
    if (a.startsWith('--scope=')) {
      const v = a.slice('--scope='.length);
      if (v === 'permanent' || v === 'session') {
        scope = v;
      } else {
        process.stderr.write(
          `[yandex-mail-mcp-trust] Invalid scope '${v}'. Use --scope=permanent | --scope=session.\n` +
          `[yandex-mail-mcp-trust] (scope='auto' is reserved for the in_reply_to flow and not allowed from CLI.)\n`,
        );
        process.exit(2);
      }
      continue;
    }
    if (a.startsWith('-')) {
      process.stderr.write(`[yandex-mail-mcp-trust] Unknown flag: ${a}\n`);
      process.exit(2);
    }
    positional.push(a);
  }
  if (positional.length !== 1) {
    process.stderr.write(
      '[yandex-mail-mcp-trust] Usage: yandex-mail-mcp-trust <address> [--scope=permanent|session]\n' +
      '       yandex-mail-mcp-trust --high-risk-send=<32-hex-fingerprint>\n',
    );
    process.exit(2);
  }
  const address = positional[0] as string;
  // Cheap syntactic check — RFC 5322 is intentionally not parsed here.
  // Same as the IMAP envelope: addresses are treated as opaque tokens.
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(address)) {
    process.stderr.write(`[yandex-mail-mcp-trust] Invalid address: '${address}'\n`);
    process.exit(2);
  }
  return { mode: 'trust', address: address.toLowerCase(), scope };
}

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
  // This is intended for tests; documented as "do not set in interactive use".
  if (process.env.YANDEX_TRUST_ASSUME_YES === '1') return true;
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const ans = (await rl.question(question)).trim();
    return ans === 'y' || ans === 'Y';
  } finally {
    rl.close();
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.mode === 'high-risk-send') {
    const ok = await promptYesNo(
      `Mint a single-use high-risk-send override for fingerprint ${args.fingerprint}? [y/N]: `,
    );
    if (!ok) {
      process.stderr.write('Aborted.\n');
      process.exit(1);
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

  const { address, scope } = args;
  const ok = await promptYesNo(`Add '${address}' to yandex-mail-mcp allowlist? [y/N]: `);
  if (!ok) {
    process.stderr.write('Aborted.\n');
    process.exit(1);
  }

  const trust_token = randomBytes(32).toString('hex');
  const expires_at_ms = Date.now() + TTL_MS;
  const pending = { address, scope, trust_token, expires_at_ms };
  const target = path.join(getStateDir(), 'pending-trust.json');
  atomicWrite(target, JSON.stringify(pending, null, 2), 0o600);

  // Token on stdout (machine-friendly). Hint on stderr (human-friendly).
  process.stdout.write(`trust_token: ${trust_token}\n`);
  process.stderr.write(
    `\n[yandex-mail-mcp-trust] Now call:\n` +
    `  yandex_trust_address({ address: "${address}", scope: "${scope}", trust_token: "${trust_token}" })\n` +
    `[yandex-mail-mcp-trust] TTL: 5 minutes.\n`,
  );
  process.exit(0);
}

main().catch((e: unknown) => {
  const err = e as Error;
  process.stderr.write(`[yandex-mail-mcp-trust] error: ${err.message ?? String(e)}\n`);
  process.exit(1);
});
