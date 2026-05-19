import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { registerTools, TOOLS } from './tools.js';
import { getAuthLevel, detectCapabilities, describeAuthLevel, isInvalidAuthLevel } from './auth.js';
import * as allowlist from './allowlist.js';
import * as imap from './imap.js';
import { auditLog } from './audit.js';

// Resolve auth level ONCE at startup. After this point the value never changes
// for the life of the process — re-reading env mid-run would be a TOCTOU
// vulnerability (the LLM could trick the user into changing env between calls).
const authLevel = getAuthLevel();
const capabilities = detectCapabilities(authLevel);

// Startup banner — stderr so we don't corrupt the stdio MCP frame on stdout.
// Only the "implicit L0" case (no env set at all) prints the verbose warning.
// If the user explicitly set YANDEX_AUTH_LEVEL=readonly that's a deliberate
// choice — we acknowledge with the standard info line.
if (isInvalidAuthLevel()) {
  process.stderr.write(`[yandex-mail] WARNING: YANDEX_AUTH_LEVEL="${process.env.YANDEX_AUTH_LEVEL}" is not recognised — falling back to READ-ONLY (L0).\n`);
  process.stderr.write('[yandex-mail] Valid values: readonly | safe | destructive | auto (or 0..3).\n');
} else if (authLevel === 0 && process.env.YANDEX_AUTH_LEVEL === undefined) {
  process.stderr.write('[yandex-mail] AUTH_LEVEL not set — running in READ-ONLY mode (L0).\n');
  process.stderr.write('[yandex-mail] To enable writes: set YANDEX_AUTH_LEVEL=safe | destructive | auto.\n');
  process.stderr.write('[yandex-mail] See: AUTH-DESIGN.md §3 for level semantics.\n');
} else {
  const visible = TOOLS.filter(t => authLevel >= t.requires.authLevel).length;
  process.stderr.write(`[yandex-mail] AUTH_LEVEL=${describeAuthLevel(authLevel)} — ${visible} tools registered.\n`);
}

// ── Phase 5: allowlist signature gate ─────────────────────────────────
// Runs BEFORE anything else (server.connect, token-load, bootstrap). Fail-closed.
// On bad signature we print a multi-line stderr recovery block (per plan-check
// W-1 fix: THREE recovery paths — delete allowlist vs delete secret+allowlist
// vs manual resign).
if (!allowlist.verifySignature()) {
  const allowlistPath = allowlist.getAllowlistPath();
  const secretPath = allowlist.getSecretPath();
  process.stderr.write(
    `[yandex-mail] FATAL: allowlist signature invalid.\n` +
    `[yandex-mail] The file ${allowlistPath} or its signing key ${secretPath} was modified outside of the connector.\n` +
    `[yandex-mail]\n` +
    `[yandex-mail] Recovery option A (lost trust, fast — ~30s IMAP re-bootstrap):\n` +
    `[yandex-mail]   delete ${allowlistPath} and restart. A fresh bootstrap will re-read last 500 sent\n` +
    `[yandex-mail]   addresses from Yandex Sent folder.\n` +
    `[yandex-mail]\n` +
    `[yandex-mail] Recovery option B (catastrophic — secret.bin compromised or lost):\n` +
    `[yandex-mail]   delete BOTH ${allowlistPath} AND ${secretPath}, then restart. A new secret is\n` +
    `[yandex-mail]   generated and every previously-trusted address is wiped. Pending-trust tokens\n` +
    `[yandex-mail]   issued under the old secret become permanently invalid.\n` +
    `[yandex-mail]\n` +
    `[yandex-mail] Recovery option C (manual): if you possess the original secret, call resign()\n` +
    `[yandex-mail]   programmatically to re-sign the current allowlist.json against it.\n` +
    `[yandex-mail]\n` +
    `[yandex-mail] See: AUTH-DESIGN.md §9.5 for the security model.\n`,
  );
  process.exit(1);
}

// Plan-check W-3 fix: orphan-sweep pending-trust.json on startup, BEFORE
// server.connect. If a CLI run wrote a pending token and the user never
// invoked the matching MCP tool (or restarted in between), prune it once
// the TTL has lapsed. Quiet — only audits if a sweep happened.
allowlist.sweepPendingTrust();

const server = new McpServer({ name: 'yandex-mail-mcp', version: '2.0.0' });

// Mutable bag shared with every tool handler via ctx.serverContext. canElicit
// starts false and is updated by the oninitialized hook below; elicit dispatches
// through the underlying SDK Server without leaking the McpServer reference
// into handler code.
const serverContext: {
  canElicit: boolean;
  elicit?: (params: { message: string; requestedSchema: { type: 'object'; properties: Record<string, { type: 'boolean' | 'string' | 'number'; title?: string; description?: string }>; required?: string[] } }) => Promise<{ action: 'accept' | 'cancel' | 'decline'; content?: Record<string, unknown> }>;
} = { canElicit: false };

// The MCP SDK dispatches `oninitialized` ASYNCHRONOUSLY when the client sends
// the `notifications/initialized` notification (see SDK server/index.js:53).
// By that point `_clientCapabilities` is populated (index.js:272), so
// `getClientCapabilities()` returns the resolved value. The MCP protocol
// guarantees `notifications/initialized` arrives before any `tools/call`, so
// handlers reading serverContext.canElicit lazily at call-time always see the
// resolved value. Must be assigned BEFORE server.connect(transport).
server.server.oninitialized = (): void => {
  const caps = server.server.getClientCapabilities();
  serverContext.canElicit = caps?.elicitation !== undefined;
  process.stderr.write(`[yandex-mail] client capabilities: elicitation=${serverContext.canElicit}\n`);
};

serverContext.elicit = (params) => server.server.elicitInput(params) as Promise<{ action: 'accept' | 'cancel' | 'decline'; content?: Record<string, unknown> }>;

registerTools(server, { authLevel, capabilities, serverContext });

async function main(): Promise<void> {
  // ── Phase 5: first-L1+-start bootstrap ───────────────────────────────
  // If we are at L1+ AND the allowlist has never been bootstrapped (no
  // bootstrap_completed_at) we mine the Sent folder ONCE for the initial
  // trust set. Failures here are stderr-logged but NOT fatal — bootstrap
  // can retry on the next start. The verify gate above already ran.
  // bootstrapState is reported in the Phase 6 server_start audit record.
  // Possible values: 'n/a_L0' | 'already_bootstrapped' | 'bootstrapped' | 'deferred'.
  let bootstrapState: string = 'n/a_L0';
  if (authLevel >= 1) {
    const file = allowlist.loadAllowlist();
    if (file.bootstrap_completed_at !== null) {
      bootstrapState = 'already_bootstrapped';
    } else {
      try {
        const limit = Number(process.env.YANDEX_ALLOWLIST_BOOTSTRAP_LIMIT ?? 500);
        const folders = await imap.getSpecialFolders();
        const added = await imap.getConnectionManager().withClient(async c => {
          return allowlist.bootstrap(c, limit, folders.sent);
        });
        process.stderr.write(`[yandex-mail] allowlist bootstrap: ${added} addresses from Sent.\n`);
        bootstrapState = 'bootstrapped';
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        process.stderr.write(`[yandex-mail] allowlist bootstrap deferred (will retry on next start): ${msg}\n`);
        bootstrapState = 'deferred';
      }
    }
  }

  // Phase 6: server_start record — emitted AFTER bootstrap block AND BEFORE
  // server.connect. Documents the resolved auth level, capability set, and
  // bootstrap outcome. No secrets in reason — only enum-like state strings.
  auditLog({
    action: 'server_start',
    status: 'success',
    level: 'info',
    ts: new Date().toISOString(),
    reason:
      'authLevel=' + authLevel +
      ',capabilities=' + Array.from(capabilities).join(',') +
      ',bootstrap_state=' + bootstrapState,
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(err => {
  process.stderr.write(`[yandex-mail] Fatal: ${String(err)}\n`);
  process.exit(1);
});
