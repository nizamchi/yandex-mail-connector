import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { registerTools, TOOLS } from './tools.js';
import { getAuthLevel, detectCapabilities, describeAuthLevel, isInvalidAuthLevel } from './auth.js';
import * as allowlist from './allowlist.js';
import * as policy from './policy.js';
import * as imap from './imap.js';
import { auditLog } from './audit.js';
import { resolveProtectedFolders } from './guards.js';
import { runHealthCheck } from './check-config.js';

// `--check` mode (v2.1.4): run a non-authenticating health check (token shape,
// state dir, allowlist signature, policy JSON, IMAP/SMTP TLS reachability) and
// exit. Must come BEFORE any module-level side effects below
// (allowlist.verifySignature can process.exit(1) on tamper; policy.loadPolicy
// can recoverFatal+exit). The check itself uses the same modules but in a
// non-fatal mode.
if (process.argv.includes('--check') || process.argv.includes('--check-config')) {
  runHealthCheck()
    .then(code => process.exit(code))
    .catch(err => {
      process.stderr.write(`[yandex-mail] health check fatal: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(2);
    });
} else {
  startServer();
}

function startServer(): void {

// Resolve auth level ONCE at startup. After this point the value never changes
// for the life of the process -- re-reading env mid-run would be a TOCTOU
// vulnerability (the LLM could trick the user into changing env between calls).
const authLevel = getAuthLevel();
const capabilities = detectCapabilities(authLevel);

// Startup banner -- stderr so we don't corrupt the stdio MCP frame on stdout.
// Only the "implicit L0" case (no env set at all) prints the verbose warning.
// If the user explicitly set YANDEX_AUTH_LEVEL=readonly that's a deliberate
// choice -- we acknowledge with the standard info line.
if (isInvalidAuthLevel()) {
  process.stderr.write(`[yandex-mail] WARNING: YANDEX_AUTH_LEVEL="${process.env.YANDEX_AUTH_LEVEL}" is not recognised -- falling back to READ-ONLY (L0).\n`);
  process.stderr.write('[yandex-mail] Valid values: readonly | safe | destructive | auto (or 0..3).\n');
} else if (authLevel === 0 && process.env.YANDEX_AUTH_LEVEL === undefined) {
  process.stderr.write('[yandex-mail] AUTH_LEVEL not set -- running in READ-ONLY mode (L0).\n');
  process.stderr.write('[yandex-mail] To enable writes: set YANDEX_AUTH_LEVEL=safe | destructive | auto.\n');
  process.stderr.write('[yandex-mail] See: AUTH-DESIGN.md §3 for level semantics.\n');
} else {
  const visible = TOOLS.filter(t => authLevel >= t.requires.authLevel).length;
  process.stderr.write(`[yandex-mail] AUTH_LEVEL=${describeAuthLevel(authLevel)} -- ${visible} tools registered.\n`);
}

// ── Phase 5: allowlist signature gate ─────────────────────────────────
// Runs BEFORE anything else (server.connect, token-load, bootstrap). Fail-closed.
// On bad signature we print a multi-line stderr recovery block (per plan-check
// W-1 fix: THREE recovery paths -- delete allowlist vs delete secret+allowlist
// vs manual resign).
if (!allowlist.verifySignature()) {
  const allowlistPath = allowlist.getAllowlistPath();
  const secretPath = allowlist.getSecretPath();
  process.stderr.write(
    `[yandex-mail] FATAL: allowlist signature invalid.\n` +
    `[yandex-mail] The file ${allowlistPath} or its signing key ${secretPath} was modified outside of the connector.\n` +
    `[yandex-mail]\n` +
    `[yandex-mail] Recovery option A (lost trust, fast -- ~30s IMAP re-bootstrap):\n` +
    `[yandex-mail]   delete ${allowlistPath} and restart. A fresh bootstrap will re-read last 500 sent\n` +
    `[yandex-mail]   addresses from Yandex Sent folder.\n` +
    `[yandex-mail]\n` +
    `[yandex-mail] Recovery option B (catastrophic -- secret.bin compromised or lost):\n` +
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

// ── Phase 1: policy loader + FATAL gate ─────────────────────────────────
// Runs AFTER allowlist.verifySignature() (which gates the allowlist HMAC
// chain and may bootstrap secret.bin if it had to call loadSecret) and
// BEFORE allowlist.sweepPendingTrust(). Order rationale: allowlist verify
// gates integrity FIRST so a tampered allowlist crashes the process before
// policy starts touching its file. Both modules share secret.bin via D1
// domain prefix; whichever calls loadSecret first bootstraps it. On policy
// load failure, policy.loadPolicy() invokes recoverFatal() which prints the
// 3-step recovery banner and calls process.exit(1). No try/catch here --
// FATAL is meant to crash.
policy.loadPolicy();

// Plan-check W-3 fix: orphan-sweep pending-trust.json on startup, BEFORE
// server.connect. If a CLI run wrote a pending token and the user never
// invoked the matching MCP tool (or restarted in between), prune it once
// the TTL has lapsed. Quiet -- only audits if a sweep happened.
allowlist.sweepPendingTrust();

// `instructions` field (MCP spec, v2.1.3): hint to clients with Tool Search
// (Claude Code in particular) about WHEN to surface this server's tools. Without
// this, Claude Code defers MCP tools and may not load them until the user
// explicitly asks for "list folders" etc. With instructions present, Tool Search
// indexes the server description and surfaces tools when the user mentions
// email-related intent. Plain prose, no markup, kept short — clients summarise
// it to the model. See: docs.anthropic.com on Claude Code MCP Tool Search.
const SERVER_INSTRUCTIONS = [
  'Yandex Mail connector — read, search, organise, and (with explicit auth)',
  'send email from a Yandex account via IMAP+SMTP. Use this server when the',
  'user mentions Yandex mail, Яндекс почта, inbox, sent, drafts, spam,',
  'folders, attachments, replies, forwarding, or any task involving',
  '@yandex.ru / @ya.ru / @yandex.com mailboxes. Read-only by default;',
  'destructive operations require server-issued one-time codes.',
].join(' ');

const server = new McpServer(
  { name: 'yandex-mail-mcp', version: '2.5.0' },
  { instructions: SERVER_INSTRUCTIONS },
);

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

// The SDK's elicitInput requires a very narrow requestedSchema generic; our
// ElicitParams is structurally compatible at runtime but wider statically.
// Cast the argument to the SDK's own parameter type (consistent with the
// existing result cast) rather than weakening our ServerContext.elicit type.
serverContext.elicit = (params) =>
  server.server.elicitInput(params as Parameters<typeof server.server.elicitInput>[0]) as Promise<{ action: 'accept' | 'cancel' | 'decline'; content?: Record<string, unknown> }>;

async function main(): Promise<void> {
  // ── Phase 5: first-L1+-start bootstrap ───────────────────────────────
  // If we are at L1+ AND the allowlist has never been bootstrapped (no
  // bootstrap_completed_at) we mine the Sent folder ONCE for the initial
  // trust set. Failures here are stderr-logged but NOT fatal -- bootstrap
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

  // Phase 6: server_start record -- emitted AFTER bootstrap block AND BEFORE
  // server.connect. Documents the resolved auth level, capability set, and
  // bootstrap outcome. No secrets in reason -- only enum-like state strings.
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

  // Phase 7: resolve protected-folder set ONCE at startup. Combines literal
  // defaults (INBOX/Sent/Drafts/Important) with cyrillic-aware special-use
  // IMAP paths from getSpecialFolders. May block on IMAP for ~1-3s; cold-start
  // latency cost is accepted because lazy resolution on first move/delete
  // would race against the LLM's first action. Always resolved regardless of
  // authLevel (cheap insurance; only the move/delete gates actually consume
  // the set). resolveProtectedFolders catches IMAP failure internally and
  // returns literal defaults -- this outer try is paranoia for a thrown
  // synchronous error before that catch runs. On total failure we log an
  // EXPLICIT empty-set warning so the operator notices destructive ops are
  // unprotected this session.
  let protectedFolders: ReadonlySet<string>;
  try {
    protectedFolders = await resolveProtectedFolders();
  } catch (e) {
    process.stderr.write('[yandex-mail] resolveProtectedFolders fatal: ' + (e instanceof Error ? e.message : String(e)) + '\n');
    protectedFolders = new Set<string>();
    process.stderr.write('[yandex-mail] WARNING: protected-folder set is EMPTY due to startup error. Destructive operations are NOT folder-gated this session. Restart to retry.\n');
  }

  // Register tools AFTER protected-folder resolution -- ctx carries the set
  // into move_email / delete_email handlers.
  registerTools(server, { authLevel, capabilities, serverContext, protectedFolders });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(err => {
  process.stderr.write(`[yandex-mail] Fatal: ${String(err)}\n`);
  process.exit(1);
});

} // close startServer()
