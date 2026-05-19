import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { registerTools, TOOLS } from './tools.js';
import { getAuthLevel, detectCapabilities, describeAuthLevel, isInvalidAuthLevel } from './auth.js';

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

const transport = new StdioServerTransport();
server.connect(transport).catch(err => {
  process.stderr.write(`[yandex-mail] Fatal: ${String(err)}\n`);
  process.exit(1);
});
