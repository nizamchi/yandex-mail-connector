import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { registerTools, TOOLS } from './tools.js';
import { getAuthLevel, detectCapabilities, describeAuthLevel } from './auth.js';

// Resolve auth level ONCE at startup. After this point the value never changes
// for the life of the process — re-reading env mid-run would be a TOCTOU
// vulnerability (the LLM could trick the user into changing env between calls).
const authLevel = getAuthLevel();
const capabilities = detectCapabilities(authLevel);

// Startup banner — stderr so we don't corrupt the stdio MCP frame on stdout.
// Only the "implicit L0" case (no env set at all) prints the verbose warning.
// If the user explicitly set YANDEX_AUTH_LEVEL=readonly that's a deliberate
// choice — we acknowledge with the standard info line.
if (authLevel === 0 && process.env.YANDEX_AUTH_LEVEL === undefined) {
  process.stderr.write('[yandex-mail] AUTH_LEVEL not set — running in READ-ONLY mode (L0).\n');
  process.stderr.write('[yandex-mail] To enable writes: set YANDEX_AUTH_LEVEL=safe | destructive | auto.\n');
  process.stderr.write('[yandex-mail] See: AUTH-DESIGN.md §3 for level semantics.\n');
} else {
  const visible = TOOLS.filter(t => authLevel >= t.requires.authLevel).length;
  process.stderr.write(`[yandex-mail] AUTH_LEVEL=${describeAuthLevel(authLevel)} — ${visible} tools registered.\n`);
}

const server = new McpServer({ name: 'yandex-mail-mcp', version: '2.0.0' });
registerTools(server, { authLevel, capabilities });

const transport = new StdioServerTransport();
server.connect(transport).catch(err => {
  process.stderr.write(`[yandex-mail] Fatal: ${String(err)}\n`);
  process.exit(1);
});
