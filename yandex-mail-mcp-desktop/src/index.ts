import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { registerTools } from './tools.js';

const server = new McpServer({ name: 'yandex-mail-mcp', version: '1.0.0' });
registerTools(server);

const transport = new StdioServerTransport();
server.connect(transport).catch(err => {
  process.stderr.write(`[yandex-mail] Fatal: ${String(err)}\n`);
  process.exit(1);
});
