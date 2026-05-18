"use strict";
var import_mcp = require("@modelcontextprotocol/sdk/server/mcp.js");
var import_stdio = require("@modelcontextprotocol/sdk/server/stdio.js");
var import_tools = require("./tools.js");
const server = new import_mcp.McpServer({ name: "yandex-mail-mcp", version: "1.0.0" });
(0, import_tools.registerTools)(server);
const transport = new import_stdio.StdioServerTransport();
server.connect(transport).catch((err) => {
  process.stderr.write(`[yandex-mail] Fatal: ${String(err)}
`);
  process.exit(1);
});
