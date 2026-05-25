#!/usr/bin/env node
// Generates docs/tools.html from src/tools.ts.
// Parses the TOOLS[] array with regex -- no tsc, no imports, no bundle tricks.
// Run: node scripts/gen-tools-docs.js  (or npm run docs from repo root)

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dir, '..');
const src  = readFileSync(resolve(root, 'yandex-mail-mcp-desktop/src/tools.ts'), 'utf8');

// ── Extract version ─────────────────────────────────────────────────────────
const verMatch = src.match(/server_version:\s*'([\d.]+)'/);
const version = verMatch?.[1] ?? '?.?.?';

// ── Extract tools ────────────────────────────────────────────────────────────
// Each tool block starts with `name: 'yandex_`. We split on that and parse
// each chunk for the fields we need.
const chunks = src.split(/(?=\{\s*\n\s*name:\s*'yandex_)/);

const tools = [];
for (const chunk of chunks) {
  const nameM = chunk.match(/name:\s*'(yandex_[^']+)'/);
  if (!nameM) continue;

  const titleM = chunk.match(/title:\s*'([^']+)'/);

  // description: backtick string, grab first non-empty line (skip НЕ-rules)
  const descM = chunk.match(/description:\s*`([\s\S]*?)`\s*,\s*\n\s*(?:inputSchema|annotations)/);
  let descFirst = '';
  if (descM) {
    const lines = descM[1].split('\n').map(l => l.trim()).filter(Boolean);
    // First line that is NOT a НЕ-rule or an Args: line
    descFirst = lines.find(l => !l.startsWith('НЕ') && !l.startsWith('Args:') && !l.startsWith('ВСЕГДА'))
      ?? lines[0]
      ?? '';
    // Trim to 90 chars
    if (descFirst.length > 90) descFirst = descFirst.slice(0, 87) + '…';
  }

  const authM = chunk.match(/requires:\s*\{[^}]*authLevel:\s*(\d)/);
  const authLevel = authM ? parseInt(authM[1], 10) : 0;

  // readOnlyHint
  const readOnly = /readOnlyHint:\s*true/.test(chunk);

  tools.push({ name: nameM[1], title: titleM?.[1] ?? '', desc: descFirst, authLevel, readOnly });
}

// ── Build HTML ───────────────────────────────────────────────────────────────
const authLabel = { 0: 'L0', 1: 'L1', 2: 'L2', 3: 'L3' };
const authColor = { 0: '#22c55e', 1: '#f59e0b', 2: '#ef4444', 3: '#8b5cf6' };
const authTitle = {
  0: 'Только чтение — доступно по умолчанию',
  1: 'Требует YANDEX_AUTH_LEVEL=safe',
  2: 'Требует YANDEX_AUTH_LEVEL=full',
  3: 'Максимальный уровень',
};

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const rows = tools.map(t => `
    <tr>
      <td><code>${esc(t.name)}</code></td>
      <td>${esc(t.title)}</td>
      <td><span class="badge l${t.authLevel}" title="${esc(authTitle[t.authLevel] ?? '')}">${authLabel[t.authLevel] ?? t.authLevel}</span></td>
      <td class="rw">${t.readOnly ? '✓' : '✗'}</td>
      <td class="desc">${esc(t.desc)}</td>
    </tr>`).join('');

const byLevel = [0, 1, 2, 3].map(l => {
  const n = tools.filter(t => t.authLevel === l).length;
  return n ? `<b>${authLabel[l]}</b> ${n}` : '';
}).filter(Boolean).join(' &nbsp;·&nbsp; ');

const html = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Yandex Mail MCP — инструменты v${version}</title>
<style>
  :root { --bg:#0f172a; --surface:#1e293b; --border:#334155; --text:#e2e8f0; --muted:#94a3b8; --green:#22c55e; --amber:#f59e0b; --red:#ef4444; --purple:#8b5cf6; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:'Inter',system-ui,sans-serif; font-size:14px; padding:32px 24px; }
  h1 { font-size:1.4rem; font-weight:700; margin-bottom:4px; }
  .meta { color:var(--muted); font-size:12px; margin-bottom:24px; }
  .meta b { color:var(--text); }
  table { width:100%; border-collapse:collapse; background:var(--surface); border-radius:10px; overflow:hidden; }
  thead { background:#0f172a; }
  th { padding:10px 14px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); font-weight:600; }
  td { padding:10px 14px; border-top:1px solid var(--border); vertical-align:top; }
  tr:hover td { background:rgba(255,255,255,.03); }
  code { font-family:'JetBrains Mono','Fira Mono',monospace; font-size:12px; color:#7dd3fc; }
  .badge { display:inline-block; padding:2px 7px; border-radius:4px; font-size:11px; font-weight:700; color:#fff; cursor:default; }
  .l0 { background:var(--green); }
  .l1 { background:var(--amber); color:#000; }
  .l2 { background:var(--red); }
  .l3 { background:var(--purple); }
  .rw { text-align:center; color:var(--muted); }
  .desc { color:var(--muted); font-size:13px; max-width:420px; }
  .legend { margin-top:20px; font-size:12px; color:var(--muted); display:flex; gap:16px; flex-wrap:wrap; }
  .legend span { display:flex; align-items:center; gap:6px; }
  footer { margin-top:16px; font-size:11px; color:var(--muted); }
</style>
</head>
<body>
<h1>Yandex Mail MCP — инструменты</h1>
<div class="meta">Версия <b>v${version}</b> &nbsp;·&nbsp; ${tools.length} инструментов &nbsp;·&nbsp; ${byLevel} &nbsp;·&nbsp; <span title="Сгенерировано из src/tools.ts">авто-генерация</span></div>
<table>
  <thead>
    <tr>
      <th>Инструмент</th>
      <th>Название</th>
      <th>Auth</th>
      <th title="Только чтение (readOnlyHint)">RO</th>
      <th>Описание</th>
    </tr>
  </thead>
  <tbody>${rows}
  </tbody>
</table>
<div class="legend">
  <span><span class="badge l0">L0</span> По умолчанию (только чтение)</span>
  <span><span class="badge l1">L1</span> YANDEX_AUTH_LEVEL=safe</span>
  <span><span class="badge l2">L2</span> YANDEX_AUTH_LEVEL=full</span>
</div>
<footer>Сгенерировано из <code>src/tools.ts</code> · <code>npm run docs</code></footer>
</body>
</html>`;

mkdirSync(resolve(root, 'docs'), { recursive: true });
const out = resolve(root, 'docs/tools.html');
writeFileSync(out, html, 'utf8');
console.log(`docs/tools.html — ${tools.length} инструментов, версия v${version}`);
