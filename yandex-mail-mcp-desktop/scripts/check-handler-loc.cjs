#!/usr/bin/env node
// check-handler-loc.cjs -- Phase 6 (D4 + H-4) handler LOC enforcement.
//
// Enforces: the yandex_send_email handler body in src/tools.ts is at most
// 60 significant lines. Significant lines = non-blank, non-pure-comment.
//
// State machine (H-4 fix): counts braces in 'code' state only. Ignores
// braces inside:
//   - line comments (// ... \n)
//   - block comments (/* ... */)
//   - single-quoted strings ('...')
//   - double-quoted strings ("...")
//   - template literals (`...`, with ${...} nesting tracked)
//
// The state machine is the verified handler-body boundary detector --
// naive brace counting would miss the closing } of an object literal
// inside a string and undercount, or hit a } inside a template literal
// and overcount.
//
// Exits 0 on pass (<=60), 3 on overrun (>60), 2 on parse failure.
// Prints `handler_loc=N` to stdout on success.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const HANDLER_LOC_CAP = 60;
const TOOLS_PATH = path.join(__dirname, '..', 'src', 'tools.ts');

let src;
try {
  src = fs.readFileSync(TOOLS_PATH, 'utf8');
} catch (e) {
  console.error('check-handler-loc: cannot read ' + TOOLS_PATH + ': ' + (e && e.message ? e.message : e));
  process.exit(2);
}

// Locate the yandex_send_email tool entry (accept either single or double quotes).
let nameIdx = src.indexOf("name: 'yandex_send_email'");
if (nameIdx === -1) nameIdx = src.indexOf('name: "yandex_send_email"');
if (nameIdx === -1) {
  console.error('check-handler-loc: cannot find yandex_send_email tool entry');
  process.exit(2);
}

const handlerKey = 'handler: async (params, ctx) => {';
const handlerOpen = src.indexOf(handlerKey, nameIdx);
if (handlerOpen === -1) {
  console.error('check-handler-loc: cannot find handler body open after yandex_send_email');
  process.exit(2);
}
const bodyStart = handlerOpen + handlerKey.length;

// State-machine scan from bodyStart, tracking { } depth in code state only.
let depth = 1; // inside the opening {
let i = bodyStart;
let state = 'code'; // 'code' | 'line-comment' | 'block-comment' | 'sq-string' | 'dq-string' | 'template'
let templateDepth = 0;
let bodyEnd = -1;

while (i < src.length) {
  const c = src[i];
  const n = i + 1 < src.length ? src[i + 1] : '';
  if (state === 'code') {
    if (c === '/' && n === '/') { state = 'line-comment';  i += 2; continue; }
    if (c === '/' && n === '*') { state = 'block-comment'; i += 2; continue; }
    if (c === "'")              { state = 'sq-string';     i++;    continue; }
    if (c === '"')              { state = 'dq-string';     i++;    continue; }
    if (c === '`')              { state = 'template';      i++;    continue; }
    if (c === '{')              { depth++;                  i++;    continue; }
    if (c === '}') {
      depth--;
      if (depth === 0) { bodyEnd = i; break; }
      i++; continue;
    }
    i++; continue;
  }
  if (state === 'line-comment') {
    if (c === '\n') state = 'code';
    i++; continue;
  }
  if (state === 'block-comment') {
    if (c === '*' && n === '/') { state = 'code'; i += 2; continue; }
    i++; continue;
  }
  if (state === 'sq-string') {
    if (c === '\\') { i += 2; continue; }
    if (c === "'")  { state = 'code'; i++; continue; }
    i++; continue;
  }
  if (state === 'dq-string') {
    if (c === '\\') { i += 2; continue; }
    if (c === '"')  { state = 'code'; i++; continue; }
    i++; continue;
  }
  // state === 'template'
  if (c === '\\') { i += 2; continue; }
  if (c === '`' && templateDepth === 0) { state = 'code'; i++; continue; }
  if (c === '$' && n === '{')           { templateDepth++; i += 2; continue; }
  if (c === '}' && templateDepth > 0)   { templateDepth--; i++; continue; }
  i++;
}

if (bodyEnd === -1) {
  console.error('check-handler-loc: handler body did not close (unbalanced braces?)');
  process.exit(2);
}

const body = src.slice(bodyStart, bodyEnd);
const lines = body.split('\n');
let inBlockCommentLines = false;
let significant = 0;
for (const lineRaw of lines) {
  const t = lineRaw.trim();
  if (t.length === 0) continue;
  // Line-spanning block-comment detection (crude, sufficient for typical
  // handler comments: a /* on one line, */ on a later line).
  if (inBlockCommentLines) {
    if (t.indexOf('*/') !== -1) inBlockCommentLines = false;
    continue;
  }
  if (t.startsWith('/*')) {
    if (t.indexOf('*/') === -1) {
      inBlockCommentLines = true;
      continue;
    }
    // single-line /* ... */
    if (t.startsWith('/*') && t.endsWith('*/')) continue;
  }
  if (t.startsWith('//')) continue;
  if (t === '*/' || t.startsWith('* ')) continue;
  significant++;
}

console.log('handler_loc=' + significant);
process.exit(significant <= HANDLER_LOC_CAP ? 0 : 3);

//
// Self-test fixtures (not executed; documentation):
//
//   fixture 1 -- simple body
//   handler: async (params, ctx) => {
//     const x = 1;
//     return x;
//   }
//   expected: handler_loc=2
//
//   fixture 2 -- braces inside strings/templates
//   handler: async (params, ctx) => {
//     const a = "{ not a brace }";
//     const b = `hello ${name}, x={5}`;
//     const c = "/" + "/";   // looks like a comment-start
//     return a + b + c;
//   }
//   expected: handler_loc=4 (state machine ignores braces in literals)
//
//   fixture 3 -- block comment with } inside
//   handler: async (params, ctx) => {
//     // close-brace } inside a comment must not pop depth
//     return 0;
//   }
//   expected: handler_loc=1 (comment line excluded; only `return 0;` counts)
