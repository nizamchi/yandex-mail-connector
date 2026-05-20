#!/usr/bin/env node
// Mirror-discipline gate for canonicalStringify (W-2 from Phase 1 plan-check).
// Asserts the function body is byte-identical between src/allowlist.ts and
// src/policy.ts. Phase 6 may extract to src/canonical-json.ts; until then,
// drift opens a cross-domain HMAC failure window (allowlist + policy share
// secret.bin; only D1 'policy:' prefix isolates message bodies, NOT
// canonicalization semantics).
//
// Closes H-1 from 01-01-REVIEW.md.

'use strict';

const fs = require('fs');
const path = require('path');

const FN_RE = /function canonicalStringify[\s\S]*?\n\}/m;

function extract(filePath) {
  const src = fs.readFileSync(filePath, 'utf-8');
  const m = src.match(FN_RE);
  if (!m) {
    process.stderr.write(
      `mirror gate: failed to extract canonicalStringify from ${filePath}\n`
    );
    process.exit(1);
  }
  return m[0];
}

const root = path.resolve(__dirname, '..');
const aPath = path.join(root, 'src', 'allowlist.ts');
const pPath = path.join(root, 'src', 'policy.ts');

const a = extract(aPath);
const p = extract(pPath);

if (a !== p) {
  process.stderr.write(
    'mirror gate: canonicalStringify divergence between allowlist.ts and policy.ts\n'
  );
  process.stderr.write('--- allowlist.ts:\n' + a + '\n');
  process.stderr.write('--- policy.ts:\n' + p + '\n');
  process.exit(1);
}

process.stdout.write('mirror gate: canonicalStringify identical (' + a.length + ' bytes)\n');
