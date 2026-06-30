#!/usr/bin/env node
// run-tests.js — compile all test files with esbuild then run them via node --test.
//
// Extracted from the inline package.json test script to avoid the 8191-char
// Windows command-line length limit (the script grew too long as tests were added).
//
// Each entry: src TypeScript file -> compiled CJS output in dist/__tests__/.
// The list must stay sorted to make additions/removals easy to review.

'use strict';

const { execSync } = require('node:child_process');
const path = require('node:path');

const root = path.join(__dirname, '..');

const TESTS = [
  'sanitize.test.ts',
  'auth.test.ts',
  'tools-registry.test.ts',
  'confirm.test.ts',
  'state-dir.test.ts',
  'allowlist.test.ts',
  'cli-trust.test.ts',
  'audit.test.ts',
  'guards.test.ts',
  'token-perm.test.ts',
  'sanitize-error.test.ts',
  'allowlist-comma-smuggling.test.ts',
  'auto-trust-reply.test.ts',
  'send-pipeline-ordering.test.ts',
  'token-paths.test.ts',
  'policy.test.ts',
  'provenance.test.ts',
  'risk-score.test.ts',
  'outbound-scan.test.ts',
  'outbound-scan-structural.test.ts',
  'outbound-scan-keyword.test.ts',
  'outbound-scan-integration.test.ts',
  'confirm-risk-tier.test.ts',
  'override-tokens.test.ts',
  'migration.test.ts',
  'allowlist-trust-meta.test.ts',
  'send-pipeline.test.ts',
  'send-pipeline-integration.test.ts',
  'cli-extensions.test.ts',
  'recent-sends.test.ts',
  'policy-doc-drift.test.ts',
  'stats.test.ts',
  'mail-index.test.ts',
  'index-auto.test.ts',
  'stemmer.test.ts',
  'unanswered.test.ts',
  'attachment-parser.test.ts',
  'get-attachment.test.ts',
  'attachments-manifest.test.ts',
  'find-attachments.test.ts',
  'read-top.test.ts',
];

const distDir = path.join(root, 'dist', '__tests__');

// Compile each test file individually so error messages point at the right file.
for (const ts of TESTS) {
  const src = path.join(root, 'src', '__tests__', ts);
  const js = ts.replace(/\.ts$/, '.js');
  const out = path.join(distDir, js);
  // Build the esbuild command: input file first, then flags.
  const cmd = [
    'esbuild',
    `"${src}"`,
    '--bundle',
    '--platform=node',
    '--target=node18',
    '--format=cjs',
    '--external:node:test',
    '--external:node:assert',
    `--outfile="${out}"`,
  ].join(' ');
  try {
    execSync(cmd, { stdio: 'inherit', cwd: root });
  } catch (e) {
    process.exit(1);
  }
}

// Run all compiled tests.
const testFiles = TESTS.map(ts => {
  const js = ts.replace(/\.ts$/, '.js');
  return `"${path.join(distDir, js)}"`;
}).join(' ');

try {
  execSync(`node --test ${testFiles}`, { stdio: 'inherit', cwd: root });
} catch (e) {
  process.exit(e.status || 1);
}
