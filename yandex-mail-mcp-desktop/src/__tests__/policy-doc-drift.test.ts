// policy-doc-drift.test.ts
//
// T-DOC-DRIFT-01: For every key in DEFAULT_POLICY (weights / thresholds /
// toplevel knobs / categories), assert POLICY.md mentions the literal key
// name. Catches "operator tunes weight but POLICY.md is stale" drift.
//
// T-DOC-DRIFT-02: For every threshold key (augment / strict / block), assert
// the integer default value appears within a 60-character proximity window
// of the key name in POLICY.md. Catches "key is mentioned but default value
// is wrong" drift (M-5 fix vs vacuous "value appears anywhere" check).
//
// Path: this test runs from dist/__tests__/policy-doc-drift.test.js. Three
// dotdots reach the repo root:
//   dist/__tests__/         -> '..' -> dist
//   dist                    -> '..' -> yandex-mail-mcp-desktop
//   yandex-mail-mcp-desktop -> '..' -> repo root (POLICY.md is here)

import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert';
import { DEFAULT_POLICY } from '../policy-defaults.js';

const policyPath = path.resolve(__dirname, '..', '..', '..', 'POLICY.md');
assert.ok(
  fs.existsSync(policyPath),
  `POLICY.md not found at resolved path: ${policyPath}. ` +
    `If you reorganised the dist layout, fix the dotdot depth in this test.`
);
const policyDocText = fs.readFileSync(policyPath, 'utf8');

test('T-DOC-DRIFT-01: POLICY.md mentions every key in DEFAULT_POLICY', () => {
  const allKeys: string[] = [
    ...Object.keys(DEFAULT_POLICY.weights),
    ...Object.keys(DEFAULT_POLICY.thresholds),
    ...Object.keys(DEFAULT_POLICY.categories),
    'outbound_keywords',
    'blocked_domains',
    'provenance_window_sec',
    'burst_window_sec',
    'burst_threshold',
    'override_block_threshold',
  ];
  for (const key of allKeys) {
    assert.ok(
      policyDocText.includes(key),
      `POLICY.md missing key '${key}' (drift gate T-DOC-DRIFT-01).`
    );
  }
});

test('T-DOC-DRIFT-02: threshold default values within 60-char proximity of key in POLICY.md', () => {
  for (const [key, value] of Object.entries(DEFAULT_POLICY.thresholds)) {
    const keyIdx = policyDocText.indexOf(key);
    assert.ok(keyIdx >= 0, `POLICY.md missing threshold key '${key}'`);
    const win = policyDocText.slice(
      Math.max(0, keyIdx - 60),
      keyIdx + key.length + 60
    );
    const re = new RegExp(`\\b${value}\\b`);
    assert.ok(
      re.test(win),
      `POLICY.md threshold '${key}' default ${value} not within 60-char proximity of key (drift gate T-DOC-DRIFT-02).`
    );
  }
});
