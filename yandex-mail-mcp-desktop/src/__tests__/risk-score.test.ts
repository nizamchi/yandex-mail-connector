// risk-score.test.ts -- Phase 4 / Layer C / PMLF v2.1.0 unit tests.
//
// 24 cases (floor per 04-01-PLAN.md is 12; 2x headroom):
//   T-RISK-EMPTY-01                        -- baseline empty ctx
//   T-RISK-NEW-TRUST-01                    -- inside-window fires
//   T-RISK-NEW-TRUST-EXPIRED-01            -- 8d past does NOT fire
//   T-RISK-NEW-TRUST-BOUNDARY-EQ-01        -- 7d exact does NOT fire (strict-LT)
//   T-RISK-NEW-TRUST-BOUNDARY-EDGE-01      -- 7d-1ms DOES fire
//   T-RISK-FIRST-USE-01                    -- firstUse=true
//   T-RISK-AUTO-TRUST-01                   -- autoTrustedThisCall
//   T-RISK-API-KEY-01                      -- top-level category match
//   T-RISK-BASE64-01                       -- B-1: subCategory predicate
//   T-RISK-BASE64-ZEROSPAN-01              -- defensive zero-byte span
//   T-RISK-POST-READ-01                    -- postReadFlag=true
//   T-RISK-MULTI-RCPT-01                   -- 6 recipients fires
//   T-RISK-MULTI-RCPT-BOUNDARY-01          -- 5 recipients does NOT fire
//   T-RISK-LARGE-BODY-01                   -- 60_000 bytes fires
//   T-RISK-LARGE-BODY-BOUNDARY-01          -- 50_000 bytes does NOT fire
//   T-RISK-BURST-01                        -- recentSendCount==threshold
//   T-RISK-COMPOSITE-01                    -- 3 signals -> pure SUM, D5 order
//   T-RISK-BLOCK-SATURATION-01             -- 75+30=105 clamps 100, tier=block
//   T-RISK-TIER-LOW-01                     -- score 15 -> low
//   T-RISK-TIER-MEDIUM-01                  -- score 30 -> medium (augment-eq)
//   T-RISK-TIER-HIGH-01                    -- score 75 -> high
//   T-RISK-TIER-BLOCK-01                   -- score 115->100 -> block (block-eq)
//   T-RISK-POLICY-OVERRIDE-01              -- thresholds override re-maps tier
//   T-RISK-DETERMINISM-01                  -- grep gate over the source
//   T-RISK-MUTATION-01                     -- ctx unchanged before/after
//   T-RISK-REASONS-FORMAT-01               -- 9 template substring asserts
//   T-RISK-EMPTY-RECIPIENTS-01             -- '(no recipient)' sentinel
//
// (Renumbered to a contiguous 1..24 in actual test order; the catalog above
// reflects the planner-traceability numbering. Total test() blocks: 24.)
//
// Every base64 ScanHit fixture uses the B-1 corrected shape
// `{ category: 'data_shape_anomaly', subCategory: 'base64_blob', ... }`
// per CONTEXT D5 rev 1 amendment. Zero fixtures use the rev-1 wrong shape.
//
// No emojis. ASCII-only. ESM `.js` suffix on imports.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';

import {
  computeRiskScore,
  type RiskContext,
} from '../risk-score.js';
import { _setPolicyForTests, _resetForTests as resetPolicy } from '../policy.js';
import { DEFAULT_POLICY, type RiskPolicy } from '../policy-defaults.js';

// ── Helpers ───────────────────────────────────────────────────

// Build a baseline RiskContext where NO signal fires. Each test tweaks
// ONE field (or a small subset) to fire signals; rest stays neutral.
function emptyCtx(overrides: Partial<RiskContext> = {}): RiskContext {
  return {
    scanResult: { hits: [], totalScore: 0, summary: '' },
    recipients: [],
    bodySize: 0,
    nowMs: 1_700_000_000_000,
    postReadFlag: false,
    autoTrustedThisCall: false,
    firstUse: false,
    recentSendCount: 0,
    ...overrides,
  };
}

// Install DEFAULT_POLICY before each test. We clone via spread so a test
// that mutates the cached policy can't poison subsequent tests.
function installDefaults(): void {
  resetPolicy();
  _setPolicyForTests({
    ...DEFAULT_POLICY,
    weights: { ...DEFAULT_POLICY.weights },
    thresholds: { ...DEFAULT_POLICY.thresholds },
    categories: { ...DEFAULT_POLICY.categories },
  });
}

// Deep-clone for mutation-safety assertions.
function clone<T>(v: T): T { return JSON.parse(JSON.stringify(v)); }

// ── Tests ─────────────────────────────────────────────────────

test('T-RISK-EMPTY-01 -- empty ctx yields zero score, low tier, no reasons', () => {
  installDefaults();
  const r = computeRiskScore(emptyCtx());
  assert.equal(r.score, 0);
  assert.equal(r.tier, 'low');
  assert.deepEqual(r.reasons, []);
});

test('T-RISK-NEW-TRUST-01 -- 3d-old trust fires new_trust weight=30, tier=medium', () => {
  installDefaults();
  const nowMs = 1_700_000_000_000;
  const ctx = emptyCtx({
    trustAddedAtMs: nowMs - 3 * 86400_000,
    recipients: ['alice@example.com'],
    nowMs,
  });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, DEFAULT_POLICY.weights.new_trust);
  assert.equal(r.score, 30);
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'new_trust');
  assert.equal(r.reasons[0].weight, 30);
  assert.ok(r.reasons[0].detail.includes('new trust:'),
    'detail should include "new trust:" prefix');
  assert.ok(r.reasons[0].detail.includes('alice@example.com'),
    'detail should include recipient address');
  assert.ok(r.reasons[0].detail.includes('3d ago'),
    'detail should include "3d ago"');
  assert.equal(r.tier, 'medium');
});

test('T-RISK-NEW-TRUST-EXPIRED-01 -- 8d-old trust does NOT fire', () => {
  installDefaults();
  const nowMs = 1_700_000_000_000;
  const ctx = emptyCtx({
    trustAddedAtMs: nowMs - 8 * 86400_000,
    recipients: ['alice@example.com'],
    nowMs,
  });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 0);
  assert.deepEqual(r.reasons, []);
  assert.equal(r.tier, 'low');
});

test('T-RISK-NEW-TRUST-BOUNDARY-EQ-01 -- 7d exact does NOT fire (strict-LT)', () => {
  installDefaults();
  const nowMs = 1_700_000_000_000;
  const ctx = emptyCtx({
    trustAddedAtMs: nowMs - 7 * 86400_000,
    recipients: ['edge@example.com'],
    nowMs,
  });
  const r = computeRiskScore(ctx);
  // Predicate is `ageMs < 7*86400_000`; exact 7d is EXPIRED.
  assert.equal(r.score, 0);
  assert.deepEqual(r.reasons, []);
  assert.equal(r.tier, 'low');
});

test('T-RISK-NEW-TRUST-BOUNDARY-EDGE-01 -- 7d-1ms DOES fire', () => {
  installDefaults();
  const nowMs = 1_700_000_000_000;
  const ctx = emptyCtx({
    trustAddedAtMs: nowMs - (7 * 86400_000 - 1),
    recipients: ['edge@example.com'],
    nowMs,
  });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 30);
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'new_trust');
  assert.equal(r.tier, 'medium');
});

test('T-RISK-FIRST-USE-01 -- firstUse=true fires weight 20, tier=low', () => {
  installDefaults();
  const ctx = emptyCtx({ firstUse: true, recipients: ['bob@example.com'] });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 20);
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'first_use');
  assert.equal(r.reasons[0].detail, 'first send to bob@example.com');
  // 20 < augment(30) -> low.
  assert.equal(r.tier, 'low');
});

test('T-RISK-AUTO-TRUST-01 -- autoTrustedThisCall fires weight 40, tier=medium', () => {
  installDefaults();
  const ctx = emptyCtx({
    autoTrustedThisCall: true,
    recipients: ['carol@example.com'],
  });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 40);
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'just_auto_trusted');
  assert.equal(r.reasons[0].detail,
    'trust auto-elevated this call for carol@example.com');
  // 40 >= augment(30) && < strict(60) -> medium.
  assert.equal(r.tier, 'medium');
});

test('T-RISK-API-KEY-01 -- top-level category match fires weight 75, tier=high', () => {
  installDefaults();
  const ctx = emptyCtx({
    scanResult: {
      hits: [
        {
          category: 'api_key_pattern',
          subCategory: 'aws_access_key',
          weight: 75,
          evidence: { byteStart: 10, byteEnd: 30, prefix4: 'AKIA' },
          matchedIn: 'body',
        },
      ],
      totalScore: 75,
      summary: '',
    },
  });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 75);
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'api_key_pattern');
  assert.equal(r.reasons[0].weight, 75);
  assert.ok(r.reasons[0].detail.includes('body contains 1 api_key_pattern hit(s)'));
  // Privacy: no credential prefix leaked.
  assert.ok(!r.reasons[0].detail.includes('AKIA'),
    'detail must NOT include the credential prefix');
  // 75 >= strict(60) && < block(100) -> high.
  assert.equal(r.tier, 'high');
});

test('T-RISK-BASE64-01 -- subCategory predicate fires weight 30 (B-1 correction)', () => {
  installDefaults();
  // CRITICAL: fixture uses the production shape from Phase 2
  // data-shapes.ts:313-320 -- subCategory carries the 'base64_blob'
  // value, NOT category. If the evaluator regressed to matching
  // h.category === 'base64_blob' this test would FAIL.
  const hit = {
    category: 'data_shape_anomaly' as const,
    subCategory: 'base64_blob' as const,
    weight: 30,
    evidence: { byteStart: 0, byteEnd: 144, prefix4: 'eyJh' },
    matchedIn: 'body' as const,
  };
  const ctx = emptyCtx({
    scanResult: { hits: [hit], totalScore: 30, summary: '' },
  });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 30);
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'base64_in_body');
  assert.equal(r.reasons[0].weight, 30);
  // 144 bytes total span -> rounded to nearest 10 -> 140.
  assert.ok(r.reasons[0].detail.includes('1 base64 blob(s)'),
    'detail should mention 1 base64 blob(s)');
  assert.ok(r.reasons[0].detail.includes('~140 chars'),
    'detail should mention ~140 chars');
  // Privacy: prefix4 not leaked.
  assert.ok(!r.reasons[0].detail.includes('eyJh'),
    'detail must NOT include the base64 prefix4');
  assert.equal(r.tier, 'medium');
});

test('T-RISK-BASE64-ZEROSPAN-01 -- byteStart===byteEnd defensive branch (no NaN)', () => {
  installDefaults();
  const hit = {
    category: 'data_shape_anomaly' as const,
    subCategory: 'base64_blob' as const,
    weight: 30,
    evidence: { byteStart: 50, byteEnd: 50, prefix4: '' },
    matchedIn: 'body' as const,
  };
  const ctx = emptyCtx({
    scanResult: { hits: [hit], totalScore: 30, summary: '' },
  });
  // Must not crash.
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 30, 'signal still fires under boolean-presence semantics');
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'base64_in_body');
  assert.ok(r.reasons[0].detail.includes('1 base64 blob(s)'));
  // totalSpan=0 -> approxChars=0 -> '~0 chars'.
  assert.ok(r.reasons[0].detail.includes('~0 chars'),
    'zero-span fixture should render ~0 chars (not NaN, not negative)');
  assert.ok(!r.reasons[0].detail.includes('NaN'),
    'detail must never contain NaN');
});

test('T-RISK-POST-READ-01 -- postReadFlag=true fires weight 30, tier=medium', () => {
  installDefaults();
  const ctx = emptyCtx({ postReadFlag: true });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 30);
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'post_read_send');
  assert.ok(r.reasons[0].detail.includes('send within 30s of inbound read'),
    'detail should reference provenance_window_sec from default policy');
  assert.equal(r.tier, 'medium');
});

test('T-RISK-MULTI-RCPT-01 -- 6 recipients fires weight 20', () => {
  installDefaults();
  const ctx = emptyCtx({
    recipients: ['a@x', 'b@x', 'c@x', 'd@x', 'e@x', 'f@x'],
  });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 20);
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'multi_recipient');
  assert.equal(r.reasons[0].detail, '6 recipients (>5)');
  // 20 < augment(30) -> low.
  assert.equal(r.tier, 'low');
});

test('T-RISK-MULTI-RCPT-BOUNDARY-01 -- 5 recipients does NOT fire (strict GT)', () => {
  installDefaults();
  const ctx = emptyCtx({
    recipients: ['a@x', 'b@x', 'c@x', 'd@x', 'e@x'],
  });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 0);
  assert.deepEqual(r.reasons, []);
  assert.equal(r.tier, 'low');
});

test('T-RISK-LARGE-BODY-01 -- bodySize=60000 fires weight 15', () => {
  installDefaults();
  const ctx = emptyCtx({ bodySize: 60_000 });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 15);
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'large_body');
  assert.ok(r.reasons[0].detail.includes('~60 KB'),
    'detail should include ~60 KB');
  assert.ok(r.reasons[0].detail.includes('>50 KB'),
    'detail should include the threshold reference');
  assert.equal(r.tier, 'low');
});

test('T-RISK-LARGE-BODY-BOUNDARY-01 -- bodySize=50000 does NOT fire (strict GT)', () => {
  installDefaults();
  const ctx = emptyCtx({ bodySize: 50_000 });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 0);
  assert.deepEqual(r.reasons, []);
  assert.equal(r.tier, 'low');
});

test('T-RISK-BURST-01 -- recentSendCount==threshold fires weight 25', () => {
  installDefaults();
  const ctx = emptyCtx({ recentSendCount: 3 });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 25);
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'burst_pattern');
  assert.ok(r.reasons[0].detail.includes('3 sends within 120s'),
    'detail should reference burst_window_sec from default policy');
  // 25 < augment(30) -> low.
  assert.equal(r.tier, 'low');
});

test('T-RISK-COMPOSITE-01 -- 3 signals pure SUM in D5 canonical order', () => {
  installDefaults();
  const ctx = emptyCtx({
    firstUse: true,            // 20
    postReadFlag: true,        // 30
    recentSendCount: 5,        // >=3 burst threshold -> 25
    recipients: ['x@y'],
  });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 75, 'pure SUM (20+30+25) per CONTEXT D6');
  assert.equal(r.reasons.length, 3);
  // D5 canonical order: first_use -> post_read_send -> burst_pattern.
  assert.deepEqual(
    r.reasons.map((x) => x.signal),
    ['first_use', 'post_read_send', 'burst_pattern'],
  );
  // 75 >= strict(60) && < block(100) -> high.
  assert.equal(r.tier, 'high');
});

test('T-RISK-BLOCK-SATURATION-01 -- 75+30=105 clamps to 100, tier=block', () => {
  installDefaults();
  const apiKeyHit = {
    category: 'api_key_pattern' as const,
    subCategory: 'aws_access_key' as const,
    weight: 75,
    evidence: { byteStart: 0, byteEnd: 20, prefix4: 'AKIA' },
    matchedIn: 'body' as const,
  };
  const base64Hit = {
    category: 'data_shape_anomaly' as const,
    subCategory: 'base64_blob' as const,
    weight: 30,
    evidence: { byteStart: 30, byteEnd: 174, prefix4: 'eyJh' },
    matchedIn: 'body' as const,
  };
  const ctx = emptyCtx({
    scanResult: { hits: [apiKeyHit, base64Hit], totalScore: 100, summary: '' },
  });
  const r = computeRiskScore(ctx);
  // Raw sum 75 + 30 = 105 -> clamp at 100.
  assert.equal(r.score, 100, 'clamp at 100 per CONTEXT D3');
  assert.equal(r.reasons.length, 2);
  assert.equal(r.tier, 'block');
});

test('T-RISK-TIER-LOW-01 -- score 15 maps to low', () => {
  installDefaults();
  const r = computeRiskScore(emptyCtx({ bodySize: 60_000 }));
  assert.equal(r.score, 15);
  assert.equal(r.tier, 'low');
});

test('T-RISK-TIER-MEDIUM-01 -- score 30 maps to medium (augment-eq boundary)', () => {
  installDefaults();
  const r = computeRiskScore(emptyCtx({ postReadFlag: true }));
  assert.equal(r.score, 30);
  // score === augment(30) -> 'medium' per D7 half-open mapping.
  assert.equal(r.tier, 'medium');
});

test('T-RISK-TIER-HIGH-01 -- score 75 maps to high', () => {
  installDefaults();
  const ctx = emptyCtx({
    scanResult: {
      hits: [
        {
          category: 'api_key_pattern',
          subCategory: 'aws_access_key',
          weight: 75,
          evidence: { byteStart: 0, byteEnd: 20, prefix4: 'XXXX' },
          matchedIn: 'body',
        },
      ],
      totalScore: 75,
      summary: '',
    },
  });
  const r = computeRiskScore(ctx);
  assert.equal(r.score, 75);
  assert.equal(r.tier, 'high');
});

test('T-RISK-TIER-BLOCK-01 -- score 115 clamps to 100, tier=block (block-eq boundary)', () => {
  installDefaults();
  const ctx = emptyCtx({
    autoTrustedThisCall: true,  // 40
    scanResult: {
      hits: [
        {
          category: 'api_key_pattern',
          subCategory: 'aws_access_key',
          weight: 75,
          evidence: { byteStart: 0, byteEnd: 20, prefix4: 'XXXX' },
          matchedIn: 'body',
        },
      ],
      totalScore: 75,
      summary: '',
    },
  });
  const r = computeRiskScore(ctx);
  // 40 + 75 = 115 -> clamp 100. score === block(100) -> 'block'.
  assert.equal(r.score, 100);
  assert.equal(r.tier, 'block');
});

test('T-RISK-POLICY-OVERRIDE-01 -- override thresholds re-maps tier', () => {
  resetPolicy();
  _setPolicyForTests({
    ...DEFAULT_POLICY,
    weights: { ...DEFAULT_POLICY.weights },
    thresholds: { augment: 10, strict: 25, block: 50 },
    categories: { ...DEFAULT_POLICY.categories },
    override_block_threshold: true,
  });
  const r = computeRiskScore(emptyCtx({ postReadFlag: true }));
  // Raw weight still 30 (unaffected by threshold override).
  assert.equal(r.score, 30);
  // Under new thresholds: 30 >= strict(25) && < block(50) -> 'high'.
  assert.equal(r.tier, 'high');
});

test('T-RISK-DETERMINISM-01 -- source contains no Math.random / Date.now / async / forbidden imports', () => {
  // Resolve source path: tests run from `dist/__tests__/...` (esbuild
  // CJS bundle) so __dirname is unstable; fall back to CWD.
  const candidates = [
    path.resolve(process.cwd(), 'src/risk-score.ts'),
    path.resolve(process.cwd(), '..', 'src/risk-score.ts'),
  ];
  let rawSource = '';
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      rawSource = fs.readFileSync(p, 'utf8');
      break;
    }
  }
  assert.ok(rawSource.length > 0, 'risk-score.ts source must be readable from one of the candidate paths');

  // Strip line-comment lines so the file-header documentation of the
  // forbidden patterns (e.g. "// NO Math.random") doesn't trip the
  // substring check. This mirrors the plan's grep gates which all use
  // `grep -v '^[[:space:]]*//'` to skip comment lines.
  const source = rawSource
    .split(/\r?\n/)
    .filter((ln) => !/^\s*\/\//.test(ln))
    .join('\n');

  // Forbidden runtime patterns (CONTEXT D11).
  assert.ok(!source.includes('Math.random'), 'risk-score.ts must NOT contain Math.random');
  assert.ok(!source.includes('Date.now'), 'risk-score.ts must NOT contain Date.now');
  assert.ok(!source.includes('process.hrtime'), 'risk-score.ts must NOT contain process.hrtime');
  assert.ok(!source.includes('setTimeout('), 'risk-score.ts must NOT contain setTimeout(');
  assert.ok(!source.includes('setInterval('), 'risk-score.ts must NOT contain setInterval(');

  // Forbidden module imports (CONTEXT D8 stateless invariant).
  assert.ok(!source.includes("from './provenance"), 'risk-score.ts must NOT import provenance');
  assert.ok(!source.includes("from './allowlist"), 'risk-score.ts must NOT import allowlist');
  assert.ok(!source.includes("from './guards"), 'risk-score.ts must NOT import guards');
  assert.ok(!source.includes("from './audit"), 'risk-score.ts must NOT import audit');
  assert.ok(!source.includes("from './recipients"), 'risk-score.ts must NOT import recipients');
});

test('T-RISK-MUTATION-01 -- computeRiskScore does not mutate ctx (deep-equal hold)', () => {
  installDefaults();
  const nowMs = 1_700_000_000_000;
  const original: RiskContext = {
    scanResult: {
      hits: [
        {
          category: 'api_key_pattern',
          subCategory: 'aws_access_key',
          weight: 75,
          evidence: { byteStart: 0, byteEnd: 20, prefix4: 'AKIA' },
          matchedIn: 'body',
        },
        {
          category: 'data_shape_anomaly',
          subCategory: 'base64_blob',
          weight: 30,
          evidence: { byteStart: 30, byteEnd: 174, prefix4: 'eyJh' },
          matchedIn: 'body',
        },
      ],
      totalScore: 100,
      summary: '',
    },
    recipients: ['alice@example.com', 'bob@example.com'],
    bodySize: 60_000,
    nowMs,
    postReadFlag: true,
    autoTrustedThisCall: true,
    firstUse: true,
    trustAddedAtMs: nowMs - 3 * 86400_000,
    recentSendCount: 4,
  };
  const before = clone(original);
  const r = computeRiskScore(original);
  // Sanity-check the call ran.
  assert.ok(r.reasons.length > 0);
  // Deep-equal invariant: ctx unchanged.
  assert.equal(JSON.stringify(original), JSON.stringify(before),
    'computeRiskScore must not mutate ctx (D8 read-only)');
});

test('T-RISK-REASONS-FORMAT-01 -- 9 detail templates match D10 substrings', () => {
  installDefaults();
  const nowMs = 1_700_000_000_000;

  // 1. new_trust
  let r = computeRiskScore(emptyCtx({
    trustAddedAtMs: nowMs - 2 * 86400_000,
    recipients: ['t1@x'],
    nowMs,
  }));
  assert.ok(r.reasons[0].detail.includes('new trust:'));
  assert.ok(r.reasons[0].detail.includes(' added '));
  assert.ok(r.reasons[0].detail.includes('d ago'));
  assert.ok(!r.reasons[0].detail.includes('NaN'));

  // 2. first_use
  r = computeRiskScore(emptyCtx({ firstUse: true, recipients: ['t2@x'] }));
  assert.ok(r.reasons[0].detail.includes('first send to '));

  // 3. just_auto_trusted
  r = computeRiskScore(emptyCtx({
    autoTrustedThisCall: true,
    recipients: ['t3@x'],
  }));
  assert.ok(r.reasons[0].detail.includes('trust auto-elevated this call for '));

  // 4. api_key_pattern
  r = computeRiskScore(emptyCtx({
    scanResult: {
      hits: [{
        category: 'api_key_pattern',
        subCategory: 'aws_access_key',
        weight: 75,
        evidence: { byteStart: 0, byteEnd: 20, prefix4: 'AKIA' },
        matchedIn: 'body',
      }],
      totalScore: 75,
      summary: '',
    },
  }));
  assert.ok(r.reasons[0].detail.includes('body contains '));
  assert.ok(r.reasons[0].detail.includes(' api_key_pattern hit(s)'));
  // Privacy negative: no credential prefix.
  assert.ok(!r.reasons[0].detail.includes('AKIA'));

  // 5. base64_in_body (B-1 corrected shape).
  r = computeRiskScore(emptyCtx({
    scanResult: {
      hits: [{
        category: 'data_shape_anomaly',
        subCategory: 'base64_blob',
        weight: 30,
        evidence: { byteStart: 0, byteEnd: 144, prefix4: 'eyJh' },
        matchedIn: 'body',
      }],
      totalScore: 30,
      summary: '',
    },
  }));
  assert.ok(r.reasons[0].detail.includes('body contains '));
  assert.ok(r.reasons[0].detail.includes(' base64 blob(s)'));
  assert.ok(r.reasons[0].detail.includes(' chars)'));
  // Privacy negative: no prefix4 leak.
  assert.ok(!r.reasons[0].detail.includes('eyJh'));

  // 6. post_read_send
  r = computeRiskScore(emptyCtx({ postReadFlag: true }));
  assert.ok(r.reasons[0].detail.includes('send within '));
  assert.ok(r.reasons[0].detail.includes('s of inbound read'));

  // 7. multi_recipient
  r = computeRiskScore(emptyCtx({
    recipients: ['a@x', 'b@x', 'c@x', 'd@x', 'e@x', 'f@x'],
  }));
  assert.ok(r.reasons[0].detail.includes(' recipients (>5)'));

  // 8. large_body
  r = computeRiskScore(emptyCtx({ bodySize: 80_000 }));
  assert.ok(r.reasons[0].detail.includes('body ~'));
  assert.ok(r.reasons[0].detail.includes(' KB (>50 KB)'));

  // 9. burst_pattern
  r = computeRiskScore(emptyCtx({ recentSendCount: 5 }));
  assert.ok(r.reasons[0].detail.includes(' sends within '));
  assert.ok(r.reasons[0].detail.includes('s'));
});

test('T-RISK-EMPTY-RECIPIENTS-01 -- empty recipients yields literal "(no recipient)" sentinel', () => {
  installDefaults();
  const r = computeRiskScore(emptyCtx({ firstUse: true, recipients: [] }));
  assert.equal(r.reasons.length, 1);
  assert.equal(r.reasons[0].signal, 'first_use');
  // Exact-match the locked template (no trailing space, no 'undefined').
  assert.equal(r.reasons[0].detail, 'first send to (no recipient)');
});
