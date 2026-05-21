// confirm-risk-tier.test.ts -- Phase 5 Layer D tier-behavior + regression
// suite. Locks per-tier surfaces (D2), v2.0.0 parity (D8), privacy
// invariants (D6), B-3 invariant (verifyCode no-await), and B-1/H-1/H-2
// regression carryover.
//
// Test catalog (18 named tests; floor 15):
//   T-CONF-LOW-PARITY-01, T-CONF-V200-CALLERS-01, T-CONF-MEDIUM-REASONS-01,
//   T-CONF-HIGH-TYPEIN-01, T-CONF-BLOCK-NO-CODE-01, T-CONF-DRYRUN-TIER-01,
//   T-CONF-MULTI-TIER-COMPOSITE-01, T-AUDIT-RISK-FIELDS-01,
//   T-AUDIT-RISK-NO-DETAIL-01, T-AUDIT-RISK-OPTIONAL-01,
//   T-B1-COMMA-SMUGGLING-REGRESSION-01, T-H1-AUTO-TRUST-REGRESSION-01,
//   T-H2-BURNED-CODE-REGRESSION-01, T-B3-NO-AWAIT-01,
//   T-CONF-TYPE-ONLY-IMPORT-01, T-CONF-REASONS-DETAIL-NOT-AUDITED-01,
//   T-CONF-LOCKOUT-INVARIANT-01, T-CONF-EXPIRY-INVARIANT-01.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  generateCode,
  verifyCode,
  actionFingerprint,
  _resetForTests as _resetConfirm,
  _expireForTests,
} from '../confirm.js';
import {
  auditLog,
  _drainForTests,
  _resetForTests as _resetAudit,
} from '../audit.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import {
  mintOverrideToken,
  consumeOverrideToken,
  _resetForTests as _resetOverride,
} from '../override-tokens.js';
import type { RiskReason, RiskTier } from '../risk-score.js';

// -- Helpers ------------------------------------------------

let _tmpCounter = 0;
function makeSandbox(): { stateDir: string; auditPath: string } {
  _tmpCounter++;
  const stateDir = path.join(
    os.tmpdir(),
    'confirm-risk-tier-' + Date.now() + '-' + _tmpCounter,
  );
  fs.mkdirSync(stateDir, { recursive: true });
  const auditPath = path.join(stateDir, 'audit.jsonl');
  return { stateDir, auditPath };
}

function snapshotEnv(): () => void {
  const keys = ['YANDEX_STATE_DIR', 'YANDEX_AUDIT_LOG', 'YANDEX_AUDIT_LOG_MAX_MB'];
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) saved[k] = process.env[k];
  return () => {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  };
}

function resetAll(): void {
  _resetConfirm();
  _resetAudit();
  _resetStateDir();
  _resetOverride();
}

interface StderrCapture {
  restore: () => void;
  text: () => string;
}

function captureStderr(): StderrCapture {
  const lines: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  (process.stderr as unknown as { write: (s: string) => boolean }).write =
    (s: string): boolean => {
      lines.push(String(s));
      return true;
    };
  return {
    restore: () => {
      (process.stderr as unknown as { write: typeof original }).write = original;
    },
    text: () => lines.join(''),
  };
}

async function readAuditLines(auditPath: string): Promise<Record<string, unknown>[]> {
  await _drainForTests();
  if (!fs.existsSync(auditPath)) return [];
  const raw = fs.readFileSync(auditPath, 'utf-8');
  return raw.split('\n').filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
}

function fakeReason(signal: string, weight: number, detail: string): RiskReason {
  return { signal, weight, detail };
}

// -- Tests --------------------------------------------------

test('T-CONF-LOW-PARITY-01: explicit riskTier:low matches v2.0.0 shape', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp = actionFingerprint('send', { to: ['a@x.com'] });
    const result = generateCode(fp, { riskTier: 'low' });
    cap.restore();
    assert.equal(typeof result.code, 'string');
    assert.equal((result.code as string).length, 6);
    assert.equal(result.tier, 'low');
    assert.equal(result.reasons, undefined);
    assert.equal(cap.text(), '');
    const audit = await readAuditLines(auditPath);
    assert.equal(audit.length, 1);
    const rec = audit[0]!;
    assert.equal(rec.action, 'code_generated');
    assert.equal(rec.status, 'success');
    assert.equal(rec.level, 'info');
    assert.ok(!('risk_score' in rec));
    assert.ok(!('risk_reasons' in rec));
    assert.ok(!('risk_tier' in rec));
    const keys = Object.keys(rec).sort();
    assert.deepEqual(keys, ['action', 'level', 'reason', 'status', 'ts']);
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-CONF-V200-CALLERS-01: no-opts call byte-identical to explicit low (REV 2 B-5)', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;

  // Run 1: no opts arg.
  resetAll();
  const cap1 = captureStderr();
  let result1: ReturnType<typeof generateCode>;
  try {
    const fp1 = actionFingerprint('send', { to: ['a@x.com'] });
    result1 = generateCode(fp1);
  } finally {
    cap1.restore();
  }
  const buffer1 = cap1.text();
  const auditList1 = await readAuditLines(auditPath);

  // Run 2: explicit { riskTier: 'low' }.
  resetAll();
  fs.rmSync(auditPath, { force: true });
  const cap2 = captureStderr();
  let result2: ReturnType<typeof generateCode>;
  try {
    const fp2 = actionFingerprint('send', { to: ['a@x.com'] });
    result2 = generateCode(fp2, { riskTier: 'low' });
  } finally {
    cap2.restore();
  }
  const buffer2 = cap2.text();
  const auditList2 = await readAuditLines(auditPath);

  try {
    // Assertions:
    assert.equal(buffer1, '');                              // no extra stderr for low tier
    assert.deepEqual(buffer1, buffer2);                     // explicit 'low' === no-opts
    assert.deepEqual(
      Object.keys(auditList1[0]!).sort(),
      Object.keys(auditList2[0]!).sort(),
    );
    assert.ok(!('risk_score' in auditList1[0]!));           // low tier OMITS risk fields
    assert.ok(!('risk_reasons' in auditList1[0]!));
    assert.ok(!('risk_tier' in auditList1[0]!));
    // Base fields byte-identical between calls:
    assert.equal(auditList1[0]!.action, auditList2[0]!.action);
    assert.equal(auditList1[0]!.status, auditList2[0]!.status);
    assert.equal(auditList1[0]!.level, auditList2[0]!.level);
    // Return shape:
    assert.equal(typeof result1.code === 'string' && (result1.code as string).length === 6, true);
    assert.equal(result1.tier, 'low');
    assert.equal(result1.reasons, undefined);               // REV 2 B-1/B-2: low omits reasons echo
    assert.equal(result2.tier, 'low');
    assert.equal(result2.reasons, undefined);
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-CONF-MEDIUM-REASONS-01: medium tier stderr + audit + return-shape echo + explicit score (REV 2 B-1/W-1)', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp = actionFingerprint('send', { to: ['bob@example.com'] });
    const reasons = [fakeReason('first_use', 20, 'first send to bob@example.com')];
    const result = generateCode(fp, { riskTier: 'medium', reasons, score: 20 });
    cap.restore();
    const stderr = cap.text();
    // PATH 1: stderr emission.
    assert.match(stderr, /medium-risk send/);
    assert.match(stderr, /first_use/);
    // PATH 2: return-shape reasons echo (Phase 6 elicit consumer).
    assert.ok(result.reasons !== undefined);
    assert.equal(result.reasons!.length, 1);
    assert.equal(result.reasons![0]!.signal, 'first_use');
    assert.equal(result.reasons![0]!.weight, 20);
    assert.equal(result.reasons![0]!.detail, 'first send to bob@example.com');
    // PATH 3: audit emission with explicit score (REV 2 W-1 -- NOT reconstructed).
    const audit = await readAuditLines(auditPath);
    assert.equal(audit.length, 1);
    assert.equal(audit[0]!.risk_score, 20);
    assert.deepEqual(audit[0]!.risk_reasons, ['first_use']);
    assert.equal(audit[0]!.risk_tier, 'medium');
    // Code still minted on medium:
    assert.equal(typeof result.code === 'string' && (result.code as string).length === 6, true);
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-CONF-HIGH-TYPEIN-01: high tier please-type nudge + return-shape echo (REV 2 B-2)', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp = actionFingerprint('send', { to: ['a@x.com'] });
    const reasons = [
      fakeReason('first_use', 20, 'first send to a@x.com'),
      fakeReason('post_read_send', 35, 'send within 600s of inbound read'),
    ];
    const result = generateCode(fp, { riskTier: 'high', reasons });
    cap.restore();
    const stderr = cap.text();
    // PATH 1: stderr nudge.
    assert.match(stderr, /please type/);
    assert.match(stderr, /do not paste/);
    // PATH 2: return-shape reasons echo.
    assert.equal(Array.isArray(result.reasons), true);
    assert.equal(result.reasons!.length, reasons.length);
    // PATH 3: audit risk_tier='high'.
    const audit = await readAuditLines(auditPath);
    assert.equal(audit[0]!.risk_tier, 'high');
    // Code still minted on high:
    assert.equal(typeof result.code === 'string' && (result.code as string).length === 6, true);
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-CONF-BLOCK-NO-CODE-01: block tier returns code=null + denied audit + risk_score 95 (REV 2 W-2)', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp = actionFingerprint('send', { to: ['a@x.com'] });
    const blockReasons = [
      fakeReason('api_key_pattern', 75, 'sk-... detected at offset 1024'),
      fakeReason('multi_recipient', 20, 'sending to 12 distinct domains'),
    ];
    // Sum 95 -> reconstruct via estimateScoreFromReasons (no explicit score).
    const result = generateCode(fp, { riskTier: 'block', reasons: blockReasons });
    cap.restore();
    const stderr = cap.text();
    assert.equal(result.code, null);
    assert.equal(result.expiresAt, 0);
    assert.equal(result.tier, 'block');
    assert.ok(result.reasons !== undefined);
    assert.equal(result.reasons!.length, 2);                // REV 2 B-1/B-2 echo on block
    const audit = await readAuditLines(auditPath);
    assert.equal(audit.length, 1);
    assert.equal(audit[0]!.action, 'code_generated');
    assert.equal(audit[0]!.status, 'denied');
    assert.equal(audit[0]!.level, 'warn');
    assert.equal(audit[0]!.risk_tier, 'block');
    assert.equal(audit[0]!.risk_score, 95);                 // REV 2 W-2 fixture sum
    assert.deepEqual(audit[0]!.risk_reasons, ['api_key_pattern', 'multi_recipient']);
    assert.match(stderr, /risk_block/);
    assert.match(stderr, /yandex-mail-mcp-trust --high-risk-send=/);
    // No code entry was created in the codes map:
    assert.equal(verifyCode(fp, '000000'), 'wrong');        // 'wrong' (no entry) not 'used'
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-CONF-BLOCK-FINGERPRINT-01: block-tier stderr embeds opts.riskFingerprint when supplied, <RISK_FINGERPRINT> placeholder otherwise (REV 3 WR-06)', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;

  // PATH 1: riskFingerprint supplied -> stderr embeds the exact value.
  resetAll();
  const cap1 = captureStderr();
  try {
    const fp = actionFingerprint('send', { to: ['a@x.com'] });
    const reasons = [fakeReason('api_key_pattern', 75, 'sk-... found')];
    const result = generateCode(fp, {
      riskTier: 'block',
      reasons,
      riskFingerprint: 'abc123',
    });
    cap1.restore();
    const stderr = cap1.text();
    assert.equal(result.code, null);
    assert.match(stderr, /--high-risk-send=abc123/);
    assert.ok(!stderr.includes('<RISK_FINGERPRINT>'), 'placeholder must NOT appear when riskFingerprint is supplied');
    // The actionFingerprint MUST NOT leak into the stderr (this was the WR-06
    // latent UX failure).
    assert.ok(!stderr.includes('--high-risk-send=' + fp), 'actionFingerprint must NOT appear in --high-risk-send line');
  } finally {
    cap1.restore();
  }

  // PATH 2: no riskFingerprint -> stderr embeds the <RISK_FINGERPRINT> placeholder.
  resetAll();
  fs.rmSync(auditPath, { force: true });
  const cap2 = captureStderr();
  try {
    const fp = actionFingerprint('send', { to: ['a@x.com'] });
    const reasons = [fakeReason('api_key_pattern', 75, 'sk-... found')];
    const result = generateCode(fp, { riskTier: 'block', reasons });
    cap2.restore();
    const stderr = cap2.text();
    assert.equal(result.code, null);
    assert.match(stderr, /--high-risk-send=<RISK_FINGERPRINT>/);
    // The actionFingerprint MUST NOT leak into the stderr.
    assert.ok(!stderr.includes('--high-risk-send=' + fp), 'actionFingerprint must NOT appear in --high-risk-send line');
  } finally {
    cap2.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-CONF-DRYRUN-TIER-01: result.tier round-trips for all 4 tiers', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  const tiers: RiskTier[] = ['low', 'medium', 'high', 'block'];
  try {
    for (const t of tiers) {
      resetAll();
      const cap = captureStderr();
      try {
        const fp = actionFingerprint('send', { to: [`tier-${t}@x.com`] });
        const result = generateCode(fp, { riskTier: t, reasons: [] });
        assert.equal(result.tier, t, `tier round-trip failed for ${t}`);
        if (t === 'block') {
          assert.equal(result.code, null);
        } else {
          assert.equal(typeof result.code, 'string');
        }
      } finally {
        cap.restore();
      }
    }
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-CONF-MULTI-TIER-COMPOSITE-01: block + mint + consume produces both audit records', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp = 'abcdef0123456789abcdef0123456789';
    const result = generateCode(fp, {
      riskTier: 'block',
      reasons: [fakeReason('api_key_pattern', 75, 'sk-key found')],
    });
    assert.equal(result.code, null);
    const { token } = mintOverrideToken(fp);
    const consumed = consumeOverrideToken(fp, token);
    cap.restore();
    assert.equal(consumed.ok, true);
    const audit = await readAuditLines(auditPath);
    const actions = audit.map((r) => r.action);
    assert.ok(actions.includes('code_generated'), 'block code_generated audit missing');
    assert.ok(actions.includes('override_token_minted'), 'mint audit missing');
    assert.ok(actions.includes('override_token_consumed'), 'consume audit missing');
    // Block record has risk_tier='block', status='denied'.
    const denied = audit.find((r) => r.action === 'code_generated' && r.status === 'denied');
    assert.ok(denied);
    assert.equal(denied!.risk_tier, 'block');
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-AUDIT-RISK-FIELDS-01: medium/high/block audit records have risk_score + risk_reasons + risk_tier', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp1 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const fp2 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const fp3 = 'cccccccccccccccccccccccccccccccc';
    generateCode(fp1, { riskTier: 'medium', reasons: [fakeReason('first_use', 20, 'd')] });
    generateCode(fp2, { riskTier: 'high', reasons: [fakeReason('post_read_send', 35, 'd')] });
    generateCode(fp3, { riskTier: 'block', reasons: [fakeReason('api_key_pattern', 75, 'd'), fakeReason('multi_recipient', 20, 'd')] });
    cap.restore();
    const audit = await readAuditLines(auditPath);
    assert.equal(audit.length, 3);
    for (const r of audit) {
      assert.equal(typeof r.risk_score, 'number');
      assert.equal(Array.isArray(r.risk_reasons), true);
      assert.ok(['low', 'medium', 'high', 'block'].includes(r.risk_tier as string));
      for (const s of r.risk_reasons as string[]) {
        assert.equal(typeof s, 'string');
      }
    }
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-AUDIT-RISK-NO-DETAIL-01: audit risk_reasons[] never contains @ / recipient substrings (privacy)', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp = 'dddddddddddddddddddddddddddddddd';
    const detail = 'first send to bob@example.com';
    generateCode(fp, {
      riskTier: 'medium',
      reasons: [fakeReason('first_use', 20, detail)],
    });
    cap.restore();
    const audit = await readAuditLines(auditPath);
    assert.equal(audit.length, 1);
    const reasonsArr = audit[0]!.risk_reasons as string[];
    for (const s of reasonsArr) {
      assert.ok(!s.includes('@'), `risk_reasons must not contain '@': ${s}`);
      assert.ok(!s.includes('example.com'), `risk_reasons must not contain recipient domain: ${s}`);
      assert.ok(!s.includes('bob'), `risk_reasons must not contain recipient local-part: ${s}`);
    }
    // Reason JSON serialization must not leak detail either.
    const rawLine = JSON.stringify(audit[0]);
    assert.ok(!rawLine.includes('bob@example.com'), 'audit line must not contain recipient address');
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-AUDIT-RISK-OPTIONAL-01: audit accepts records without risk_* fields (Phase 1/2/3 forward-compat)', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  try {
    auditLog({ action: 'foo', status: 'success', level: 'info', ts: new Date().toISOString() });
    const audit = await readAuditLines(auditPath);
    assert.equal(audit.length, 1);
    assert.equal(audit[0]!.action, 'foo');
    assert.ok(!('risk_score' in audit[0]!));
    assert.ok(!('risk_reasons' in audit[0]!));
    assert.ok(!('risk_tier' in audit[0]!));
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-B1-COMMA-SMUGGLING-REGRESSION-01: normalizeRecipients still expands smuggled addresses', async () => {
  // Re-import the v2.0.0 invariant on the post-Phase-5 surface.
  const { normalizeRecipients } = await import('../recipients.js');
  const r = normalizeRecipients(['Alice <alice@trusted.com>, attacker@evil.com']);
  assert.deepEqual(
    r.addresses.sort(),
    ['alice@trusted.com', 'attacker@evil.com'].sort(),
  );
});

test('T-H1-AUTO-TRUST-REGRESSION-01: auto-trust scope=session persists for isAllowed check', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  delete process.env.YANDEX_AUDIT_LOG;
  resetAll();
  try {
    const allowlist = await import('../allowlist.js');
    allowlist._resetForTests();
    // Add a session-scope trust entry programmatically (mirrors v2.0.0 auto-trust path).
    allowlist.addTrusted('replyguy@example.com', 'session', 'auto_trust_reply');
    assert.equal(allowlist.isAllowed('replyguy@example.com'), true);
  } finally {
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-H2-BURNED-CODE-REGRESSION-01: verified code cannot be reverified', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp = actionFingerprint('send', { to: ['burn@x.com'] });
    const result = generateCode(fp, { riskTier: 'medium', reasons: [fakeReason('first_use', 20, 'd')] });
    cap.restore();
    assert.equal(typeof result.code, 'string');
    assert.equal(verifyCode(fp, result.code as string), true);
    assert.equal(verifyCode(fp, result.code as string), 'used');
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-B3-NO-AWAIT-01: confirm.ts verifyCode body has 0 await tokens (B-3 invariant)', () => {
  // Locate src/confirm.ts relative to the compiled test file in dist/__tests__.
  // Walk up from the bundled CJS location to find the workspace root.
  const candidates = [
    path.resolve(process.cwd(), 'src/confirm.ts'),
    path.resolve(__dirname, '../../src/confirm.ts'),
    path.resolve(__dirname, '../../../src/confirm.ts'),
  ];
  let src: string | null = null;
  for (const c of candidates) {
    if (fs.existsSync(c)) { src = fs.readFileSync(c, 'utf-8'); break; }
  }
  assert.ok(src !== null, 'could not locate src/confirm.ts');
  // Extract verifyCode body: from `export function verifyCode` to the next top-level `}` line.
  const startRe = /^export function verifyCode\b/m;
  const startMatch = src!.match(startRe);
  assert.ok(startMatch !== null, 'verifyCode declaration not found');
  const startIdx = startMatch!.index!;
  // Walk lines from startIdx until we hit a top-level closing `}` (a line beginning with `}` at column 0).
  const tail = src!.slice(startIdx);
  const endRe = /\n\}\n/;
  const endMatch = tail.match(endRe);
  assert.ok(endMatch !== null, 'verifyCode closing brace not found');
  const body = tail.slice(0, endMatch!.index! + endMatch![0]!.length);
  // Strip // line comments before counting (the B-3 reminder comment mentions await indirectly).
  const stripped = body.replace(/\/\/[^\n]*/g, '');
  // Count occurrences of `await ` as a word.
  const matches = stripped.match(/\bawait\b/g) || [];
  assert.equal(matches.length, 0, `verifyCode must have 0 await tokens, got ${matches.length}`);
});

test('T-CONF-TYPE-ONLY-IMPORT-01: confirm.ts imports RiskTier/RiskReason as type-only', () => {
  const candidates = [
    path.resolve(process.cwd(), 'src/confirm.ts'),
    path.resolve(__dirname, '../../src/confirm.ts'),
    path.resolve(__dirname, '../../../src/confirm.ts'),
  ];
  let src: string | null = null;
  for (const c of candidates) {
    if (fs.existsSync(c)) { src = fs.readFileSync(c, 'utf-8'); break; }
  }
  assert.ok(src !== null);
  // type-only import present.
  assert.match(src!, /import type \{ RiskTier, RiskReason \} from '\.\/risk-score\.js'/);
  // No runtime import of computeRiskScore.
  assert.equal(src!.includes('computeRiskScore'), false, 'confirm.ts must not invoke computeRiskScore');
  // No non-type curly import of RiskTier (runtime form).
  const runtimeCurly = src!.match(/^import \{[^}]*RiskTier/gm) || [];
  // The only match should be the `import type { ... }` (which won't match the `import {` pattern).
  assert.equal(runtimeCurly.length, 0, 'RiskTier must be type-only import');
});

test('T-CONF-REASONS-DETAIL-NOT-AUDITED-01: malicious detail string never appears in audit JSON line', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
    const maliciousDetail = 'recipient leak: attacker@evil.com password=hunter2 sk-1234567890';
    const result = generateCode(fp, {
      riskTier: 'medium',
      reasons: [fakeReason('api_key_pattern', 30, maliciousDetail)],
    });
    cap.restore();
    // Return shape MAY contain the detail (in-process Phase 6 elicit consumer).
    assert.equal(result.reasons![0]!.detail, maliciousDetail);
    // Audit boundary MUST strip detail.
    const audit = await readAuditLines(auditPath);
    const rawLine = JSON.stringify(audit[0]);
    assert.ok(!rawLine.includes('attacker@evil.com'));
    assert.ok(!rawLine.includes('hunter2'));
    assert.ok(!rawLine.includes('sk-1234567890'));
    // Only the signal ID survives:
    assert.deepEqual(audit[0]!.risk_reasons, ['api_key_pattern']);
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-CONF-LOCKOUT-INVARIANT-01: high-tier lockout still triggers at 5 failures', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp = actionFingerprint('send', { to: ['lock@x.com'] });
    generateCode(fp, { riskTier: 'high', reasons: [fakeReason('first_use', 20, 'd')] });
    // 5 wrong attempts trip the lockout window; 6th observes 'locked'.
    for (let i = 0; i < 5; i++) {
      const r = verifyCode(fp, '000000');
      assert.equal(r, 'wrong');
    }
    assert.equal(verifyCode(fp, '000000'), 'locked');
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('T-CONF-EXPIRY-INVARIANT-01: medium-tier expiry still returns expired', async () => {
  const restoreEnv = snapshotEnv();
  const { stateDir, auditPath } = makeSandbox();
  process.env.YANDEX_STATE_DIR = stateDir;
  process.env.YANDEX_AUDIT_LOG = auditPath;
  resetAll();
  const cap = captureStderr();
  try {
    const fp = actionFingerprint('send', { to: ['exp@x.com'] });
    const result = generateCode(fp, { riskTier: 'medium', reasons: [fakeReason('first_use', 20, 'd')] });
    _expireForTests(fp);
    assert.equal(verifyCode(fp, result.code as string), 'expired');
  } finally {
    cap.restore();
    restoreEnv();
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});
