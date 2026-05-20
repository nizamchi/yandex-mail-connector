// policy.ts -- PMLF (Phase 1) risk-policy loader.
//
// Mirrors the HMAC sign/verify discipline of allowlist.ts. Load-once per
// CONTEXT D7 -- no hot-reload; operator must restart the MCP server after
// editing risk-policy.json.
//
// File: <state-dir>/risk-policy.json (override: YANDEX_POLICY_FILE).
// Schema: RiskPolicySchema (Zod, strict, all keys required).
// Integrity: HMAC-SHA256 over 'policy:' + canonicalStringify(policy) using
//            shared <state-dir>/secret.bin (D1 domain prefix isolates this
//            from allowlist.ts which signs without a prefix).
// Anti-tamper: lowering thresholds.block without override_block_threshold:true
//              falls back to defaults + stderr warning (D3).
// First-launch (D5): write defaults, sign, stderr log.
// FATAL (D6): print 3-step recovery banner + process.exit(1) via test-
//             substitutable _fatalStderr / _fatalExit hooks (B-2).
//
// Coupling constraint (R-6): secret.bin is shared with allowlist.ts. Phase 7
// rotation flow MUST resign both allowlist.json AND risk-policy.json in one
// transaction. Phase 1 does no rotation.
//
// CRITICAL: this module does NOT import from allowlist.ts. canonicalStringify
// is copied verbatim into this file (W-2 mirror discipline, enforced by
// `npm run check:canonical-mirror` in T-10). Cross-module HMAC sharing risks
// accidental domain mixing (D1).
//
// No `any`. ESM `.js` suffix on internal imports.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';

import { getStateDir } from './state-dir.js';
import { DEFAULT_POLICY, type RiskPolicy } from './policy-defaults.js';

// ── Zod schema ────────────────────────────────────────────────
// Every key in DEFAULT_POLICY appears here as required (no .optional()).
// .strict() rejects unknown keys -- both operator typos and attacker-
// injected extra fields. Numeric weight + threshold + window fields use
// z.number().int().nonnegative() -- negative weights make no semantic
// sense and would invert tier ordering.

const weightsSchema = z.object({
  new_trust: z.number().int().nonnegative(),
  first_use: z.number().int().nonnegative(),
  just_auto_trusted: z.number().int().nonnegative(),
  base64_in_body: z.number().int().nonnegative(),
  api_key_pattern: z.number().int().nonnegative(),
  emails_in_body: z.number().int().nonnegative(),
  payment_card: z.number().int().nonnegative(),
  govt_id: z.number().int().nonnegative(),
  medical_secret: z.number().int().nonnegative(),
  medical_elevated: z.number().int().nonnegative(),
  classified_marking: z.number().int().nonnegative(),
  crypto_seed: z.number().int().nonnegative(),
  data_shape_anomaly: z.number().int().nonnegative(),
  post_read_send: z.number().int().nonnegative(),
  cross_thread: z.number().int().nonnegative(),
  multi_recipient: z.number().int().nonnegative(),
  large_body: z.number().int().nonnegative(),
  burst_pattern: z.number().int().nonnegative(),
}).strict();

const thresholdsSchema = z.object({
  augment: z.number().int().nonnegative(),
  strict: z.number().int().nonnegative(),
  block: z.number().int().nonnegative(),
}).strict();

const categoriesSchema = z.object({
  payment_cards: z.boolean(),
  ru_banking: z.boolean(),
  govt_ids: z.boolean(),
  credentials_fuzzy: z.boolean(),
  structural_secrets: z.boolean(),
  crypto_web3: z.boolean(),
  medical: z.boolean(),
  classified_markings: z.boolean(),
  exfil_phrases: z.boolean(),
  data_shapes: z.boolean(),
  demographic_pii: z.boolean(),
}).strict();

export const RiskPolicySchema = z.object({
  version: z.literal(1),
  weights: weightsSchema,
  thresholds: thresholdsSchema,
  outbound_keywords: z.array(z.string()),
  blocked_domains: z.array(z.string()),
  provenance_window_sec: z.number().int().nonnegative(),
  burst_window_sec: z.number().int().nonnegative(),
  burst_threshold: z.number().int().nonnegative(),
  categories: categoriesSchema,
  override_block_threshold: z.boolean(),
}).strict();

// ── Module-locals ─────────────────────────────────────────────

let cachedPolicy: RiskPolicy | null = null;
let loaded: boolean = false;
let secretCache: Buffer | null = null;

// ── Path resolution ───────────────────────────────────────────

export function getPolicyPath(): string {
  const explicit = process.env.YANDEX_POLICY_FILE;
  if (explicit !== undefined && explicit.length > 0) {
    return path.resolve(explicit);
  }
  return path.join(getStateDir(), 'risk-policy.json');
}

function secretPath(): string {
  return path.join(getStateDir(), 'secret.bin');
}

// ── Secret management ─────────────────────────────────────────
// IDENTICAL semantics to allowlist.ts loadSecret. The secret file is SHARED
// with allowlist.ts -- domain prefix isolates the two HMAC users (D1).

function loadSecret(): Buffer {
  if (secretCache !== null) return secretCache;
  const p = secretPath();
  if (fs.existsSync(p)) {
    const buf = fs.readFileSync(p);
    if (buf.length !== 32) {
      throw new Error(`policy secret at ${p} has unexpected length ${buf.length} (expected 32). Delete the file to regenerate (this wipes all allowlist trust too).`);
    }
    secretCache = buf;
    return buf;
  }
  const buf = randomBytes(32);
  atomicWrite(p, buf, 0o600);
  secretCache = buf;
  return buf;
}

// ── Canonicalization ──────────────────────────────────────────
// MIRROR DISCIPLINE (W-2): this function is a byte-identical copy of
// canonicalStringify in src/allowlist.ts. If semantics change in either
// module, the change MUST land in BOTH modules in the same commit.
// Phase 6 refactor may extract this to src/canonical-json.ts; until then,
// the mirror is enforced by the grep gate in package.json scripts.test
// (see T-10 / `npm run check:canonical-mirror`).
function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalStringify).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k])).join(',') + '}';
}

// ── HMAC sign with 'policy:' domain prefix ────────────────────
// Domain prefix prevents allowlist.json signatures being replayed into
// risk-policy.json. Same secret.bin, different message preimages (D1).
function signPolicy(policy: RiskPolicy, secret: Buffer): string {
  return createHmac('sha256', secret).update('policy:' + canonicalStringify(policy)).digest('hex');
}

// ── Atomic write helper ───────────────────────────────────────
// Byte-identical pattern to allowlist.ts atomicWrite (W-2 mirror principle
// extends here in spirit; the bodies are short so no scripted gate).

function atomicWrite(target: string, data: Buffer | string, mode: number): void {
  const tmp = target + '.tmp';
  try {
    fs.writeFileSync(tmp, data, { mode });
    fs.renameSync(tmp, target);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    throw new Error(`atomicWrite to ${target} failed: ${err.message ?? String(e)}`);
  }
}

// ── File format ───────────────────────────────────────────────

interface PolicyFile {
  policy: RiskPolicy;
  signature: string;
}

function writePolicy(policy: RiskPolicy): void {
  const secret = loadSecret();
  const file: PolicyFile = {
    policy,
    signature: signPolicy(policy, secret),
  };
  atomicWrite(getPolicyPath(), JSON.stringify(file, null, 2), 0o600);
}

// ── FATAL recovery with test-substitutable hook seam (B-2) ─────
// Production wiring uses process.stderr.write + process.exit(1).
// Tests substitute via _setFatalHooksForTests so the in-process node:test
// runner is not killed when the FATAL path is exercised. Convention mirror:
// same underscore-prefix pattern as _resetForTests.
//
// Production code MUST NOT call _setFatalHooksForTests. The underscore
// prefix is the convention signal; the grep gate in package.json scripts
// (T-10) enforces no production caller exists outside __tests__/.

let _fatalExit: (code: number) => never = (code) => process.exit(code);
let _fatalStderr: (msg: string) => void = (msg) => { process.stderr.write(msg); };

export function _setFatalHooksForTests(opts: {
  exit?: (code: number) => never;
  stderr?: (msg: string) => void;
}): () => void {
  const prev = { exit: _fatalExit, stderr: _fatalStderr };
  if (opts.exit) _fatalExit = opts.exit;
  if (opts.stderr) _fatalStderr = opts.stderr;
  return () => { _fatalExit = prev.exit; _fatalStderr = prev.stderr; };
}

function recoverFatal(reason: string): never {
  const p = getPolicyPath();
  _fatalStderr(
    `\nFATAL: risk-policy.json ${reason}.\n` +
    `  Recovery options:\n` +
    `    1. Delete ${p} -- regenerates from defaults on next start.\n` +
    `    2. Restore from backup if you have one.\n` +
    `    3. Run yandex-mail-mcp-trust --policy reset to rewrite from defaults (Phase 7).\n\n`
  );
  return _fatalExit(1);
}

// ── Deep-freeze helper ────────────────────────────────────────
// Returned policy is frozen at top level + key sub-objects to prevent
// Phase 2+ consumers from mutating shared state.

function freezePolicy(p: RiskPolicy): RiskPolicy {
  return Object.freeze({
    ...p,
    weights: Object.freeze({ ...p.weights }),
    thresholds: Object.freeze({ ...p.thresholds }),
    categories: Object.freeze({ ...p.categories }),
    outbound_keywords: Object.freeze([...p.outbound_keywords]),
    blocked_domains: Object.freeze([...p.blocked_domains]),
  }) as RiskPolicy;
}

// ── Public API ────────────────────────────────────────────────

export function loadPolicy(): RiskPolicy {
  const explicit = process.env.YANDEX_POLICY_FILE;
  const usingExplicit = explicit !== undefined && explicit.length > 0;
  const filePath = getPolicyPath();

  if (!fs.existsSync(filePath)) {
    if (usingExplicit) {
      // Mirror token.ts M-2: an explicit override at a non-existent path is
      // almost always a typo. Auto-creating there could write 0o600 to an
      // unexpected location. Throw with a clear, actionable error.
      throw new Error(
        `YANDEX_POLICY_FILE=${explicit} (resolved: ${filePath}) is not readable. ` +
        `Unset YANDEX_POLICY_FILE to fall back to <state-dir>/risk-policy.json (auto-created with defaults), ` +
        `or create the file with valid policy + HMAC signature.`
      );
    }
    // First-launch (D5): write defaults + sign + stderr log.
    writePolicy(DEFAULT_POLICY);
    process.stderr.write(
      '[yandex-mail-mcp] risk-policy.json created at ' + filePath + ' with defaults\n'
    );
    cachedPolicy = freezePolicy(DEFAULT_POLICY);
    loaded = true;
    return cachedPolicy;
  }

  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    recoverFatal('read failed: ' + (err.message ?? String(e)));
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    const err = e as Error;
    recoverFatal('parse failed: ' + err.message);
  }

  // Wrapper shape: { policy: ..., signature: ... }
  if (
    typeof parsed !== 'object' || parsed === null ||
    typeof (parsed as { signature?: unknown }).signature !== 'string' ||
    typeof (parsed as { policy?: unknown }).policy !== 'object' ||
    (parsed as { policy?: unknown }).policy === null
  ) {
    recoverFatal('parse failed: risk-policy.json missing policy/signature wrapper');
  }
  const wrapper = parsed as PolicyFile;

  // Schema validation.
  let policy: RiskPolicy;
  try {
    policy = RiskPolicySchema.parse(wrapper.policy);
  } catch (e) {
    const err = e as z.ZodError;
    const details = err.issues.map(i => i.path.join('.') + ': ' + i.message).join('; ');
    recoverFatal('schema validation failed: ' + details);
  }

  // HMAC verification.
  let secret: Buffer;
  try {
    secret = loadSecret();
  } catch (e) {
    const err = e as Error;
    recoverFatal('secret.bin corruption: ' + err.message);
  }
  const expectedHex = signPolicy(policy, secret);
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  const actualBuf = Buffer.from(wrapper.signature, 'hex');
  if (expectedBuf.length !== actualBuf.length || expectedBuf.length === 0) {
    recoverFatal('signature invalid');
  }
  let sigOk = false;
  try {
    sigOk = timingSafeEqual(expectedBuf, actualBuf);
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    recoverFatal('signature invalid');
  }

  // Anti-tamper (D3): a forged file would already be rejected by HMAC above;
  // this branch handles the case where an attacker WITH the secret (or the
  // user themselves under prompt-injection coercion) lowered the block
  // threshold and re-signed. Only thresholds.block is protected -- lowering
  // augment/strict is intentionally allowed (D3).
  if (
    policy.thresholds.block < DEFAULT_POLICY.thresholds.block &&
    policy.override_block_threshold !== true
  ) {
    process.stderr.write(
      `[yandex-mail-mcp] policy rejected: block threshold lowered to ` +
      `${policy.thresholds.block} (default ${DEFAULT_POLICY.thresholds.block}) ` +
      `without override_block_threshold:true. Falling back to defaults. ` +
      `To accept lowered block threshold, set override_block_threshold:true in the file ` +
      `and re-sign by running 'yandex-mail-mcp-trust --policy reset' (Phase 7) or by ` +
      `deleting risk-policy.json to regenerate defaults.\n`
    );
    cachedPolicy = freezePolicy(DEFAULT_POLICY);
    loaded = true;
    return cachedPolicy;
  }

  cachedPolicy = freezePolicy(policy);
  loaded = true;
  return cachedPolicy;
}

export function getPolicy(): RiskPolicy {
  if (!loaded) {
    throw new Error('getPolicy() called before loadPolicy()');
  }
  return cachedPolicy ?? DEFAULT_POLICY;
}

export function _resetForTests(): void {
  cachedPolicy = null;
  loaded = false;
  secretCache = null;
}
