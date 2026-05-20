// policy.ts -- PMLF (Phase 1) risk-policy loader.
//
// Mirrors the HMAC sign/verify discipline of allowlist.ts (T-03 adds the
// actual signing in this file). Load-once per CONTEXT D7 -- no hot-reload;
// operator must restart the MCP server after editing risk-policy.json.
//
// File: <state-dir>/risk-policy.json (override: YANDEX_POLICY_FILE).
// Schema: RiskPolicySchema (Zod, strict, all keys required).
// Integrity: HMAC-SHA256 over 'policy:' + canonicalStringify(policy)
//            using shared <state-dir>/secret.bin (D1 domain prefix isolates
//            this from allowlist.ts which signs without a prefix).
// Anti-tamper: lowering thresholds.block without override_block_threshold:true
//              falls back to defaults + stderr warning (D3).
// First-launch (D5): write defaults, sign, stderr log.
// FATAL (D6): print 3-step recovery banner + process.exit(1) via test-
//             substitutable _fatalStderr / _fatalExit hooks (B-2).
//
// CRITICAL: this module does NOT import from allowlist.ts. canonicalStringify
// is copied verbatim into this file (W-2 mirror discipline, enforced by
// `npm run check:canonical-mirror` in T-10). Cross-module HMAC sharing risks
// accidental domain mixing (D1).
//
// No `any`. ESM `.js` suffix on internal imports.

import * as fs from 'node:fs';
import * as path from 'node:path';
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

// ── Path resolution ───────────────────────────────────────────

export function getPolicyPath(): string {
  const explicit = process.env.YANDEX_POLICY_FILE;
  if (explicit !== undefined && explicit.length > 0) {
    return path.resolve(explicit);
  }
  return path.join(getStateDir(), 'risk-policy.json');
}

// ── FATAL recovery (stub; T-06 replaces with hook-based banner) ──

function recoverFatal(reason: string): never {
  throw new Error('FATAL: ' + reason);
}

// ── Public API ────────────────────────────────────────────────

export function loadPolicy(): RiskPolicy {
  const filePath = getPolicyPath();
  if (!fs.existsSync(filePath)) {
    // First-launch behavior added in T-05; for now return defaults without
    // writing.
    cachedPolicy = DEFAULT_POLICY;
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
  // T-03 will validate the wrapper shape; for now assume the parsed value
  // is the policy directly. Schema validation:
  try {
    const policy = RiskPolicySchema.parse(parsed);
    cachedPolicy = policy;
    loaded = true;
    return cachedPolicy;
  } catch (e) {
    const err = e as z.ZodError;
    recoverFatal('schema validation failed: ' + err.message);
  }
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
}
