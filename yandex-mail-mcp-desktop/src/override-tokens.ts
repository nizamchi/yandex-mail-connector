// override-tokens.ts -- block-tier override system (Phase 5 / Layer 1.5 v2.1.0).
//
// Threat model: a 'block'-tier send is refused by generateCode (no HMAC code
// minted; D2). To still proceed, the operator runs the out-of-band CLI
// `yandex-mail-mcp-trust --high-risk-send=<fingerprint>` which mints a 64-hex
// raw token, prints it on stdout, and persists a record (hash + nonce +
// expiry) to <state-dir>/override-tokens.jsonl. The LLM cannot read the CLI
// stdout (separate process), so the token transits via the human terminal
// into the elicit prompt or env var. Tokens are SINGLE-USE, FINGERPRINT-BOUND,
// and CROSS-PROCESS race-guarded (D5).
//
// Storage discipline:
//   - JSONL append-only-style file at <state-dir>/override-tokens.jsonl,
//     mode 0o600.
//   - We store SHA-256(rawToken).slice(0,32) as token_hash, NOT the raw token.
//     An attacker reading the file cannot replay -- they would need a
//     preimage to the SHA-256 hash.
//   - HMAC-SHA256 over (secret.bin || 'override:' || fingerprint || ':' || nonce)
//     produces the raw token. Domain prefix 'override:' is byte-disjoint from
//     allowlist.ts (empty prefix) and policy.ts ('policy:') -- prevents
//     cross-namespace HMAC replay. Pattern mirrors policy.ts:171-173.
//   - Atomic rewrite: write tmp, fs.renameSync -- mirrors allowlist.ts:143-153.
//
// Cross-process race guard (REV 2 B-4):
//   Two parallel MCP send_email tool calls can both reach consumeOverrideToken
//   for the same token. The original v2.0.0 read-filter-write window left a
//   TOCTOU race: both callers observe used_at_ms===null in cache and both
//   could mark the record used. The race guard re-reads the JSONL file just
//   before the atomic rewrite (synchronous, bypass cache), re-checks
//   used_at_ms, and rejects the loser as 'used'. Residual TOCTOU window
//   between the re-read and fs.renameSync is < 1 ms of synchronous syscall.
//   Documented in 05-01-PLAN.md threat T-05-01.
//
// secret.bin reuse (D7):
//   We do NOT generate the secret here. Phase 1 (policy.ts:loadSecret) owns
//   the lifecycle. If <state-dir>/secret.bin is missing at loadOverrideTokens
//   time, we call loadPolicy() once to trigger Phase 1's side-effect, then
//   re-read.
//
// FATAL recovery (D6 of Phase 1; same pattern):
//   On HMAC re-derivation mismatch during consumeOverrideToken (lookup hits
//   by token_hash but secret/fingerprint/nonce reproduction does not match),
//   we print a 3-step recovery banner and process.exit(1) via test-
//   substitutable hooks. Tampered token_hash is a different branch -- that
//   yields lookup-miss -> {ok:false, reason:'unknown'} with NO fatal exit.
//
// No `any`. ESM `.js` suffix on internal imports. ASCII-only.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHmac, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { getStateDir } from './state-dir.js';
import { loadPolicy } from './policy.js';
import { auditLog } from './audit.js';

// -- Constants -----------------------------------------------

const TTL_MS = 30 * 60 * 1000;          // 30 minutes
const FINGERPRINT_HEX_LEN = 32;
const TOKEN_BYTES = 32;                  // 32 raw bytes -> 64 hex chars (HMAC-SHA256 hex)
const SECRET_DOMAIN_PREFIX = 'override:';
const USED_GC_GRACE_MS = 7 * 86400_000;  // GC used records older than 7d
const EXPIRY_GC_GRACE_MS = 86400_000;    // GC expired records older than 1d

// -- Types (file-local) -------------------------------------

interface OverrideTokenRecord {
  fingerprint: string;       // 32 hex chars (narrow shape per D4)
  token_hash: string;        // sha256(rawToken).slice(0,32)
  nonce: string;             // 8 hex chars (randomBytes(4))
  minted_at_ms: number;
  expires_at_ms: number;
  used_at_ms: number | null;
}

// -- Module-local state -------------------------------------

let cache: OverrideTokenRecord[] = [];
let loaded = false;
let _fatalExit: (code: number) => never = (code) => process.exit(code);
let _fatalStderr: (msg: string) => void = (msg) => { process.stderr.write(msg); };

// -- Path resolution ----------------------------------------

function tokensPath(): string {
  return path.join(getStateDir(), 'override-tokens.jsonl');
}

function secretPath(): string {
  return path.join(getStateDir(), 'secret.bin');
}

// -- Secret access (D7 indirect-init pattern) ---------------
// We do NOT call randomBytes here. Phase 1 owns secret.bin lifecycle.

function loadSecret(): Buffer {
  const p = secretPath();
  if (!fs.existsSync(p)) {
    // Trigger Phase 1's side effect (writes secret.bin).
    loadPolicy();
  }
  const buf = fs.readFileSync(p);
  if (buf.length !== 32) {
    throw new Error(
      `override-tokens: secret.bin at ${p} has unexpected length ${buf.length} (expected 32). ` +
      `Delete the file to regenerate via policy.ts (this wipes allowlist trust + invalidates ALL override-tokens).`
    );
  }
  return buf;
}

// -- FATAL hook seam (mirrors policy.ts:217-228) ------------

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
  const p = tokensPath();
  _fatalStderr(
    `\nFATAL: override-tokens.jsonl ${reason}.\n` +
    `  Recovery options:\n` +
    `    1. Delete ${p} -- all minted tokens become invalid (operator must re-mint via CLI).\n` +
    `    2. Restore from backup if you have one.\n` +
    `    3. Phase 7 rotation flow will rewrite override-tokens.jsonl alongside policy.json + allowlist.json.\n\n`
  );
  return _fatalExit(1);
}

// -- Atomic write helper (mirrors allowlist.ts:143-153) -----

function atomicWriteJsonl(target: string, records: readonly OverrideTokenRecord[]): void {
  // Prune dead records before writing -- bounded growth (T-05-12).
  const now = Date.now();
  const live = records.filter((r) => {
    if (r.used_at_ms !== null && (now - r.used_at_ms) > USED_GC_GRACE_MS) return false;
    if (now > r.expires_at_ms + EXPIRY_GC_GRACE_MS) return false;
    return true;
  });
  const body = live.map((r) => JSON.stringify(r)).join('\n') + (live.length > 0 ? '\n' : '');
  const tmp = target + '.tmp';
  try {
    fs.writeFileSync(tmp, body, { mode: 0o600 });
    fs.renameSync(tmp, target);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    throw new Error(`atomicWriteJsonl(${target}): ${err.message ?? String(e)}`);
  }
}

// -- Fresh-read helper (REV 2 B-4 race guard) ---------------
// Reads JSONL directly from disk, BYPASSING cache. Used by the race guard
// step 9 in consumeOverrideToken AND by the post-write re-read in
// mintOverrideToken / consumeOverrideToken.
//
// REV 3 WR-01: on parse error we MUST recoverFatal -- symmetric with
// loadOverrideTokens. The previous "return [] on parse error" policy was
// a silent-data-loss vector: a corrupt line after a successful write
// would empty the cache, and because `loaded === true` was already set
// inside mint/consume, the next call would skip loadOverrideTokens and
// see an empty cache forever -- every existing token becomes
// reason='unknown' until process restart. recoverFatal mirrors the
// loadOverrideTokens corruption-detect policy (recovery banner +
// process.exit(1) via test-substitutable hooks).

function _readJsonlFresh(): OverrideTokenRecord[] {
  const p = tokensPath();
  let raw: string;
  try {
    raw = fs.readFileSync(p, 'utf-8');
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === 'ENOENT') return [];
    throw e;
  }
  const out: OverrideTokenRecord[] = [];
  const lines = raw.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined || line.length === 0) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(line);
    } catch (e) {
      const err = e as Error;
      // REV 3 WR-01: mirror loadOverrideTokens. Parse failure on a primitive
      // used both as race guard AND as post-write re-read MUST be loud, not
      // silent. Silent return [] previously masked corruption + emptied
      // cache + dropped all future consumes to reason='unknown'.
      recoverFatal('parse failed during fresh-read at line ' + (i + 1) + ': ' + err.message);
    }
    if (validateRecord(obj)) out.push(obj);
  }
  return out;
}

// -- Record validation --------------------------------------

function validateRecord(obj: unknown): obj is OverrideTokenRecord {
  if (typeof obj !== 'object' || obj === null) return false;
  const r = obj as Record<string, unknown>;
  if (typeof r.fingerprint !== 'string' || !/^[0-9a-f]{32}$/.test(r.fingerprint)) return false;
  if (typeof r.token_hash !== 'string' || !/^[0-9a-f]{32}$/.test(r.token_hash)) return false;
  if (typeof r.nonce !== 'string' || !/^[0-9a-f]{8}$/.test(r.nonce)) return false;
  if (typeof r.minted_at_ms !== 'number' || !Number.isFinite(r.minted_at_ms)) return false;
  if (typeof r.expires_at_ms !== 'number' || !Number.isFinite(r.expires_at_ms)) return false;
  if (r.used_at_ms !== null && (typeof r.used_at_ms !== 'number' || !Number.isFinite(r.used_at_ms))) return false;
  return true;
}

// -- Public API ---------------------------------------------

// D4: fingerprint preimage = sorted-recipients|subject|bodyLength|riskScore.
// PRIVACY INVARIANT: body CONTENT MUST NOT enter the preimage; only bodyLength.
// Locked by T-OVERRIDE-FINGERPRINT-PRIVACY-01 (function-body extract grep).
export function riskFingerprint(
  action: string,
  params: { recipients: readonly string[]; subject: string; bodyLength: number },
  riskScore: number,
): string {
  void action; // action is fed into actionFingerprint (confirm.ts), not riskFingerprint
  const sortedLowered = [...params.recipients]
    .map((r) => r.toLowerCase())
    .sort()
    .join(',');
  const preimage =
    sortedLowered + '|' +
    params.subject + '|' +
    String(params.bodyLength) + '|' +
    String(riskScore);
  return createHash('sha256').update(preimage).digest('hex').slice(0, 32);
}

export function loadOverrideTokens(): void {
  if (loaded) return;
  const p = tokensPath();
  let raw: string;
  try {
    raw = fs.readFileSync(p, 'utf-8');
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === 'ENOENT') {
      cache = [];
      loaded = true;
      return;
    }
    recoverFatal('read failed: ' + (err.message ?? String(e)));
  }
  const lines = raw.split('\n');
  const out: OverrideTokenRecord[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined || line.length === 0) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(line);
    } catch (e) {
      const err = e as Error;
      recoverFatal('parse failed at line ' + (i + 1) + ': ' + err.message);
    }
    if (!validateRecord(obj)) {
      recoverFatal('schema validation failed at line ' + (i + 1));
    }
    out.push(obj);
  }
  cache = out;
  loaded = true;
}

export function mintOverrideToken(fingerprint: string): {
  token: string;
  fingerprint: string;
  expiresAtMs: number;
} {
  if (!/^[0-9a-f]{32}$/.test(fingerprint)) {
    throw new Error(`mintOverrideToken: fingerprint must be exactly ${FINGERPRINT_HEX_LEN} hex chars`);
  }
  loadOverrideTokens();
  const secret = loadSecret();
  const nonce = randomBytes(4).toString('hex'); // 8 hex chars
  // Raw token: HMAC-SHA256(secret, 'override:' + fingerprint + ':' + nonce) -> 64 hex.
  const rawToken = createHmac('sha256', secret)
    .update(SECRET_DOMAIN_PREFIX + fingerprint + ':' + nonce)
    .digest('hex');
  void TOKEN_BYTES; // documents the byte size; HMAC-SHA256 hex output is 64 chars (32 bytes).
  const tokenHash = createHash('sha256').update(rawToken).digest('hex').slice(0, 32);
  const mintedAtMs = Date.now();
  const expiresAtMs = mintedAtMs + TTL_MS;
  const record: OverrideTokenRecord = {
    fingerprint,
    token_hash: tokenHash,
    nonce,
    minted_at_ms: mintedAtMs,
    expires_at_ms: expiresAtMs,
    used_at_ms: null,
  };
  cache.push(record);
  atomicWriteJsonl(tokensPath(), cache);
  // Re-read cache from disk so the in-memory mirror reflects post-prune state.
  cache = _readJsonlFresh();
  loaded = true;
  auditLog({
    action: 'override_token_minted',
    status: 'success',
    level: 'info',
    ts: new Date().toISOString(),
    reason: 'fp=' + fingerprint.slice(0, 8) + ',ttl_min=30',
  });
  return { token: rawToken, fingerprint, expiresAtMs };
}

// REV 3 WR-02 (STRIDE Repudiation closure): emit one audit record per
// denied consume attempt. Uses SHA-256(input).slice(0,16) for both the
// supplied token and the supplied fingerprint -- privacy-safe identifiers
// that let forensics correlate replay/probe attempts without ever
// revealing the raw token or full fingerprint hex. action is a NEW string
// ('override_consume_denied') deliberately distinct from
// 'override_token_consumed' (the success path), so a single grep over the
// audit log differentiates success vs denial.
function _auditDeniedConsume(
  suppliedToken: string,
  fingerprint: string,
  reason: 'used' | 'expired' | 'wrong_fingerprint' | 'unknown',
): void {
  const tokenIdHash = createHash('sha256').update(suppliedToken).digest('hex').slice(0, 16);
  const fingerprintHash = createHash('sha256').update(fingerprint).digest('hex').slice(0, 16);
  auditLog({
    action: 'override_consume_denied',
    status: 'denied',
    level: 'warn',
    ts: new Date().toISOString(),
    reason,
    token_id_hash: tokenIdHash,
    fingerprint_hash: fingerprintHash,
  });
}

export function consumeOverrideToken(
  fingerprint: string,
  token: string,
): { ok: true } | { ok: false; reason: 'unknown' | 'wrong_fingerprint' | 'used' | 'expired' | 'forged' } {
  loadOverrideTokens();

  // Step 2: hash supplied token.
  if (typeof token !== 'string' || token.length === 0) {
    // Empty/non-string token -- audit with reason='unknown'. Use empty
    // string as the suppliedToken for the hash (still privacy-safe; the
    // forensic value is just "a denial happened against this fingerprint").
    _auditDeniedConsume(typeof token === 'string' ? token : '', fingerprint, 'unknown');
    return { ok: false, reason: 'unknown' };
  }
  const suppliedHash = createHash('sha256').update(token).digest('hex').slice(0, 32);

  // Step 3: find by token_hash in cache (in-memory).
  let target: OverrideTokenRecord | undefined;
  for (const r of cache) {
    // timingSafeEqual on hex byte buffers (constant-time equality).
    const a = Buffer.from(r.token_hash, 'hex');
    const b = Buffer.from(suppliedHash, 'hex');
    if (a.length === b.length && a.length > 0) {
      try {
        if (timingSafeEqual(a, b)) {
          target = r;
          break;
        }
      } catch {
        // length mismatch / bad buffer -- skip.
      }
    }
  }

  // Step 4: not found -> unknown (tampered-token_hash branch).
  if (target === undefined) {
    _auditDeniedConsume(token, fingerprint, 'unknown');
    return { ok: false, reason: 'unknown' };
  }

  // Step 5: HMAC re-derivation defense-in-depth.
  // Recompute raw-token HMAC over (secret, 'override:' + fingerprint + ':' + nonce),
  // hash it, timingSafeEqual against record.token_hash. If mismatch -> FATAL
  // (tampered nonce / secret rotated / file corruption from another writer).
  const secret = loadSecret();
  const expectedRaw = createHmac('sha256', secret)
    .update(SECRET_DOMAIN_PREFIX + target.fingerprint + ':' + target.nonce)
    .digest('hex');
  const expectedHash = createHash('sha256').update(expectedRaw).digest('hex').slice(0, 32);
  const eA = Buffer.from(expectedHash, 'hex');
  const eB = Buffer.from(target.token_hash, 'hex');
  let hmacOk = false;
  if (eA.length === eB.length && eA.length > 0) {
    try {
      hmacOk = timingSafeEqual(eA, eB);
    } catch {
      hmacOk = false;
    }
  }
  if (!hmacOk) {
    recoverFatal('token_hash signature mismatch');
    // Unreachable in production; defensive return for tests that suppress fatal exit.
    return { ok: false, reason: 'forged' };
  }

  // Step 6: fingerprint binding (timing-safe).
  const fA = Buffer.from(target.fingerprint, 'hex');
  const fB = Buffer.from(fingerprint, 'hex');
  let fpOk = false;
  if (fA.length === fB.length && fA.length > 0) {
    try {
      fpOk = timingSafeEqual(fA, fB);
    } catch {
      fpOk = false;
    }
  }
  if (!fpOk) {
    _auditDeniedConsume(token, fingerprint, 'wrong_fingerprint');
    return { ok: false, reason: 'wrong_fingerprint' };
  }

  // Step 7: single-use (intra-process check).
  if (target.used_at_ms !== null) {
    _auditDeniedConsume(token, fingerprint, 'used');
    return { ok: false, reason: 'used' };
  }

  // Step 8: TTL check.
  if (Date.now() > target.expires_at_ms) {
    _auditDeniedConsume(token, fingerprint, 'expired');
    return { ok: false, reason: 'expired' };
  }

  // Step 9: RACE GUARD (REV 2 B-4) -- re-read JSONL from disk, re-check
  // used_at_ms, mutate, atomic-rewrite. Closes the read-filter-write TOCTOU
  // window between intra-process and cross-process consumers.
  const records2 = _readJsonlFresh();
  let target2Idx = -1;
  for (let i = 0; i < records2.length; i++) {
    const r = records2[i];
    if (r === undefined) continue;
    const a = Buffer.from(r.token_hash, 'hex');
    const b = Buffer.from(suppliedHash, 'hex');
    if (a.length === b.length && a.length > 0) {
      try {
        if (timingSafeEqual(a, b)) {
          target2Idx = i;
          break;
        }
      } catch {
        // skip
      }
    }
  }
  if (target2Idx === -1) {
    // Concurrent prune dropped the record (e.g. another writer reaped it).
    _auditDeniedConsume(token, fingerprint, 'unknown');
    return { ok: false, reason: 'unknown' };
  }
  const target2 = records2[target2Idx] as OverrideTokenRecord;
  if (target2.used_at_ms !== null) {
    // Concurrent consumer won the race.
    _auditDeniedConsume(token, fingerprint, 'used');
    return { ok: false, reason: 'used' };
  }
  target2.used_at_ms = Date.now();
  atomicWriteJsonl(tokensPath(), records2);
  cache = _readJsonlFresh();

  // Step 10: audit emission.
  auditLog({
    action: 'override_token_consumed',
    status: 'success',
    level: 'info',
    ts: new Date().toISOString(),
    reason: 'fp=' + fingerprint.slice(0, 8),
  });

  // Step 11: return ok.
  return { ok: true };
}

export function _resetForTests(): void {
  cache = [];
  loaded = false;
}
