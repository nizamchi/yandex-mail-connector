// detectors/credentials.ts -- category 2.4 (credentials & secrets fuzzy keywords).
//
// CONTEXT decisions enforced:
//   D5: structural-pass detector position (keyword shape).
//   D8: ScanHit.evidence.byteStart/byteEnd index ORIGINAL bytes via map.
//   D9-D11: per-keyword weight = ctx.policy.weights.outbound_keyword (10);
//           per-scan cap = ctx.policy.weights.outbound_keyword_cap (40).
//           Excess overflow drops lowest-weight hits first.
//   D12 carry (scoped to 2.4): hits are buffered as credentials_fuzzy and
//           PROMOTED by the orchestrator's pendingCat24 hook ONLY if at least
//           one realHit (any non-credentials_fuzzy hit) OR another cat-2.4 hit
//           lives within +/- 200 NORMALIZED JS code units of the pending hit
//           (per L4 / Patch 6 / B-2.2).
//   D21: detector receives policy via DetectorContext.
//   D27: ScanHit.category === 'credentials_fuzzy' singular.
//
// The hook body itself (applyCompanionCheck) lands in T-02-02-08 as part of
// orchestrator wiring. This detector just emits the buffered hits along with
// the normalized window index encoded in subCategory so the hook can do the
// O(N*M) distance check without re-tokenising the body.
//
// Keyword lists lifted verbatim from dictionary section 2.4 (RU + EN +
// extension cues). Case-folding already happened in ctx.pp.normalized.
//
// Pure function over DetectorContext.

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { emitRedactedMatch } from '../../outbound-scan.js';

// Keywords case-folded; matched against ctx.pp.normalized (also case-folded).
// All multi-word keywords use single-space separators (preprocess preserves
// runs of whitespace as-is; the W-01 fast path does not collapse them).
// We use \b boundaries on Latin-only tokens; for Cyrillic tokens we rely on
// lookahead/lookbehind via word-boundary anchors against \p{L} -- but since
// JavaScript's \b is ASCII-only, we anchor Cyrillic keywords with a
// preceding-and-following non-letter check (manual implementation in the
// scan loop below). For simplicity (and to avoid catastrophic-backtracking
// risk), each keyword is a literal substring; we scan via indexOf in a loop.
//
// Per-keyword shape: { token: string, subCategory: string }.
// subCategory is the canonical English tag stored in audit / hit metadata.

interface KeywordSpec {
  token: string;
  subCategory: string;
}

const KEYWORDS: ReadonlyArray<KeywordSpec> = Object.freeze([
  // RU password / passphrase
  { token: 'пароль',            subCategory: 'password' },
  { token: 'парольная фраза',   subCategory: 'passphrase' },
  { token: 'мой пароль',        subCategory: 'password' },
  { token: 'новый пароль',      subCategory: 'password' },
  { token: 'временный пароль',  subCategory: 'password' },
  // RU secret / token
  { token: 'секретный ключ',    subCategory: 'secret_key' },
  { token: 'секретный код',     subCategory: 'secret_code' },
  { token: 'ключ доступа',      subCategory: 'access_key' },
  { token: 'токен доступа',     subCategory: 'access_token' },
  { token: 'токен',             subCategory: 'token' },
  { token: 'секрет',            subCategory: 'secret' },
  { token: 'api-ключ',          subCategory: 'api_key' },
  { token: 'api ключ',          subCategory: 'api_key' },
  { token: 'апи-ключ',          subCategory: 'api_key' },
  { token: 'апи ключ',          subCategory: 'api_key' },
  // RU recovery / 2FA
  { token: 'резервный код',     subCategory: 'recovery_code' },
  { token: 'код восстановления',subCategory: 'recovery_code' },
  { token: 'кодовое слово',     subCategory: 'secret_question' },
  { token: 'двухфакторная',     subCategory: '2fa' },
  { token: '2fa',               subCategory: '2fa' },
  { token: 'otp',               subCategory: 'otp' },
  { token: 'отп-код',           subCategory: 'otp' },
  { token: 'смс-код',           subCategory: 'sms_code' },
  { token: 'смс с кодом',       subCategory: 'sms_code' },
  { token: 'пин-код',           subCategory: 'pin' },
  // RU file-extension cues
  { token: '.p12',              subCategory: 'cert_p12' },
  { token: '.pfx',              subCategory: 'cert_pfx' },
  { token: '.pem',              subCategory: 'cert_pem' },
  // EN password / passphrase
  { token: 'password',          subCategory: 'password' },
  { token: 'passwd',            subCategory: 'password' },
  { token: 'passphrase',        subCategory: 'passphrase' },
  { token: 'my password',       subCategory: 'password' },
  { token: 'your password',     subCategory: 'password' },
  { token: 'temporary password',subCategory: 'password' },
  { token: 'new password',      subCategory: 'password' },
  // EN secret / token
  { token: 'secret',            subCategory: 'secret' },
  { token: 'token',             subCategory: 'token' },
  { token: 'secret key',        subCategory: 'secret_key' },
  { token: 'client secret',     subCategory: 'client_secret' },
  { token: 'access key',        subCategory: 'access_key' },
  { token: 'access token',      subCategory: 'access_token' },
  { token: 'refresh token',     subCategory: 'refresh_token' },
  { token: 'bearer token',      subCategory: 'bearer_token' },
  { token: 'api key',           subCategory: 'api_key' },
  { token: 'api_key',           subCategory: 'api_key' },
  { token: 'apikey',            subCategory: 'api_key' },
  { token: 'api-key',           subCategory: 'api_key' },
  // EN recovery / 2FA / auth
  { token: 'recovery code',     subCategory: 'recovery_code' },
  { token: 'backup code',       subCategory: 'backup_code' },
  { token: 'one-time code',     subCategory: 'otp' },
  { token: 'one time password', subCategory: 'otp' },
  { token: 'mfa code',          subCategory: '2fa' },
  { token: '2fa code',          subCategory: '2fa' },
  { token: 'auth code',         subCategory: 'auth_code' },
  { token: 'pin code',          subCategory: 'pin' },
  { token: 'pin number',        subCategory: 'pin' },
]);

// Returns true if c is an ASCII letter, digit, underscore, or any Cyrillic
// letter or digit. Used as a manual word-boundary check so we don't have to
// rely on \b (which is ASCII-only).
function isWordChar(cp: number): boolean {
  if (cp >= 48 && cp <= 57) return true;   // 0-9
  if (cp >= 65 && cp <= 90) return true;   // A-Z
  if (cp >= 97 && cp <= 122) return true;  // a-z
  if (cp === 95) return true;              // _
  if (cp >= 0x0400 && cp <= 0x04FF) return true;  // Cyrillic
  return false;
}

// Returns true if the candidate match at [start, end) in `text` has
// non-word neighbours on both sides (or string boundary).
// Token-aware: if the token itself begins (resp. ends) with a non-word char,
// the left (resp. right) word-boundary check is bypassed -- the token's own
// boundary character already separates it from word chars on that side.
function isWordBoundary(text: string, start: number, end: number, tok: string): boolean {
  const tokStartIsWord = isWordChar(tok.charCodeAt(0));
  const tokEndIsWord = isWordChar(tok.charCodeAt(tok.length - 1));
  const beforeOk = !tokStartIsWord || start === 0 || !isWordChar(text.charCodeAt(start - 1));
  const afterOk = !tokEndIsWord || end === text.length || !isWordChar(text.charCodeAt(end));
  return beforeOk && afterOk;
}

export const detectCredentialsFuzzy: DetectorFn = (ctx: DetectorContext): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.credentials_fuzzy) return [];

  const perKeywordWeight = policy.weights.outbound_keyword;
  const cap = policy.weights.outbound_keyword_cap;

  const text = ctx.pp.normalized;
  const map = ctx.pp.normalizedToOriginalByte;
  const originalByteLen = ctx.pp.originalByteLength;
  const hits: ScanHit[] = [];

  // Track per-hit normalized start so the orchestrator's pendingCat24 hook
  // (installed in T-02-02-08) can do +/- 200 normalized-space distance
  // checks WITHOUT recomputing offsets through the original-byte map.
  // We encode the normalized index in subCategory as 'token:NNN' so the
  // hook can recover it without a side-channel. This is intentional per
  // plan T-02-02-08 spec ("subCategory: 'keyword:<token>'") and matches
  // the canonical D27 prefix (credentials_fuzzy) on category.

  for (const spec of KEYWORDS) {
    const tok = spec.token;
    let from = 0;
    while (from <= text.length - tok.length) {
      const idx = text.indexOf(tok, from);
      if (idx === -1) break;
      const end = idx + tok.length;
      from = end;  // advance past this match

      // Word-boundary check (anchored to L of either side).
      if (!isWordBoundary(text, idx, end, tok)) continue;

      // Cap enforcement -- if we'd exceed the cap, drop this hit. (Per plan:
      // "Excess overflow hits dropped (lowest weight first)." All our hits
      // share the same per-keyword weight, so dropping the newest is
      // equivalent to dropping the lowest-weight one in our flat model.
      // The promotion hook in T-02-02-08 may further re-rank.)
      const projected = hits.length * perKeywordWeight + perKeywordWeight;
      if (projected > cap) break;

      const byteStart = map[idx] ?? 0;
      const byteEnd = end < map.length ? map[end] : (map[map.length - 1] ?? originalByteLen);
      const prefix4 = tok.slice(0, 4);

      // Encode the normalized start index in subCategory so the cat-2.4
      // companion-check hook (T-02-02-08) can do distance math in
      // NORMALIZED-space per L4 without recomputing offsets.
      const taggedSub = `${spec.subCategory}:${idx}`;

      emitRedactedMatch('credentials_fuzzy', taggedSub, byteStart, byteEnd, prefix4);
      hits.push({
        category: 'credentials_fuzzy',
        subCategory: taggedSub,
        weight: perKeywordWeight,
        evidence: { byteStart, byteEnd, prefix4 },
        matchedIn: ctx.matchedIn,
      });
    }
    if (hits.length * perKeywordWeight >= cap) break;
  }

  return hits;
};
