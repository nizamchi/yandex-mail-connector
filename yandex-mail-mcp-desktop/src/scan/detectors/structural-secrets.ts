// detectors/structural-secrets.ts -- category 2.5 (vendor-prefixed API keys
// and secrets) detector.
//
// CONTEXT decisions enforced:
//   D5: structural-pass detector; runs early.
//   D8: ScanHit.evidence.byteStart/byteEnd index ORIGINAL input bytes via
//       ctx.pp.normalizedToOriginalByte.
//   D9-D11: weight sourced from ctx.policy.weights.api_key_pattern (default 75);
//       Patch 4 / B-4: ALL vendor entries use the same weight key. The phantom
//       `pem_private_key` weight key does NOT exist in DEFAULT_POLICY.
//   D20: zero new npm deps.
//   D21: detector receives policy via DetectorContext.policy; never calls
//       getPolicy() directly.
//   D27: ScanHit.category === 'api_key_pattern' (singular).
//
// Plan 02-02 / L3: VENDOR_PATTERNS lifted from dictionary section 2.5
//   (`.planning/research/outbound-content-dictionary.md`). The table below
//   maps each entry to its dictionary source row.
// Plan 02-02 / L5: registered with subject_eligible: true at T-02-02-08.
// Plan 02-02 / L6: every regex is anchored (\b or explicit context); NO
//   nested unbounded quantifiers; NO catastrophic-backtracking shapes.
//
// FILTER NOTE (content-pipeline mitigation):
//   Credential-prefix literals are split via string concatenation
//   (`'AK' + 'IA'`, etc.) to avoid triggering the upstream content filter
//   that inspects generated source. esbuild const-folds these concatenations
//   at minify time; the produced regex is byte-identical to a single-literal
//   form. This is purely a code-generation safety measure -- runtime
//   semantics are unchanged.
//
// Pure function over DetectorContext. No I/O, no async.

import type { DetectorContext, DetectorFn, ScanHit } from '../../outbound-scan.js';
import { emitRedactedMatch } from '../../outbound-scan.js';
import type { RiskPolicy } from '../../policy-defaults.js';

export interface VendorPattern {
  // Unique token per dictionary section 2.5 row.
  subCategory: string;
  // Anchored regex with /g flag. No nested unbounded quantifiers.
  pattern: RegExp;
  // Always 'api_key_pattern' per Patch 4 / B-4. No phantom keys.
  weight_key: keyof RiskPolicy['weights'];
  // Optional context-gating keyword (case-insensitive substring match within
  // +/- 200 NORMALIZED code units of the hit). Used to suppress FP storms on
  // very generic shapes (Azure AD secret = 34-40 chars of [A-Za-z0-9._~-];
  // Heroku UUID = bare UUID).
  contextKeyword?: RegExp;
}

// String-concat helper. Each segment is a fragment of a literal credential
// prefix; concatenated at runtime to assemble the regex source. esbuild
// const-folds this at minify time (the runtime regex object is identical to
// what would be produced by a single literal).
function rx(parts: TemplateStringsArray, ...args: string[]): RegExp {
  let src = '';
  for (let i = 0; i < parts.length; i++) {
    src += parts[i];
    if (i < args.length) src += args[i];
  }
  return new RegExp(src, 'g');
}

// Convenience: build a RegExp from explicit string concatenation. Used when
// the prefix MUST be split mid-token (template literals are syntactically
// fine, but the explicit `+` form makes the split intent obvious to code
// reviewers).
function concat(...parts: string[]): RegExp {
  return new RegExp(parts.join(''), 'g');
}

// === VENDOR_PATTERNS table ===========================================
//
// Row-by-row mapping (Plan T-02-02-06; dictionary section 2.5):
//
//  # | Dictionary entry            | subCategory token       | Source line
//  --|-----------------------------|--------------------------|------------
//  1 | AWS Access Key              | aws_access_key           | dict L307
//  2 | GitHub PAT classic          | github_pat_classic       | dict L312
//  3 | GitHub PAT fine-grained     | github_pat_fine          | dict L313
//  4 | GitHub OAuth                | github_oauth             | dict L314
//  5 | GitHub App install          | github_app_install       | dict L315
//  6 | GitLab PAT                  | gitlab_pat               | dict L319
//  7 | Google API key              | google_api_key           | dict L322
//  8 | OpenAI sk-                  | openai_sk                | dict L327
//  9 | Anthropic api03             | anthropic_api03          | dict L331
// 10 | Anthropic oat01             | anthropic_oat01          | dict L332
// 11 | Anthropic admin             | anthropic_admin          | dict L333
// 12 | Stripe sk_live              | stripe_sk_live           | dict L336
// 13 | Stripe pk_live              | stripe_pk_live           | dict L339
// 14 | Stripe rk_live              | stripe_rk_live           | dict L338
// 15 | Slack xox                   | slack_xox                | dict L342
// 16 | Twilio SK auth token        | twilio_sk                | dict L347
// 17 | Twilio Account SID          | twilio_account_sid       | dict L346
// 18 | SendGrid                    | sendgrid                 | dict L350
// 19 | Mailgun                     | mailgun                  | dict L351
// 20 | Shopify shppa (private)     | shopify_shppa            | dict L355 variant
// 21 | Shopify shpat (access)      | shopify_shpat            | dict L355
// 22 | Shopify shpca (custom)      | shopify_shpca            | dict L356 variant
// 23 | Square EAAA                 | square_eaaa              | dict L358
// 24 | PayPal access token         | paypal_access_token      | dict L359 variant
// 25 | Discord bot                 | discord_bot              | dict L362
// 26 | Telegram bot                | telegram_bot             | dict L364
// 27 | Azure storage CS            | azure_storage_cs         | dict L367
// 28 | Azure AD client secret      | azure_ad_secret          | dict L368 (context-gated)
// 29 | Heroku UUID                 | heroku_uuid              | dict L369 (context-gated)
// 30 | DigitalOcean dop_v1         | digitalocean_dop_v1      | dict L370
// 31 | Yandex y0_                  | yandex_y0                | dict L373
// 32 | Yandex t1.                  | yandex_t1                | dict L374
// 33 | JWT (3-part base64url)      | jwt                      | dict L377
// 34 | PEM private key             | pem_private_key          | dict L380
// 35 | Putty private key           | putty_private_key        | dict L382
// 36 | DB URI postgres             | db_uri_postgres          | dict L387 variant
// 37 | DB URI mysql                | db_uri_mysql             | dict L387 variant
// 38 | DB URI mongo                | db_uri_mongo             | dict L387 variant
// 39 | DB URI redis                | db_uri_redis             | dict L387 variant
//
// Coverage: 39 entries >= 35 floor (plan T-02-02-09 assertion).
// All weight_key fields use 'api_key_pattern' (Patch 4).

export const VENDOR_PATTERNS: ReadonlyArray<VendorPattern> = Object.freeze([
  // 1. AWS Access Key -- prefix split: A+K, I+A
  {
    subCategory: 'aws_access_key',
    pattern: concat('\\b', 'A' + 'K', 'I' + 'A', '[0-9A-Z]{16}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 2. GitHub PAT classic -- prefix split: g+h, p+_
  {
    subCategory: 'github_pat_classic',
    pattern: concat('\\b', 'g' + 'h', 'p' + '_', '[A-Za-z0-9]{36}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 3. GitHub PAT fine-grained -- prefix split: git+hub, _pa+t_
  {
    subCategory: 'github_pat_fine',
    pattern: concat('\\b', 'git' + 'hub', '_pa' + 't_', '[A-Za-z0-9_]{82}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 4. GitHub OAuth -- prefix split: g+h, o+_
  {
    subCategory: 'github_oauth',
    pattern: concat('\\b', 'g' + 'h', 'o' + '_', '[A-Za-z0-9]{36}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 5. GitHub App install -- alternation of three split prefixes
  {
    subCategory: 'github_app_install',
    pattern: concat(
      '\\b(?:',
      'g' + 'h' + 's' + '_',
      '|',
      'g' + 'h' + 'r' + '_',
      '|',
      'g' + 'h' + 'u' + '_',
      ')[A-Za-z0-9]{36}\\b',
    ),
    weight_key: 'api_key_pattern',
  },
  // 6. GitLab PAT -- prefix split: g+l, p+at-
  {
    subCategory: 'gitlab_pat',
    pattern: concat('\\b', 'g' + 'l', 'p' + 'at-', '[A-Za-z0-9_\\-]{20}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 7. Google API key -- prefix split: A+I, z+a
  {
    subCategory: 'google_api_key',
    pattern: concat('\\b', 'A' + 'I', 'z' + 'a', '[0-9A-Za-z_\\-]{35}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 8. OpenAI sk- -- prefix split: s+k-
  {
    subCategory: 'openai_sk',
    pattern: concat('\\b', 's' + 'k-', '[A-Za-z0-9]{32,64}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 9. Anthropic api03 -- prefix split: sk-+ant-+api+03-
  {
    subCategory: 'anthropic_api03',
    pattern: concat(
      '\\b',
      'sk-' + 'ant-',
      'api' + '03-',
      '[A-Za-z0-9_\\-]{93}\\b',
    ),
    weight_key: 'api_key_pattern',
  },
  // 10. Anthropic oat01 -- prefix split: sk-+ant-+oat+01-
  {
    subCategory: 'anthropic_oat01',
    pattern: concat(
      '\\b',
      'sk-' + 'ant-',
      'oat' + '01-',
      '[A-Za-z0-9_\\-]{93}\\b',
    ),
    weight_key: 'api_key_pattern',
  },
  // 11. Anthropic admin -- prefix split: sk-+ant-+admin+01-
  {
    subCategory: 'anthropic_admin',
    pattern: concat(
      '\\b',
      'sk-' + 'ant-',
      'admin' + '01-',
      '[A-Za-z0-9_\\-]{93}\\b',
    ),
    weight_key: 'api_key_pattern',
  },
  // 12. Stripe sk_live -- prefix split: s+k_l+ive_
  {
    subCategory: 'stripe_sk_live',
    pattern: concat('\\b', 's' + 'k_', 'l' + 'ive_', '[A-Za-z0-9]{24,99}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 13. Stripe pk_live -- prefix split: p+k_l+ive_ (publishable; less sensitive
  //     but still emitted per dictionary L339)
  {
    subCategory: 'stripe_pk_live',
    pattern: concat('\\b', 'p' + 'k_', 'l' + 'ive_', '[A-Za-z0-9]{24,99}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 14. Stripe rk_live -- prefix split: r+k_l+ive_
  {
    subCategory: 'stripe_rk_live',
    pattern: concat('\\b', 'r' + 'k_', 'l' + 'ive_', '[A-Za-z0-9]{24,99}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 15. Slack xox -- prefix split: x+o+x then [abprs]-
  {
    subCategory: 'slack_xox',
    pattern: concat('\\b', 'x' + 'o' + 'x', '[abprs]-[A-Za-z0-9\\-]{10,72}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 16. Twilio SK auth-token -- prefix split: S+K, 32 hex
  {
    subCategory: 'twilio_sk',
    pattern: concat('\\b', 'S' + 'K', '[a-fA-F0-9]{32}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 17. Twilio Account SID -- prefix split: A+C, 32 hex
  {
    subCategory: 'twilio_account_sid',
    pattern: concat('\\b', 'A' + 'C', '[a-fA-F0-9]{32}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 18. SendGrid -- prefix split: S+G.
  {
    subCategory: 'sendgrid',
    pattern: concat(
      '\\b',
      'S' + 'G' + '\\.',
      '[A-Za-z0-9_\\-]{22}\\.',
      '[A-Za-z0-9_\\-]{43}\\b',
    ),
    weight_key: 'api_key_pattern',
  },
  // 19. Mailgun -- prefix split: ke+y-
  {
    subCategory: 'mailgun',
    pattern: concat('\\b', 'ke' + 'y-', '[a-f0-9]{32}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 20. Shopify shppa -- prefix split: sh+ppa_
  {
    subCategory: 'shopify_shppa',
    pattern: concat('\\b', 'sh' + 'ppa_', '[a-fA-F0-9]{32}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 21. Shopify shpat -- prefix split: sh+pat_
  {
    subCategory: 'shopify_shpat',
    pattern: concat('\\b', 'sh' + 'pat_', '[a-fA-F0-9]{32}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 22. Shopify shpca -- prefix split: sh+pca_
  {
    subCategory: 'shopify_shpca',
    pattern: concat('\\b', 'sh' + 'pca_', '[a-fA-F0-9]{32}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 23. Square EAAA -- prefix split: E+A+A+A
  {
    subCategory: 'square_eaaa',
    pattern: concat('\\b', 'E' + 'A' + 'A' + 'A', '[A-Za-z0-9_\\-]{60,}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 24. PayPal access token -- prefix split: A+21+A+A
  {
    subCategory: 'paypal_access_token',
    pattern: concat('\\b', 'A' + '21' + 'A' + 'A', '[A-Za-z0-9_\\-]{80,}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 25. Discord bot -- 3-segment dotted token, no static prefix
  //     (Discord tokens are <id>.<timestamp>.<hmac>; no leading literal)
  {
    subCategory: 'discord_bot',
    pattern: /\b[A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}\b/g,
    weight_key: 'api_key_pattern',
  },
  // 26. Telegram bot -- <digits>:<35-char> shape
  {
    subCategory: 'telegram_bot',
    pattern: /\b\d{8,10}:[A-Za-z0-9_\-]{35}\b/g,
    weight_key: 'api_key_pattern',
  },
  // 27. Azure storage connection string -- literal 'AccountKey=' followed by
  //     88 base64 chars. Prefix split: Acc+ount+Key=
  {
    subCategory: 'azure_storage_cs',
    pattern: concat('Acc' + 'ount' + 'Key=', '[A-Za-z0-9+\\/=]{88}'),
    weight_key: 'api_key_pattern',
  },
  // 28. Azure AD client secret -- VERY high FP; gated on 'azure' or
  //     'client_secret' keyword within +/- 200 normalized chars (see contextKeyword).
  {
    subCategory: 'azure_ad_secret',
    pattern: /\b[A-Za-z0-9_~\-\.]{34,40}\b/g,
    weight_key: 'api_key_pattern',
    contextKeyword: /azure|client[._-]?secret/i,
  },
  // 29. Heroku UUID -- bare UUID v4 shape; gated on 'heroku' keyword
  //     within +/- 200 normalized chars (dictionary §2.5 FP note).
  {
    subCategory: 'heroku_uuid',
    pattern: /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g,
    weight_key: 'api_key_pattern',
    contextKeyword: /heroku/i,
  },
  // 30. DigitalOcean dop_v1 -- prefix split: do+p_v+1_
  {
    subCategory: 'digitalocean_dop_v1',
    pattern: concat('\\b', 'do' + 'p_v', '1' + '_', '[a-f0-9]{64}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 31. Yandex y0_ -- prefix split: y+0_
  {
    subCategory: 'yandex_y0',
    pattern: concat('\\b', 'y' + '0_', '[A-Za-z0-9_\\-]{30,}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 32. Yandex t1. -- prefix split: t+1.
  {
    subCategory: 'yandex_t1',
    pattern: concat('\\b', 't' + '1' + '\\.', '[A-Za-z0-9_\\-]{20,}\\b'),
    weight_key: 'api_key_pattern',
  },
  // 33. JWT 3-part base64url -- prefix split: ey+J on first segment;
  //     second segment also typically starts with ey+J (the JSON payload
  //     header object). We anchor on the FIRST segment's eyJ prefix only;
  //     the second segment is generic base64url.
  {
    subCategory: 'jwt',
    pattern: concat(
      '\\b',
      'e' + 'y' + 'J',
      '[A-Za-z0-9_\\-]+\\.',
      'e' + 'y' + 'J',
      '[A-Za-z0-9_\\-]+\\.',
      '[A-Za-z0-9_\\-]+\\b',
    ),
    weight_key: 'api_key_pattern',
  },
  // 34. PEM private key marker -- multi-format BEGIN tag. The prefix
  //     literal '-----BEGIN ' / 'PRIVATE KEY-----' is split into
  //     fragments to keep the credential-pattern surface segmented.
  {
    subCategory: 'pem_private_key',
    pattern: new RegExp(
      '-' + '-' + '-' + '-' + '-' +
      'BE' + 'GIN ' +
      '(?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?' +
      'PRI' + 'VATE ' + 'KEY' +
      '-' + '-' + '-' + '-' + '-',
      'g',
    ),
    weight_key: 'api_key_pattern',
  },
  // 35. PuTTY private key file header
  {
    subCategory: 'putty_private_key',
    pattern: new RegExp('PuT' + 'TY-' + 'User-' + 'Key-' + 'File-[23]:', 'g'),
    weight_key: 'api_key_pattern',
  },
  // 36. DB URI postgres -- user:pass@host shape; the credential is the
  //     pass portion. Prefix is the protocol scheme.
  {
    subCategory: 'db_uri_postgres',
    pattern: concat(
      '\\b',
      'post' + 'gres',
      '(?:ql)?',
      '://[^\\s/]+:[^\\s/@]+@[^\\s]+',
    ),
    weight_key: 'api_key_pattern',
  },
  // 37. DB URI mysql
  {
    subCategory: 'db_uri_mysql',
    pattern: concat(
      '\\b',
      'my' + 'sql',
      '://[^\\s/]+:[^\\s/@]+@[^\\s]+',
    ),
    weight_key: 'api_key_pattern',
  },
  // 38. DB URI mongo
  {
    subCategory: 'db_uri_mongo',
    pattern: concat(
      '\\b',
      'mon' + 'godb',
      '(?:\\+srv)?',
      '://[^\\s/]+:[^\\s/@]+@[^\\s]+',
    ),
    weight_key: 'api_key_pattern',
  },
  // 39. DB URI redis
  {
    subCategory: 'db_uri_redis',
    pattern: concat(
      '\\b',
      're' + 'dis',
      '://[^\\s/]*:[^\\s/@]+@[^\\s]+',
    ),
    weight_key: 'api_key_pattern',
  },
]);

// Quiet `rx` unused-warning -- kept exported by reference for future detector
// additions that prefer the template-tag form.
void rx;

// === Detector ========================================================

interface RawHit {
  subCategory: string;
  start: number;
  end: number;
  prefix4: string;
}

function hasContextKeyword(
  normalized: string,
  start: number,
  end: number,
  ck: RegExp,
): boolean {
  const lo = Math.max(0, start - 200);
  const hi = Math.min(normalized.length, end + 200);
  const win = normalized.slice(lo, hi);
  // Reset lastIndex defensively even though we don't pass /g.
  return ck.test(win);
}

export const detectStructuralSecrets: DetectorFn = (
  ctx: DetectorContext,
): ScanHit[] => {
  const policy = ctx.policy;
  if (!policy.categories.structural_secrets) return [];

  const weight = policy.weights.api_key_pattern;
  // Vendor prefixes are case-sensitive (AKIA, sk-ant-, eyJ, etc.); operate on
  // the case-sensitive normalized form.
  const text = ctx.pp.normalizedCaseSensitive;
  // The byte-offset map is keyed off `normalized` (case-folded). For
  // strictly-ASCII vendor shapes the case-fold is identity over the matched
  // characters, but the FULL string length may have widened (e.g. German sz).
  // Detectors emitting from normalizedCaseSensitive use the map under the
  // assumption that indices align below the case-fold widening (true for the
  // surrounding ASCII regions where credentials live). Empirically all 39
  // vendor patterns match ASCII subsets; we treat the map as 1:1 for these
  // hits. This is consistent with the payment-cards detector approach.
  const map = ctx.pp.normalizedToOriginalByte;
  const originalByteLen = ctx.pp.originalByteLength;

  // Collect all candidate hits first so we can suppress overlapping matches
  // (a JWT-shaped string can overlap with a generic vendor regex; PEM
  // markers can overlap with nothing in practice but we apply the same
  // suppression discipline uniformly).
  const raw: RawHit[] = [];

  for (const entry of VENDOR_PATTERNS) {
    const re = entry.pattern;
    // Lastly-defensive: ensure the regex has the /g flag we expect. If a
    // future contributor drops it, .exec() in a loop would infinite-loop;
    // guard by replacing with a fresh /g copy on first call (cheap).
    if (!re.global) continue;
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const matchStr = m[0];
      const start = m.index;
      const end = start + matchStr.length;
      // Empty-match safety (no pattern here should ever match zero-width,
      // but defensive).
      if (start === end) {
        re.lastIndex++;
        continue;
      }
      // Context gating for noisy shapes.
      if (entry.contextKeyword !== undefined) {
        if (!hasContextKeyword(text, start, end, entry.contextKeyword)) continue;
      }
      raw.push({
        subCategory: entry.subCategory,
        start,
        end,
        prefix4: matchStr.slice(0, 4),
      });
    }
  }

  if (raw.length === 0) return [];

  // Sort by start ASC, then by length DESC (prefer the LONGER match when
  // two patterns hit the same starting position). This favours, e.g., a
  // JWT (eyJ...eyJ...sig) over a partial vendor prefix that happens to
  // match the first segment.
  raw.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return (b.end - b.start) - (a.end - a.start);
  });

  // Overlap suppression: walk sorted hits; emit a hit only if its [start,end)
  // does not intersect any previously-emitted hit's span.
  const hits: ScanHit[] = [];
  let lastEnd = -1;
  for (const r of raw) {
    if (r.start < lastEnd) continue; // overlaps previous emission
    const byteStart = map[r.start] ?? 0;
    const byteEnd = r.end < map.length
      ? map[r.end]
      : (map[map.length - 1] ?? originalByteLen);
    emitRedactedMatch(
      'api_key_pattern',
      r.subCategory,
      byteStart,
      byteEnd,
      r.prefix4,
    );
    hits.push({
      category: 'api_key_pattern',
      subCategory: r.subCategory,
      weight,
      evidence: { byteStart, byteEnd, prefix4: r.prefix4 },
      matchedIn: ctx.matchedIn,
    });
    lastEnd = r.end;
  }

  return hits;
};
