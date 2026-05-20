// recipients.ts -- B-1 fix: parser-symmetric recipient normalization.
//
// Why this module exists
// ----------------------
// Pre-fix, yandex_send_email used a hand-rolled regex (`extractAddr`) to pull
// "one address per to[]/cc[]/bcc[] string" for the TOFU allowlist gate, while
// the SMTP layer handed the same raw strings to nodemailer's RFC 5322
// addressparser, which splits on top-level commas. The two parsers disagreed
// on inputs like:
//
//   "Alice <alice@trusted.com>, attacker@evil.com"
//
// -- the gate saw one address, SMTP delivered to two. Comma-smuggling
// bypassed the allowlist completely. This is BLOCKER B-1 from the v2.0.0
// deep review and a load-bearing claim against threat T-INT-03 (BCC exfil
// via prompt injection).
//
// What this module guarantees
// ---------------------------
// `normalizeRecipients(strings)` parses every input string with the SAME
// addressparser nodemailer uses internally, then returns:
//   - `addresses`: deduped, lowercase, ground-truth address set the gate
//                  must check.
//   - `normalized`: a FLAT string[] where each entry is exactly ONE address
//                   in `<addr>` form -- safe to hand to nodemailer because
//                   addressparser on each entry will never split further.
//
// By feeding the SAME normalized array to both the allowlist gate AND
// nodemailer, the set-equality invariant
//
//   set(addresses-allowlist-checked) === set(addresses-SMTP-will-receive)
//
// holds by construction.
//
// Library-signature verification (no tsc safety net -- see CLAUDE.md):
//   - @types/nodemailer/lib/addressparser/index.d.ts:28 confirms
//     `addressparser(s, { flatten: true })` returns `Address[]` with shape
//     `{ name: string; address: string }`. Verified 2026-05-20.
//   - nodemailer/lib/addressparser/index.js handles RFC 5322 groups
//     ("Group: a@x.com, b@y.com;"); flatten:true walks groups so every
//     member surfaces as an individual address (no group leakage).
//
// Test coverage: __tests__/allowlist-comma-smuggling.test.ts (T-B1-01..08).

// eslint-disable-next-line @typescript-eslint/no-require-imports
import addressparser = require('nodemailer/lib/addressparser');

export interface NormalizeResult {
  // Flat, deduped, lowercase address set. This is what isAllowed() must check
  // against the allowlist. Order is preserved from input scan order (first
  // appearance wins) for stable audit forensics.
  readonly addresses: readonly string[];

  // Flat string[] where every entry is exactly one address rendered as a
  // pure-address string ("addr@domain", no display name, no brackets). Safe
  // to hand to nodemailer; addressparser on each entry yields exactly one
  // address by construction.
  readonly normalized: readonly string[];
}

// Count how many addresses an arbitrary recipient string would yield when
// fed to nodemailer's addressparser. Used by the Zod schema refinement to
// reject smuggled inputs at the boundary (defence in depth).
export function countAddresses(s: string): number {
  if (typeof s !== 'string') return 0;
  const trimmed = s.trim();
  if (trimmed.length === 0) return 0;
  try {
    const parsed = addressparser(trimmed, { flatten: true });
    // Only count entries that actually have an address part. addressparser
    // can return phantom name-only entries on malformed input; those are
    // not deliverable, so they don't count.
    let n = 0;
    for (const e of parsed) {
      if (e.address && e.address.length > 0) n += 1;
    }
    return n;
  } catch {
    // Conservative: malformed input that the parser cannot read counts as
    // zero addresses -- the Zod schema treats "no address" as a separate
    // failure mode (`min(1)` on the array stays in force).
    return 0;
  }
}

// Validate that every element of a recipient array resolves to AT MOST one
// address. This is the boundary check the Zod schema refinement wires up.
// Returns null on success, or a stable string reason on failure that the
// schema can attach as the validation message.
export function validateNoSmuggling(arr: readonly string[] | undefined): string | null {
  if (arr === undefined) return null;
  for (let i = 0; i < arr.length; i += 1) {
    const s = arr[i] ?? '';
    const n = countAddresses(s);
    if (n > 1) {
      return `recipient[${i}] contains ${n} addresses; one address per entry only ` +
        `(comma-smuggling rejected -- use separate array entries for multiple recipients)`;
    }
  }
  return null;
}

// Core normalizer. Parses every input through addressparser (flatten:true so
// RFC 5322 groups are walked), lower-cases addresses, deduplicates, and
// rebuilds a flat single-address string[] suitable for nodemailer.
export function normalizeRecipients(input: readonly string[] | undefined): NormalizeResult {
  if (!input || input.length === 0) {
    return { addresses: [], normalized: [] };
  }
  const seen = new Set<string>();
  const addresses: string[] = [];
  const normalized: string[] = [];
  for (const raw of input) {
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    let parsed: ReadonlyArray<{ address: string; name: string }>;
    try {
      parsed = addressparser(trimmed, { flatten: true });
    } catch {
      // Skip unparseable entries. The schema/allowlist gate will reject the
      // overall send if no usable addresses survive (`to.min(1)`).
      continue;
    }
    for (const entry of parsed) {
      if (!entry.address || entry.address.length === 0) continue;
      const lower = entry.address.toLowerCase();
      if (seen.has(lower)) continue;
      seen.add(lower);
      addresses.push(lower);
      // Normalized SMTP entry: bare address (no display name). Display names
      // are an injection surface for SMTP command smuggling and the allowlist
      // gate ignores them anyway -- stripping is a feature, not a loss.
      normalized.push(lower);
    }
  }
  return { addresses, normalized };
}
