// allowlist-comma-smuggling.test.ts -- TDD reproduction for BLOCKER B-1.
//
// Threat: yandex_send_email's TOFU allowlist gate uses a hand-rolled regex
// (extractAddr) to pull a single address out of each to[]/cc[]/bcc[] string.
// nodemailer downstream uses an RFC 5322 address-list parser that splits on
// top-level commas. The two parsers disagree on multi-address strings:
//
//   "Alice <alice@trusted.com>, attacker@evil.com"
//     extractAddr   -> "alice@trusted.com"            (1 addr; allowlist passes)
//     addressparser -> [alice@trusted.com, attacker@evil.com]  (2 addrs sent)
//
// Result: allowlist gate sees ONE address, SMTP delivers to TWO. The exfil
// address bypasses the gate completely. This is the primary defence against
// T-INT-03 (BCC exfil via prompt injection) and a load-bearing v2.0.0 claim.
//
// Fix direction (per MILESTONE-v2.0.0-DEEP-REVIEW.md §B-1):
//   - normalizeRecipients() must parse each input string with nodemailer's
//     addressparser and return EVERY address it would extract, so that the
//     set of addresses the allowlist checks equals the set SMTP receives.
//   - The send pipeline must pass the NORMALIZED flat string[] to nodemailer
//     (each entry = exactly one bare address) so the two parsers cannot
//     diverge by construction.
//   - The Zod schema for to/cc/bcc must reject inputs whose element resolves
//     to more than one address (defence-in-depth at the boundary).
//
// Invariants (must NOT regress -- see debug file):
//   Quoted display name with comma: 'Display, Name <a@x.com>' is ONE address.
//
// All test cases reference T-B1-NN per the debug file.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  normalizeRecipients,
  countAddresses,
  type NormalizeResult,
} from '../recipients.js';

// ── T-B1-01: bracketed primary + bare smuggled second ──────────────────

test('T-B1-01: "Alice <alice@trusted.com>, attacker@evil.com" expands to TWO addresses', () => {
  const input = ['Alice <alice@trusted.com>, attacker@evil.com'];
  const r: NormalizeResult = normalizeRecipients(input);
  // After normalization the gate must see BOTH addresses, not just the first.
  assert.deepEqual(
    r.addresses.sort(),
    ['alice@trusted.com', 'attacker@evil.com'].sort(),
    'allowlist gate must see every address nodemailer would deliver to',
  );
  // And the normalized array fed to nodemailer must be flat (one addr per entry).
  for (const entry of r.normalized) {
    assert.equal(
      countAddresses(entry),
      1,
      `normalized entry "${entry}" must contain exactly one address`,
    );
  }
});

// ── T-B1-02: bare + bare (no brackets) ─────────────────────────────────

test('T-B1-02: "alice@trusted.com, evil@attacker.com" expands to TWO addresses', () => {
  const input = ['alice@trusted.com, evil@attacker.com'];
  const r: NormalizeResult = normalizeRecipients(input);
  assert.deepEqual(
    r.addresses.sort(),
    ['alice@trusted.com', 'evil@attacker.com'].sort(),
  );
  for (const entry of r.normalized) {
    assert.equal(countAddresses(entry), 1);
  }
});

// ── T-B1-03: cc / bcc paths share the same normalizer ──────────────────

test('T-B1-03: cc and bcc strings are normalized with the same guarantees', () => {
  // We exercise the normalizer with arrays representing cc/bcc inputs.
  const cc = normalizeRecipients(['"CC One" <cc1@trusted.com>, smuggled-cc@evil.com']);
  assert.deepEqual(cc.addresses.sort(), ['cc1@trusted.com', 'smuggled-cc@evil.com'].sort());

  const bcc = normalizeRecipients(['bcc@trusted.com, exfil@evil.com, more@evil.com']);
  assert.deepEqual(
    bcc.addresses.sort(),
    ['bcc@trusted.com', 'exfil@evil.com', 'more@evil.com'].sort(),
  );
  for (const entry of bcc.normalized) {
    assert.equal(countAddresses(entry), 1);
  }
});

// ── T-B1-04: RFC 5322 group syntax policy ──────────────────────────────
// Policy chosen: EXPAND. addressparser({flatten:true}) walks groups and
// returns all members as a flat list, which means each member goes through
// the allowlist gate individually. This is the safe default: a group that
// contains an untrusted member is rejected as a whole, because at least one
// member will fail the gate.

test('T-B1-04: group syntax "Group: a@x.com, b@x.com;" is expanded; every member is gated', () => {
  const r = normalizeRecipients(['Friends: alice@trusted.com, bob@evil.com;']);
  // Both group members must appear in the address set so isAllowed sees each.
  assert.ok(r.addresses.includes('alice@trusted.com'), 'group member alice must be visible to gate');
  assert.ok(r.addresses.includes('bob@evil.com'), 'group member bob must be visible to gate');
  // Group expansion must yield flat entries -- nodemailer receives one addr per string.
  for (const entry of r.normalized) {
    assert.equal(countAddresses(entry), 1);
  }
});

// ── T-B1-05: false-positive guard -- quoted display name with comma ────
// "Doe, Jane <jane@trusted.com>" is ONE address in RFC 5322. A naive
// "reject any string with a comma" implementation would falsely reject it.

test('T-B1-05: quoted display name with comma stays a single address (no false reject)', () => {
  const r = normalizeRecipients(['"Doe, Jane" <jane@trusted.com>']);
  assert.equal(r.addresses.length, 1, 'quoted-display-name comma must not split into two addresses');
  assert.equal(r.addresses[0], 'jane@trusted.com');
  assert.equal(r.normalized.length, 1);
  assert.equal(countAddresses(r.normalized[0] ?? ''), 1);
});

// ── T-B1-06: addresses are lowercased + de-duplicated (case-insensitive set) ──

test('T-B1-06: addresses are normalized to lowercase and de-duplicated', () => {
  const r = normalizeRecipients(['ALICE@TRUSTED.COM', 'alice@trusted.com', 'Alice <alice@trusted.com>']);
  assert.deepEqual(r.addresses, ['alice@trusted.com'], 'case-insensitive dedupe expected');
});

// ── T-B1-07: empty/whitespace inputs are dropped without crashing ──────

test('T-B1-07: empty + whitespace-only entries are dropped (no throw, no empty addresses)', () => {
  const r = normalizeRecipients(['', '   ', 'alice@trusted.com']);
  assert.deepEqual(r.addresses, ['alice@trusted.com']);
  for (const entry of r.normalized) {
    assert.ok(entry.trim().length > 0, 'normalized must not contain empty/whitespace entries');
    assert.equal(countAddresses(entry), 1);
  }
});

// ── T-B1-08: parity with addressparser (ground truth) ──────────────────
// This test confirms that normalizeRecipients() produces the SAME set of
// addresses that nodemailer's addressparser would extract when given the
// same input joined with ", ". This is the load-bearing invariant:
//   set(allowlist-checked) === set(SMTP-delivered).

test('T-B1-08: normalizer parity with nodemailer addressparser ground truth', () => {
  // We re-import addressparser here as ground truth -- same parser nodemailer
  // uses internally when building the envelope.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const addressparser = require('nodemailer/lib/addressparser') as (s: string, opts?: { flatten?: boolean }) => Array<{ address: string; name: string }>;
  const cases: string[][] = [
    ['Alice <alice@trusted.com>, attacker@evil.com'],
    ['a@x.com, b@y.com, c@z.com'],
    ['"Doe, Jane" <jane@trusted.com>'],
    ['Friends: alice@trusted.com, bob@evil.com;'],
  ];
  for (const inputArr of cases) {
    const r = normalizeRecipients(inputArr);
    const ground = new Set<string>();
    for (const s of inputArr) {
      for (const parsed of addressparser(s, { flatten: true })) {
        if (parsed.address) ground.add(parsed.address.toLowerCase());
      }
    }
    assert.deepEqual(
      new Set(r.addresses),
      ground,
      `normalizer must match addressparser ground-truth for input ${JSON.stringify(inputArr)}`,
    );
  }
});
