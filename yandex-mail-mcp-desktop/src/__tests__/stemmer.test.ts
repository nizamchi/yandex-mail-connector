import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { stem } from '../stemmer.js';

// The load-bearing property is COLLAPSE: every inflected form of a word must
// reduce to the SAME stem (so a token and the query form match), not any
// particular stem string.
function allSame(words: string[]): void {
  const stems = words.map(stem);
  const first = stems[0];
  for (let i = 1; i < stems.length; i++) {
    assert.equal(stems[i], first, `"${words[i]}" -> "${stems[i]}" must equal "${words[0]}" -> "${first}"`);
  }
}

// ── Russian (the priority case) ───────────────────────────────────────

test('RU: выписка / выписку / выписки / выписке / выпиской collapse', () => {
  allSame(['выписка', 'выписку', 'выписки', 'выписке', 'выпиской']);
});

test('RU: документ / документы / документа / документу / документом collapse', () => {
  allSame(['документ', 'документы', 'документа', 'документу', 'документом']);
});

test('RU: договор / договору / договоров / договором collapse', () => {
  allSame(['договор', 'договору', 'договоров', 'договором']);
});

test('RU: справка / справку / справки collapse', () => {
  allSame(['справка', 'справку', 'справки']);
});

test('RU: short words (<= 3 chars) are left intact', () => {
  for (const w of ['имя', 'он', 'до', 'я']) {
    assert.equal(stem(w), w.toLowerCase());
  }
});

// ── English ───────────────────────────────────────────────────────────

test('EN: invoice / invoices collapse (plural s, not es over-strip)', () => {
  allSame(['invoice', 'invoices']);
});

test('EN: report / reports / reporting / reported collapse', () => {
  allSame(['report', 'reports', 'reporting', 'reported']);
});

test('EN: statement / statements collapse', () => {
  allSame(['statement', 'statements']);
});

test('EN: business is not split (ss guard)', () => {
  assert.equal(stem('business'), 'business');
});

test('EN: ies -> i (cities/parties internally consistent)', () => {
  assert.equal(stem('cities'), 'citi');
  assert.equal(stem('parties'), 'parti');
});

// ── Robustness ────────────────────────────────────────────────────────

test('digits and non-alpha pass through unchanged', () => {
  assert.equal(stem('12345'), '12345');
  assert.equal(stem('2024'), '2024');
});

test('empty string passes through', () => {
  assert.equal(stem(''), '');
});

test('idempotent: stem(stem(x)) === stem(x)', () => {
  for (const w of ['выписку', 'документами', 'reporting', 'invoices', 'договоров']) {
    assert.equal(stem(stem(w)), stem(w), `stem must be idempotent for "${w}"`);
  }
});

test('lowercases before stemming (case-insensitive)', () => {
  assert.equal(stem('ВЫПИСКУ'), stem('выписку'));
  assert.equal(stem('Invoices'), stem('invoices'));
});
