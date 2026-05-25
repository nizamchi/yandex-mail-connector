// stats.test.ts -- unit tests for the pure aggregator.
//
// All 13 tests required by 20260525-yandex-stats-tool/PLAN.md §"Test plan".
// Each test constructs an in-memory async iterator of EnvelopeRow fixtures
// and asserts the aggregate() output shape -- no IMAP, no IO.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { aggregate, validateGroupBy, type EnvelopeRow, type GroupByField } from '../stats.js';

function mk(overrides: Partial<EnvelopeRow>): EnvelopeRow {
  return {
    uid: 1,
    from: [{ address: 'alice@example.com', name: 'Alice' }],
    to:   [{ address: 'you@example.com',   name: 'You' }],
    subject: 'hello',
    date: '2025-06-15T12:00:00.000Z',
    size: 5000,
    seen: true,
    flagged: false,
    hasAttachments: false,
    ...overrides,
  };
}

async function* fromArray(items: EnvelopeRow[]): AsyncIterable<EnvelopeRow> {
  for (const it of items) yield it;
}

// T1: single group_by sender counts unique senders correctly.
test('T1: sender group_by counts unique senders', async () => {
  const fixtures = [
    mk({ from: [{ address: 'a@x.com' }] }),
    mk({ from: [{ address: 'a@x.com' }] }),
    mk({ from: [{ address: 'b@y.com' }] }),
  ];
  const r = await aggregate(fromArray(fixtures), { groupBy: ['sender'] });
  assert.equal(r.total_scanned, 3);
  assert.equal(r.rows.length, 2);
  // Sorted by count desc -- a@x.com first with count=2.
  assert.deepEqual(r.rows[0].key, ['a@x.com']);
  assert.equal(r.rows[0].count, 2);
  assert.deepEqual(r.rows[1].key, ['b@y.com']);
  assert.equal(r.rows[1].count, 1);
});

// T2: single group_by year buckets by date.year UTC.
test('T2: year group_by buckets by date.year UTC', async () => {
  const fixtures = [
    mk({ date: '2024-01-01T00:00:00.000Z' }),
    mk({ date: '2024-12-31T23:00:00.000Z' }),
    mk({ date: '2025-06-15T12:00:00.000Z' }),
  ];
  const r = await aggregate(fromArray(fixtures), { groupBy: ['year'] });
  assert.equal(r.rows.length, 2);
  const byKey = new Map(r.rows.map(x => [x.key[0], x.count]));
  assert.equal(byKey.get('2024'), 2);
  assert.equal(byKey.get('2025'), 1);
});

// T3: composite ['year','domain'] -- composite key + sorted output.
test('T3: composite [year, domain] produces composite keys', async () => {
  const fixtures = [
    mk({ from: [{ address: 'x@vtb.ru' }],     date: '2025-01-01T00:00:00.000Z' }),
    mk({ from: [{ address: 'y@vtb.ru' }],     date: '2025-06-01T00:00:00.000Z' }),
    mk({ from: [{ address: 'z@sber.ru' }],    date: '2024-03-01T00:00:00.000Z' }),
  ];
  const r = await aggregate(fromArray(fixtures), { groupBy: ['year', 'domain'] });
  assert.equal(r.rows.length, 2);
  assert.deepEqual(r.rows[0].key, ['2025', 'vtb.ru']);   // count=2
  assert.equal(r.rows[0].count, 2);
  assert.deepEqual(r.rows[1].key, ['2024', 'sber.ru']);
  assert.equal(r.rows[1].count, 1);
});

// T4: top_n cap -- truncated=true, rows.length === top_n.
test('T4: top_n cap sets truncated and trims', async () => {
  const fixtures: EnvelopeRow[] = [];
  for (let i = 0; i < 20; i++) {
    // Each unique sender appears (i+1) times so count desc is well-defined.
    for (let j = 0; j <= i; j++) {
      fixtures.push(mk({ from: [{ address: `s${i}@x.com` }], uid: i * 100 + j }));
    }
  }
  const r = await aggregate(fromArray(fixtures), { groupBy: ['sender'], topN: 5 });
  assert.equal(r.truncated, true);
  assert.equal(r.rows.length, 5);
  // Highest count first (i=19 -> 20 emails).
  assert.equal(r.rows[0].count, 20);
  assert.equal(r.rows[0].key[0], 's19@x.com');
});

// T5: date filter since+until counts only matching envelopes.
test('T5: date filter since+until restricts scan', async () => {
  const fixtures = [
    mk({ date: '2024-01-01T00:00:00.000Z' }),  // outside (before since)
    mk({ date: '2025-03-15T00:00:00.000Z' }),  // in range
    mk({ date: '2025-06-15T00:00:00.000Z' }),  // in range
    mk({ date: '2026-01-01T00:00:00.000Z' }),  // outside (after until)
  ];
  const r = await aggregate(fromArray(fixtures), {
    groupBy: ['year'],
    since: '2025-01-01T00:00:00.000Z',
    until: '2025-12-31T23:59:59.000Z',
  });
  assert.equal(r.total_scanned, 2);
  assert.equal(r.rows.length, 1);
  assert.deepEqual(r.rows[0].key, ['2025']);
  assert.equal(r.rows[0].count, 2);
});

// T6: missing fields bucket as <unknown>, do not crash.
test('T6: missing fields bucket as <unknown>', async () => {
  const fixtures = [
    mk({ from: [] }),                                      // no from
    mk({ date: '' }),                                      // no date
    mk({ to: [] }),                                        // no to
  ];
  // sender on first
  const rSender = await aggregate(fromArray([fixtures[0]]), { groupBy: ['sender'] });
  assert.equal(rSender.rows[0].key[0], '<unknown>');
  // year on second (no date)
  const rYear = await aggregate(fromArray([fixtures[1]]), { groupBy: ['year'] });
  assert.equal(rYear.rows[0].key[0], '<unknown>');
  // to_first on third
  const rTo = await aggregate(fromArray([fixtures[2]]), { groupBy: ['to_first'] });
  assert.equal(rTo.rows[0].key[0], '<unknown>');
});

// T7: subject prefix detection across variants.
test('T7: subject_prefix classifies Re/Fwd/Fw/bare', async () => {
  const fixtures = [
    mk({ subject: 'Re: foo' }),
    mk({ subject: 'RE: foo' }),
    mk({ subject: 'Fw: foo' }),
    mk({ subject: 'Fwd: foo' }),
    mk({ subject: 'bare' }),
  ];
  const r = await aggregate(fromArray(fixtures), { groupBy: ['subject_prefix'] });
  const byKey = new Map(r.rows.map(x => [x.key[0], x.count]));
  assert.equal(byKey.get('Re:'), 2);
  assert.equal(byKey.get('Fwd:'), 2);
  assert.equal(byKey.get('none'), 1);
});

// T8: subject_normalized strips multiple prefixes.
test('T8: subject_normalized strips Re/Fwd/Re chains', async () => {
  const fixtures = [
    mk({ subject: 'Re: Fwd: Re: foo' }),
    mk({ subject: 'foo' }),
    mk({ subject: 'FWD: FOO' }),
  ];
  const r = await aggregate(fromArray(fixtures), { groupBy: ['subject_normalized'] });
  assert.equal(r.rows.length, 1);
  assert.deepEqual(r.rows[0].key, ['foo']);
  assert.equal(r.rows[0].count, 3);
});

// T9: size bucket boundary -- 9999 -> <10KB, 10000 -> 10-100KB, ...
test('T9: size_bucket boundaries', async () => {
  const fixtures = [
    mk({ size: 9999,    uid: 1 }),    // <10KB
    mk({ size: 10000,   uid: 2 }),    // 10-100KB
    mk({ size: 99999,   uid: 3 }),    // 10-100KB
    mk({ size: 100000,  uid: 4 }),    // 100KB-1MB
    mk({ size: 999999,  uid: 5 }),    // 100KB-1MB
    mk({ size: 1000000, uid: 6 }),    // >1MB
  ];
  const r = await aggregate(fromArray(fixtures), { groupBy: ['size_bucket'] });
  const byKey = new Map(r.rows.map(x => [x.key[0], x.count]));
  assert.equal(byKey.get('<10KB'), 1);
  assert.equal(byKey.get('10-100KB'), 2);
  assert.equal(byKey.get('100KB-1MB'), 2);
  assert.equal(byKey.get('>1MB'), 1);
});

// T10: duplicate group_by throws.
test('T10: duplicate group_by fields throw', async () => {
  assert.throws(
    () => validateGroupBy(['sender', 'sender'] as GroupByField[]),
    /duplicate group_by field/,
  );
});

// T11: empty group_by throws.
test('T11: empty group_by throws', async () => {
  assert.throws(
    () => validateGroupBy([] as GroupByField[]),
    /non-empty array/,
  );
});

// T12: > 3 group_by fields throws.
test('T12: composite > 3 fields throws', async () => {
  assert.throws(
    () => validateGroupBy(['sender', 'year', 'domain', 'month'] as GroupByField[]),
    /at most 3 fields/,
  );
});

// T13: scan_time_ms is positive number.
test('T13: scan_time_ms is positive number', async () => {
  const r = await aggregate(fromArray([mk({})]), { groupBy: ['sender'] });
  assert.equal(typeof r.scan_time_ms, 'number');
  assert.ok(r.scan_time_ms > 0, 'expected scan_time_ms > 0, got ' + r.scan_time_ms);
});
