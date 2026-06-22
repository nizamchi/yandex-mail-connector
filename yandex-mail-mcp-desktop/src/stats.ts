// stats.ts -- pure server-side aggregator over EnvelopeRow stream.
//
// Why pure: the aggregator takes any AsyncIterable<EnvelopeRow> and emits a
// fixed-shape result. No IMAP, no IO, no clock dependency (scan_time_ms is
// measured around the iteration). This makes the entire aggregation logic
// unit-testable with hand-rolled in-memory iterators -- no MCP transport,
// no IMAP mocks, no network.
//
// Motivation: a user asked an agent for "статистика по входящим кто мне
// больше пишет по годам" and the agent downloaded 3765 envelopes page by
// page through yandex_list_emails, burning its entire context budget on
// raw envelopes just to count them. The fix is to aggregate server-side
// and ship only the counts (a few KB) instead of the envelopes (hundreds
// of KB). Bridge until Layer 2 ships a persistent SQLite index.

import type { EmailAddress } from './imap.js';

// ── Public types ──────────────────────────────────────────────────────

// Envelope shape needed by the aggregator. Compatible subset of EmailHeader,
// kept narrow so tests don't have to construct full EmailHeader fixtures.
export interface EnvelopeRow {
  uid: number;
  from: EmailAddress[];
  to: EmailAddress[];
  subject: string;
  date: string;             // ISO 8601; '' if envelope.date was null/invalid
  size: number;
  seen: boolean;
  flagged: boolean;
  hasAttachments: boolean;  // derived from BODYSTRUCTURE captured on streamEnvelopes (schema 3+)
}

// Available group_by fields. Adding one = update FIELD_BUCKETERS below.
export type GroupByField =
  | 'sender' | 'sender_name' | 'domain'
  | 'year' | 'month' | 'year_month' | 'weekday' | 'hour' | 'date'
  | 'to_first'
  | 'subject_prefix' | 'subject_normalized'
  | 'size_bucket' | 'has_attachments'
  | 'flag_seen' | 'flag_flagged';

export interface AggregateOptions {
  groupBy: GroupByField[];
  since?: string;     // ISO date; envelopes with date < since are skipped
  until?: string;     // ISO date; envelopes with date > until are skipped
  topN?: number;      // default 50; cap on returned rows after sort
}

export interface AggRow {
  key: string[];              // matches groupBy order
  count: number;
  total_size_bytes: number;
  earliest: string;           // ISO date of oldest envelope in bucket
  latest: string;             // ISO date of newest envelope in bucket
}

export interface AggregateResult {
  rows: AggRow[];
  total_scanned: number;
  scan_time_ms: number;
  truncated: boolean;
  date_range: { from?: string; to?: string };
}

// ── Constants ────────────────────────────────────────────────────────

const MAX_COMPOSITE_FIELDS = 3;
const DEFAULT_TOP_N = 50;
const MAX_TOP_N = 1000;
const COMPOSITE_DELIM = '\x01';   // SOH; cannot appear in field values
const UNKNOWN = '<unknown>';
const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'] as const;

// All valid group_by fields, for validation.
const VALID_FIELDS: ReadonlySet<GroupByField> = new Set<GroupByField>([
  'sender', 'sender_name', 'domain',
  'year', 'month', 'year_month', 'weekday', 'hour', 'date',
  'to_first',
  'subject_prefix', 'subject_normalized',
  'size_bucket', 'has_attachments',
  'flag_seen', 'flag_flagged',
]);

// ── Bucketers ────────────────────────────────────────────────────────

// Parse env.date into Date or null. Accepts ISO strings only (that's what
// imap.ts emits via envelope.date.toISOString()).
function parseDate(s: string): Date | null {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function pad2(n: number): string {
  return n < 10 ? '0' + n : String(n);
}

function bucketSize(bytes: number): string {
  if (bytes < 10_000)          return '<10KB';
  if (bytes < 100_000)         return '10-100KB';
  if (bytes < 1_000_000)       return '100KB-1MB';
  return '>1MB';
}

// Detect "Re:"/"Fwd:"/"Fw:" prefix on a subject line. Returns the canonical
// prefix label or 'none'.
const PREFIX_RE = /^(re|fwd?|fw)\s*:\s*/i;
function subjectPrefix(subject: string): string {
  const m = subject.match(PREFIX_RE);
  if (!m) return 'none';
  const tok = m[1].toLowerCase();
  if (tok === 're') return 'Re:';
  return 'Fwd:';        // 'fw' and 'fwd' both normalize to Fwd:
}

// Strip ALL leading Re:/Fwd:/Fw: prefixes (handles "Re: Fwd: Re: foo").
function subjectNormalized(subject: string): string {
  let s = subject;
  // bounded loop: subjects are short, but guard with a hard limit
  for (let i = 0; i < 32; i++) {
    const next = s.replace(PREFIX_RE, '');
    if (next === s) break;
    s = next;
  }
  return s.trim().toLowerCase();
}

// Per-field bucketer. Returns the string key for the bucket. Returns
// UNKNOWN sentinel when the source field is missing/invalid -- never throws,
// never returns undefined. Date-based buckets get UNKNOWN if date is null.
function bucketField(field: GroupByField, env: EnvelopeRow): string {
  const date = parseDate(env.date);
  switch (field) {
    case 'sender': {
      const addr = env.from[0]?.address ?? '';
      return addr ? addr.toLowerCase() : UNKNOWN;
    }
    case 'sender_name': {
      const a = env.from[0];
      if (!a) return UNKNOWN;
      if (a.name && a.name.trim()) return a.name.trim();
      // fallback to local-part of address
      const addr = a.address ?? '';
      const at = addr.indexOf('@');
      return at > 0 ? addr.slice(0, at) : (addr || UNKNOWN);
    }
    case 'domain': {
      const addr = env.from[0]?.address ?? '';
      const at = addr.lastIndexOf('@');
      return at >= 0 ? addr.slice(at + 1).toLowerCase() : UNKNOWN;
    }
    case 'year':
      return date ? String(date.getUTCFullYear()) : UNKNOWN;
    case 'month':
      return date ? pad2(date.getUTCMonth() + 1) : UNKNOWN;
    case 'year_month':
      return date ? String(date.getUTCFullYear()) + '-' + pad2(date.getUTCMonth() + 1) : UNKNOWN;
    case 'weekday':
      return date ? WEEKDAYS[date.getUTCDay()] : UNKNOWN;
    case 'hour':
      return date ? pad2(date.getUTCHours()) : UNKNOWN;
    case 'date':
      return date
        ? String(date.getUTCFullYear()) + '-' + pad2(date.getUTCMonth() + 1) + '-' + pad2(date.getUTCDate())
        : UNKNOWN;
    case 'to_first': {
      const addr = env.to[0]?.address ?? '';
      return addr ? addr.toLowerCase() : UNKNOWN;
    }
    case 'subject_prefix':
      return subjectPrefix(env.subject ?? '');
    case 'subject_normalized':
      return subjectNormalized(env.subject ?? '') || UNKNOWN;
    case 'size_bucket':
      return bucketSize(env.size ?? 0);
    case 'has_attachments':
      // Derived from BODYSTRUCTURE captured on the streaming fetch (v2.9.0+).
      // Reports the field as set by imap.ts parseHeader via extractAttachments.
      return env.hasAttachments ? 'yes' : 'no';
    case 'flag_seen':
      return env.seen ? 'seen' : 'unseen';
    case 'flag_flagged':
      return env.flagged ? 'flagged' : 'unflagged';
  }
}

// ── Validation ───────────────────────────────────────────────────────

export function validateGroupBy(groupBy: GroupByField[]): void {
  if (!Array.isArray(groupBy) || groupBy.length === 0) {
    throw new Error('group_by must be a non-empty array');
  }
  if (groupBy.length > MAX_COMPOSITE_FIELDS) {
    throw new Error('group_by accepts at most ' + MAX_COMPOSITE_FIELDS + ' fields (cardinality explosion guard)');
  }
  const seen = new Set<string>();
  for (const f of groupBy) {
    if (!VALID_FIELDS.has(f)) {
      throw new Error('unknown group_by field: ' + String(f));
    }
    if (seen.has(f)) {
      throw new Error('duplicate group_by field: ' + f);
    }
    seen.add(f);
  }
}

// ── Aggregator ───────────────────────────────────────────────────────

interface BucketAccum {
  key: string[];
  count: number;
  total_size_bytes: number;
  earliest_ms: number;
  earliest: string;
  latest_ms: number;
  latest: string;
}

export async function aggregate(
  iter: AsyncIterable<EnvelopeRow>,
  options: AggregateOptions,
): Promise<AggregateResult> {
  validateGroupBy(options.groupBy);
  const topN = Math.min(Math.max(options.topN ?? DEFAULT_TOP_N, 1), MAX_TOP_N);
  const sinceMs = options.since ? new Date(options.since).getTime() : null;
  const untilMs = options.until ? new Date(options.until).getTime() : null;
  if (sinceMs !== null && isNaN(sinceMs)) throw new Error('invalid "since" date: ' + options.since);
  if (untilMs !== null && isNaN(untilMs)) throw new Error('invalid "until" date: ' + options.until);

  const t0 = Date.now();
  const buckets = new Map<string, BucketAccum>();
  let total_scanned = 0;
  let actualFromMs: number | null = null;
  let actualToMs: number | null = null;

  for await (const env of iter) {
    const d = parseDate(env.date);
    const dMs = d ? d.getTime() : null;
    // Date filter -- skip envelope if outside [since, until].
    if (sinceMs !== null && dMs !== null && dMs < sinceMs) continue;
    if (untilMs !== null && dMs !== null && dMs > untilMs) continue;
    // Note: envelopes with no date pass the filter only when no filter is set
    // for that side (so a missing date is bucketed as <unknown> for date-based
    // fields, but does not get silently dropped from sender-only aggregations).
    if (sinceMs !== null && dMs === null) continue;
    if (untilMs !== null && dMs === null) continue;

    total_scanned++;
    if (dMs !== null) {
      if (actualFromMs === null || dMs < actualFromMs) actualFromMs = dMs;
      if (actualToMs   === null || dMs > actualToMs)   actualToMs   = dMs;
    }

    const keyParts = options.groupBy.map(f => bucketField(f, env));
    const compositeKey = keyParts.join(COMPOSITE_DELIM);
    let bucket = buckets.get(compositeKey);
    const isoDate = d ? d.toISOString() : '';
    const size = typeof env.size === 'number' && env.size > 0 ? env.size : 0;
    if (!bucket) {
      bucket = {
        key: keyParts,
        count: 0,
        total_size_bytes: 0,
        earliest_ms: dMs ?? Number.POSITIVE_INFINITY,
        earliest: isoDate,
        latest_ms: dMs ?? Number.NEGATIVE_INFINITY,
        latest: isoDate,
      };
      buckets.set(compositeKey, bucket);
    }
    bucket.count++;
    bucket.total_size_bytes += size;
    if (dMs !== null) {
      if (dMs < bucket.earliest_ms) { bucket.earliest_ms = dMs; bucket.earliest = isoDate; }
      if (dMs > bucket.latest_ms)   { bucket.latest_ms   = dMs; bucket.latest   = isoDate; }
    }
  }

  // Sort: count desc, then key tuple asc lexicographically.
  const sorted = Array.from(buckets.values()).sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    for (let i = 0; i < a.key.length; i++) {
      const ak = a.key[i] ?? '';
      const bk = b.key[i] ?? '';
      if (ak < bk) return -1;
      if (ak > bk) return  1;
    }
    return 0;
  });
  const truncated = sorted.length > topN;
  const trimmed = truncated ? sorted.slice(0, topN) : sorted;
  const rows: AggRow[] = trimmed.map(b => ({
    key: b.key,
    count: b.count,
    total_size_bytes: b.total_size_bytes,
    earliest: b.earliest,
    latest: b.latest,
  }));

  const date_range: { from?: string; to?: string } = {};
  if (options.since) date_range.from = options.since;
  else if (actualFromMs !== null) date_range.from = new Date(actualFromMs).toISOString();
  if (options.until) date_range.to = options.until;
  else if (actualToMs !== null) date_range.to = new Date(actualToMs).toISOString();

  return {
    rows,
    total_scanned,
    // Always >= 1 to keep "positive number" invariant (T13). Date.now() can
    // tick zero ms on small fixtures; clamp to at least 1.
    scan_time_ms: Math.max(1, Date.now() - t0),
    truncated,
    date_range,
  };
}
