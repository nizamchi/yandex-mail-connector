// Tests for sanitizeError() — Phase 8, Task 2, T-08-01.

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { sanitizeError } from '../sanitize.js';

test('sanitizeError: 40-char hex token redacted', () => {
  const sha = 'a'.repeat(40);
  const out = sanitizeError(new Error(`token=${sha}`));
  assert.match(out, /\[REDACTED-TOKEN\]/);
  assert.ok(!out.includes(sha));
});

test('sanitizeError: 44-char base64 token redacted', () => {
  const b64 = 'AAAA'.repeat(11); // 44 chars
  const out = sanitizeError(new Error(`val=${b64}`));
  assert.match(out, /\[REDACTED-TOKEN\]/);
  assert.ok(!out.includes(b64));
});

test('sanitizeError: email address redacted', () => {
  const out = sanitizeError(new Error('IMAP failed for user@yandex.ru on inbox'));
  assert.match(out, /\[REDACTED-EMAIL\]/);
  assert.ok(!out.includes('user@yandex.ru'));
});

test('sanitizeError: password JSON value redacted', () => {
  const out = sanitizeError(new Error('config: {"password":"hunter2hunter2","user":"x"}'));
  assert.match(out, /"password":"\[REDACTED\]"/);
  assert.ok(!out.includes('hunter2hunter2'));
});

test('sanitizeError: OAuth access_token JSON value redacted', () => {
  const out = sanitizeError(new Error('{"access_token":"y0_AgAAA_secret_value_42","email":"x@y.com"}'));
  assert.match(out, /"access_token":"\[REDACTED\]"/);
  assert.ok(!out.includes('y0_AgAAA_secret_value_42'));
});

test('sanitizeError: secret JSON key redacted (W-1)', () => {
  const out = sanitizeError(new Error('payload {"secret":"abcdef"}'));
  assert.match(out, /"secret":"\[REDACTED\]"/);
  assert.ok(!out.includes('abcdef'));
});

test('sanitizeError: key JSON key redacted (W-1)', () => {
  const out = sanitizeError(new Error('payload {"key":"deadbeef"}'));
  assert.match(out, /"key":"\[REDACTED\]"/);
  assert.ok(!out.includes('deadbeef'));
});

test('sanitizeError: api_key JSON key redacted (W-1)', () => {
  const out = sanitizeError(new Error('payload {"api_key":"sk_test_xyz"}'));
  assert.match(out, /"api_key":"\[REDACTED\]"/);
  assert.ok(!out.includes('sk_test_xyz'));
});

test('sanitizeError: Bearer header inline redacted (W-1)', () => {
  const out = sanitizeError(new Error('curl got Bearer abc123_token_xyz back'));
  assert.match(out, /Bearer \[REDACTED\]/);
  assert.ok(!out.includes('abc123_token_xyz'));
});

test('sanitizeError: Authorization header inline redacted (W-1)', () => {
  const out = sanitizeError(new Error('stack: Authorization: Basic dXNlcjpwYXNz'));
  assert.match(out, /Authorization: \[REDACTED\]/);
  assert.ok(!out.includes('dXNlcjpwYXNz'));
});

test('sanitizeError: ECONNREFUSED -> [NetworkError]', () => {
  const out = sanitizeError(new Error('connect ECONNREFUSED 1.2.3.4:993'));
  assert.match(out, /^\[NetworkError\]/);
});

test('sanitizeError: Invalid login -> [AuthError]', () => {
  const out = sanitizeError(new Error('Invalid login or password'));
  assert.match(out, /^\[AuthError\]/);
});

test('sanitizeError: imapflow-style -> [ImapError]', () => {
  class IMAPError extends Error { constructor(m: string) { super(m); this.name = 'IMAPError'; } }
  const out = sanitizeError(new IMAPError('command timed out'));
  assert.match(out, /^\[ImapError\]/);
});

test('sanitizeError: nodemailer-style (responseCode) -> [SmtpError]', () => {
  const e = Object.assign(new Error('Connection closed'), { responseCode: 421 });
  const out = sanitizeError(e);
  assert.match(out, /^\[SmtpError\]/);
});

test('sanitizeError: daily_send_limit_exceeded preserved + [GuardError]', () => {
  const out = sanitizeError(new Error('daily_send_limit_exceeded: limit=50, remaining=0'));
  assert.match(out, /^\[GuardError\]/);
  assert.ok(out.includes('daily_send_limit_exceeded'));
  assert.ok(out.includes('limit=50'));
});

test('sanitizeError: plain Error -> [Error]', () => {
  const out = sanitizeError(new Error('something boring went wrong'));
  assert.match(out, /^\[Error\]/);
});

test('sanitizeError: idempotent (no double-prefix)', () => {
  const first = sanitizeError(new Error('Invalid login'));
  const second = sanitizeError(first);
  assert.equal(first, second);
});

test('sanitizeError: input already bracketed not double-prefixed', () => {
  const out = sanitizeError('[GuardError] protected_folder: INBOX');
  assert.equal(out, '[GuardError] protected_folder: INBOX');
});

test('sanitizeError: handles string input', () => {
  const out = sanitizeError('plain string error');
  assert.match(out, /^\[Error\] plain string error/);
});

test('sanitizeError: handles undefined / null', () => {
  assert.match(sanitizeError(undefined), /^\[Error\] undefined/);
  assert.match(sanitizeError(null), /^\[Error\] null/);
});

test('sanitizeError: collapses multiline messages to single line', () => {
  const out = sanitizeError(new Error('line1\nline2\nline3'));
  assert.ok(!out.includes('\n'));
});
