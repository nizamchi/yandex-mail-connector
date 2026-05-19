import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  sanitizeForDisplay,
  wrapUntrusted,
  UNTRUSTED_BEGIN,
  UNTRUSTED_END,
} from '../sanitize.js';

test('sanitizeForDisplay: passes plain ASCII through', () => {
  assert.equal(sanitizeForDisplay('hello'), 'hello');
});

test('sanitizeForDisplay: strips C0 control chars', () => {
  // \x01..\x08, \x0B..\x1F, plus \t — all C0 except space.
  const input = 'a\x01b\x07c\x1Fd';
  assert.equal(sanitizeForDisplay(input), 'abcd');
});

test('sanitizeForDisplay: collapses CR / LF / CRLF runs into single space', () => {
  assert.equal(sanitizeForDisplay('x\ny\r\nz\rw'), 'x y z w');
});

test('sanitizeForDisplay: truncates with ellipsis at custom maxLen', () => {
  const out = sanitizeForDisplay('a'.repeat(500), { maxLen: 100 });
  assert.equal(out.length, 100);
  assert.ok(out.endsWith('...'), `expected to end with "..." — got "${out.slice(-5)}"`);
});

test('sanitizeForDisplay: default maxLen = 200', () => {
  const out = sanitizeForDisplay('a'.repeat(500));
  assert.equal(out.length, 200);
  assert.ok(out.endsWith('...'));
});

test('sanitizeForDisplay: handles undefined / null / empty', () => {
  assert.equal(sanitizeForDisplay(undefined), '');
  assert.equal(sanitizeForDisplay(null), '');
  assert.equal(sanitizeForDisplay(''), '');
});

test('sanitizeForDisplay: trims and collapses multiple spaces', () => {
  assert.equal(sanitizeForDisplay('  hello   world  '), 'hello world');
});

test('sanitizeForDisplay: preserves angle brackets (no HTML decoding)', () => {
  const out = sanitizeForDisplay('<script>alert</script> <real@x.com>');
  assert.ok(out.includes('<real@x.com>'), `address bracket form preserved — got "${out}"`);
  // Angle brackets themselves are not stripped (they are not control chars).
  assert.ok(out.includes('<script>'), 'no HTML decoding/strip — literal text retained');
});

test('sanitizeForDisplay: strips C1 control range (0x7F-0x9F)', () => {
  const input = 'a\x7Fb\x80c\x9Fd';
  assert.equal(sanitizeForDisplay(input), 'abcd');
});

test('wrapUntrusted: emits both markers around body', () => {
  const out = wrapUntrusted('hello world');
  assert.ok(out.startsWith(UNTRUSTED_BEGIN), 'starts with BEGIN marker');
  assert.ok(out.endsWith(UNTRUSTED_END), 'ends with END marker');
  assert.ok(out.includes('hello world'), 'body sandwiched');
  assert.equal(out, `${UNTRUSTED_BEGIN}\nhello world\n${UNTRUSTED_END}`);
});

test('wrapUntrusted: empty body still produces 3 lines', () => {
  const out = wrapUntrusted('');
  const parts = out.split('\n');
  assert.equal(parts.length, 3);
  assert.equal(parts[0], UNTRUSTED_BEGIN);
  assert.equal(parts[1], '');
  assert.equal(parts[2], UNTRUSTED_END);
});

test('wrapUntrusted: null / undefined body normalised to empty', () => {
  assert.equal(wrapUntrusted(null), `${UNTRUSTED_BEGIN}\n\n${UNTRUSTED_END}`);
  assert.equal(wrapUntrusted(undefined), `${UNTRUSTED_BEGIN}\n\n${UNTRUSTED_END}`);
});
