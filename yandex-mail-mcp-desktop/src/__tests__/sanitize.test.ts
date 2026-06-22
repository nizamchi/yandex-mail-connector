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
  // \x01..\x08, \x0B..\x1F, plus \t -- all C0 except space.
  const input = 'a\x01b\x07c\x1Fd';
  assert.equal(sanitizeForDisplay(input), 'abcd');
});

test('sanitizeForDisplay: collapses CR / LF / CRLF runs into single space', () => {
  assert.equal(sanitizeForDisplay('x\ny\r\nz\rw'), 'x y z w');
});

test('sanitizeForDisplay: truncates with ellipsis at custom maxLen', () => {
  const out = sanitizeForDisplay('a'.repeat(500), { maxLen: 100 });
  assert.equal(out.length, 100);
  assert.ok(out.endsWith('...'), `expected to end with "..." -- got "${out.slice(-5)}"`);
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
  assert.ok(out.includes('<real@x.com>'), `address bracket form preserved -- got "${out}"`);
  // Angle brackets themselves are not stripped (they are not control chars).
  assert.ok(out.includes('<script>'), 'no HTML decoding/strip -- literal text retained');
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

// ---- LD-6: bidi / zero-width / BOM format-char strip (CVE-2021-42574) -------
// All invisible codepoints are written as \uXXXX JS escape sequences in source --
// never raw glyphs. JS resolves them at runtime; the source file stays ASCII-safe.

test('sanitizeForDisplay: strips RLO (\u202E) bidi override', () => {
  // RIGHT-TO-LEFT OVERRIDE -- reverses display rendering (extension-spoof vector).
  const input = 'a\u202Eb';
  assert.equal(sanitizeForDisplay(input), 'ab');
});

test('sanitizeForDisplay: strips ZWSP (\u200B) zero-width space', () => {
  // ZERO WIDTH SPACE -- invisible separator that can bypass string-equality checks.
  const input = 'a\u200Bb';
  assert.equal(sanitizeForDisplay(input), 'ab');
});

test('sanitizeForDisplay: strips BOM (\uFEFF)', () => {
  // BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE.
  const input = '\uFEFFhello';
  assert.equal(sanitizeForDisplay(input), 'hello');
});

test('sanitizeForDisplay: strips directional isolate (\u2066 LRI) and PDI (\u2069)', () => {
  // LEFT-TO-RIGHT ISOLATE (\u2066) + POP DIRECTIONAL ISOLATE (\u2069).
  const input = 'a\u2066b\u2069c';
  assert.equal(sanitizeForDisplay(input), 'abc');
});

test('sanitizeForDisplay: strips word-joiner (\u2060)', () => {
  // WORD JOINER -- invisible operator in the \u2060-\u2064 range.
  const input = 'a\u2060b';
  assert.equal(sanitizeForDisplay(input), 'ab');
});

test('sanitizeForDisplay: strips full set of FORMAT_CHARS in one pass', () => {
  // One representative per sub-range, all as \uXXXX escapes:
  // \u200B ZWSP, \u200C ZWNJ, \u200D ZWJ, \u200E LRM, \u200F RLM
  // \u202A LRE, \u202E RLO (bidi overrides)
  // \u2060 WJ (word-joiner)
  // \u2066 LRI, \u2069 PDI (directional isolates)
  // \uFEFF BOM
  const input = 'x'
    + '\u200B\u200C\u200D\u200E\u200F'
    + '\u202A\u202E'
    + '\u2060'
    + '\u2066\u2069'
    + '\uFEFF'
    + 'y';
  assert.equal(sanitizeForDisplay(input), 'xy');
});

test('sanitizeForDisplay: folds \u2028 LINE SEPARATOR to space like LF', () => {
  // \u2028 LINE SEPARATOR -- NOT matched by [\r\n]+ in the existing NEWLINES regex.
  const input = 'x\u2028y\u2028z';
  assert.equal(sanitizeForDisplay(input), 'x y z');
});

test('sanitizeForDisplay: folds \u2029 PARAGRAPH SEPARATOR to space like LF', () => {
  // \u2029 PARAGRAPH SEPARATOR -- NOT matched by [\r\n]+.
  const input = 'x\u2029y\u2029z';
  assert.equal(sanitizeForDisplay(input), 'x y z');
});

test('sanitizeForDisplay: folds mixed \u2028 and \u2029 runs to single space', () => {
  // Consecutive LS/PS runs collapse to a single space (same behaviour as CR/LF).
  const input = 'x\u2028\u2029y';
  assert.equal(sanitizeForDisplay(input), 'x y');
});

test('sanitizeForDisplay: RLO extension-spoof -- codepoint absent from output', () => {
  // Trojan-Source / CVE-2021-42574: filename designed to reverse display rendering
  // so the viewer sees 'photo.jpg' but the system processes 'photo\u202Egpj.exe'.
  const input = 'photo\u202Egpj.exe';
  const out = sanitizeForDisplay(input);
  // The RLO codepoint must not survive into output.
  assert.ok(!out.includes('\u202E'), `U+202E must not appear in output -- got: ${JSON.stringify(out)}`);
  // The surrounding ASCII bytes are retained.
  assert.ok(out.includes('photo'), 'prefix retained');
  assert.ok(out.includes('gpj.exe'), 'suffix retained');
});

// ---- POSITIVE no-regression: ordinary unicode and Cyrillic must pass through --

test('sanitizeForDisplay: Cyrillic filename passes through byte-for-byte', () => {
  // Cyrillic block \u0400-\u04FF is entirely outside every FORMAT_CHARS strip range.
  // '\u0414\u043E\u0433\u043E\u0432\u043E\u0440.pdf' = 'Dogovor.pdf' in Cyrillic.
  const cyrillic = '\u0414\u043E\u0433\u043E\u0432\u043E\u0440.pdf';
  assert.equal(sanitizeForDisplay(cyrillic), cyrillic);
});

test('sanitizeForDisplay: ordinary accented Latin unicode passes through unchanged', () => {
  // \u00E9 = e with acute, \u00FC = u with diaeresis -- plain BMP letters, not format chars.
  const accented = 'r\u00E9sum\u00E9_m\u00FCller.pdf';
  assert.equal(sanitizeForDisplay(accented), accented);
});
