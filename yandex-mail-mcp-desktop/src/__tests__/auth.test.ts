import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  getAuthLevel,
  detectCapabilities,
  describeAuthLevel,
} from '../auth.js';

test('getAuthLevel: empty env → 0', () => {
  assert.equal(getAuthLevel({}), 0);
});

test('getAuthLevel: readonly → 0', () => {
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: 'readonly' }), 0);
});

test('getAuthLevel: safe → 1', () => {
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: 'safe' }), 1);
});

test('getAuthLevel: destructive → 2', () => {
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: 'destructive' }), 2);
});

test('getAuthLevel: auto → 3', () => {
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: 'auto' }), 3);
});

test('getAuthLevel: numeric strings 0..3', () => {
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '0' }), 0);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '1' }), 1);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '2' }), 2);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '3' }), 3);
});

test('getAuthLevel: case-insensitive (SAFE, Destructive, AuTo)', () => {
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: 'SAFE' }), 1);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: 'Destructive' }), 2);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: 'AuTo' }), 3);
});

test('getAuthLevel: trims whitespace', () => {
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '  safe  ' }), 1);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '\tdestructive\n' }), 2);
});

test('getAuthLevel: out-of-range fallback to 0', () => {
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '4' }), 0);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '-1' }), 0);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '99' }), 0);
});

test('getAuthLevel: unknown tokens fallback to 0', () => {
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: 'admin' }), 0);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: 'root' }), 0);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: 'yolo' }), 0);
});

test('getAuthLevel: empty string → 0', () => {
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '' }), 0);
  assert.equal(getAuthLevel({ YANDEX_AUTH_LEVEL: '   ' }), 0);
});

test('detectCapabilities: every level returns empty Set', () => {
  for (const lvl of [0, 1, 2, 3] as const) {
    const caps = detectCapabilities(lvl);
    assert.equal(caps.size, 0, `level ${lvl} must have empty capabilities in Layer 1`);
  }
});

test('describeAuthLevel: contains expected substrings', () => {
  assert.ok(describeAuthLevel(0).includes('READ-ONLY'), 'L0 must say READ-ONLY');
  assert.ok(describeAuthLevel(1).includes('SAFE'), 'L1 must say SAFE');
  assert.ok(describeAuthLevel(2).includes('DESTRUCTIVE'), 'L2 must say DESTRUCTIVE');
  assert.ok(describeAuthLevel(3).includes('AUTO'), 'L3 must say AUTO');
});
