import { test, describe, beforeEach } from 'node:test';
import { strict as assert } from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  actionFingerprint,
  generateCode,
  verifyCode,
  _resetForTests,
  _expireForTests,
  _expireLockoutForTests,
  _internalFailuresSize,
} from '../confirm.js';

describe('confirm.ts', () => {
  beforeEach(() => {
    _resetForTests();
  });

  describe('actionFingerprint', () => {
    test('stable across key reordering', () => {
      const a = actionFingerprint('send', { a: 1, b: 2 });
      const b = actionFingerprint('send', { b: 2, a: 1 });
      assert.equal(a, b);
    });

    test('stable across `to` array reordering', () => {
      const a = actionFingerprint('send', { to: ['a@x', 'b@x'], subject: 's' });
      const b = actionFingerprint('send', { to: ['b@x', 'a@x'], subject: 's' });
      assert.equal(a, b);
    });

    test('different action ⇒ different fp', () => {
      const a = actionFingerprint('send', { to: ['a@x'] });
      const b = actionFingerprint('destroy', { to: ['a@x'] });
      assert.notEqual(a, b);
    });

    test('different params ⇒ different fp', () => {
      const a = actionFingerprint('send', { to: ['a@x'], subject: 'one' });
      const b = actionFingerprint('send', { to: ['a@x'], subject: 'two' });
      assert.notEqual(a, b);
    });

    test('32-char hex', () => {
      const fp = actionFingerprint('send', { to: ['a@x'] });
      assert.match(fp, /^[0-9a-f]{32}$/);
    });
  });

  describe('generateCode', () => {
    test('6-digit decimal', () => {
      const fp = actionFingerprint('send', { to: ['a@x'] });
      const { code } = generateCode(fp);
      assert.match(code, /^\d{6}$/);
    });

    test('expiresAt ≈ now+5min', () => {
      const fp = actionFingerprint('send', { to: ['a@x'] });
      const before = Date.now();
      const { expiresAt } = generateCode(fp);
      const after = Date.now();
      const lower = before + 5 * 60 * 1000 - 5000;
      const upper = after + 5 * 60 * 1000 + 5000;
      assert.ok(expiresAt >= lower && expiresAt <= upper, `expiresAt=${expiresAt} not in window [${lower}, ${upper}]`);
    });

    test('re-issue replaces', () => {
      const fp = actionFingerprint('send', { to: ['a@x'] });
      const first = generateCode(fp);
      generateCode(fp);
      const r = verifyCode(fp, first.code);
      assert.notEqual(r, true);
      assert.notEqual(r, 'expired');
      // Expected: 'wrong' (re-issue replaced the entry; old code no longer matches).
      assert.equal(r, 'wrong');
    });
  });

  describe('verifyCode matrix', () => {
    test('correct code ⇒ true → used', () => {
      const fp = actionFingerprint('send', { to: ['a@x'] });
      const { code } = generateCode(fp);
      assert.equal(verifyCode(fp, code), true);
      assert.equal(verifyCode(fp, code), 'used');
    });

    test('wrong code ⇒ wrong', () => {
      const fp = actionFingerprint('send', { to: ['a@x'] });
      generateCode(fp);
      assert.equal(verifyCode(fp, '000000'), 'wrong');
    });

    test('expired ⇒ expired', () => {
      const fp = actionFingerprint('send', { to: ['a@x'] });
      const { code } = generateCode(fp);
      _expireForTests(fp);
      assert.equal(verifyCode(fp, code), 'expired');
    });

    test('no entry for fp ⇒ wrong', () => {
      const fp = actionFingerprint('send', { to: ['never-generated@x'] });
      assert.equal(verifyCode(fp, '123456'), 'wrong');
    });

    test('unknown fp does NOT touch failures map (B-2)', () => {
      for (let i = 0; i < 100; i++) {
        const fp = actionFingerprint('send', { to: [`rand-${i}@x`], nonce: i });
        verifyCode(fp, '000000');
      }
      assert.equal(_internalFailuresSize(), 0, 'failures map must remain empty for unknown fingerprints');
    });

    test('lockout after 5 wrong in 60s', () => {
      const fp = actionFingerprint('send', { to: ['a@x'] });
      const { code } = generateCode(fp);
      for (let i = 0; i < 5; i++) {
        assert.equal(verifyCode(fp, '000000'), 'wrong');
      }
      // 6th call — even with correct code — must be locked
      assert.equal(verifyCode(fp, code), 'locked');
    });

    test('lockout is per-fp', () => {
      const fpA = actionFingerprint('send', { to: ['a@x'] });
      const fpB = actionFingerprint('send', { to: ['b@x'] });
      generateCode(fpA);
      const { code: codeB } = generateCode(fpB);
      for (let i = 0; i < 5; i++) verifyCode(fpA, '000000');
      assert.equal(verifyCode(fpB, codeB), true);
    });

    test('lockout ends after fast-forward', () => {
      const fp = actionFingerprint('send', { to: ['a@x'] });
      const { code } = generateCode(fp);
      for (let i = 0; i < 5; i++) verifyCode(fp, '000000');
      assert.equal(verifyCode(fp, code), 'locked');
      _expireLockoutForTests(fp);
      // After lockout fast-forward, correct code verifies (entry still valid).
      assert.equal(verifyCode(fp, code), true);
    });
  });

  describe('verifyCode shape invariants (B-3)', () => {
    test('verifyCode body contains no await', () => {
      // Locate confirm.ts relative to the running test bundle. We try a few
      // candidate paths so the test works both as a TS file under tsx and as
      // a bundled CJS test in dist/__tests__/.
      const candidates = [
        path.resolve(__dirname, '..', 'confirm.ts'),
        path.resolve(__dirname, '..', '..', 'src', 'confirm.ts'),
        path.resolve(process.cwd(), 'src', 'confirm.ts'),
        path.resolve(process.cwd(), 'yandex-mail-mcp-desktop', 'src', 'confirm.ts'),
      ];
      let src: string | null = null;
      for (const c of candidates) {
        try {
          src = fs.readFileSync(c, 'utf8');
          break;
        } catch { /* try next */ }
      }
      assert.ok(src, 'confirm.ts source must be readable for shape check');
      const idx = src.indexOf('export function verifyCode');
      assert.ok(idx >= 0, 'verifyCode export must exist');
      // Walk braces to find the matching closing brace.
      const openBrace = src.indexOf('{', idx);
      assert.ok(openBrace >= 0);
      let depth = 0;
      let end = -1;
      for (let i = openBrace; i < src.length; i++) {
        const ch = src[i];
        if (ch === '{') depth++;
        else if (ch === '}') {
          depth--;
          if (depth === 0) { end = i; break; }
        }
      }
      assert.ok(end > openBrace, 'matching brace not found');
      const body = src.slice(openBrace, end);
      assert.ok(!/\bawait\b/.test(body), 'verifyCode body must contain no await token');
    });
  });
});
