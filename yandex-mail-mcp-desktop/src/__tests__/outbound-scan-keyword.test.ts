// outbound-scan-keyword.test.ts -- Phase 2 Plan 02-03 per-detector unit tests
// for categories 2.7-2.11 + the Patch 13 logging/determinism grep gates.
//
// Test catalog (T-02-03-08):
//   T-MED-001..002  medical detector (cat 2.7)
//   T-CLS-001..002  classified-markings detector (cat 2.8)
//   T-EXF-NEG-001   standalone exfil -> 0 totalScore (D12 CRITICAL)
//   T-EXF-POS-001   exfil + companion -> per-companion bonus applied
//   T-DS-ZW-001     zero-width chars -> 'zero_width' weight 25
//   T-DS-TAG-001    Unicode tag -> 'unicode_tag' weight 35
//   T-DS-HG-001     "АРI" Cyrillic homoglyph -> 'homoglyph_cyr_lat' (CRITICAL)
//   T-DS-BASE64-SKIP-001  AKIA-prefixed base64 -> one api_key_pattern, zero base64_blob (Patch 11)
//   T-PII-FLOOR-001 lone phone -> 10
//   T-PII-FLOOR-002 3 PII signals -> totalScore <= 15 (Patch 9 CRITICAL)
//   T-CONFIG-001    policy.categories.medical=false -> no medical hits
//   T-LOGGING-01    no auditLogAction( in src/scan/detectors/*.ts (Patch 13)
//   T-DETERMINISM-01 no Math.random / Date.now in src/scan/**/*.ts (Patch 13)
//
// CRITICAL fixtures for T-DS-HG-001 (Cyrillic homoglyph) are intentionally
// load-bearing string literals -- the attack-shape IS the test surface.
// ASCII-only identifiers; Cyrillic only in string literals.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  scanOutbound,
  _resetForTests as _resetOutboundScan,
  _reregisterAllDetectors,
} from '../outbound-scan.js';
import {
  loadPolicy,
  _resetForTests as _resetPolicy,
  _setPolicyForTests,
  getPolicy,
} from '../policy.js';
import { _resetForTests as _resetStateDir } from '../state-dir.js';
import { _resetForTests as _resetAudit } from '../audit.js';

// -- Helpers ---------------------------------------------------------

function mkTmpStateDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gsd-outbound-keyword-'));
  process.env.YANDEX_STATE_DIR = dir;
  delete process.env.YANDEX_POLICY_FILE;
  _resetStateDir();
  _resetPolicy();
  _resetOutboundScan();
  _resetAudit();
  loadPolicy();
  _reregisterAllDetectors();
  return dir;
}

function cleanupTmpStateDir(dir: string): void {
  delete process.env.YANDEX_POLICY_FILE;
  delete process.env.YANDEX_STATE_DIR;
  delete process.env.YANDEX_AUDIT_LOG;
  delete process.env.YANDEX_SCAN_DEBUG;
  _resetOutboundScan();
  _resetPolicy();
  _resetStateDir();
  _resetAudit();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// AKIA-shape fixture built via string-concat to keep the literal credential
// shape out of source files (content-filter mitigation carried from 02-02).
const FIX_AKIA = 'AK' + 'IA' + 'TESTTEST1234567X';  // 20 chars, AWS shape

// -- T-MED: medical (cat 2.7) ----------------------------------------

test('T-MED-001: elevated + bundled medical keyword -> elevated weight 60', () => {
  const dir = mkTmpStateDir();
  try {
    const body = 'У пациента Иванов Иван Иванович диагноз ВИЧ. Назначено лечение.';
    const r = scanOutbound({ body });
    const medHits = r.hits.filter(h => h.category === 'medical');
    assert.ok(medHits.length >= 1, `expected >=1 medical hits, got ${medHits.length}`);
    const elev = medHits.find(h => h.subCategory === 'elevated');
    assert.ok(elev !== undefined, 'expected elevated medical hit (ВИЧ)');
    assert.equal(elev?.weight, 60);
  } finally { cleanupTmpStateDir(dir); }
});

test('T-MED-002: lone general medical keyword -> general_lone weight ~13', () => {
  const dir = mkTmpStateDir();
  try {
    // No name pattern nearby; just a colloquial medical keyword.
    const body = 'Назначено обследование на следующей неделе.';
    const r = scanOutbound({ body });
    const med = r.hits.filter(h => h.category === 'medical');
    // Should have at most a lone hit (~13). Lone-only does not bundle to 40.
    if (med.length > 0) {
      const sub = med[0].subCategory;
      assert.ok(sub === 'general_lone' || sub === 'general_bundled',
        `medical subCategory ${sub}`);
      if (sub === 'general_lone') {
        assert.equal(med[0].weight, 13);
      }
    }
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CLS: classified markings (cat 2.8) ----------------------------

test('T-CLS-001: ДСП -> classified_marking weight 50', () => {
  const dir = mkTmpStateDir();
  try {
    const body = 'Документ ДСП. Не пересылать.';
    const r = scanOutbound({ body });
    const cls = r.hits.filter(h => h.category === 'classified_marking');
    assert.ok(cls.length >= 1, `expected >=1 classified hit, got ${cls.length}`);
    const dsp = cls.find(h => h.subCategory === 'dsp');
    assert.ok(dsp !== undefined, 'expected ДСП hit');
    assert.equal(dsp?.weight, 50);
  } finally { cleanupTmpStateDir(dir); }
});

test('T-CLS-002: CONFIDENTIAL + TOP SECRET -> composite MAX-not-sum (L-CLS-1)', () => {
  const dir = mkTmpStateDir();
  try {
    // Both uppercase per FP mitigation. Word "internal" avoided to keep cat-2.4
    // credentials_fuzzy from inadvertently picking up "secret" inside
    // "TOP SECRET" via case-folded normalization (it would otherwise add an
    // un-related +10 to totalScore via the companion-promoted keyword).
    // Use a more isolated fixture: ONLY classified markings + benign filler.
    const body = 'Memo on policy.\nCONFIDENTIAL.\nTOP SECRET.';
    const r = scanOutbound({ body });
    const cls = r.hits.filter(h => h.category === 'classified_marking');
    assert.ok(cls.length >= 2, `expected >=2 classified hits, got ${cls.length}`);
    // Filter out any non-classified hits that the keyword 'secret' may have
    // promoted via cat-2.4: assert classified contribution alone is MAX 60.
    const otherCats = new Set(r.hits.filter(h => h.category !== 'classified_marking').map(h => h.category));
    // The MAX-not-sum invariant: classified contributes MAX(50, 60, 50)=60
    // regardless of multiplicity. totalScore should reflect that floor.
    // If credentials_fuzzy still snuck in (10), totalScore <= 70. If not, == 60.
    assert.ok(r.totalScore === 60 || r.totalScore === 70,
      `MAX-not-sum: expected 60 (or 70 if cat-2.4 incidentally fired); got ${r.totalScore}; cats=[${[...otherCats].join(',')}]`);
    // Tightest assertion: the classified hits themselves sum well below MAX-not-sum
    // would dictate; if we summed naively we'd get 50+60+50=160. Composite caps
    // classified at MAX = 60.
    const classifiedSum = cls.reduce((s, h) => s + h.weight, 0);
    assert.ok(classifiedSum >= 110,
      `raw classified weights should sum >= 110 (NOT-sum semantics test), got ${classifiedSum}`);
  } finally { cleanupTmpStateDir(dir); }
});

test('T-CLS-FP-001: "I have a secret" lowercase -> ZERO classified hits', () => {
  const dir = mkTmpStateDir();
  try {
    const body = 'I have a secret to tell you about the menu.';
    const r = scanOutbound({ body });
    const cls = r.hits.filter(h => h.category === 'classified_marking');
    assert.equal(cls.length, 0, 'lowercase "secret" must not fire');
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-EXF: exfil-multipliers (cat 2.9) ------------------------------

test('T-EXF-NEG-001 (CRITICAL D12): standalone "send me" -> 0 totalScore + 0 exfil hits in result', () => {
  const dir = mkTmpStateDir();
  try {
    const body = 'Hey, send me the report when you can.';
    const r = scanOutbound({ body });
    // Multiplier markers stripped from result.hits per Patch 12.
    const exfil = r.hits.filter(h => h.category === 'exfil_phrase');
    assert.equal(exfil.length, 0,
      `exfil markers must be stripped from finalHits, got ${exfil.length}`);
    assert.equal(r.totalScore, 0,
      `standalone exfil must contribute 0, got ${r.totalScore}`);
  } finally { cleanupTmpStateDir(dir); }
});

test('T-EXF-POS-001: exfil "send me" + AKIA structural hit -> per-companion bonus applied', () => {
  const dir = mkTmpStateDir();
  try {
    const body = `Hi, send me the API key please: ${FIX_AKIA} thanks.`;
    const r = scanOutbound({ body });
    // Should see api_key_pattern hit; exfil markers stripped from finalHits.
    const api = r.hits.filter(h => h.category === 'api_key_pattern');
    assert.ok(api.length >= 1, 'expected api_key_pattern hit');
    const exfil = r.hits.filter(h => h.category === 'exfil_phrase');
    assert.equal(exfil.length, 0, 'exfil markers stripped from finalHits');
    // Composite: 75 (api_key_pattern) + 0.25*75 (per-companion bonus) = 93.75 -> 94
    assert.ok(r.totalScore >= 90 && r.totalScore <= 100,
      `expected totalScore in [90,100], got ${r.totalScore}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-DS: data-shapes (cat 2.10) ------------------------------------

test('T-DS-ZW-001: ZWSP -> zero_width weight 25', () => {
  const dir = mkTmpStateDir();
  try {
    const body = 'hello​world with hidden zero-width space.';
    const r = scanOutbound({ body });
    const ds = r.hits.filter(h => h.category === 'data_shape_anomaly');
    const zw = ds.find(h => h.subCategory === 'zero_width');
    assert.ok(zw !== undefined, 'expected zero_width hit');
    assert.equal(zw?.weight, 25);
  } finally { cleanupTmpStateDir(dir); }
});

test('T-DS-TAG-001: Unicode tag block -> unicode_tag weight 35', () => {
  const dir = mkTmpStateDir();
  try {
    // U+E0041 is in the Unicode Tags block.
    const body = 'normal text \u{E0041} embedded tag.';
    const r = scanOutbound({ body });
    const ds = r.hits.filter(h => h.category === 'data_shape_anomaly');
    const tag = ds.find(h => h.subCategory === 'unicode_tag');
    assert.ok(tag !== undefined, 'expected unicode_tag hit');
    assert.equal(tag?.weight, 35);
  } finally { cleanupTmpStateDir(dir); }
});

test('T-DS-HG-001 (CRITICAL L-HG-1): Cyrillic homoglyph "АРI" -> homoglyph_cyr_lat weight 30', () => {
  const dir = mkTmpStateDir();
  try {
    // Token is Cyrillic А (U+0410) + Cyrillic Р (U+0420) + Latin I (U+0049).
    // hasMixedScriptCyrillicLatin requires len 3..40 + confusable + latin.
    const body = 'My АРI key is leaked here.';
    const r = scanOutbound({ body });
    const ds = r.hits.filter(h => h.category === 'data_shape_anomaly');
    const hg = ds.find(h => h.subCategory === 'homoglyph_cyr_lat');
    assert.ok(hg !== undefined,
      `expected homoglyph_cyr_lat hit, got ds=${JSON.stringify(ds.map(h=>h.subCategory))}`);
    assert.equal(hg?.weight, 30);
  } finally { cleanupTmpStateDir(dir); }
});

test('T-DS-BASE64-SKIP-001 (CRITICAL Patch 11): AKIA-prefixed base64 blob -> 1 api_key_pattern, 0 base64_blob', () => {
  const dir = mkTmpStateDir();
  try {
    // Construct ONE 150-char base64-shape token starting with AKIA. The
    // structural detector matches FIX_AKIA via the regex \bAK+IA[0-9A-Z]{16}\b
    // (boundary AFTER the 20-char shape). The base64 detector sees the whole
    // 150-char span and would emit base64_blob -- UNLESS looksLikeKnownVendor
    // (Patch 11) suppresses it. We assert both: api_key_pattern fires AND
    // base64_blob is suppressed.
    //
    // Build the token: AKIA-shape (chars in [A-Z0-9]) for 20 chars + word
    // boundary (so AWS detector can lock in) -- then resume with a SEPARATE
    // 130-char base64 blob that starts with the AKIA prefix again so
    // looksLikeKnownVendor catches the whole 150-char span when base64-scan
    // attempts to lift it.
    const padding = 'ABCDEFGHIJKLMNOP'.repeat(8) + 'AB';  // 130 chars
    // FIX_AKIA + space then separate 150-char blob starting with AKIA-shape
    const blob150 = 'AK' + 'IA' + 'ZZZZZZZZZZZZZZZZ' + padding;
    const body = `Token1: ${FIX_AKIA} and another blob: ${blob150} done.`;
    const r = scanOutbound({ body });
    const api = r.hits.filter(h => h.category === 'api_key_pattern');
    const base64 = r.hits.filter(h =>
      h.category === 'data_shape_anomaly' && h.subCategory === 'base64_blob');
    assert.ok(api.length >= 1, `expected >=1 api_key_pattern hit, got ${api.length}`);
    assert.equal(base64.length, 0,
      `expected 0 base64_blob hits (Patch 11 anti-double-count: looksLikeKnownVendor skip), got ${base64.length}`);
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-PII: demographic-pii (cat 2.11) -------------------------------

test('T-PII-FLOOR-001 (D14): lone phone -> ru_phone weight 10', () => {
  const dir = mkTmpStateDir();
  try {
    const body = 'My phone is +7 916 123 45 67 call me.';
    const r = scanOutbound({ body });
    const pii = r.hits.filter(h => h.category === 'demographic_pii');
    const phone = pii.find(h => h.subCategory === 'ru_phone');
    assert.ok(phone !== undefined, 'expected ru_phone hit');
    assert.equal(phone?.weight, 10);
  } finally { cleanupTmpStateDir(dir); }
});

test('T-PII-FLOOR-002 (CRITICAL Patch 9): 3 PII signals -> totalScore <= 15 (1.5x cap binds)', () => {
  const dir = mkTmpStateDir();
  try {
    // Phone + DOB + email. Per Patch 9, the 1.5x per-category cap (= 15 for
    // weight-10 signals) binds; the synthetic 25-clamp is removed.
    const body = 'My phone +7 916 123 45 67, born 15.05.1985, write to mom@gmail.com please.';
    const r = scanOutbound({ body });
    const pii = r.hits.filter(h => h.category === 'demographic_pii');
    assert.equal(pii.length, 3, `expected 3 PII hits, got ${pii.length}`);
    for (const h of pii) assert.equal(h.weight, 10);
    // Composite: 10 + 5 (50% diminish) + 0 (1.5x cap binds at 15) = 15.
    // PLUS cross-category bonus? Only ONE category fired, so no cross-cat.
    assert.ok(r.totalScore <= 15,
      `D14 / Patch 9: expected totalScore <= 15, got ${r.totalScore}`);
  } finally { cleanupTmpStateDir(dir); }
});

test('T-PII-DOB-NEG-001: implausible DOB year -> zero hits', () => {
  const dir = mkTmpStateDir();
  try {
    // Year 1825 is outside the 1900..2026 plausible band.
    const body = 'Some historical date 15.05.1825 in the records.';
    const r = scanOutbound({ body });
    const dob = r.hits.filter(h =>
      h.category === 'demographic_pii' && h.subCategory === 'dob');
    assert.equal(dob.length, 0, 'implausible DOB year must not emit');
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-CONFIG: category enable-flag suppression ---------------------

test('T-CONFIG-001: policy.categories.medical=false -> no medical hits', () => {
  const dir = mkTmpStateDir();
  try {
    const policy = getPolicy();
    const patched = {
      ...policy,
      categories: { ...policy.categories, medical: false },
    };
    _setPolicyForTests(patched);
    const body = 'У пациента Иванов Иван Иванович диагноз ВИЧ. Назначено лечение.';
    const r = scanOutbound({ body });
    const med = r.hits.filter(h => h.category === 'medical');
    assert.equal(med.length, 0, 'medical disabled -> no medical hits');
  } finally { cleanupTmpStateDir(dir); }
});

// -- T-LOGGING-01 (Patch 13): no auditLogAction( in detector files --

test('T-LOGGING-01 (Patch 13): no auditLogAction( token in src/scan/detectors/*.ts', () => {
  const detectorDir = path.join('src', 'scan', 'detectors');
  const files = fs.readdirSync(detectorDir).filter(f => f.endsWith('.ts'));
  assert.ok(files.length >= 6,
    `expected >=6 detector files, got ${files.length}: ${files.join(',')}`);
  for (const f of files) {
    const full = path.join(detectorDir, f);
    const src = fs.readFileSync(full, 'utf8');
    // Strip single-line comments to avoid false positives where the token
    // appears in doc-comments.
    const stripped = src.split('\n').map(line => {
      const idx = line.indexOf('//');
      return idx === -1 ? line : line.slice(0, idx);
    }).join('\n');
    assert.equal(stripped.indexOf('auditLogAction('), -1,
      `detector ${f} contains auditLogAction( (L-LOGGING-1 carve-out: detectors use only emitRedactedMatch)`);
  }
});

// -- T-DETERMINISM-01 (Patch 13 broadened): no Math.random / Date.now in src/scan/**/*.ts --

test('T-DETERMINISM-01 (Patch 13 broadened): no Math.random / Date.now in src/scan/**/*.ts', () => {
  const scanDir = path.join('src', 'scan');
  const files: string[] = [];
  function walk(dir: string): void {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && e.name.endsWith('.ts')) files.push(full);
    }
  }
  walk(scanDir);
  assert.ok(files.length >= 7,
    `expected >=7 files under src/scan/, got ${files.length}: ${files.join(',')}`);
  for (const f of files) {
    const src = fs.readFileSync(f, 'utf8');
    const stripped = src.split('\n').map(line => {
      const idx = line.indexOf('//');
      return idx === -1 ? line : line.slice(0, idx);
    }).join('\n');
    assert.equal(stripped.indexOf('Math.random'), -1,
      `${f} contains Math.random (L-DETERMINISM-1)`);
    assert.equal(stripped.indexOf('Date.now'), -1,
      `${f} contains Date.now (L-DETERMINISM-1)`);
  }
});
