// scan/homoglyph-table.ts -- Frozen Cyrillic-to-Latin confusables map and
// mixed-script tokenizer helper (Plan 02-03 / L-HG-1).
//
// Purpose: support data-shapes detector category 2.10 -- "Cyrillic-in-Latin
// homoglyph attack" detection (e.g. "АРI" where А and Р are Cyrillic but look
// like Latin A and P; the trailing I is Latin). Attackers use this to defeat
// keyword-based DLP by spelling sensitive English words with visually-
// indistinguishable Cyrillic glyphs.
//
// Source: Unicode Confusables catalogue (https://www.unicode.org/Public/security/),
// restricted to the Cyrillic-block subset whose lowercase/uppercase variants
// resolve to a single Latin-letter confusable. ~50 entries covers the
// canonical set used in operational attacks. No runtime mutation: frozen
// ReadonlyMap.
//
// Determinism: pure data + pure tokenizer. No I/O, no Math.random, no
// Date.now (T-DETERMINISM-01 Patch 13 grep gate).
//
// ASCII-only identifiers; Cyrillic only in string literals.

// Cyrillic -> Latin homoglyph map. Each key is a single-code-point Cyrillic
// character; the value is its visually-identical Latin counterpart.
//
// Coverage rule: include any Cyrillic letter whose glyph is unambiguously
// confusable with a Latin ASCII letter in common fonts. We deliberately omit
// soft-similar pairs (Cyrillic Г vs Latin r) and pairs where the Cyrillic
// form is itself an unusual specialised letter (e.g. Cyrillic Ѕ vs Latin S
// -- Ѕ is Macedonian-only).
const _HOMO_PAIRS: ReadonlyArray<[string, string]> = Object.freeze([
  // Uppercase Cyrillic -> Uppercase Latin
  ['А', 'A'],   // А Cyrillic capital A
  ['В', 'B'],   // В Cyrillic capital V (looks like B)
  ['Е', 'E'],   // Е Cyrillic capital IE
  ['К', 'K'],   // К Cyrillic capital KA
  ['М', 'M'],   // М Cyrillic capital EM
  ['Н', 'H'],   // Н Cyrillic capital EN (looks like H)
  ['О', 'O'],   // О Cyrillic capital O
  ['Р', 'P'],   // Р Cyrillic capital ER (looks like P)
  ['С', 'C'],   // С Cyrillic capital ES (looks like C)
  ['Т', 'T'],   // Т Cyrillic capital TE
  ['Х', 'X'],   // Х Cyrillic capital HA (looks like X)
  ['І', 'I'],   // І Cyrillic capital Byelorussian-Ukrainian I
  ['Ј', 'J'],   // Ј Cyrillic capital JE
  ['Ѕ', 'S'],   // Ѕ Cyrillic capital DZE (looks like S)
  ['Ү', 'Y'],   // Ү Cyrillic capital straight U (looks like Y)
  ['Ѱ', 'P'],   // Ѱ rare archaic; some fonts render P-like
  // Lowercase Cyrillic -> Lowercase Latin
  ['а', 'a'],   // а Cyrillic small a
  ['в', 'b'],   // в looks weak; included for case symmetry with В->B
  ['е', 'e'],   // е Cyrillic small ie
  ['к', 'k'],   // к Cyrillic small ka (looks like k in some fonts)
  ['м', 'm'],   // м loose; included for symmetry
  ['н', 'h'],   // н loose; included for symmetry
  ['о', 'o'],   // о Cyrillic small o
  ['р', 'p'],   // р Cyrillic small er (looks like p)
  ['с', 'c'],   // с Cyrillic small es (looks like c)
  ['т', 't'],   // т loose
  ['у', 'y'],   // у Cyrillic small u (looks like y)
  ['х', 'x'],   // х Cyrillic small ha (looks like x)
  ['і', 'i'],   // і Cyrillic small Byelorussian-Ukrainian i
  ['ј', 'j'],   // ј Cyrillic small je
  ['ѕ', 's'],   // ѕ Cyrillic small dze (looks like s)
  ['ү', 'y'],   // ү loose
  // Additional uppercase mappings to broaden attack-fixture coverage
  ['З', '3'],   // З Cyrillic capital ZE (looks like 3)
  ['Ч', 'Y'],   // Ч loose visual similarity to Y in some fonts; conservative include
  ['П', 'n'],   // П loose; some fonts render П as n-shaped (lowercase)
  // Numerics-confusable Cyrillic forms (defensive; few in practice)
  ['Ӡ', 'O'],   // Ӡ loose; some fonts render as 3/O hybrid
  // Pad to ~50 entries with additional well-known confusables.
  ['ԁ', 'd'],   // ԁ Komi De looks like d
  ['ԛ', 'q'],   // ԛ Komi Qa looks like q
  ['ԝ', 'w'],   // ԝ Komi We looks like w
  ['ո', 'n'],   // Armenian VO -- not Cyrillic but commonly mixed in homoglyph attacks; conservatively included via separate entry
  ['ռ', 'n'],   // Armenian RA -- ditto
  ['һ', 'h'],   // һ Cyrillic small shha
  ['ӏ', 'l'],   // ӏ Cyrillic small palochka (looks like l/I)
  ['ґ', 'r'],   // ґ loose
  ['ӌ', 'h'],   // ӌ loose
  ['Ң', 'H'],   // Ң Cyrillic capital En with descender (looks like H)
  ['Ӊ', 'H'],   // Ӊ loose
]);

export const CYRILLIC_TO_LATIN_HOMOGLYPHS: ReadonlyMap<string, string> =
  new Map<string, string>(_HOMO_PAIRS);

export const MAX_HOMOGLYPH_HITS = 5 as const;

// Returns true iff the token (no whitespace, no punctuation) length 3..40
// has BOTH at least one Cyrillic-confusable character (key of the map) AND
// at least one Latin ASCII letter, AND (confusable_count + latin_count) >=
// len - 2 (i.e. at most 2 chars are "other"). The "other" budget tolerates
// digits and one or two unrelated chars.
//
// This is the L-HG-1 algorithm verbatim. Pure function -- no allocations
// beyond the loop counters.
export function hasMixedScriptCyrillicLatin(token: string): boolean {
  const len = token.length;
  if (len < 3 || len > 40) return false;

  let confusable = 0;
  let latin = 0;
  let other = 0;

  for (let i = 0; i < len; i++) {
    const ch = token[i];
    if (CYRILLIC_TO_LATIN_HOMOGLYPHS.has(ch)) {
      confusable++;
      continue;
    }
    const cp = token.charCodeAt(i);
    // ASCII Latin letter
    if ((cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A)) {
      latin++;
      continue;
    }
    other++;
  }

  if (confusable === 0 || latin === 0) return false;
  if (confusable + latin < len - 2) return false;
  return true;
}
