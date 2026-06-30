// stemmer.ts -- dependency-free light stemmer for RU + EN search tokens.
//
// Goal: collapse inflectional variants so "выписку" (accusative) finds a subject
// "выписка" (nominative), and "invoices" finds "invoice". Applied SYMMETRICALLY
// at index build and at query time (same function both sides) -- that symmetry is
// the whole point: a token and its query form must reduce to the same stem.
//
// Why hand-rolled, not Snowball-via-npm: the connector ships as a single esbuild
// bundle with zero native deps and `npm audit`=0. A light suffix-stripper covers
// the high-frequency inflections that matter for deterministic retrieval while
// adding no dependency; the agent layer above handles true semantic nuance
// (synonyms, paraphrase). If quality ever proves insufficient, vendoring the full
// Snowball stemmers is a follow-on -- the call site (one function) does not change.
//
// Conservative by design:
//   - a MIN_STEM floor stops over-stripping short words into collisions;
//   - only the FIRST (longest) matching ending is removed (single pass);
//   - unknown scripts (digits, latin-in-cyrillic-mix, etc.) pass through;
//   - never returns empty -- if stripping would underflow MIN_STEM, the token is
//     returned unchanged.

const MIN_STEM = 3;

// Russian inflectional endings. Listed here unsorted for readability; sorted
// longest-first at module load so the most specific ending wins (e.g. "ами"
// before "и"). Covers reflexive, adjective, common verb, and noun/case endings.
// Single-character endings are restricted to vowels + ь/й (stripping a lone
// consonant over-strips), so e.g. "документ" is left intact while "документы",
// "документа", "документу" all reduce to "документ".
const RU_ENDINGS_RAW: string[] = [
  // reflexive
  'ся', 'сь',
  // gerund / participle / verb
  'ться', 'тся', 'ешь', 'ете', 'йте', 'ишь', 'ите', 'нно', 'вши', 'вшись',
  'ть', 'ла', 'ло', 'ли', 'на', 'но', 'ны', 'ет', 'ют', 'ит', 'ат', 'ят',
  // adjective
  'ого', 'ему', 'ому', 'ыми', 'ими', 'его', 'ая', 'яя', 'ое', 'ее', 'ые',
  'ий', 'ый', 'ой', 'ей', 'ую', 'юю', 'ою', 'ею', 'их', 'ых', 'ом', 'ем', 'им', 'ым',
  // noun / case (multi-char first)
  'иями', 'ями', 'ами', 'иях', 'ях', 'ах', 'иям', 'ям', 'ам', 'ев', 'ов', 'ие', 'ье',
  // single-char vowels + soft markers
  'а', 'я', 'о', 'е', 'у', 'ю', 'ы', 'и', 'й', 'ь',
];

// English INFLECTIONAL suffixes only (verb/adverb), longest-first. Plurals are
// handled by the Porter step-1a special cases in stemEn (NOT a plain "es"/"s"
// strip, which would split "invoices" -> "invoic" while "invoice" stays put and
// break the match). Derivational suffixes (ment/ness/ization) are deliberately
// NOT stripped -- they over-stem (statement -> state) and hurt precision for a
// retrieval primitive.
const EN_INFLECTION_RAW: string[] = ['edly', 'ing', 'ed', 'ly'];

function sortLongestFirst(a: string[]): string[] {
  return a.slice().sort((x, y) => y.length - x.length);
}

const RU_ENDINGS = sortLongestFirst(RU_ENDINGS_RAW);
const EN_INFLECTION = sortLongestFirst(EN_INFLECTION_RAW);

// 0x0400-0x04FF is the Cyrillic block. One Cyrillic char anywhere is enough to
// route a token to the Russian rules (search tokens are single words).
const CYRILLIC_RE = /[Ѐ-ӿ]/;

function stripFirst(word: string, endings: string[]): string {
  for (const e of endings) {
    if (word.length - e.length >= MIN_STEM && word.endsWith(e)) {
      return word.slice(0, word.length - e.length);
    }
  }
  return word;
}

function stemRu(word: string): string {
  return stripFirst(word, RU_ENDINGS);
}

function stemEn(word: string): string {
  if (word.length <= MIN_STEM) return word;
  // Porter step 1a -- plurals.
  let w = word;
  if (w.endsWith('sses')) w = w.slice(0, -2);                    // assesses -> assess
  else if (w.endsWith('ies')) w = w.slice(0, -3) + 'i';          // parties -> parti, cities -> citi
  else if (w.endsWith('ss')) { /* keep: business -> business, not busines */ }
  else if (w.endsWith('s')) w = w.slice(0, -1);                  // invoices -> invoice, reports -> report
  // Light step 1b/1c -- verb/adverb inflection (MIN_STEM guarded inside stripFirst).
  w = stripFirst(w, EN_INFLECTION);                             // reporting -> report, quickly -> quick
  return w.length >= MIN_STEM ? w : word;
}

// stem: lowercase-in, stemmed-out. Tokenizer lowercases already, but we guard
// here too so the function is correct standalone (tests, query path).
export function stem(token: string): string {
  if (!token) return token;
  const w = token.toLowerCase();
  if (w.length <= MIN_STEM) return w;
  return CYRILLIC_RE.test(w) ? stemRu(w) : stemEn(w);
}
