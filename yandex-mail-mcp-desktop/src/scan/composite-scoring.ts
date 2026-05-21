// Exfil-phrase multiplier markers are stripped from finalHits by design.
// Downstream Phase 4 sees exfil pressure ONLY via totalScore deltas, not
// as discrete hits. If Phase 4 needs exfil hit visibility, change the
// contract here in v2.2.
//
// scan/composite-scoring.ts -- pure composite-score math for Phase 2 Plan
// 02-03 (L-COMP-1 revision 2; Patches 9 + 10 + 12 applied).
//
// Algorithm (verbatim from 02-03-PLAN.md <decisions> L-COMP-1):
//   Step 1: Separate multiplier markers (subCategory === 'multiplier') from
//           real hits.
//   Step 2: Group real hits by category. For each category:
//             - classified_marking -> MAX-not-sum (L-CLS-1).
//             - other -> 1st hit full weight, 2nd+ at 50%, capped at 1.5x
//                        of the largest single hit weight.
//           Patch 9 (revision 2): NO Math.min(categoryContribution, 25)
//           floor for demographic_pii. The 1.5x cap (= 15 for weight-10
//           signals) binds before any synthetic floor would fire -- the
//           clamp was dead code and is removed.
//   Step 3: Apply exfil-multiplier bonus PER-COMPANION IDEMPOTENT (Patch 10).
//           For each real hit, if ANY multiplier marker lives within 200
//           bytes of the real hit's byteStart, add (realHit.weight * 0.25)
//           ONCE for that companion. Total multiplier bonus clamped at +25
//           absolute (D12 belt-and-suspenders).
//   Step 4: Cross-category bonus: +10 when >= 3 distinct real categories fire.
//   Step 5: Sum -> NaN/Infinity guard via !Number.isFinite -> clamp [0, 100]
//           -> Math.round.
//   Step 6: finalHits = real hits sorted by weight desc, ties by category asc.
//           Multiplier markers are NOT included (Patch 12 contract).
//
// Pure function; no input mutation. No Math.random, no Date.now. Determinism
// enforced by T-DETERMINISM-01 (Patch 13 broadened).

import type { ScanHit } from '../outbound-scan.js';

export interface CompositeResult {
  totalScore: number;
  // Real hits, sorted; multiplier markers stripped per Patch 12.
  finalHits: ScanHit[];
}

const MULTIPLIER_WINDOW = 200;       // bytes; L-EXF-1 distance gate
const MULTIPLIER_BONUS_CAP = 25;     // CONTEXT D12 absolute cap
const CROSS_CATEGORY_THRESHOLD = 3;  // distinct categories
const CROSS_CATEGORY_BONUS = 10;     // +10 when threshold met
const COMPANION_FRACTION = 0.25;     // 25% of real-hit weight per companion
const DIMINISHING_RETURNS = 0.5;     // 2nd+ hit weight multiplier
const PER_CATEGORY_CAP_FACTOR = 1.5; // cap at 1.5x w1

// WR-01 defence-in-depth: categories that MUST NEVER appear in finalHits.
// Patch 12 already strips exfil_phrase multiplier markers via the Step 1
// subCategory==='multiplier' split, but a future drift -- e.g. a detector
// emitting an exfil_phrase hit without subCategory='multiplier', or a Phase
// 4 pre-composite injection bug -- would let that hit count as a distinct
// real category and trigger the +10 cross-category bonus. We filter the
// distinct-category set against this exclusion list so the bonus is robust
// against detector-author drift, not just trusting Step 1 to be the only
// guard.
const SHOULD_NEVER_REACH_FINAL_HITS: ReadonlySet<string> = new Set([
  'exfil_phrase',
]);

export function composeFinalScore(hits: ScanHit[]): CompositeResult {
  // Step 1: separate multiplier markers from real hits.
  const multipliers: ScanHit[] = [];
  const realHits: ScanHit[] = [];
  for (const h of hits) {
    if (h.subCategory === 'multiplier') multipliers.push(h);
    else realHits.push(h);
  }

  // Step 2: group by category, apply diminishing returns + per-category cap.
  const byCategory = new Map<string, ScanHit[]>();
  for (const h of realHits) {
    const arr = byCategory.get(h.category);
    if (arr === undefined) byCategory.set(h.category, [h]);
    else arr.push(h);
  }

  let baseScore = 0;
  for (const [category, hs] of byCategory.entries()) {
    // Sort descending by weight so the 1st (full-credit) hit is the heaviest.
    hs.sort((a, b) => b.weight - a.weight);
    const w1 = hs[0]?.weight ?? 0;

    let categoryContribution: number;
    if (category === 'classified_marking') {
      // L-CLS-1: MAX, not sum, not diminishing.
      categoryContribution = w1;
    } else {
      // Standard: 1st full, 2nd+ at DIMINISHING_RETURNS, cap at 1.5x w1.
      let sum = w1;
      for (let i = 1; i < hs.length; i++) {
        sum += hs[i].weight * DIMINISHING_RETURNS;
      }
      const cap = w1 * PER_CATEGORY_CAP_FACTOR;
      categoryContribution = Math.min(sum, cap);
    }

    // Patch 9 (revision 2): NO Math.min(categoryContribution, 25) clamp for
    // demographic_pii. The 1.5x per-category cap above (15 for weight-10
    // signals) binds BEFORE 25 ever would; the synthetic floor was dead code.

    baseScore += categoryContribution;
  }

  // Step 3: apply exfil multipliers -- PER-COMPANION IDEMPOTENT (Patch 10).
  // For EACH real hit, check whether ANY multiplier marker lives within
  // MULTIPLIER_WINDOW bytes. If yes, add (h.weight * COMPANION_FRACTION) ONCE
  // for that companion. This is NOT a per-multiplier loop -- prior revision-1
  // was per-multiplier and double-counted when 2+ multipliers shared a
  // companion. The total accumulated bonus is then absolute-capped at
  // MULTIPLIER_BONUS_CAP (D12 belt-and-suspenders).
  let multiplierBonus = 0;
  if (multipliers.length > 0) {
    for (const h of realHits) {
      const target = h.evidence.byteStart;
      let nearby = false;
      for (const mk of multipliers) {
        if (Math.abs(mk.evidence.byteStart - target) <= MULTIPLIER_WINDOW) {
          nearby = true;
          break;
        }
      }
      if (nearby) multiplierBonus += h.weight * COMPANION_FRACTION;
    }
    multiplierBonus = Math.min(multiplierBonus, MULTIPLIER_BONUS_CAP);
  }

  // Step 4: cross-category bonus (+10 when >= 3 distinct real categories fire).
  // WR-01 defence-in-depth: exclude SHOULD_NEVER_REACH_FINAL_HITS categories
  // from the distinct-category count. Step 1 already strips multiplier
  // markers via subCategory==='multiplier', but if a future bug ever lets an
  // exfil_phrase hit leak through Step 1 (e.g. emitted without the multiplier
  // subCategory), this guard keeps the +10 bonus computed from REAL
  // categories only.
  let distinctCategories = 0;
  for (const cat of byCategory.keys()) {
    if (!SHOULD_NEVER_REACH_FINAL_HITS.has(cat)) distinctCategories++;
  }
  if (process.env.YANDEX_SCAN_DEBUG === '1') {
    let leaked = 0;
    for (const h of realHits) {
      if (SHOULD_NEVER_REACH_FINAL_HITS.has(h.category)) leaked++;
    }
    if (leaked > 0) {
      process.stderr.write(
        `[composite-scoring] WARN: ${leaked} stripped-category hit(s) leaked into realHits (expected 0 -- Patch 12 contract drift)\n`,
      );
    }
  }
  const crossBonus = distinctCategories >= CROSS_CATEGORY_THRESHOLD ? CROSS_CATEGORY_BONUS : 0;

  // Step 5: sum + NaN/Infinity guard + clamp + round.
  let total = baseScore + multiplierBonus + crossBonus;
  // !Number.isFinite catches BOTH NaN AND +/-Infinity in one predicate.
  if (!Number.isFinite(total)) total = 0;
  if (total < 0) total = 0;
  if (total > 100) total = 100;
  total = Math.round(total);

  // Step 6: produce finalHits (real hits sorted; multipliers DROPPED per Patch 12).
  const finalHits = realHits.slice().sort((a, b) => {
    if (b.weight !== a.weight) return b.weight - a.weight;
    return a.category < b.category ? -1 : a.category > b.category ? 1 : 0;
  });

  return { totalScore: total, finalHits };
}
