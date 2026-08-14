/**
 * Internal ML-DSA helpers whose contracts are narrower than the FIPS 204 primitives they replace.
 */

/**
 * Compute a signing hint from the adjusted low bits used by the optimized ML-DSA signing path.
 *
 * This is the Section 5.1 / pq-crystals alternative to FIPS 204 Algorithm 39. Its arguments are
 * `adjustedLowBits = (LowBits(w - cs2) + ct0) mod q` and `originalHighBits = HighBits(w)`.
 * They are not the `(z, r)` arguments accepted by the generic `MakeHint` algorithm.
 */
export function makeHintFromAdjustedLowBits(
  adjustedLowBits: number,
  originalHighBits: number,
  gamma2: number,
  q: number
): number {
  return adjustedLowBits <= gamma2 ||
    adjustedLowBits > q - gamma2 ||
    (adjustedLowBits === q - gamma2 && originalHighBits === 0)
    ? 0
    : 1;
}
