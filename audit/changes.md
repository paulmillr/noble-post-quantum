# Audit changes

Combined from the per-module reviews (ML-KEM, SLH-DSA, ML-DSA, hybrid: 2026-07-05, baseline
commit `11f13b4`; Falcon: 2026-07-25). Only changes are listed — the "reviewed, matches spec"
findings are omitted. All ACVP / Wycheproof / KAT vectors pass after each change.

## Vulnerability fixes

- **Falcon padded signature malleability (SUF-CMA break, `src/falcon.ts`).** The padded detached
  decoder derived the payload width from the input (`data.length - NONCELEN - 1`) instead of the
  parameter set's fixed `sigLen`, and `verify()` did no length check, so any number of trailing
  `0x00` bytes could be appended to a valid `falcon512padded`/`falcon1024padded` signature and
  still verify — distinct signature byte strings for the same `(msg, pk)` without the secret key.
  Impacts consumers that treat signature bytes (or their hash) as a unique identifier
  (replay/idempotency caches, dedup, content-addressed storage). No key recovery, no new-message
  forgery. Unpadded Falcon was never affected (`decodeUnpaddedSig` enforces exact length).
  Fixed by taking the payload width from `opts.sigLen` when padded. The attached padded coder
  shared the flaw in the other direction (a container shorter than the fixed part borrowed bytes,
  letting a truncated encoding open to the same message); it now rejects `msgLen < 0`.

## Bug fixes

- **SLH-DSA `verify` threw on wrong-length signatures** (`src/slh-dsa.ts`). The
  `sig.length !== sigCoder.bytesLen` check sat *after* `sigCoder.decode`, which throws on any
  length mismatch — dead code. FIPS 205 Alg. 20 step 1 requires `return false`, and ml-dsa already
  did. Check moved before decode. (The ACVP harness had a try/catch working around this.)
- **`combineSigners.verify` threw `RangeError` on wrong-length signatures** (`src/hybrid.ts`).
  Same check-after-decode class; length check moved before decode. Malformed *publicKey* still
  throws (API misuse), in both cases.
- **Hybrid `keygen(seed)` returned the caller's seed as `secretKey`** (`k.secretKey === seed`).
  Mutating the seed silently changed the key; wiping one wiped the other. Root is now detached via
  `copyBytes`, with wipe-on-throw. Only object identity changes.
- **Hybrid `this`-dependence broke destructured usage.** `getPublicKey`, `ecdhKem.encapsulate` and
  `nistCurveKem.encapsulate` used `this.keygen` / `this.decapsulate`, so
  `const { getPublicKey } = XWing` threw `TypeError`. Now closures over local functions.
- **ML-DSA `externalMu` inputs were not length-checked** (`src/ml-dsa.ts`). `internal.sign` /
  `internal.verify` accepted any µ length, producing signatures bound to a non-standard
  representative (FIPS 204 defines µ = H(tr‖M) as exactly 64 bytes). Both paths now
  `abytes(msg, CRH_BYTES, 'mu')`.

## Secret-hygiene fixes

- **ML-KEM `decapsulate` left derived encryption randomness in memory** — `kr[32:64]` (the K-PKE
  randomness `r` from the decrypted message) was not wiped, though `encapsulate` wiped its
  counterpart. Added to the final `cleanBytes`.
- **ML-DSA `extraEntropy` was validated after secret expansion, and generated entropy was never
  wiped.** A bad length threw only after `secretCoder.decode` had produced s1/s2/t0 and Â, which
  the exception path never wipes. Validation now runs before any secret material is touched; `rnd`
  is wiped after ρ′ derivation when the library generated it (caller-provided entropy stays
  caller-owned).
- **Hybrid seed expander leaked the combined seed buffer** — `concreteHybridKem` returned
  `concatBytes` of two adjacent subarrays of the SHAKE output, leaving the original (holding both
  child seeds) unwiped. It now returns the SHAKE output directly, which `expandDecapsulationKey`
  already wipes.

## Performance changes

ML-KEM (NTT layer, measured in isolation: forward −18%, inverse −25%, MultiplyNTTs −18%):

- Kyber-only conditional `±Q` reduction in the FFT field ops (`_crystals.ts`); gated on `isKyber`
  because ML-DSA feeds centered-negative coefficients into the first butterfly stage. Note
  `__tests.NTT` on out-of-range input is now garbage-in-garbage-out.
- `BaseCaseMultiply` keeps intermediates in int32 (`a1·b1·zeta` reached ~2^35, forcing V8 into
  Float64Mod and degrading *every* `crystals.mod` call site via type feedback).
- `polyAdd`/`polySub` conditional reduction (same `[0, q)` invariant).
- `bitsCoder.encode` uses `& 0xff` instead of calling `getMask(bufLen)` (with its `anumber`
  validation) per output byte. Also benefits ML-DSA packing.

SLH-DSA (SHA2 variants ~1.7–2.2× faster; SHAKE ~3–6%, Keccak-bound):

- Scratch-buffer hashing: `thash1`/`thashN`/`PRFaddr` use `digestInto`/`xofInto` on per-context
  buffers instead of allocating an output and zeroing state per call. All retention sites audited
  and `copyBytes`-ed; aliasing contract documented on `Context`, mirroring the `XOF` contract.
- `setAddr` writes big-endian bytes directly instead of allocating a `DataView` per call.
- `treehash` node buffer hoisted out of the per-leaf loop.

ML-DSA:

- `HINT_M = (q−1)/(2γ2)` hoisted out of `UseHint` (it ran `Math.floor` per coefficient).

Experimental, unstabilized: **`ml_kem768.prepare(publicKey)`** caches public data only (Â, t̂, ek
copy, H(ek)) — encapsulate/decapsulate ~1.7–2.1× faster for repeated ops against one key. Open:
API naming, whether `keygen` should return it, whether hybrid should thread it through.

## Negative results (recorded so they are not retried)

- **The ML-KEM `%`-elimination tricks are ~10–15% *slower* for ML-DSA** (neutral for
  `polyAdd`/`polySub`), for structural reasons: ML-DSA's first-stage butterfly operands may be
  centered-negative, so `a − t` can drop below `−q` and a single correction is insufficient; and
  for the 23-bit q, V8 compiles `%` to one int32 division. Experiments reverted; comments in
  `_crystals.ts` and `ml-dsa.ts` record the measurement.
- **Secret-retaining caches rejected** across SLH-DSA (top-layer XMSS tree), ML-DSA (NTT(s1/s2/t0))
  and hybrid (expanded child secret keys): the win is modest and they keep secret-derived material
  between calls, unlike the public-data-only ML-KEM `prepare()`.
- Remaining headroom is mostly in dependencies: Keccak dominates ML-KEM (~50%) and ML-DSA (~33%);
  a low-level single-block SHA-256 compression hook would help SLH-DSA's SHA2 lane (~another 1.5×)
  but belongs in `@noble/hashes`; X25519/P-256 scalar mults dominate the hybrids (`@noble/curves`).

## Tests added

- `test/basic.test.ts` — ML-KEM modulus-check boundary (coefficient = q rejected, q−1 accepted,
  all three sets); secret-key `H(ek)` corruption throws while `z` corruption does not; implicit
  rejection equals `SHAKE256(z‖c, 32)` exactly. SLH-DSA wrong-length signatures (truncated,
  extended, empty) return `false` on SHA2 and SHAKE variants, `verify` and `internal.verify`.
  ML-DSA `externalMu` rejects 0/63/65-byte µ; malformed hint encodings (counter > ω, non-zero
  padding, truncation) return `false` without throwing.
- `test/falcon.test.ts` — padded malleability: zero-appended and padding-truncated detached
  signatures rejected, attached seal rejects truncation/extension, unpadded control still rejects.
- `test/hybrid.test.ts` — wrong-length aggregate signatures return `false`; `keygen` secretKey is
  detached from the caller's seed (XWing, QSF, KitchenSink); full cycle works when destructured.
