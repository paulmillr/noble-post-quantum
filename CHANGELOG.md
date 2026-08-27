# Changelog for noble-post-quantum

## 0.7.1 (2026-08-27)

- Added `@noble/post-quantum/webcrypto.js`, an async noble-style wrapper around the experimental built-in WebCrypto implementations of ML-KEM-512, ML-KEM-768, ML-KEM-1024, and ML-KEM-768 + X25519. It supports deterministic raw-seed key generation, public-key derivation, encapsulation, decapsulation, and a memoized `isSupported()` probe that performs a complete round trip instead of checking method presence alone.
- Snapshot all options to ensure they're not mutated later
- Snapshot msg in `falcon*.attached.open()`
- Ensure `falcon*.attached.open()` throws correct error for malformed sig / pubkey
- `combineKEMS()` and `combineSigners()` now expect valid byte arrays
- Enforce digest lengths promised by pre-hash XOF OIDs: 32b for SHAKE128, 64b for SHAKE256
- Improve zeroization
- Improve Falcon signing and parsing: imported compact secret keys are rejected when the reconstructed sampler deviation is outside Falcon's proof interval
- Harden WebCrypto input validation

Special thanks to Leon Acosta (from QuantaKrypto audits).

## 0.7.0 (2026-08-09)

### Breaking changes

- Removed legacy `hybrid` aliases:
  - `XWing` and `MLKEM768X25519` → `ml_kem768_x25519`.
  - `MLKEM768P256` → `ml_kem768_p256`.
  - `MLKEM1024P384` → `ml_kem1024_p384`.
  - `QSFMLKEM768P256` → `QSF_ml_kem768_p256`.
  - `QSFMLKEM1024P384` → `QSF_ml_kem1024_p384`.
  - `KitchenSinkMLKEM768X25519` → `KitchenSink_ml_kem768_x25519`.
- Stopped exporting `afunction` from `utils`; it moved to `@noble/curves/utils.js`.

### Other changes

- Fixed the length check in detached, non-default Falcon.
- Fixed an intermediate overflow in `MultiplyNTTs`, where `a1 * b1 * zeta` could reach approximately 2³⁵.
- Changed ML-DSA signing to draw entropy before decoding the secret key, so an RNG exception cannot leave partially decoded key material live.
- Made ML-DSA `externalMu` require a 64-byte `msg` value.
- Made ML-KEM detach the caller's public key before caching it.
- Made `equalBytes` validate its inputs and tightened other checks and error messages.
- Improved SLH-DSA performance by up to 2×.
- Improved hybrid ML-KEM-768 and X25519 performance by 16–42%.
- Upgraded noble dependencies to 2.3.0.
- Reduced unpacked package size from 813 KB to 654 KB by disabling source maps.

## 0.6.1 (2026-04-12)

- Fixed byte-array types for compatibility with both TypeScript 5.6 and TypeScript 5.9+.
  - TypeScript 5.6 uses `Uint8Array`, while TypeScript 5.9+ made it generic as `Uint8Array<ArrayBuffer>`.
  - This previously caused incompatibilities and errors such as `TS2345`.
  - See [TypeScript issue #62240](https://github.com/microsoft/TypeScript/issues/62240) for more context.
- Updated noble dependencies to the hardened 2.2 releases following the recent audits.

### New contributors

- [@tob-scott-a](https://github.com/tob-scott-a) made their first contribution in [pull request #39](https://github.com/paulmillr/noble-post-quantum/pull/39).

## 0.6.0 (2026-03-31)

- Implemented Falcon signatures in preparation for FN-DSA and FIPS 206.
- Completed the March 2026 self-audit with no major findings and incorporated numerous minor security and stability improvements.
- Added detailed documentation throughout the package.

## 0.5.4 (2025-12-22)

- Fixed the default randomness length in `ecdhKem.encapsulate`, contributed by [@FiloSottile](https://github.com/FiloSottile) in [pull request #35](https://github.com/paulmillr/noble-post-quantum/pull/35).
- Renamed `hybrid.js` exports to align with the other modules. The old names remain available until version 0.6:

```js
import {
  ml_kem768_x25519, ml_kem768_p256, ml_kem1024_p384,
  KitchenSink_ml_kem768_x25519, XWing,
  QSF_ml_kem768_p256, QSF_ml_kem1024_p384,
} from '@noble/post-quantum/hybrid.js';
```

### New contributors

- [@FiloSottile](https://github.com/FiloSottile) made their first contribution in [pull request #35](https://github.com/paulmillr/noble-post-quantum/pull/35).

## 0.5.3 (2025-12-21)

- Implemented [`irtf-cfrg-concrete-hybrid-kems-02`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/), contributed by [@panva](https://github.com/panva) in [pull request #34](https://github.com/paulmillr/noble-post-quantum/pull/34).

```ts
import { MLKEM768X25519, MLKEM768P256, MLKEM1024P384 } from '@noble/post-quantum/hybrid.js';
```

### New contributors

- [@MurasameKei](https://github.com/MurasameKei) made their first contribution in [pull request #31](https://github.com/paulmillr/noble-post-quantum/pull/31).

## 0.5.2 (2025-09-22)

- Disabled extensionless imports. If you used `/ml-dsa`, switch to `/ml-dsa.js`. See [0.5.0](https://github.com/paulmillr/noble-post-quantum/releases/tag/0.5.0) for more details.
- Specified exported submodules in `package.json` to ensure TypeScript autocompletion.

### GitHub Immutable Releases

This GitHub release does not include the standalone `noble-post-quantum.js` while issues related to newly introduced GitHub Immutable Releases are resolved.

## 0.5.1 (2025-08-25)

- Updated to stable version 2 releases of noble-hashes and noble-curves.

## 0.5.0 (2025-08-19)

### New features

- Added the hybrid post-quantum algorithms X-Wing, KitchenSinkMLKEM768X25519, QSFMLKEM768P256, and QSFMLKEM1024P384.
- Added `context` support to ML-DSA and SLH-DSA.
- Added `getPublicKey` to ML-KEM and ML-DSA.

### Changes

- Made the package ESM-only. ESM can be loaded from CommonJS on Node.js 20.19+.
  - Node.js 20.19 is now the minimum required version.
  - Reduced unpacked package size from 423 KB to 312 KB.
- Required the `.js` extension for all modules.
  - Old: `@noble/post-quantum/slh-dsa`.
  - New: `@noble/post-quantum/slh-dsa.js`.
  - This simplifies native browser usage without transpilers.
- Changed argument order across all methods for consistency with noble-curves.
  - `sign(secretKey, msg, rnd)` → `sign(msg, secretKey, opts)`.
  - `verify(publicKey, msg, sig, ctx)` → `verify(sig, msg, publicKey, opts)`.
- Updated to noble-hashes version 2 for a smaller package and improved security.
- Added a new prehash API.
- Upgraded the TypeScript compilation environment to TypeScript 5.9 and ES2022.

## 0.4.1 (2025-04-24)

- Made modules available with a `.js` extension.
  - Old: `@noble/post-quantum/slh-dsa`.
  - New: `@noble/post-quantum/slh-dsa.js`.
  - The old path remains available.
  - This simplifies native browser usage without transpilers.
- Made SLH-DSA zeroize key-generation inputs when the argument is undefined.
- Updated noble-hashes to [1.8.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.8.0).
- Made TypeScript source runnable without compilation on Node.js 24 through [`erasableSyntaxOnly`](https://devblogs.microsoft.com/typescript/announcing-typescript-5-8/#the---erasablesyntaxonly-option).

### New contributors

- [@panva](https://github.com/panva) made their first contribution in [pull request #20](https://github.com/paulmillr/noble-post-quantum/pull/20).

## 0.4.0 (2025-02-06)

- Exported both external and internal prehashed versions of the algorithms.
- Reused the noble-hashes polyfill for `setBigUint64`.

## 0.3.1 (2025-01-18)

- Enabled TypeScript `verbatimModuleSyntax` in preparation for native Node.js type stripping.
- Updated noble-hashes to [1.7.1](https://github.com/paulmillr/noble-hashes/releases/tag/1.7.1).
- Improved documentation.

## 0.3.0 (2025-01-03)

- Published the package on [JSR](https://jsr.io/@noble/post-quantum).
- Enabled TypeScript [`isolatedDeclarations`](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-5-5.html#isolated-declarations), simplifying generated documentation and related tooling.
- Added extensive comments to improve autocompletion, code generation, and general code comprehension.
- Updated noble-hashes to [1.7.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.7.0).

## 0.2.1 (2024-11-23)

- Exposed context-based methods from ML-DSA.
- Updated noble-hashes to version 1.6.0.

## 0.2.0 (2024-08-22)

- Updated to the final FIPS 203, 204, and 205 specifications and removed support for non-FIPS Kyber.

## 0.1.0 (2024-04-02)

- Initial release
