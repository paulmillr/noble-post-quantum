# noble-post-quantum

Auditable & minimal JS implementation of post-quantum public-key cryptography.

- 🔒 Auditable
- 🪶 Minimal: 7KB (gzipped) ML-KEM, unused code is excluded from your builds
- 🏎 Fast: hand-optimized for caveats of JS engines
- 🔍 Reliable: ACVP / wycheproof tests ensure correctness
- 🦾 ML-KEM & CRYSTALS-Kyber: lattice-based KEM from FIPS-203
- 🔋 ML-DSA & CRYSTALS-Dilithium: lattice-based signatures from FIPS-204
- 🐈 SLH-DSA & SPHINCS+: hash-based Winternitz signatures from FIPS-205
- 🦅 Falcon: lattice-based signatures from Falcon Round 3
- 🍡 Hybrid algorithms (combining classic & post-quantum)

> [!IMPORTANT]
> NIST published draft [IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf),
> which proposes prohibiting classical cryptography (RSA, DSA, ECDSA, ECDH) after 2035.
> Australia's ASD does the same [after 2030](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography).
> Take this into account when designing new cryptographic systems.

### This library belongs to _noble_ cryptography

> **noble cryptography** — high-security, easily auditable set of contained cryptographic libraries and tools.

- Zero or minimal dependencies
- Highly readable TypeScript / JS code
- PGP-signed releases and transparent NPM builds
- All libraries:
  [ciphers](https://github.com/paulmillr/noble-ciphers),
  [curves](https://github.com/paulmillr/noble-curves),
  [hashes](https://github.com/paulmillr/noble-hashes),
  [post-quantum](https://github.com/paulmillr/noble-post-quantum),
  5kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)
- WASM version: [awasm-noble](https://github.com/paulmillr/awasm-noble)
- [Check out the homepage](https://paulmillr.com/noble/)
  for reading resources, documentation, and apps built with noble

## Usage

> `npm install @noble/post-quantum`

> `deno add jsr:@noble/post-quantum`

We support all major platforms and runtimes.
For React Native, you may need a
[polyfill for getRandomValues](https://github.com/LinusU/react-native-get-random-values).
A standalone file
[noble-post-quantum.js](https://github.com/paulmillr/noble-post-quantum/releases) is also available.

```js
// import * from '@noble/post-quantum'; // Error: use sub-imports instead
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
  slh_dsa_shake_128f,
  slh_dsa_shake_128s,
  slh_dsa_shake_192f,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa.js';
import {
  falcon512, falcon512padded, falcon1024, falcon1024padded,
} from '@noble/post-quantum/falcon.js';
import {
  ml_kem768_x25519, ml_kem768_p256, ml_kem1024_p384,
  KitchenSink_ml_kem768_x25519, QSF_ml_kem768_p256, QSF_ml_kem1024_p384,
} from '@noble/post-quantum/hybrid.js';
```

- [ML-KEM / Kyber](#ml-kem--kyber-shared-secrets)
- [ML-DSA / Dilithium](#ml-dsa--dilithium-signatures)
- [SLH-DSA / SPHINCS+](#slh-dsa--sphincs-signatures)
- [Falcon](#falcon-signatures)
- [hybrid: X-Wing, KitchenSink and others](#hybrid-x-wing-kitchensink-and-others)
- [What should I use?](#what-should-i-use)
- [Security](#security)
- [Contributing & testing](#contributing--testing)
- [Speed](#speed)
- [License](#license)

### ML-KEM / Kyber shared secrets

```ts
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { equalBytes, randomBytes } from '@noble/post-quantum/utils.js';
const seed = randomBytes(64); // seed is optional
const aliceKeys = ml_kem768.keygen(seed);
const { cipherText, sharedSecret: bobShared } = ml_kem768.encapsulate(aliceKeys.publicKey);
const aliceShared = ml_kem768.decapsulate(cipherText, aliceKeys.secretKey);

// Warning: Can be MITM-ed
const malloryKeys = ml_kem768.keygen();
const malloryShared = ml_kem768.decapsulate(cipherText, malloryKeys.secretKey); // No error!
console.log(equalBytes(aliceShared, malloryShared)); // false: different key!
```

Lattice-based key encapsulation mechanism, defined in [FIPS-203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) ([website](https://www.pq-crystals.org/kyber/resources.shtml), [repo](https://github.com/pq-crystals/kyber)).
Can be used as follows:

1. *Alice* generates secret & public keys, then sends publicKey to *Bob*
2. *Bob* generates shared secret for Alice publicKey.
  bobShared never leaves *Bob* system and is unknown to other parties
3. *Alice* gets and decrypts cipherText from Bob
  Now, both Alice and Bob have same sharedSecret key
  without exchanging in plainText: aliceShared == bobShared.

There are some concerns with regards to security: see
[djb blog](https://blog.cr.yp.to/20231003-countcorrectly.html) and
[mailing list](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/W2VOzy0wz_E).
Old, incompatible version (Kyber) is not provided. Open an issue if you need it.

> [!WARNING]
> Unlike ECDH, KEM doesn't verify whether it was "Bob" who've sent the ciphertext.
> Instead of throwing an error when the ciphertext is encrypted by a different pubkey,
> `decapsulate` will simply return a different shared secret.
> ML-KEM is also probabilistic and relies on quality of CSPRNG.

### ML-DSA / Dilithium signatures

```ts
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
const seed = randomBytes(32); // seed is optional
const keys = ml_dsa65.keygen(seed);
const msg = new TextEncoder().encode('hello noble');
const sig = ml_dsa65.sign(msg, keys.secretKey);
const isValid = ml_dsa65.verify(sig, msg, keys.publicKey);
```

Lattice-based digital signature algorithm, defined in [FIPS-204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) ([website](https://www.pq-crystals.org/dilithium/index.shtml),
[repo](https://github.com/pq-crystals/dilithium)).
The internals are similar to ML-KEM, but keys and params are different.

`sign` / `verify` accept optional parameters:

```ts
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha512 } from '@noble/hashes/sha2.js';
const keys = ml_dsa65.keygen();
const msg = new TextEncoder().encode('hello noble');
const ctx = new Uint8Array([1, 2, 3]);
const sigCtx = ml_dsa65.sign(msg, keys.secretKey, { context: ctx }); // verify needs same context
const sigDet = ml_dsa65.sign(msg, keys.secretKey, { extraEntropy: false }); // deterministic
const hml = ml_dsa65.prehash(sha512); // HashML-DSA
const sigPre = hml.sign(msg, keys.secretKey);
const isValidPre = hml.verify(sigPre, msg, keys.publicKey);
```

- `context`: domain-separation byte string, up to 255 bytes; must match between `sign` and `verify`
- `extraEntropy`: hedged-signing randomness. Default is 32 random bytes;
  `false` produces deterministic signatures; custom 32-byte value is also allowed
- `prehash(hash)`: pre-hash variant (HashML-DSA) from FIPS-204

Unknown option keys are rejected rather than ignored, so a misspelling such as
`{ ctx }` fails loudly instead of silently signing with no domain separation.

`externalMu`, which treats `msg` as the precomputed 64-byte message representative
µ, is available on `ml_dsa*.internal.sign` / `internal.verify` only. The public
wrappers reject it: `sign` formats `M'` before the 64-byte check so it could never
accept a µ, and `verify` did not forward it, returning `false` for a valid
external-mu signature.

### SLH-DSA / SPHINCS+ signatures

```ts
import {
  slh_dsa_sha2_128f as sph,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
  slh_dsa_shake_128f,
  slh_dsa_shake_128s,
  slh_dsa_shake_192f,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa.js';

const keys2 = sph.keygen();
const msg2 = new TextEncoder().encode('hello noble');
const sig2 = sph.sign(msg2, keys2.secretKey);
const isValid2 = sph.verify(sig2, msg2, keys2.publicKey);
```

Hash-based digital signature algorithm, defined in [FIPS-205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) ([website](https://sphincs.org), [repo](https://github.com/sphincs/sphincsplus)). We implement spec v3.1 with FIPS adjustments.

- sha2 vs shake (sha3): indicates internal hash function used
- 128 / 192 / 256: indicates security level in bits
- s / f: indicates small vs fast trade-off

`sign` / `verify` accept the same optional `context`, `extraEntropy` and `prehash(hash)`
(HashSLH-DSA) parameters as ML-DSA. With `extraEntropy: false`, signing is deterministic.

SLH-DSA is slow: see [benchmarks](#speed) for key size & speed.

### Falcon signatures

```ts
import { falcon512, falcon1024 } from '@noble/post-quantum/falcon.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
const seed3 = randomBytes(48); // seed is optional
const keys3 = falcon512.keygen(seed3);
const msg3 = new TextEncoder().encode('hello noble');
const sig3 = falcon512.sign(msg3, keys3.secretKey);
const isValid3 = falcon512.verify(sig3, msg3, keys3.publicKey);
```

Lattice-based digital signature algorithm, submitted to NIST PQC Round 3 ([website](https://falcon-sign.info/), [Round 3 submissions](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions)).

> [!WARNING]
> This is Falcon Round 3, not FN-DSA. FN-DSA is not final yet.
> FN-DSA (FIPS-206) would most likely be backwards-incompatible with Falcon.
> The implementation passes the published Round 3 KATs.

- `falcon512`, `falcon1024`: variable-length detached signatures
- `falcon512padded`, `falcon1024padded`: fixed-length detached signatures
- `attached.seal(...)` / `attached.open(...)`: attached-signature API for Round 3 vectors and interop

> [!WARNING]
> Falcon signing is randomized by design. Leave signing options unset in production so every
> signature receives a fresh 40-byte public nonce and a fresh 48-byte sampler seed from the system
> CSPRNG. Falcon's `extraEntropy` option does not have the hedged semantics used by ML-DSA and
> SLH-DSA:
>
> - `extraEntropy: false` seeds an AES-CTR-DRBG with 48 zero bytes. It makes signatures
>   deterministic for a fixed key and message, and reuses the same nonce and initial random stream
>   across different messages. This is outside the Falcon Round 3 randomized-hash design.
> - A 48-byte `extraEntropy` value replaces system randomness; it is not mixed with fresh entropy.
>   Reusing a value therefore reuses the signing stream.
> - The raw `random` callback overrides `extraEntropy` and supplies both the nonce and sampler seed.
>   It exists for test-vector reproduction and should not be used as a production randomness hook.
>
> In particular, do not copy ML-DSA examples that use `extraEntropy: false` into Falcon code.

`attached.open(...)` throws when verification fails and returns a zero-copy view of the embedded
message when it succeeds. That view aliases the caller-provided signature buffer; copy it if
independent ownership is needed. Detached `verify(...)` returns `false` for an invalid signature.

### hybrid: X-Wing, KitchenSink and others

```js
import {
  ml_kem768_x25519, ml_kem768_p256, ml_kem1024_p384,
  KitchenSink_ml_kem768_x25519,
  QSF_ml_kem768_p256, QSF_ml_kem1024_p384,
} from '@noble/post-quantum/hybrid.js';
```

The hybrid submodule combines post-quantum algorithms with elliptic curve cryptography:

- `ml_kem768_x25519`: ML-KEM-768 + X25519, implementing X-Wing under the descriptive
  `ml_kem768_x25519` export name. There is no separate `XWing` alias.
- `ml_kem768_p256`: ML-KEM-768 + P-256 using the current CG framework construction
- `ml_kem1024_p384`: ML-KEM-1024 + P-384 using the current CG framework construction
- `KitchenSink_ml_kem768_x25519`: ML-KEM-768 + X25519 with HKDF-SHA256 combiner
- `QSF_ml_kem768_p256`, `QSF_ml_kem1024_p384`: legacy compatibility presets for the older
  QSF/C2PRI naming and labels. New code should use `ml_kem768_p256` and `ml_kem1024_p384`.

The current `ml_kem*` presets are tested against these work-in-progress specifications:

- [irtf-cfrg-hybrid-kems-12](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12)
- [irtf-cfrg-concrete-hybrid-kems-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-03)
- [connolly-cfrg-xwing-kem-10](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10)

`QSF(...)` is the legacy API name for the construction now called the C2PRI combiner. It derives
the final secret from `ssPQ || ssT || ctT || ekT || label`; omitting the PQ ciphertext and
encapsulation key is intentional and relies on the PQ KEM's C2PRI property. The `QSF_*` presets
retain older draft labels and vectors for compatibility, so they do not implement the current
concrete preset encodings. They are also unrelated to the separate universal-combiner example in
NIST SP 800-227.

### What should I use?

|         | Speed  | Key size    | Sig / CT size | Created in | Popularized in | Post-quantum? |
| ------- | ------ | ----------- | ------------- | ---------- | -------------- | ------------- |
| RSA     | Normal | 256B - 2KB  | 256B - 2KB    | 1970s      | 1990s          | No            |
| ECC     | Normal | 32 - 256B   | 48 - 128B     | 1980s      | 2010s          | No            |
| ML-KEM  | Fast   | 0.8 - 1.6KB | 0.8 - 1.6KB   | 1990s      | 2020s          | Yes           |
| ML-DSA  | Normal | 1.3 - 2.5KB | 2.5 - 4.5KB   | 1990s      | 2020s          | Yes           |
| SLH-DSA | Slow   | 32 - 128B   | 17 - 50KB     | 1970s      | 2020s          | Yes           |
| FN-DSA  | Slow   | 0.9 - 1.8KB | 0.6 - 1.2KB   | 1990s      | 2020s          | Yes           |

ML-KEM is a KEM, not a signature scheme: its last column is ciphertext (CT) size.
We suggest using ECC + ML-KEM for key agreement, ECC + SLH-DSA for signatures.

ML-KEM and ML-DSA are lattice-based. SLH-DSA is hash-based, which means it is built on top of older, more conservative primitives. NIST guidance for security levels:

- Category 3 (~AES-192): ML-KEM-768, ML-DSA-65, SLH-DSA-192
- Category 5 (~AES-256): ML-KEM-1024, ML-DSA-87, SLH-DSA-256

NIST recommends cat-3+, while Australian [ASD only allows cat-5 after 2030](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography).

It's also useful to check out draft [NIST SP 800-131Ar3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar3.ipd.pdf)
for "Transitioning the Use of Cryptographic Algorithms and Key Lengths".

For [hashes](https://github.com/paulmillr/noble-hashes), use SHA512 or SHA3-512 (not SHA256); and for [ciphers](https://github.com/paulmillr/noble-ciphers) ensure AES-256 or ChaCha.

## Security

The library has not been independently audited yet.

- at version 0.6.1, in Apr 2026, it was audited by ourselves (self-audited)
  - Scope: everything
  - [Changes since audit](https://github.com/paulmillr/noble-post-quantum/compare/0.6.1..main)

If you see anything unusual: investigate and report.

### Constant-timeness

This pure JavaScript implementation does not claim constant-time execution. JavaScript engines,
JIT compilers, garbage collection, floating-point operations and `bigint` arithmetic do not offer
the execution guarantees needed for a formal constant-time claim.

- ML-DSA signing uses rejection loops, early-exit norm checks and conditional arithmetic whose
  execution depends on secret-key and per-signature state. Fresh randomized signing is the default,
  but it does not turn the implementation into a constant-time one.
- Falcon signing uses data-dependent Gaussian and rejection sampling, floating-point operations,
  and `bigint` paths. Its timing and microarchitectural side-channel posture is materially weaker
  than a hardened native implementation. Deterministic or repeated signing randomness can make
  observations easier to correlate and should be avoided.
- These limitations matter most when an attacker can measure signing closely, such as hostile
  co-tenancy, shared hardware, or a high-resolution local timing oracle. Use an isolated execution
  environment or a reviewed native/constant-time backend when that is part of the threat model.

We actively research how to improve this property for post-quantum algorithms in JS. Even hardware
ML-KEM implementations require careful side-channel engineering and [have had practical attacks](https://eprint.iacr.org/2023/1084).

### Supply chain security

- **Commits** are signed with PGP keys to prevent forgery. Be sure to verify the commit signatures
- **Releases** are made transparently through token-less GitHub CI and Trusted Publishing. Be sure to verify the [provenance logs](https://docs.npmjs.com/generating-provenance-statements) for authenticity.
- **Rare releasing** is practiced to minimize the need for re-audits by end-users.
- **Dependencies** are minimized and strictly pinned to reduce supply-chain risk.
  - We use as few dependencies as possible.
  - Version ranges are locked, and changes are checked with npm-diff.
- **Dev dependencies** are excluded from end-user installs; they're only used for development and build steps.

For this package, there are 3 dependencies; and a few dev dependencies:

- [noble-hashes](https://github.com/paulmillr/noble-hashes) provides cryptographic hashing functionality, used internally in every algorithm
- [noble-curves](https://github.com/paulmillr/noble-curves) provides elliptic curve cryptography for hybrid algorithms
- [noble-ciphers](https://github.com/paulmillr/noble-ciphers) provides AES-CTR DRBG and ChaCha20, used internally in Falcon
- jsbt is used for benchmarking / testing / build tooling and developed by the same author
- prettier, fast-check and typescript are used for code quality / test generation / ts compilation

### Randomness

We rely on the built-in
[`crypto.getRandomValues`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues),
which is considered a cryptographically secure PRNG.

Browsers have had weaknesses in the past - and could again - but implementing a userspace CSPRNG is even worse, as there’s no reliable userspace source of high-quality entropy.

## Speed

> `npm run benchmark`

Noble is the fastest JS implementation of post-quantum algorithms.

There is experimental [git branch](https://github.com/paulmillr/noble-post-quantum/tree/awasm),
which uses WASM-based [awasm-noble](https://github.com/paulmillr/awasm-noble) for hashing.
It has 80% faster ML-KEM, 30% faster ML-DSA, 2.3x faster SLH-DSA-SHA256, 15x faster SLH-DSA-SHAKE.
Try it out.

Benchmarks on Apple M4 (operations/sec, **higher is better**):

| Primitive         | Keygen | Signing | Verification | Shared secret |
| ----------------- | ------ | ------- | ------------ | ------------- |
| ML-KEM-768        | 4661   |         |              | 4089          |
| ML-DSA-65         | 719    | 294     | 610          |               |
| Falcon512         | 14     | 749     | 2160         |               |
| SLH-DSA-SHA2-192f | 321    | 11       | 198          |               |
| Pre-quantum x/ed25519 | 12648  | 6157    | 1255         | 1981          |

SLH-DSA (`s` variants have 2x shorter signatures; SHAKE is very slow):

|            | keygen | sign   | verify |
| ---------- | ------ | ------ | ------ |
| sha2_128f  | 2ms    | 47ms   | 3ms    |
| shake_128f | 10ms   | 237ms  | 14ms   |
| sha2_192f  | 3.2ms  | 93ms   | 5.1ms  |
| shake_192f | 15ms   | 396ms  | 21ms   |
| sha2_256f  | 8.5ms  | 187ms  | 5.2ms  |
| shake_256f | 40ms   | 813ms  | 22ms   |
| sha2_128s  | 140ms  | 1068ms | 1.1ms  |
| shake_128s | 673ms  | 5114ms | 5.2ms  |
| sha2_192s  | 209ms  | 2114ms | 1.9ms  |
| shake_192s | 974ms  | 8779ms | 7.1ms  |
| sha2_256s  | 137ms  | 1941ms | 2.7ms  |
| shake_256s | 645ms  | 7689ms | 11ms   |

Key and signature sizes:

| Variant | Public key | Secret key | Signature / Ciphertext |
|---|---:|---:|---:|
| ML-KEM-512 | 800 | 1632 | 768 |
| ML-KEM-768 | 1184 | 2400 | 1088 |
| ML-KEM-1024 | 1568 | 3168 | 1568 |
| ML-DSA-44 | 1312 | 2560 | 2420 |
| ML-DSA-65 | 1952 | 4032 | 3309 |
| ML-DSA-87 | 2592 | 4896 | 4627 |
| Falcon512 | 897 | 1281 | 666 |
| Falcon1024 | 1793 | 2305 | 1280 |
| SLH-DSA-128f | 32 | 64 | 17088 |
| SLH-DSA-128s | 32 | 64 | 7856 |
| SLH-DSA-192f | 48 | 96 | 35664 |
| SLH-DSA-192s | 48 | 96 | 16224 |
| SLH-DSA-256f | 64 | 128 | 49856 |
| SLH-DSA-256s | 64 | 128 | 29792 |


## License

The MIT License (MIT)

Copyright (c) 2024 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
