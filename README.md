# noble-post-quantum

Auditable & minimal JS implementation of post-quantum public-key cryptography.

- 🔒 Auditable
- 🔻 Tree-shakeable: unused code is excluded from your builds
- 🔍 Reliable: tests ensure correctness
- 🦾 ML-KEM & CRYSTALS-Kyber: lattice-based KEM from FIPS-203
- 🔋 ML-DSA & CRYSTALS-Dilithium: lattice-based signatures from FIPS-204
- 🐈 SLH-DSA & SPHINCS+: hash-based Winternitz signatures from FIPS-205
- 🦅 Falcon: lattice-based signatures from Falcon Round 3
- 🍡 Hybrid algorithms, combining classic & post-quantum: Concrete, XWing, KitchenSink
- 🪶 16KB (gzipped) for everything, including bundled hashes & curves

Take a glance at [GitHub Discussions](https://github.com/paulmillr/noble-post-quantum/discussions) for questions and support.

> [!IMPORTANT]
> NIST published [IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf),
> prohibiting classical cryptography (RSA, DSA, ECDSA, ECDH) after 2035.
> Australian ASD does same thing [after 2030](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography).
> Take it into an account while designing a new cryptographic system.

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
  KitchenSink_ml_kem768_x25519, XWing,
  QSF_ml_kem768_p256, QSF_ml_kem1024_p384,
} from '@noble/post-quantum/hybrid.js';
```

- [ML-KEM / Kyber](#ml-kem--kyber-shared-secrets)
- [ML-DSA / Dilithium](#ml-dsa--dilithium-signatures)
- [SLH-DSA / SPHINCS+](#slh-dsa--sphincs-signatures)
- [Falcon](#falcon-signatures)
- [hybrid: XWing, KitchenSink and others](#hybrid-xwing-kitchensink-and-others)
- [What should I use?](#what-should-i-use)
- [Security](#security)
- [Speed](#speed)
- [Contributing & testing](#contributing--testing)
- [License](#license)

### ML-KEM / Kyber shared secrets

```ts
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { notDeepStrictEqual } from 'node:assert';
const seed = randomBytes(64); // seed is optional
const aliceKeys = ml_kem768.keygen(seed);
const { cipherText, sharedSecret: bobShared } = ml_kem768.encapsulate(aliceKeys.publicKey);
const aliceShared = ml_kem768.decapsulate(cipherText, aliceKeys.secretKey);

// Warning: Can be MITM-ed
const malloryKeys = ml_kem768.keygen();
const malloryShared = ml_kem768.decapsulate(cipherText, malloryKeys.secretKey); // No error!
notDeepStrictEqual(aliceShared, malloryShared); // Different key!
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

### hybrid: XWing, KitchenSink and others

```js
import {
  ml_kem768_x25519, ml_kem768_p256, ml_kem1024_p384,
  KitchenSink_ml_kem768_x25519, XWing,
  QSF_ml_kem768_p256, QSF_ml_kem1024_p384,
} from '@noble/post-quantum/hybrid.js';
```

Hybrid submodule combine post-quantum algorithms with elliptic curve cryptography:

- `ml_kem768_x25519`: ML-KEM-768 + X25519 (CG Framework, same as XWing)
- `ml_kem768_p256`: ML-KEM-768 + P-256 (CG Framework)
- `ml_kem1024_p384`: ML-KEM-1024 + P-384 (CG Framework)
- `KitchenSink_ml_kem768_x25519`: ML-KEM-768 + X25519 with HKDF-SHA256 combiner
- `QSF_ml_kem768_p256`: ML-KEM-768 + P-256 (QSF construction)
- `QSF_ml_kem1024_p384`: ML-KEM-1024 + P-384 (QSF construction)

The following spec drafts are matched:

- [irtf-cfrg-hybrid-kems-07](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/)
- [irtf-cfrg-concrete-hybrid-kems-02](https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/)
- [connolly-cfrg-xwing-kem-09](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [tls-westerbaan-xyber768d00-03](https://datatracker.ietf.org/doc/draft-tls-westerbaan-xyber768d00/)

### What should I use?

|         | Speed  | Key size    | Sig size    | Created in | Popularized in | Post-quantum? |
| ------- | ------ | ----------- | ----------- | ---------- | -------------- | ------------- |
| RSA     | Normal | 256B - 2KB  | 256B - 2KB  | 1970s      | 1990s          | No            |
| ECC     | Normal | 32 - 256B   | 48 - 128B   | 1980s      | 2010s          | No            |
| ML-KEM  | Fast   | 1.6 - 31KB  | 1KB         | 1990s      | 2020s          | Yes           |
| ML-DSA  | Normal | 1.3 - 2.5KB | 2.5 - 4.5KB | 1990s      | 2020s          | Yes           |
| SLH-DSA | Slow   | 32 - 128B   | 17 - 50KB   | 1970s      | 2020s          | Yes           |
| FN-DSA  | Slow   | 0.9 - 1.8KB | 0.6 - 1.2KB | 1990s      | 2020s          | Yes           |

We suggest to use ECC + ML-KEM for key agreement, ECC + SLH-DSA for signatures.

ML-KEM and ML-DSA are lattice-based. SLH-DSA is hash-based, which means it is built on top of older, more conservative primitives. NIST guidance for security levels:

- Category 3 (~AES-192): ML-KEM-768, ML-DSA-65, SLH-DSA-192
- Category 5 (~AES-256): ML-KEM-1024, ML-DSA-87, SLH-DSA-256

NIST recommends to use cat-3+, while australian [ASD only allows cat-5 after 2030](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography).

It's also useful to check out [NIST SP 800-131Ar3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar3.ipd.pdf)
for "Transitioning the Use of Cryptographic Algorithms and Key Lengths".

For [hashes](https://github.com/paulmillr/noble-hashes), use SHA512 or SHA3-512 (not SHA256); and for [ciphers](https://github.com/paulmillr/noble-ciphers) ensure AES-256 or ChaCha.

## Security

The library has not been independently audited yet.

- at version 0.6.1, in Apr 2026, it was audited by ourselves (self-audited)
  - Scope: everything
  - [Changes since audit](https://github.com/paulmillr/noble-post-quantum/compare/0.6.1..main)

If you see anything unusual: investigate and report.

### Constant-timeness

There is no protection against side-channel attacks.
We actively research how to provide this property for post-quantum algorithms in JS.
Keep in mind that even hardware versions ML-KEM [are vulnerable](https://eprint.iacr.org/2023/1084).

### Supply chain security

- **Commits** are signed with PGP keys to prevent forgery. Be sure to verify the commit signatures
- **Releases** are made transparently through token-less GitHub CI and Trusted Publishing. Be sure to verify the [provenance logs](https://docs.npmjs.com/generating-provenance-statements) for authenticity.
- **Rare releasing** is practiced to minimize the need for re-audits by end-users.
- **Dependencies** are minimized and strictly pinned to reduce supply-chain risk.
  - We use as few dependencies as possible.
  - Version ranges are locked, and changes are checked with npm-diff.
- **Dev dependencies** are excluded from end-user installs; they're only used for development and build steps.

For this package, there are 2 dependencies; and a few dev dependencies:

- [noble-hashes](https://github.com/paulmillr/noble-hashes) provides cryptographic hashing functionality, used internally in every algorithm
- [noble-curves](https://github.com/paulmillr/noble-curves) provides elliptic curve cryptography for hybrid algorithms
- jsbt is used for benchmarking / testing / build tooling and developed by the same author
- prettier, fast-check and typescript are used for code quality / test generation / ts compilation

### Randomness

We rely on the built-in
[`crypto.getRandomValues`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues),
which is considered a cryptographically secure PRNG.

Browsers have had weaknesses in the past - and could again - but implementing a userspace CSPRNG is even worse, as there’s no reliable userspace source of high-quality entropy.

## Contributing & testing

- `npm install && npm run build && npm test` will build the code and run tests.
- `npm run lint` / `npm run format` will run linter / fix linter issues.
- `npm run bench` will run benchmarks
- `npm run build:release` will build single file

Check out [github.com/paulmillr/guidelines](https://github.com/paulmillr/guidelines)
for general coding practices and rules.

See [paulmillr.com/noble](https://paulmillr.com/noble/)
for useful resources, articles, documentation and demos
related to the library.

## Speed

> `npm run bench`

Noble is the fastest JS implementation of post-quantum algorithms.

Benchmarks on Apple M4 (**higher is better**):

```
# ML-KEM768
keygen x 4,277 ops/sec @ 233μs/op
encapsulate x 3,470 ops/sec @ 288μs/op
decapsulate x 3,757 ops/sec @ 266μs/op
# ML-DSA65
keygen x 669 ops/sec @ 1ms/op
sign x 271 ops/sec @ 3ms/op
verify x 565 ops/sec @ 1ms/op
# SLH-DSA SHA2 192f
keygen x 235 ops/sec @ 4ms/op
sign x 8 ops/sec @ 117ms/op
verify x 159 ops/sec @ 6ms/op
# Falcon512
keygen x 14 ops/sec @ 66ms/op ± 11.01% (56ms..96ms)
sign x 749 ops/sec @ 1ms/op
verify x 2,160 ops/sec @ 462μs/op
# Falcon1024
keygen x 4 ops/sec @ 247ms/op ± 5.22% (234ms..266ms)
sign x 343 ops/sec @ 2ms/op
verify x 950 ops/sec @ 1ms/op
```

Compared with pre-quantum:

| OPs/sec           | Keygen | Signing | Verification | Shared secret |
| ----------------- | ------ | ------- | ------------ | ------------- |
| ECC x/ed25519     | 12648  | 6157    | 1255         | 1981          |
| ML-KEM-768        | 4277   |         |              | 3757          |
| ML-DSA65          | 669    | 271     | 565          |               |
| SLH-DSA-SHA2-192f | 235    | 8       | 159          |               |
| Falcon512         | 14     | 749     | 950          |               |

SLH-DSA:

|           | sig size | keygen | sign   | verify |
| --------- | -------- | ------ | ------ | ------ |
| sha2_128f | 18088    | 4ms    | 90ms   | 6ms    |
| sha2_192f | 35664    | 6ms    | 160ms  | 9ms    |
| sha2_256f | 49856    | 15ms   | 340ms  | 9ms    |
| sha2_128s | 7856     | 260ms  | 2000ms | 2ms    |
| sha2_192s | 16224    | 380ms  | 3800ms | 3ms    |
| sha2_256s | 29792    | 250ms  | 3400ms | 4ms    |
| shake_192f | 35664   | 21ms   | 553ms  | 29ms   |
| shake_192s | 16224   | 260ms  | 2635ms | 2ms    |

## License

The MIT License (MIT)

Copyright (c) 2024 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
