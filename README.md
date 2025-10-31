# noble-post-quantum

Auditable & minimal JS implementation of post-quantum public-key cryptography.

- 🔒 Auditable
- 🔻 Tree-shakeable: unused code is excluded from your builds
- 🔍 Reliable: tests ensure correctness
- 🦾 ML-KEM & CRYSTALS-Kyber: lattice-based KEM from FIPS-203
- 🔋 ML-DSA & CRYSTALS-Dilithium: lattice-based signatures from FIPS-204
- 🐈 SLH-DSA & SPHINCS+: hash-based Winternitz signatures from FIPS-205
- 🍡 Hybrid algorithms, combining classic & post-quantum
- 🪶 16KB (gzipped) for everything, including bundled noble-hashes & noble-curves

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
- [Check out homepage](https://paulmillr.com/noble/)
  for reading resources, documentation and apps built with noble

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
  XWing,
  KitchenSinkMLKEM768X25519,
  QSFMLKEM768P256, QSFMLKEM1024P384
} from '@noble/post-quantum/hybrids.js';
```

- [ML-KEM / Kyber](#ml-kem--kyber-shared-secrets)
- [ML-DSA / Dilithium](#ml-dsa--dilithium-signatures)
- [SLH-DSA / SPHINCS+](#slh-dsa--sphincs-signatures)
- [Hybrids: XWing, KitchenSink and others](#hybrids-xwing-kitchensink-and-others)
- [What should I use?](#what-should-i-use)
- [Security](#security)
- [Speed](#speed)
- [Contributing & testing](#contributing--testing)
- [License](#license)

### ML-KEM / Kyber shared secrets

```ts
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
const seed = randomBytes(64); // seed is optional
const aliceKeys = ml_kem768.keygen(seed);
const { cipherText, sharedSecret: bobShared } = ml_kem768.encapsulate(aliceKeys.publicKey);
const aliceShared = ml_kem768.decapsulate(cipherText, aliceKeys.secretKey);

// Warning: Can be MITM-ed
const malloryKeys = ml_kem768.keygen();
const malloryShared = ml_kem768.decapsulate(cipherText, malloryKeys.secretKey); // No error!
notDeepStrictEqual(aliceShared, malloryShared); // Different key!
```

Lattice-based key encapsulation mechanism, defined in [FIPS-203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
Can be used as follows:

1. *Alice* generates secret & public keys, then sends publicKey to *Bob*
2. *Bob* generates shared secret for Alice publicKey.
  bobShared never leaves *Bob* system and is unknown to other parties
3. *Alice* gets and decrypts cipherText from Bob
  Now, both Alice and Bob have same sharedSecret key
  without exchanging in plainText: aliceShared == bobShared.

See [website](https://www.pq-crystals.org/kyber/resources.shtml) and [repo](https://github.com/pq-crystals/kyber).
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

Lattice-based digital signature algorithm, defined in [FIPS-204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf). See
[website](https://www.pq-crystals.org/dilithium/index.shtml) and
[repo](https://github.com/pq-crystals/dilithium).
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

Hash-based digital signature algorithm, defined in [FIPS-205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).
See [website](https://sphincs.org) and [repo](https://github.com/sphincs/sphincsplus). We implement spec v3.1 with FIPS adjustments.

There are many different kinds,
but basically `sha2` / `shake` indicate internal hash, `128` / `192` / `256` indicate security level, and `s` /`f` indicate trade-off (Small / Fast).
SLH-DSA is slow: see [benchmarks](#speed) for key size & speed.

### Hybrids: XWing, KitchenSink and others

```js
import {
  XWing,
  KitchenSinkMLKEM768X25519,
  QSFMLKEM768P256, QSFMLKEM1024P384
} from '@noble/post-quantum/hybrids.js';
```

XWing is x25519+mlkem768, just like kitchensink.

The following spec drafts are matched:

- [irtf-cfrg-hybrid-kems](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/)
- [connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [tls-westerbaan-xyber768d00](https://datatracker.ietf.org/doc/draft-tls-westerbaan-xyber768d00/)

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

- Category 3 (~AES-192): ML-KEM-768, ML-DSA-65, SLH-DSA-[SHA2/shake]-192[s/f]
- Category 5 (~AES-256): ML-KEM-1024, ML-DSA-87, SLH-DSA-[SHA2/shake]-256[s/f]

NIST recommends to use cat-3+, while australian [ASD only allows cat-5 after 2030](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography).

It's also useful to check out [NIST SP 800-131Ar3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar3.ipd.pdf)
for "Transitioning the Use of Cryptographic Algorithms and Key Lengths".

For [hashes](https://github.com/paulmillr/noble-hashes), use SHA512 or SHA3-512 (not SHA256); and for [ciphers](https://github.com/paulmillr/noble-ciphers) ensure AES-256 or ChaCha.

## Security

The library has not been independently audited yet.

If you see anything unusual: investigate and report.

### Constant-timeness

There is no protection against side-channel attacks.
We actively research how to provide this property for post-quantum algorithms in JS.
Keep in mind that even hardware versions ML-KEM [are vulnerable](https://eprint.iacr.org/2023/1084).

### Supply chain security

- **Commits** are signed with PGP keys, to prevent forgery. Make sure to verify commit signatures
- **Releases** are transparent and built on GitHub CI.
  Check out [attested checksums of single-file builds](https://github.com/paulmillr/noble-post-quantum/attestations)
  and [provenance logs](https://github.com/paulmillr/noble-post-quantum/actions/workflows/release.yml)
- **Rare releasing** is followed to ensure less re-audit need for end-users
- **Dependencies** are minimized and locked-down: any dependency could get hacked and users will be downloading malware with every install.
  - We make sure to use as few dependencies as possible
  - Automatic dep updates are prevented by locking-down version ranges; diffs are checked with `npm-diff`
- **Dev Dependencies** are disabled for end-users; they are only used to develop / build the source code

For this package, there is 1 dependency; and a few dev dependencies:

- [noble-hashes](https://github.com/paulmillr/noble-hashes) provides cryptographic hashing functionality
- micro-bmark, micro-should and jsbt are used for benchmarking / testing / build tooling and developed by the same author
- prettier, fast-check and typescript are used for code quality / test generation / ts compilation. It's hard to audit their source code thoroughly and fully because of their size

### Randomness

We're deferring to built-in
[crypto.getRandomValues](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues)
which is considered cryptographically secure (CSPRNG).

In the past, browsers had bugs that made it weak: it may happen again.
Implementing a userspace CSPRNG to get resilient to the weakness
is even worse: there is no reliable userspace source of quality entropy.

## Speed

Noble is the fastest JS implementation of post-quantum algorithms.
WASM libraries can be faster.
For SLH-DSA, SHAKE slows everything down 8x, and -s versions do another 20-50x slowdown.

Benchmarks on Apple M4 (**higher is better**):

| OPs/sec           | Keygen | Signing | Verification | Shared secret |
| ----------------- | ------ | ------- | ------------ | ------------- |
| ECC x/ed25519     | 14216  | 6849    | 1400         | 1981          |
| ML-KEM-768        | 3778   |         |              | 3750          |
| ML-DSA65          | 580    | 272     | 546          |               |
| SLH-DSA-SHA2-192f | 245    | 8       | 169          |               |

```
# ML-KEM768
keygen x 3,778 ops/sec @ 264μs/op
encapsulate x 3,220 ops/sec @ 310μs/op
decapsulate x 4,029 ops/sec @ 248μs/op
# ML-DSA65
keygen x 580 ops/sec @ 1ms/op
sign x 272 ops/sec @ 3ms/op
verify x 546 ops/sec @ 1ms/op
# SLH-DSA SHA2 192f
keygen x 245 ops/sec @ 4ms/op
sign x 8 ops/sec @ 114ms/op
verify x 169 ops/sec @ 5ms/op
```

SLH-DSA (\_shake is 8x slower):

|           | sig size | keygen | sign   | verify |
| --------- | -------- | ------ | ------ | ------ |
| sha2_128f | 18088    | 4ms    | 90ms   | 6ms    |
| sha2_128s | 7856     | 260ms  | 2000ms | 2ms    |
| sha2_192f | 35664    | 6ms    | 160ms  | 9ms    |
| sha2_192s | 16224    | 380ms  | 3800ms | 3ms    |
| sha2_256f | 49856    | 15ms   | 340ms  | 9ms    |
| sha2_256s | 29792    | 250ms  | 3400ms | 4ms    |

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

## License

The MIT License (MIT)

Copyright (c) 2024 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
