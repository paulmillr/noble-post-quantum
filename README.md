# noble-post-quantum

Auditable & minimal JS implementation of public-key post-quantum cryptography.

- 🔒 Auditable
- 🔻 Tree-shakeable: unused code is excluded from your builds
- 🔍 Reliable: tests ensure correctness
- 🦾 ML-KEM & CRYSTALS-Kyber: lattice-based kem from FIPS-203
- 🔋 ML-DSA & CRYSTALS-Dilithium: lattice-based signatures from FIPS-204
- 🐈 SLH-DSA & SPHINCS+: hash-based signatures from FIPS-205
- 🪶 77KB (15KB gzipped) for everything including bundled hashes

For discussions, questions and support, visit
[GitHub Discussions](https://github.com/paulmillr/noble-post-quantum/discussions)
section of the repository. Check out [What should I use](#what-should-i-use) section for benchmarks
and algorithm selection guidance.

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
  4kb [secp256k1](https://github.com/paulmillr/noble-secp256k1) /
  [ed25519](https://github.com/paulmillr/noble-ed25519)
- [Check out homepage](https://paulmillr.com/noble/)
  for reading resources, documentation and apps built with noble

## Usage

> npm install @noble/post-quantum

We support all major platforms and runtimes.
For [Deno](https://deno.land), ensure to use
[npm specifier](https://deno.land/manual@v1.28.0/node/npm_specifiers).
For React Native, you may need a
[polyfill for getRandomValues](https://github.com/LinusU/react-native-get-random-values).
A standalone file
[noble-post-quantum.js](https://github.com/paulmillr/noble-post-quantum/releases) is also available.

```js
// import * from '@noble/post-quantum'; // Error: use sub-imports instead
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
import {
  slh_dsa_sha2_128f, slh_dsa_sha2_128s,
  slh_dsa_sha2_192f, slh_dsa_sha2_192s,
  slh_dsa_sha2_256f, slh_dsa_sha2_256s,
  slh_dsa_shake_128f, slh_dsa_shake_128s,
  slh_dsa_shake_192f, slh_dsa_shake_192s,
  slh_dsa_shake_256f, slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa';
// import { ml_kem768 } from 'npm:@noble/post-quantum@0.1.0/ml-kem'; // Deno
```

- [ML-KEM / Kyber](#ml-kem--kyber-shared-secrets)
- [ML-DSA / Dilithium](#ml-dsa--dilithium-signatures)
- [SLH-DSA / SPHINCS+](#slh-dsa--sphincs-signatures)
- [What should I use?](#what-should-i-use)
- [Security](#security)
- [Speed](#speed)
- [Contributing & testing](#contributing--testing)
- [Resources](#resources)
- [License](#license)

### ML-KEM / Kyber shared secrets

```ts
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';
// [Alice] generates secret & public keys, then sends publicKey to Bob
const aliceKeys = ml_kem768.keygen();
const alicePub = aliceKeys.publicKey;

// [Bob] generates shared secret for Alice publicKey
// bobShared never leaves [Bob] system and is unknown to other parties
const { cipherText, sharedSecret: bobShared } = ml_kem768.encapsulate(alicePub);

// Alice gets and decrypts cipherText from Bob
const aliceShared = ml_kem768.decapsulate(cipherText, aliceKeys.secretKey);

// Now, both Alice and Both have same sharedSecret key
// without exchanging in plainText: aliceShared == bobShared

// Warning: Can be MITM-ed
const carolKeys = kyber1024.keygen();
const carolShared = kyber1024.decapsulate(cipherText, carolKeys.secretKey); // No error!
notDeepStrictEqual(aliceShared, carolShared); // Different key!
```

Lattice-based key encapsulation mechanism, defined in [FIPS-203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).

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
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
const seed = new TextEncoder().encode('not a safe seed');
const aliceKeys = ml_dsa65.keygen(seed);
const msg = new Uint8Array(1);
const sig = ml_dsa65.sign(aliceKeys.secretKey, msg);
const isValid = ml_dsa65.verify(aliceKeys.publicKey, msg, sig);
```

Lattice-based digital signature algorithm, defined in [FIPS-204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf). See
[website](https://www.pq-crystals.org/dilithium/index.shtml) and
[repo](https://github.com/pq-crystals/dilithium).
The internals are similar to ML-KEM, but keys and params are different.

### SLH-DSA / SPHINCS+ signatures

```ts
import {
  slh_dsa_sha2_128f, slh_dsa_sha2_128s,
  slh_dsa_sha2_192f, slh_dsa_sha2_192s,
  slh_dsa_sha2_256f, slh_dsa_sha2_256s,
  slh_dsa_shake_128f, slh_dsa_shake_128s,
  slh_dsa_shake_192f, slh_dsa_shake_192s,
  slh_dsa_shake_256f, slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa';

const aliceKeys = sph.keygen();
const msg = new Uint8Array(1);
const sig = sph.sign(aliceKeys.secretKey, msg);
const isValid = sph.verify(aliceKeys.publicKey, msg, sig);
```

Hash-based digital signature algorithm, defined in [FIPS-205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).
See [website](https://sphincs.org) and [repo](https://github.com/sphincs/sphincsplus).
We implement spec v3.1 with FIPS adjustments. Some wasm libraries use older specs.

> [!NOTE]  
> SLH-DSA is slow: see benchmarks below

### What should I use?

|           | Speed  | Key size    | Sig size    | Created in | Popularized in | Post-quantum? |
| --------- | ------ | ----------- | ----------- | ---------- | -------------- | ------------- |
| RSA       | Normal | 256B - 2KB  | 256B - 2KB  | 1970s      | 1990s          | No            |
| ECC       | Normal | 32 - 256B   | 48 - 128B   | 1980s      | 2010s          | No            |
| ML-KEM    | Fast   | 1.6 - 31KB  | 1KB         | 1990s      | 2020s          | Yes           |
| ML-DSA    | Normal | 1.3 - 2.5KB | 2.5 - 4.5KB | 1990s      | 2020s          | Yes           |
| SLH-DSA   | Slow   | 32 - 128B   | 17 - 50KB   | 1970s      | 2020s          | Yes           |

We suggest to use ECC + ML-KEM for key agreement, SLH-DSA for signatures.

ML-KEM and ML-DSA are lattice-based, so they're less "proven".
There's some chance of advancement, which will break this algorithm class.
SLH-DSA, while being slow, is built on top of older, conservative primitives.

Symmetrical algorithms like AES and ChaCha (available in [noble-ciphers](https://github.com/paulmillr/noble-ciphers))
suffer less from quantum computers. For AES, simply update from AES-128 to AES-256.

## Security

The library has not been independently audited yet.

There is no protection against side-channel attacks.

If you see anything unusual: investigate and report.

## Speed

Noble is the fastest JS implementation of post-quantum algorithms.
WASM libraries can be faster.

| OPs/sec      | Keygen | Signing | Verification | Shared secret |
| ------------ | ------ | ------- | ------------ | ------------- |
| ECC ed25519  | 10270  | 5110    | 1050         | 1470          |
| ML-KEM-768   | 2300   |         |              | 2000          |
| ML-DSA44     | 670    | 120     | 620          |               |
| SLH-DSA-SHA2-128f | 250    | 10       | 167          |               |

For SLH-DSA, SHAKE slows everything down 8x, and -s versions do another 20-50x slowdown.

Detailed benchmarks on Apple M2:

```
ML-KEM
keygen
├─ML-KEM-512 x 3,784 ops/sec @ 264μs/op
├─ML-KEM-768 x 2,305 ops/sec @ 433μs/op
└─ML-KEM-1024 x 1,510 ops/sec @ 662μs/op
encrypt
├─ML-KEM-512 x 3,283 ops/sec @ 304μs/op
├─ML-KEM-768 x 1,993 ops/sec @ 501μs/op
└─ML-KEM-1024 x 1,366 ops/sec @ 731μs/op
decrypt
├─ML-KEM-512 x 3,450 ops/sec @ 289μs/op
├─ML-KEM-768 x 2,035 ops/sec @ 491μs/op
└─ML-KEM-1024 x 1,343 ops/sec @ 744μs/op

ML-DSA
keygen
├─ML-DSA44 x 669 ops/sec @ 1ms/op
├─ML-DSA65 x 386 ops/sec @ 2ms/op
└─ML-DSA87 x 236 ops/sec @ 4ms/op
sign
├─ML-DSA44 x 123 ops/sec @ 8ms/op
├─ML-DSA65 x 120 ops/sec @ 8ms/op
└─ML-DSA87 x 78 ops/sec @ 12ms/op
verify
├─ML-DSA44 x 618 ops/sec @ 1ms/op
├─ML-DSA65 x 367 ops/sec @ 2ms/op
└─ML-DSA87 x 220 ops/sec @ 4ms/op

SLH-DSA
keygen
├─slh_dsa_sha2_128f x 245 ops/sec @ 4ms/op
├─slh_dsa_sha2_192f x 166 ops/sec @ 6ms/op
├─slh_dsa_sha2_256f x 64 ops/sec @ 15ms/op
├─slh_dsa_shake_128f x 35 ops/sec @ 28ms/op
├─slh_dsa_shake_192f x 23 ops/sec @ 41ms/op
├─slh_dsa_shake_256f x 9 ops/sec @ 110ms/op
├─slh_dsa_sha2_128s x 3 ops/sec @ 257ms/op
├─slh_dsa_sha2_192s x 2 ops/sec @ 381ms/op
└─slh_dsa_sha2_256s x 3 ops/sec @ 250ms/op
sign
├─slh_dsa_sha2_128f x 10 ops/sec @ 94ms/op
├─slh_dsa_sha2_192f x 6 ops/sec @ 163ms/op
├─slh_dsa_sha2_256f x 2 ops/sec @ 338ms/op
├─slh_dsa_shake_128f x 1 ops/sec @ 671ms/op
├─slh_dsa_shake_192f x 0 ops/sec @ 1088ms/op
├─slh_dsa_shake_256f x 0 ops/sec @ 2219ms/op
├─slh_dsa_sha2_128s x 0 ops/sec @ 1954ms/op
├─slh_dsa_sha2_192s x 0 ops/sec @ 3789ms/op
└─slh_dsa_sha2_256s x 0 ops/sec @ 3404ms/op
verify
├─slh_dsa_sha2_128f x 162 ops/sec @ 6ms/op
├─slh_dsa_sha2_192f x 111 ops/sec @ 9ms/op
├─slh_dsa_sha2_256f x 105 ops/sec @ 9ms/op
├─slh_dsa_shake_128f x 24 ops/sec @ 40ms/op
├─slh_dsa_shake_192f x 17 ops/sec @ 58ms/op
├─slh_dsa_shake_256f x 16 ops/sec @ 59ms/op
├─slh_dsa_sha2_128s x 495 ops/sec @ 2ms/op
├─slh_dsa_sha2_192s x 293 ops/sec @ 3ms/op
└─slh_dsa_sha2_256s x 220 ops/sec @ 4ms/op
```

## Contributing & testing

1. Clone the repository
2. `npm install` to install build dependencies like TypeScript
3. `npm run build` to compile TypeScript code
4. `npm run test` will execute all main tests

## Resources

Check out [paulmillr.com/noble](https://paulmillr.com/noble/)
for useful resources, articles, documentation and demos
related to the library.

## License

The MIT License (MIT)

Copyright (c) 2024 Paul Miller [(https://paulmillr.com)](https://paulmillr.com)

See LICENSE file.
