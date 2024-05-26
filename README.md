# noble-post-quantum

Auditable & minimal JS implementation of public-key post-quantum cryptography.

- 🔒 Auditable
- 🔻 Tree-shaking-friendly: use only what's necessary, other code won't be included
- 🦾 ML-KEM & CRYSTALS-Kyber: lattice-based kem
- 🔋 ML-DSA & CRYSTALS-Dilithium: lattice-based signatures
- 🐈 SLH-DSA & SPHINCS+: hash-based signatures
- 📄 FIPS-203, FIPS-204, FIPS-205 drafts
- 🪶 113KB (20KB gzipped) for everything including hashes, 71KB (14KB gzipped) for ML-KEM build

Check out [What should I use](#what-should-i-use) section for benchmarks
and algorithm selection guidance. For discussions, questions and support, visit
[GitHub Discussions](https://github.com/paulmillr/noble-post-quantum/discussions)
section of the repository.

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
// import * from '@noble/post-quantum'; // Error: use sub-imports, to ensure small app size
import { ml_kem768, kyber768 } from '@noble/post-quantum/ml-kem';
// import { ml_kem768, kyber768 } from 'npm:@noble/post-quantum@0.1.0/ml-kem'; // Deno
```

- [What should I use?](#what-should-i-use)
- [ML-KEM / Kyber](#ml-kem--kyber-shared-secrets)
- [ML-DSA / Dilithium](#ml-dsa--dilithium-signatures)
- [SLH-DSA / SPHINCS+](#slh-dsa--sphincs-signatures)
- [Security](#security)
- [Speed](#speed)
- [Contributing & testing](#contributing--testing)
- [Resources](#resources)
- [License](#license)

### What should I use?

|           | Speed  | Key size    | Sig size    | Created in | Popularized in | Post-quantum? |
| --------- | ------ | ----------- | ----------- | ---------- | -------------- | ------------- |
| RSA       | Normal | 256B - 2KB  | 256B - 2KB  | 1970s      | 1990s          | No            |
| ECC       | Normal | 32 - 256B   | 48 - 128B   | 1980s      | 2010s          | No            |
| Kyber     | Fast   | 1.6 - 31KB  | 1KB         | 1990s      | 2020s          | Yes           |
| Dilithium | Normal | 1.3 - 2.5KB | 2.5 - 4.5KB | 1990s      | 2020s          | Yes           |
| SPHINCS   | Slow   | 32 - 128B   | 17 - 50KB   | 1970s      | 2020s          | Yes           |

Speed (higher is better):

| OPs/sec      | Keygen | Signing | Verification | Shared secret |
| ------------ | ------ | ------- | ------------ | ------------- |
| ECC ed25519  | 10270  | 5110    | 1050         | 1470          |
| Kyber-512    | 3050   |         |              | 2090          |
| Dilithium-2  | 580    | 170     | 550          |               |
| SPHINCS-128f | 200    | 8       | 140          |               |

tl;dr: ECC + ML-KEM for key agreement, SLH-DSA for pq signatures.

It's recommended to use SPHINCS, which is built on
top of older, conservative primitives.

Kyber and Dilithium are lattice-based, so they're less "proven".
There's some chance of advancement, which will break this algorithm class.

FIPS wants to release final standards in 2024.
Until then, they provide no test vectors, meaning
implementations could be producing invalid output.
Moreover, if you'll use non-FIPS versions, or even FIPS
versions today, it's possible the final spec will be
incompatible, and you'll be stuck with old implementations.
Similar to what happened to Keccak and SHA-3.

Symmetrical algorithms like AES and ChaCha (available in [noble-ciphers](https://github.com/paulmillr/noble-ciphers))
suffer less from quantum computers. For AES, simply update from AES-128 to AES-256.

### ML-KEM / Kyber shared secrets

```ts
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';
// import { kyber512, kyber768, kyber1024 } from '@noble/post-quantum/ml-kem';
// import { kyber512_90s, kyber768_90s, kyber1024_90s } from '@noble/post-quantum/ml-kem';
const aliceKeys = ml_kem768.keygen();
const alicePub = aliceKeys.publicKey;
const { cipherText, sharedSecret: bobShared } = ml_kem768.encapsulate(alicePub);
const aliceShared = ml_kem768.decapsulate(cipherText, aliceKeys.secretKey); // [Alice] decrypts sharedSecret from Bob
// aliceShared == bobShared
```

Lattice-based key encapsulation mechanism.
See [official site](https://www.pq-crystals.org/kyber/resources.shtml),
[repo](https://github.com/pq-crystals/kyber),
[spec](https://datatracker.ietf.org/doc/draft-cfrg-schwabe-kyber/).

Key encapsulation is similar to DH / ECDH (think X25519), with important differences:

- We can't verify if it was "Bob" who've sent the shared secret.
  In ECDH, it's always verified
- It is probabalistic and relies on quality of randomness (CSPRNG).
  ECDH doesn't (to this extent).
- Kyber decapsulation never throws an error, even when shared secret was
  encrypted by a different public key. It will just return a different
  shared secret

There are some concerns with regards to security: see
[djb blog](https://blog.cr.yp.to/20231003-countcorrectly.html) and
[mailing list](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/W2VOzy0wz_E).

Three versions are provided:

1. Kyber
2. Kyber-90s, using algorithms from 1990s
3. ML-KEM aka [FIPS-203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf)

```ts
// Alice generates keys
const aliceKeys = kyber1024.keygen(); // [Alice] generates key pair (secret and public key)
const alicePub = aliceKeys.publicKey; // [Alice] sends public key to Bob (somehow)
// aliceKeys.secretKey never leaves [Alice] system and unknown to other parties

// Bob creates cipherText for Alice
// [Bob] generates shared secret for Alice publicKey
const { cipherText, sharedSecret: bobShared } = kyber1024.encapsulate(alicePub);
// bobShared never leaves [Bob] system and unknown to other parties

// Alice gets cipherText from Bob
// [Alice] decrypts sharedSecret from Bob
const aliceShared = kyber1024.decapsulate(cipherText, aliceKeys.secretKey);

// Now, both Alice and Both have same sharedSecret key without exchanging in plainText
deepStrictEqual(aliceShared, bobShared);

// Warning: Can be MITM-ed
const carolKeys = kyber1024.keygen();
const carolShared = kyber1024.decapsulate(cipherText, carolKeys.secretKey); // No error!
notDeepStrictEqual(aliceShared, carolShared); // Different key!
```

### ML-DSA / Dilithium signatures

```ts
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa';
// import { dilithium_v30, dilithium_v31 } from '@noble/post-quantum/ml-dsa';
// import { dilithium_v30_aes, dilithium_v31_aes } from '@noble/post-quantum/ml-dsa';
const seed = new TextEncoder().encode('not a safe seed')
const aliceKeys = ml_dsa65.keygen(seed);
const msg = new Uint8Array(1);
const sig = ml_dsa65.sign(aliceKeys.secretKey, msg);
const isValid = ml_dsa65.verify(aliceKeys.publicKey, msg, sig);
```

Lattice-based digital signature algorithm. See
[official site](https://www.pq-crystals.org/dilithium/index.shtml),
[repo](https://github.com/pq-crystals/dilithium).
Dilithium has similar internals to Kyber, but their keys and params are different.

Three versions are provided:

1. Dilithium v3.0, v3.0 AES
2. Dilithium v3.1, v3.1 AES
3. ML-DSA aka [FIPS-204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf)

### SLH-DSA / SPHINCS+ signatures

```ts
import { slh_dsa_sha2_128f as sph } from '@noble/post-quantum/slh-dsa';
// import { sphincs_shake_128f_simple } from '@noble/post-quantum/slh-dsa';
// import { sphincs_sha2_128f_simple } from '@noble/post-quantum/slh-dsa';
// Full list of imports can be seen below in "FIPS-205" section details
const aliceKeys = sph.keygen();
const msg = new Uint8Array(1);
const sig = sph.sign(aliceKeys.secretKey, msg);
const isValid = sph.verify(aliceKeys.publicKey, msg, sig);
```

Hash-based digital signature algorithm. See [official site](https://sphincs.org).
We implement spec v3.1 with latest FIPS-205 changes.
It's compatible with the latest version in the [official repo](https://github.com/sphincs/sphincsplus).
Some wasm libraries use older specs.

Three versions are provided:

1. SHAKE256-based
2. SHA2-based
3. SLH-DSA aka [FIPS-205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.ipd.pdf)

The pattern for exported name is:

```
sphincs_{HASH}_{BITS}{SIZE}_{KIND}

where
  HASH: shake | sha2
  BITS: 128 | 192 | 256
  SIZE: f | s (full, short)
  KIND: simple | robust

// Examples
sphincs_shake_128f_simple
sphincs_sha2_192s_robust
```

All imports:

```ts
import {
  sphincs_shake_128f_simple,
  sphincs_shake_128f_robust,
  sphincs_shake_128s_simple,
  sphincs_shake_128s_robust,
  sphincs_shake_192f_simple,
  sphincs_shake_192f_robust,
  sphincs_shake_192s_simple,
  sphincs_shake_192s_robust,
  sphincs_shake_256f_simple,
  sphincs_shake_256f_robust,
  sphincs_shake_256s_simple,
  sphincs_shake_256s_robust,
} from '@noble/post-quantum/slh-dsa';

import {
  sphincs_sha2_128f_simple,
  sphincs_sha2_128f_robust,
  sphincs_sha2_128s_simple,
  sphincs_sha2_128s_robust,
  sphincs_sha2_192f_simple,
  sphincs_sha2_192f_robust,
  sphincs_sha2_192s_simple,
  sphincs_sha2_192s_robust,
  sphincs_sha2_256f_simple,
  sphincs_sha2_256f_robust,
  sphincs_sha2_256s_simple,
  sphincs_sha2_256s_robust,
} from '@noble/post-quantum/slh-dsa';

import {
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
} from '@noble/post-quantum/slh-dsa';
```

## Security

The library has not been independently audited yet.

If you see anything unusual: investigate and report.

## Speed

To summarize, noble is the fastest JS implementation of post-quantum algorithms.

Check out [What should I use](#what-should-i-use) table for now.

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
