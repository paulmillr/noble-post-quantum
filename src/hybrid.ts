/**
 * Post-Quantum Hybrid Cryptography
 *
 * The current implementation is flawed and likely redundant. We should offer
 * a small, generic API to compose hybrid schemes instead of reimplementing
 * protocol-specific logic (SSH, GPG, etc.) with ad hoc encodings.
 *
 * 1. Core Issues
 *    - sign/verify: implemented as two separate operations with different keys.
 *    - EC getSharedSecret: could be refactored into a proper KEM.
 *    - Multiple calls: keys, signatures, and shared secrets could be
 *      concatenated to reduce the number of API invocations.
 *    - Reinvention: most libraries add strange domain separations and
 *      encodings instead of simple byte concatenation.
 *
 * 2. API Goals
 *    - Provide primitives to build hybrids generically.
 *    - Avoid embedding SSH- or GPG-specific formats in the core API.
 *
 * 3. Edge Cases
 *    • Variable-length signatures:
 *      - DER-encoded (Weierstrass curves).
 *      - Falcon (unpadded).
 *      - Concatenation works only if length is fixed; otherwise a length
 *        prefix is required (but that breaks compatibility).
 *
 *    • getSharedSecret:
 *      - Default: non-KEM (authenticated ECDH).
 *      - KEM conversion: generate a random SK to remove implicit auth.
 *
 * 4. Common Pitfalls
 *    - Seed expansion:
 *      • Expanding a small seed into multiple keys reduces entropy.
 *      • API should allow identity mapping (no expansion).
 *
 *    - Skipping full point encoding:
 *      • Some omit the compression byte (parity) for WebCrypto compatibility.
 *      • Better: hash the raw secret; coordinate output is already non-uniform.
 *      • Some curves (e.g., X448) produce secrets that must be re-hashed to match
 *        symmetric-key lengths.
 *
 *    - Combiner inconsistencies:
 *      • Different domain separations and encodings across libraries.
 *      • Should live at the application layer, since key lengths vary.
 *
 * 5. Protocol Examples
 *    - SSH:
 *      • Concatenate keys.
 *      • Combiner: SHA-512.
 *
 *    - GPG:
 *      • Concatenate keys.
 *      • Combiner: SHA3-256(kemShare || ecdhShare || ciphertext || pubKey || algId || domSep || len(domSep))
 *
 *    - TLS:
 *      • Transcript-based derivation (HKDF).
 *
 * 6. Relevant Specs & Implementations
 *    - IETF Hybrid KEM drafts:
 *      • draft-irtf-cfrg-hybrid-kems
 *      • draft-connolly-cfrg-xwing-kem
 *      • draft-westerbaan-tls-xyber768d00
 *
 *    - PQC Libraries:
 *      • superdilithium (cyph/pqcrypto.js) – low adoption.
 *      • hybrid-pqc (DogeProtocol, quantumcoinproject) – complex encodings.
 *
 * 7. Signatures
 *    - Ed25519: fixed-size, easy to support.
 *    - Variable-size: introduces custom format requirements; best left to
 *      higher-level code.
 *
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { type EdDSA } from '@noble/curves/abstract/edwards.js';
import { type MontgomeryECDH } from '@noble/curves/abstract/montgomery.js';
import { type ECDSA } from '@noble/curves/abstract/weierstrass.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { p256, p384 } from '@noble/curves/nist.js';
import {
  asciiToBytes,
  bytesToNumberBE,
  bytesToNumberLE,
  concatBytes,
  numberToBytesBE,
} from '@noble/curves/utils.js';
import { expand, extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha3_256, shake256 } from '@noble/hashes/sha3.js';
import { abytes, ahash, anumber, type CHash, type CHashXOF } from '@noble/hashes/utils.js';
import { ml_kem1024, ml_kem768 } from './ml-kem.ts';
import {
  cleanBytes,
  randomBytes,
  splitCoder,
  type CryptoKeys,
  type KEM,
  type Signer,
} from './utils.ts';

type CurveAll = ECDSA | EdDSA | MontgomeryECDH;
type CurveECDH = ECDSA | MontgomeryECDH;
type CurveSign = ECDSA | EdDSA;

// Can re-use if decide to signatures support, on other hand getSecretKey is specific and ugly
function ecKeygen(curve: CurveAll, allowZeroKey: boolean = false) {
  const lengths = curve.lengths;
  let keygen = curve.keygen;
  if (allowZeroKey) {
    // This is ugly, but we need to return exact results here.
    const wCurve = curve as typeof p256;
    const Fn = wCurve.Point.Fn;
    if (!Fn) throw new Error('No Point.Fn');
    keygen = (seed: Uint8Array = randomBytes(lengths.seed)) => {
      abytes(seed, lengths.seed!, 'seed');
      const seedScalar = Fn.isLE ? bytesToNumberLE(seed) : bytesToNumberBE(seed);
      const secretKey = Fn.toBytes(Fn.create(seedScalar)); // Fixes modulo bias, but not zero
      return { secretKey, publicKey: curve.getPublicKey(secretKey) };
    };
  }
  return {
    lengths: { secretKey: lengths.secretKey, publicKey: lengths.publicKey, seed: lengths.seed },
    keygen,
    getPublicKey: (secretKey: Uint8Array) => curve.getPublicKey(secretKey),
  };
}

/**
 * Wraps an ECDH-capable curve as a KEM.
 * @param curve - Curve with `getSharedSecret`.
 * @param allowZeroKey - Whether zero-valued secret scalars are allowed during keygen.
 * @returns KEM wrapper over the curve.
 * @throws If the curve does not expose `getSharedSecret`. {@link Error}
 * @example
 * Wrap an ECDH-capable curve as a generic KEM.
 * ```ts
 * import { x25519 } from '@noble/curves/ed25519.js';
 * import { ecdhKem } from '@noble/post-quantum/hybrid.js';
 * const kem = ecdhKem(x25519);
 * const publicKeyLen = kem.lengths.publicKey;
 * ```
 */
export function ecdhKem(curve: CurveECDH, allowZeroKey: boolean = false): KEM {
  const kg = ecKeygen(curve, allowZeroKey);
  if (!curve.getSharedSecret) throw new Error('wrong curve'); // ed25519 doesn't have one!
  return {
    lengths: { ...kg.lengths, msg: kg.lengths.seed, cipherText: kg.lengths.publicKey },
    keygen: kg.keygen,
    getPublicKey: kg.getPublicKey,
    encapsulate(publicKey: Uint8Array, rand: Uint8Array = randomBytes(curve.lengths.seed)) {
      const ek = this.keygen(rand).secretKey;
      const sharedSecret = this.decapsulate(publicKey, ek);
      const cipherText = curve.getPublicKey(ek);
      cleanBytes(ek);
      return { sharedSecret, cipherText };
    },
    decapsulate(cipherText: Uint8Array, secretKey: Uint8Array) {
      const res = curve.getSharedSecret(secretKey, cipherText);
      return curve.lengths.publicKeyHasPrefix ? res.subarray(1) : res;
    },
  };
}

/**
 * Wraps a curve signer as a generic `Signer`.
 * @param curve - Curve with `sign` and `verify`.
 * @param allowZeroKey - Whether zero-valued secret scalars are allowed during keygen.
 * @returns Signer wrapper over the curve.
 * @throws If the curve does not expose `sign` and `verify`. {@link Error}
 * @example
 * Wrap a curve signer as a generic signer.
 * ```ts
 * import { ed25519 } from '@noble/curves/ed25519.js';
 * import { ecSigner } from '@noble/post-quantum/hybrid.js';
 * const signer = ecSigner(ed25519);
 * const sigLen = signer.lengths.signature;
 * ```
 */
export function ecSigner(curve: CurveSign, allowZeroKey: boolean = false): Signer {
  const kg = ecKeygen(curve, allowZeroKey);
  if (!curve.sign || !curve.verify) throw new Error('wrong curve'); // ed25519 doesn't have one!
  return {
    lengths: { ...kg.lengths, signature: curve.lengths.signature, signRand: 0 },
    keygen: kg.keygen,
    getPublicKey: kg.getPublicKey,
    sign: (message, secretKey) => curve.sign(message, secretKey),
    verify: (signature, message, publicKey) => curve.verify(signature, message, publicKey),
  };
}

function splitLengths<K extends string, T extends { lengths: Partial<Record<K, number>> }>(
  lst: T[],
  name: K
) {
  return splitCoder(
    name,
    ...lst.map((i) => {
      if (typeof i.lengths[name] !== 'number') throw new Error('wrong length: ' + name);
      return i.lengths[name];
    })
  );
}

/** Seed-expansion callback used by the hybrid combiners. */
export type ExpandSeed = (seed: Uint8Array, len: number) => Uint8Array;
type XOF = CHashXOF<any, { dkLen: number }>;

// It is XOF for most cases, but can be more complex!
/**
 * Adapts an XOF into an `ExpandSeed` callback.
 * @param xof - Extendable-output hash function.
 * @returns Seed expander using `dkLen`.
 * @example
 * Adapt an XOF into a seed expander.
 * ```ts
 * import { shake256 } from '@noble/hashes/sha3.js';
 * import { expandSeedXof } from '@noble/post-quantum/hybrid.js';
 * const expandSeed = expandSeedXof(shake256);
 * const seed = expandSeed(new Uint8Array([1]), 4);
 * ```
 */
export function expandSeedXof(xof: XOF): ExpandSeed {
  return (seed: Uint8Array, seedLen: number) => xof(seed, { dkLen: seedLen });
}

/** Combines public keys, ciphertexts, and shared secrets into one shared secret. */
export type Combiner = (
  publicKeys: Uint8Array[],
  cipherTexts: Uint8Array[],
  sharedSecrets: Uint8Array[]
) => Uint8Array;

function combineKeys(
  realSeedLen: number | undefined, // how much bytes expandSeed expects
  expandSeed: ExpandSeed,
  ...ck: CryptoKeys[]
) {
  const seedCoder = splitLengths(ck, 'seed');
  const pkCoder = splitLengths(ck, 'publicKey');
  // Allows to use identity functions for combiner/expandSeed
  if (realSeedLen === undefined) realSeedLen = seedCoder.bytesLen;
  anumber(realSeedLen);
  function expandDecapsulationKey(seed: Uint8Array) {
    abytes(seed, realSeedLen!);
    const expanded = seedCoder.decode(expandSeed(seed, seedCoder.bytesLen));
    const keys = ck.map((i, j) => i.keygen(expanded[j]));
    const secretKey = keys.map((i) => i.secretKey);
    const publicKey = keys.map((i) => i.publicKey);
    return { secretKey, publicKey };
  }
  return {
    info: { lengths: { seed: realSeedLen, publicKey: pkCoder.bytesLen, secretKey: realSeedLen } },
    getPublicKey(secretKey: Uint8Array) {
      return this.keygen(secretKey).publicKey;
    },
    keygen(seed: Uint8Array = randomBytes(realSeedLen)) {
      const { publicKey: pk, secretKey } = expandDecapsulationKey(seed);
      const publicKey = pkCoder.encode(pk);
      cleanBytes(pk);
      cleanBytes(secretKey);
      return { secretKey: seed, publicKey };
    },
    expandDecapsulationKey,
    realSeedLen,
  };
}

// This generic function that combines multiple KEMs into single one
/**
 * Combines multiple KEMs into one composite KEM.
 * @param realSeedLen - Input seed length expected by `expandSeed`.
 * @param realMsgLen - Shared-secret length returned by `combiner`.
 * @param expandSeed - Seed expander used to derive per-KEM seeds.
 * @param combiner - Combines the per-KEM outputs into one shared secret.
 * @param kems - KEM implementations to combine.
 * @returns Composite KEM.
 * @example
 * Combine multiple KEMs into one composite KEM.
 * ```ts
 * import { shake256 } from '@noble/hashes/sha3.js';
 * import { combineKEMS, expandSeedXof } from '@noble/post-quantum/hybrid.js';
 * import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
 * const hybrid = combineKEMS(
 *   32,
 *   32,
 *   expandSeedXof(shake256),
 *   (_pk, _ct, sharedSecrets) => sharedSecrets[0],
 *   ml_kem768,
 *   ml_kem768
 * );
 * const { publicKey } = hybrid.keygen();
 * ```
 */
export function combineKEMS(
  realSeedLen: number | undefined, // how much bytes expandSeed expects
  realMsgLen: number | undefined, // how much bytes combiner returns
  expandSeed: ExpandSeed,
  combiner: Combiner,
  ...kems: KEM[]
): KEM {
  const keys = combineKeys(realSeedLen, expandSeed, ...kems);
  const ctCoder = splitLengths(kems, 'cipherText');
  const pkCoder = splitLengths(kems, 'publicKey');
  const msgCoder = splitLengths(kems, 'msg');
  if (realMsgLen === undefined) realMsgLen = msgCoder.bytesLen;
  anumber(realMsgLen);
  return {
    lengths: {
      ...keys.info.lengths,
      msg: realMsgLen,
      msgRand: msgCoder.bytesLen,
      cipherText: ctCoder.bytesLen,
    },
    getPublicKey: keys.getPublicKey,
    keygen: keys.keygen,
    encapsulate(pk: Uint8Array, randomness: Uint8Array = randomBytes(msgCoder.bytesLen)) {
      const pks = pkCoder.decode(pk);
      const rand = msgCoder.decode(randomness);
      const enc = kems.map((i, j) => i.encapsulate(pks[j], rand[j]));
      const sharedSecret = enc.map((i) => i.sharedSecret);
      const cipherText = enc.map((i) => i.cipherText);
      const res = {
        sharedSecret: combiner(pks, cipherText, sharedSecret),
        cipherText: ctCoder.encode(cipherText),
      };
      cleanBytes(sharedSecret, cipherText);
      return res;
    },
    decapsulate(ct: Uint8Array, seed: Uint8Array) {
      const cts = ctCoder.decode(ct);
      const { publicKey, secretKey } = keys.expandDecapsulationKey(seed);
      const sharedSecret = kems.map((i, j) => i.decapsulate(cts[j], secretKey[j]));
      return combiner(publicKey, cts, sharedSecret);
    },
  };
}
// There is no specs for this, but can be useful
// realSeedLen: how much bytes expandSeed expects.
/**
 * Combines multiple signers into one composite signer.
 * @param realSeedLen - Input seed length expected by `expandSeed`.
 * @param expandSeed - Seed expander used to derive per-signer seeds.
 * @param signers - Signers to combine.
 * @returns Composite signer.
 * @example
 * Combine multiple signers into one composite signer.
 * ```ts
 * import { shake256 } from '@noble/hashes/sha3.js';
 * import { combineSigners, expandSeedXof } from '@noble/post-quantum/hybrid.js';
 * import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
 * const hybrid = combineSigners(32, expandSeedXof(shake256), ml_dsa44, ml_dsa44);
 * const { publicKey } = hybrid.keygen();
 * ```
 */
export function combineSigners(
  realSeedLen: number | undefined,
  expandSeed: ExpandSeed,
  ...signers: Signer[]
): Signer {
  const keys = combineKeys(realSeedLen, expandSeed, ...signers);
  const sigCoder = splitLengths(signers, 'signature');
  const pkCoder = splitLengths(signers, 'publicKey');
  return {
    lengths: { ...keys.info.lengths, signature: sigCoder.bytesLen, signRand: 0 },
    getPublicKey: keys.getPublicKey,
    keygen: keys.keygen,
    sign(message, seed) {
      const { secretKey } = keys.expandDecapsulationKey(seed);
      // NOTE: we probably can make different hashes for different algorithms
      // same way as we do for kem, but not sure if this a good idea.
      const sigs = signers.map((i, j) => i.sign(message, secretKey[j]));
      return sigCoder.encode(sigs);
    },
    verify: (signature, message, publicKey) => {
      const pks = pkCoder.decode(publicKey);
      const sigs = sigCoder.decode(signature);
      for (let i = 0; i < signers.length; i++) {
        if (!signers[i].verify(sigs[i], message, pks[i])) return false;
      }
      return true;
    },
  };
}

/**
 * Builds a QSF hybrid KEM preset from a PQ KEM and an elliptic-curve KEM.
 * @param label - Domain-separation label.
 * @param pqc - Post-quantum KEM.
 * @param curveKEM - Classical curve KEM.
 * @param xof - XOF used for seed expansion.
 * @param kdf - Hash used for the final combiner.
 * @returns Hybrid KEM.
 * @example
 * Build a QSF hybrid KEM preset from a PQ KEM and an elliptic-curve KEM.
 * ```ts
 * import { p256 } from '@noble/curves/nist.js';
 * import { sha3_256, shake256 } from '@noble/hashes/sha3.js';
 * import { QSF, ecdhKem } from '@noble/post-quantum/hybrid.js';
 * import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
 * const kem = QSF('example', ml_kem768, ecdhKem(p256, true), shake256, sha3_256);
 * const publicKeyLen = kem.lengths.publicKey;
 * ```
 */
export function QSF(label: string, pqc: KEM, curveKEM: KEM, xof: XOF, kdf: CHash): KEM {
  ahash(xof);
  ahash(kdf);
  return combineKEMS(
    32,
    32,
    expandSeedXof(xof),
    (pk, ct, ss) => kdf(concatBytes(ss[0], ss[1], ct[1], pk[1], asciiToBytes(label))),
    pqc,
    curveKEM
  );
}

/** QSF preset combining ML-KEM-768 with P-256. */
export const QSF_ml_kem768_p256: KEM = /* @__PURE__ */ (() =>
  QSF(
    'QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)',
    ml_kem768,
    ecdhKem(p256, true),
    shake256,
    sha3_256
  ))();
/** QSF preset combining ML-KEM-1024 with P-384. */
export const QSF_ml_kem1024_p384: KEM = /* @__PURE__ */ (() =>
  QSF(
    'QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)',
    ml_kem1024,
    ecdhKem(p384, true),
    shake256,
    sha3_256
  ))();

/**
 * Builds the "KitchenSink" hybrid KEM combiner.
 * @param label - Domain-separation label.
 * @param pqc - Post-quantum KEM.
 * @param curveKEM - Classical curve KEM.
 * @param xof - XOF used for seed expansion.
 * @param hash - Hash used for HKDF extraction and expansion.
 * @returns Hybrid KEM.
 * @example
 * Build the "KitchenSink" hybrid KEM combiner.
 * ```ts
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { shake256 } from '@noble/hashes/sha3.js';
 * import { createKitchenSink, ecdhKem } from '@noble/post-quantum/hybrid.js';
 * import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
 * import { x25519 } from '@noble/curves/ed25519.js';
 * const kem = createKitchenSink('example', ml_kem768, ecdhKem(x25519), shake256, sha256);
 * const publicKeyLen = kem.lengths.publicKey;
 * ```
 */
export function createKitchenSink(
  label: string,
  pqc: KEM,
  curveKEM: KEM,
  xof: XOF,
  hash: CHash
): KEM {
  ahash(xof);
  ahash(hash);
  return combineKEMS(
    32,
    32,
    expandSeedXof(xof),
    (pk, ct, ss) => {
      const preimage = concatBytes(ss[0], ss[1], ct[0], pk[0], ct[1], pk[1], asciiToBytes(label));
      const len = 32;
      const ikm = concatBytes(asciiToBytes('hybrid_prk'), preimage);
      const prk = extract(hash, ikm);
      const info = concatBytes(
        numberToBytesBE(len, 2),
        asciiToBytes('shared_secret'),
        asciiToBytes('')
      );
      const res = expand(hash, prk, info, len);
      cleanBytes(prk, info, ikm, preimage);
      return res;
    },
    pqc,
    curveKEM
  );
}

const x25519kem = /* @__PURE__ */ ecdhKem(x25519);
/** KitchenSink preset combining ML-KEM-768 with X25519. */
export const KitchenSink_ml_kem768_x25519: KEM = /* @__PURE__ */ (() =>
  createKitchenSink(
    'KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)',
    ml_kem768,
    x25519kem,
    shake256,
    sha256
  ))();

// Always X25519 and ML-KEM - 768, no point to export
/** X25519 + ML-KEM-768 hybrid preset. */
export const ml_kem768_x25519: KEM = /* @__PURE__ */ (() =>
  combineKEMS(
    32,
    32,
    expandSeedXof(shake256),
    // Awesome label, so much escaping hell in a single line.
    (pk, ct, ss) => sha3_256(concatBytes(ss[0], ss[1], ct[1], pk[1], asciiToBytes('\\.//^\\'))),
    ml_kem768,
    x25519kem
  ))();

function nistCurveKem(curve: ECDSA, scalarLen: number, elemLen: number, nseed: number): KEM {
  const Fn = curve.Point.Fn;
  if (!Fn) throw new Error('no Point.Fn');
  function rejectionSampling(seed: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array } {
    let sk: bigint;
    for (let start = 0, end = scalarLen; ; start = end, end += scalarLen) {
      if (end > seed.length) throw new Error('rejection sampling failed');
      sk = Fn.fromBytes(seed.subarray(start, end), true);
      if (Fn.isValidNot0(sk)) break;
    }
    const secretKey = Fn.toBytes(Fn.create(sk));
    const publicKey = curve.getPublicKey(secretKey, false);
    return { secretKey, publicKey };
  }

  return {
    lengths: {
      secretKey: scalarLen,
      publicKey: elemLen,
      seed: nseed,
      msg: nseed,
      cipherText: elemLen,
    },
    keygen(seed: Uint8Array = randomBytes(nseed)) {
      abytes(seed, nseed, 'seed');
      return rejectionSampling(seed);
    },
    getPublicKey(secretKey: Uint8Array) {
      return curve.getPublicKey(secretKey, false);
    },
    encapsulate(publicKey: Uint8Array, rand: Uint8Array = randomBytes(nseed)) {
      abytes(rand, nseed, 'rand');
      const { secretKey: ek } = rejectionSampling(rand);
      const sharedSecret = this.decapsulate(publicKey, ek);
      const cipherText = curve.getPublicKey(ek, false);
      cleanBytes(ek);
      return { sharedSecret, cipherText };
    },
    decapsulate(cipherText: Uint8Array, secretKey: Uint8Array) {
      const full = curve.getSharedSecret(secretKey, cipherText);
      return full.subarray(1);
    },
  };
}

function concreteHybridKem(label: string, mlkem: KEM, curve: ECDSA, nseed: number): KEM {
  const { secretKey: scalarLen, publicKeyUncompressed: elemLen } = curve.lengths;
  if (!scalarLen || !elemLen) throw new Error('wrong curve');
  const curveKem = nistCurveKem(curve, scalarLen, elemLen, nseed);
  const mlkemSeedLen = 64;
  const totalSeedLen = mlkemSeedLen + nseed;

  return combineKEMS(
    32,
    32,
    (seed: Uint8Array) => {
      abytes(seed, 32);
      const expanded = shake256(seed, { dkLen: totalSeedLen });
      const mlkemSeed = expanded.subarray(0, mlkemSeedLen);
      const curveSeed = expanded.subarray(mlkemSeedLen, totalSeedLen);
      return concatBytes(mlkemSeed, curveSeed);
    },
    (pk, ct, ss) => sha3_256(concatBytes(ss[0], ss[1], ct[1], pk[1], asciiToBytes(label))),
    mlkem,
    curveKem
  );
}

/** P-256 + ML-KEM-768 hybrid preset. */
export const ml_kem768_p256: KEM = /* @__PURE__ */ (() =>
  concreteHybridKem('MLKEM768-P256', ml_kem768, p256, 128))();

/** P-384 + ML-KEM-1024 hybrid preset. */
export const ml_kem1024_p384: KEM = /* @__PURE__ */ (() =>
  concreteHybridKem('MLKEM1024-P384', ml_kem1024, p384, 48))();

// Legacy aliases
/** Legacy alias for `ml_kem768_x25519`. */
export const XWing: KEM = /* @__PURE__ */ (() => ml_kem768_x25519)();
/** Legacy alias for `ml_kem768_x25519`. */
export const MLKEM768X25519: KEM = /* @__PURE__ */ (() => ml_kem768_x25519)();
/** Legacy alias for `ml_kem768_p256`. */
export const MLKEM768P256: KEM = /* @__PURE__ */ (() => ml_kem768_p256)();
/** Legacy alias for `ml_kem1024_p384`. */
export const MLKEM1024P384: KEM = /* @__PURE__ */ (() => ml_kem1024_p384)();
/** Legacy alias for `QSF_ml_kem768_p256`. */
export const QSFMLKEM768P256: KEM = /* @__PURE__ */ (() => QSF_ml_kem768_p256)();
/** Legacy alias for `QSF_ml_kem1024_p384`. */
export const QSFMLKEM1024P384: KEM = /* @__PURE__ */ (() => QSF_ml_kem1024_p384)();
/** Legacy alias for `KitchenSink_ml_kem768_x25519`. */
export const KitchenSinkMLKEM768X25519: KEM = /* @__PURE__ */ (() =>
  KitchenSink_ml_kem768_x25519)();
