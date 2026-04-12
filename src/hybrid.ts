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
 *      • Combiner:
 *        SHA3-256(kemShare || ecdhShare || ciphertext || pubKey || algId || domSep || len(domSep))
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
  copyBytes,
  randomBytes,
  splitCoder,
  validateSigOpts,
  validateVerOpts,
  type CryptoKeys,
  type KEM,
  type Signer,
  type TArg,
  type TRet,
} from './utils.ts';

type CurveAll = ECDSA | EdDSA | MontgomeryECDH;
type CurveECDH = ECDSA | MontgomeryECDH;
type CurveSign = ECDSA | EdDSA;

// Can re-use if decide to signatures support, on other hand getSecretKey is specific and ugly
function ecKeygen(curve: CurveAll, allowZeroKey: boolean = false) {
  const lengths = curve.lengths;
  let keygen = curve.keygen;
  if (allowZeroKey) {
    // Only the ECDSA/Weierstrass branch uses raw scalar-byte secret keys here. Edwards seeds are
    // hashed/pruned and Montgomery keys are clamped byte strings, so forcing Point.Fn semantics on
    // those curves would change key construction instead of just relaxing scalar range handling.
    if (!('getSharedSecret' in curve && 'sign' in curve && 'verify' in curve))
      throw new Error('allowZeroKey requires a Weierstrass curve');
    // This legacy flag is really "skip the +1 shift" for vector matching, not "accept scalar 0".
    // It swaps seeded Weierstrass keygen from reduction into [1, ORDER) to direct reduction into
    // [0, ORDER), which preserves exact reduced bytes but still leaves scalar 0 invalid.
    // This is ugly, but we need to return exact results here.
    const wCurve = curve as ECDSA;
    const Fn = wCurve.Point.Fn;
    // Unlike noble-curves' seeded Weierstrass keygen, this path removes the post-reduction +1.
    // That is enough to match exact reduced-vector bytes, but an all-zero seed still reduces to
    // scalar 0 here and getPublicKey(secretKey) throws instead of "allowing zero".
    keygen = (seed: TArg<Uint8Array> = randomBytes(lengths.seed)) => {
      abytes(seed, lengths.seed!, 'seed');
      const seedScalar = Fn.isLE ? bytesToNumberLE(seed) : bytesToNumberBE(seed);
      // Reduce directly into [0, ORDER); scalar 0 still stays invalid.
      const secretKey = Fn.toBytes(Fn.create(seedScalar));
      return {
        secretKey: secretKey as TRet<Uint8Array>,
        publicKey: curve.getPublicKey(secretKey) as TRet<Uint8Array>,
      };
    };
  }
  return {
    lengths: { secretKey: lengths.secretKey, publicKey: lengths.publicKey, seed: lengths.seed },
    keygen: (seed?: TArg<Uint8Array>) =>
      keygen(seed) as TRet<{
        secretKey: Uint8Array;
        publicKey: Uint8Array;
      }>,
    getPublicKey: (secretKey: TArg<Uint8Array>) =>
      curve.getPublicKey(secretKey) as TRet<Uint8Array>,
  };
}

/**
 * Wraps an ECDH-capable curve as a KEM.
 * Shared secrets stay in the wrapped curve's raw ECDH byte format with no built-in KDF.
 * On SEC 1 / Weierstrass curves, that means the compressed shared-point body without the
 * 1-byte `0x02` / `0x03` prefix.
 * The X25519 path also leaves RFC 7748's optional all-zero shared-secret check to callers.
 * @param curve - Curve with `getSharedSecret`.
 * @param allowZeroKey - Legacy vector-matching toggle for Weierstrass keygen.
 * On Weierstrass curves this removes the usual post-reduction `+1` shift, changing seeded scalar
 * reduction from `[1, ORDER)` to direct reduction into `[0, ORDER)`. It does not make scalar zero
 * valid: an all-zero seed still derives scalar `0` and throws in `curve.getPublicKey(...)`.
 * Only supported on Weierstrass/ECDSA curves.
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
export function ecdhKem(curve: CurveECDH, allowZeroKey: boolean = false): TRet<KEM> {
  const kg = ecKeygen(curve, allowZeroKey);
  if (!curve.getSharedSecret) throw new Error('wrong curve'); // ed25519 doesn't have one!
  return {
    lengths: { ...kg.lengths, msg: kg.lengths.seed, cipherText: kg.lengths.publicKey },
    keygen: kg.keygen,
    getPublicKey: kg.getPublicKey,
    encapsulate(
      publicKey: TArg<Uint8Array>,
      rand: TArg<Uint8Array> = randomBytes(curve.lengths.seed)
    ) {
      // Some curve.keygen(seed) paths reuse the provided seed buffer as secretKey; detach caller
      // randomness first so cleanBytes() only wipes wrapper-owned material.
      const seed = copyBytes(rand);
      let ek: Uint8Array | undefined = undefined;
      try {
        ek = this.keygen(seed).secretKey;
        const sharedSecret = this.decapsulate(publicKey, ek);
        const cipherText = curve.getPublicKey(ek) as TRet<Uint8Array>;
        return { sharedSecret, cipherText };
      } finally {
        // Invalid peer public keys can make decapsulation throw; wipe both the detached seed and
        // derived ephemeral secret key even when encapsulation aborts before returning.
        cleanBytes(seed);
        if (ek) cleanBytes(ek);
      }
    },
    decapsulate(cipherText: TArg<Uint8Array>, secretKey: TArg<Uint8Array>) {
      const res = curve.getSharedSecret(secretKey, cipherText);
      return (curve.lengths.publicKeyHasPrefix ? res.subarray(1) : res) as TRet<Uint8Array>;
    },
  };
}

/**
 * Wraps a curve signer as a generic `Signer`.
 * Signatures stay in the wrapped curve's native byte encoding.
 * This wrapper does not normalize or document which per-curve signing options are meaningful.
 * @param curve - Curve with `sign` and `verify`.
 * @param allowZeroKey - Legacy vector-matching toggle for Weierstrass keygen.
 * On Weierstrass curves this removes the usual post-reduction `+1` shift, changing seeded scalar
 * reduction from `[1, ORDER)` to direct reduction into `[0, ORDER)`. It does not make scalar zero
 * valid: an all-zero seed still derives scalar `0` and throws in `curve.getPublicKey(...)`.
 * Only supported on Weierstrass/ECDSA curves.
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
export function ecSigner(curve: CurveSign, allowZeroKey: boolean = false): TRet<Signer> {
  const kg = ecKeygen(curve, allowZeroKey);
  if (!curve.sign || !curve.verify) throw new Error('wrong curve'); // ed25519 doesn't have one!
  return {
    lengths: { ...kg.lengths, signature: curve.lengths.signature, signRand: 0 },
    keygen: kg.keygen,
    getPublicKey: kg.getPublicKey,
    sign: (message, secretKey, opts = {}) => {
      validateSigOpts(opts);
      // This generic wrapper intentionally keeps the Signer contract to message + key only.
      // Backend-specific knobs like ECDSA extraEntropy or Ed25519ctx context cannot be forwarded
      // uniformly through combineSigners(), so callers that need them must use the curve directly.
      if (opts.extraEntropy !== undefined)
        throw new Error(
          'ecSigner does not support extraEntropy; use the underlying curve directly'
        );
      if (opts.context !== undefined)
        throw new Error('ecSigner does not support context; use the underlying curve directly');
      return curve.sign(message, secretKey) as TRet<Uint8Array>;
    },
    /** Verify one wrapped curve signature.
     * Returns the wrapped curve's `verify()` result for well-formed inputs. Throws on unsupported
     * generic opts and lets wrapped-curve malformed-input errors escape unchanged.
     */
    verify: (signature, message, publicKey, opts = {}) => {
      validateVerOpts(opts);
      if (opts.context !== undefined)
        throw new Error('ecSigner does not support context; use the underlying curve directly');
      return curve.verify(signature, message, publicKey);
    },
  };
}

function splitLengths<K extends string, T extends { lengths: Partial<Record<K, number>> }>(
  lst: T[],
  name: K
) {
  // Preserve caller order exactly; raw numeric fields still decode as splitCoder() subarray views.
  return splitCoder(
    name,
    ...lst.map((i) => {
      if (typeof i.lengths[name] !== 'number') throw new Error('wrong length: ' + name);
      return i.lengths[name];
    })
  );
}

/** Seed-expansion callback used by the hybrid combiners. */
export type ExpandSeed = (seed: TArg<Uint8Array>, len: number) => TRet<Uint8Array>;
type XOF = CHashXOF<any, { dkLen: number }>;

// It is XOF for most cases, but can be more complex!
/**
 * Adapts an XOF into an `ExpandSeed` callback.
 * The returned callback interprets its second argument as an output byte length passed as `dkLen`.
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
export function expandSeedXof(xof: TArg<XOF>): TRet<ExpandSeed> {
  // Forward the caller seed directly: XOFs are expected to treat inputs as read-only, and this
  // adapter only translates the requested byte length into the hash API's `dkLen` option.
  return ((seed: TArg<Uint8Array>, seedLen: number): TRet<Uint8Array> =>
    (xof as XOF)(seed, { dkLen: seedLen }) as TRet<Uint8Array>) as TRet<ExpandSeed>;
}

/** Combines public keys, ciphertexts, and shared secrets into one shared secret. */
export type Combiner = (
  publicKeys: TArg<Uint8Array[]>,
  cipherTexts: TArg<Uint8Array[]>,
  sharedSecrets: TArg<Uint8Array[]>
) => TRet<Uint8Array>;

function combineKeys(
  realSeedLen: number | undefined, // how much bytes expandSeed expects
  expandSeed_: TArg<ExpandSeed>,
  ...ck_: TArg<CryptoKeys[]>
) {
  const expandSeed = expandSeed_ as ExpandSeed;
  const ck = ck_ as CryptoKeys[];
  const seedCoder = splitLengths(ck, 'seed');
  const pkCoder = splitLengths(ck, 'publicKey');
  // Allows to use identity functions for combiner/expandSeed
  if (realSeedLen === undefined) realSeedLen = seedCoder.bytesLen;
  anumber(realSeedLen);
  function expandDecapsulationKey(seed: TArg<Uint8Array>): TRet<{
    secretKey: Uint8Array[];
    publicKey: Uint8Array[];
  }> {
    abytes(seed, realSeedLen!);
    const expandedRaw = expandSeed(seed, seedCoder.bytesLen);
    // Identity/subarray expanders can hand back caller-owned seed storage. Detach those outputs so
    // later cleanup can wipe the expanded schedule without mutating the caller's root seed bytes.
    const expandedSeed = expandedRaw.buffer === seed.buffer ? copyBytes(expandedRaw) : expandedRaw;
    const expanded: Uint8Array[] = [];
    const keySecret: Uint8Array[] = [];
    const secretKey: Uint8Array[] = [];
    const publicKey: Uint8Array[] = [];
    let ok = false;
    try {
      // seedCoder.decode() returns zero-copy slices into expandedSeed and can throw before child
      // keygen() runs, so keep the raw expanded buffer separate and copy each child seed before any
      // later cleanup wipes the shared backing bytes.
      for (const part of seedCoder.decode(expandedSeed)) expanded.push(copyBytes(part));
      for (let i = 0; i < ck.length; i++) {
        const keys = ck[i].keygen(expanded[i]);
        keySecret.push(keys.secretKey);
        secretKey.push(copyBytes(keys.secretKey));
        publicKey.push(keys.publicKey);
      }
      ok = true;
      return { secretKey, publicKey } as TRet<{
        secretKey: Uint8Array[];
        publicKey: Uint8Array[];
      }>;
    } finally {
      // Child keygen() can throw after deriving only a prefix of the composite key schedule. Keep
      // the exported copies on success, but wipe all temporary and partially built secret material
      // on either path so failures do not strand derived child seeds in memory.
      cleanBytes(expandedSeed, expanded, keySecret);
      if (!ok) cleanBytes(secretKey);
    }
  }
  return {
    info: { lengths: { seed: realSeedLen, publicKey: pkCoder.bytesLen, secretKey: realSeedLen } },
    getPublicKey(secretKey: TArg<Uint8Array>) {
      // Composite secret keys are root seeds, so public-key derivation reruns key expansion from
      // that seed instead of decoding a packed child-secret-key structure.
      return this.keygen(secretKey).publicKey as TRet<Uint8Array>;
    },
    keygen(seed: TArg<Uint8Array> = randomBytes(realSeedLen)) {
      const { publicKey: pk, secretKey } = expandDecapsulationKey(seed);
      try {
        const publicKey = pkCoder.encode(pk) as TRet<Uint8Array>;
        return { secretKey: seed as TRet<Uint8Array>, publicKey };
      } finally {
        cleanBytes(pk);
        // The exported secretKey is the caller/root seed itself; child secret keys are internal
        // expansion outputs that are cleaned whether encoding succeeds or throws.
        cleanBytes(secretKey);
      }
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
  expandSeed: TArg<ExpandSeed>,
  combiner: TArg<Combiner>,
  ...kems: TArg<KEM[]>
): TRet<KEM> {
  const rawCombiner = combiner as Combiner;
  const rawKems = kems as KEM[];
  const keys = combineKeys(realSeedLen, expandSeed, ...rawKems);
  const ctCoder = splitLengths(rawKems, 'cipherText');
  const pkCoder = splitLengths(rawKems, 'publicKey');
  const msgCoder = splitLengths(rawKems, 'msg');
  if (realMsgLen === undefined) realMsgLen = msgCoder.bytesLen;
  anumber(realMsgLen);
  const lengths = Object.freeze({
    ...keys.info.lengths,
    msg: realMsgLen,
    msgRand: msgCoder.bytesLen,
    cipherText: ctCoder.bytesLen,
  });
  return Object.freeze({
    lengths,
    getPublicKey: keys.getPublicKey,
    keygen: keys.keygen,
    encapsulate(
      pk: TArg<Uint8Array>,
      randomness: TArg<Uint8Array> = randomBytes(msgCoder.bytesLen)
    ) {
      const pks = pkCoder.decode(pk);
      const rand = msgCoder.decode(randomness);
      const sharedSecret: Uint8Array[] = [];
      const cipherText: Uint8Array[] = [];
      try {
        for (let i = 0; i < rawKems.length; i++) {
          const enc = rawKems[i].encapsulate(pks[i], rand[i]);
          sharedSecret.push(enc.sharedSecret);
          cipherText.push(enc.cipherText);
        }
        return {
          // Detach the combiner result before cleanup: a caller-provided combiner may alias one of
          // the child sharedSecret buffers, and those child buffers are zeroized immediately below.
          sharedSecret: copyBytes(rawCombiner(pks, cipherText, sharedSecret)),
          cipherText: ctCoder.encode(cipherText) as TRet<Uint8Array>,
        };
      } finally {
        // Child encapsulation or combiner failures can happen after some components already
        // returned secret material; zeroize whatever was produced before propagating the error.
        cleanBytes(sharedSecret, cipherText);
      }
    },
    decapsulate(ct: TArg<Uint8Array>, seed: TArg<Uint8Array>) {
      const cts = ctCoder.decode(ct);
      const { publicKey, secretKey } = keys.expandDecapsulationKey(seed);
      const sharedSecret = rawKems.map((i, j) => i.decapsulate(cts[j], secretKey[j]));
      try {
        // Detach the decapsulation result before cleanup: the combiner may hand back one of the
        // child shared-secret buffers, and those temporary buffers are zeroized below.
        return copyBytes(rawCombiner(publicKey, cts, sharedSecret));
      } finally {
        // Decapsulation only needs the expanded child secret keys and child shared secrets for this
        // call; keep the caller/root seed intact, but wipe all derived material even on errors.
        cleanBytes(secretKey, sharedSecret);
      }
    },
  });
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
  expandSeed: TArg<ExpandSeed>,
  ...signers: TArg<Signer[]>
): TRet<Signer> {
  const rawSigners = signers as Signer[];
  const keys = combineKeys(realSeedLen, expandSeed, ...rawSigners);
  const sigCoder = splitLengths(rawSigners, 'signature');
  const pkCoder = splitLengths(rawSigners, 'publicKey');
  return {
    lengths: { ...keys.info.lengths, signature: sigCoder.bytesLen, signRand: 0 },
    getPublicKey: keys.getPublicKey,
    keygen: keys.keygen,
    sign(message, seed, opts = {}) {
      validateSigOpts(opts);
      // This generic wrapper intentionally keeps the composite signer contract to message + root
      // seed only. Per-signer opts like context or extraEntropy cannot be preserved uniformly
      // across mixed backends, so callers that need them must use the underlying signer directly.
      if (opts.extraEntropy !== undefined)
        throw new Error(
          'combineSigners does not support extraEntropy; use the underlying signer directly'
        );
      if (opts.context !== undefined)
        throw new Error(
          'combineSigners does not support context; use the underlying signer directly'
        );
      const { secretKey } = keys.expandDecapsulationKey(seed);
      try {
        const sigs = rawSigners.map((i, j) => i.sign(message, secretKey[j]));
        return sigCoder.encode(sigs) as TRet<Uint8Array>;
      } finally {
        // Composite secret keys are root seeds; the per-signer child secret keys are temporary
        // expansion outputs and must not stay live after the combined signature is produced.
        cleanBytes(secretKey);
      }
    },
    /** Verify one combined signature.
     * Returns `false` when the aggregate signature/publicKey decode succeeds but any child verify
     * check fails. Throws on unsupported generic opts or malformed aggregate encodings.
     */
    verify: (signature, message, publicKey, opts = {}) => {
      validateVerOpts(opts);
      if (opts.context !== undefined)
        throw new Error(
          'combineSigners does not support context; use the underlying signer directly'
        );
      const pks = pkCoder.decode(publicKey);
      const sigs = sigCoder.decode(signature);
      for (let i = 0; i < rawSigners.length; i++) {
        if (!rawSigners[i].verify(sigs[i], message, pks[i])) return false;
      }
      return true;
    },
  };
}

/**
 * Builds a QSF hybrid KEM preset from a PQ KEM and an elliptic-curve KEM.
 * The combined shared-secret length follows `kdf.outputLen`; the built-in presets use 32-byte
 * SHA3-256 output, while custom `kdf` choices inherit their own digest size.
 * Its combiner hashes `ss0 || ss1 || ct1 || pk1 || label`, not the full
 * `(c1, c2, ek1, ek2)` example input shape from SP 800-227 equation (15).
 * Labels are encoded with `asciiToBytes()`, so non-ASCII labels are rejected.
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
export function QSF(
  label: string,
  pqc: TArg<KEM>,
  curveKEM: TArg<KEM>,
  xof: TArg<XOF>,
  kdf: CHash
): TRet<KEM> {
  ahash(xof);
  ahash(kdf);
  return combineKEMS(
    32,
    kdf.outputLen,
    expandSeedXof(xof),
    (pk: TArg<Uint8Array[]>, ct: TArg<Uint8Array[]>, ss: TArg<Uint8Array[]>) =>
      kdf(concatBytes(ss[0], ss[1], ct[1], pk[1], asciiToBytes(label))),
    pqc,
    curveKEM
  );
}

/** QSF preset combining ML-KEM-768 with P-256. */
export const QSF_ml_kem768_p256: TRet<KEM> = /* @__PURE__ */ (() =>
  QSF(
    'QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)',
    ml_kem768,
    ecdhKem(p256, true),
    shake256,
    sha3_256
  ))();
/** QSF preset combining ML-KEM-1024 with P-384. */
export const QSF_ml_kem1024_p384: TRet<KEM> = /* @__PURE__ */ (() =>
  QSF(
    'QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)',
    ml_kem1024,
    ecdhKem(p384, true),
    shake256,
    sha3_256
  ))();

/**
 * Builds the "KitchenSink" hybrid KEM combiner.
 * The current builder always derives a fixed 32-byte output,
 * regardless of the hash's native output size.
 * Its HKDF extract step uses implicit zero salt with IKM
 * `hybrid_prk || ss0 || ss1 || ct0 || pk0 || ct1 || pk1 || label`.
 * Its HKDF expand step fixes `info` to `len || 'shared_secret' || ''`.
 * Labels are encoded with `asciiToBytes()`, so non-ASCII labels are rejected.
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
  pqc: TArg<KEM>,
  curveKEM: TArg<KEM>,
  xof: TArg<XOF>,
  hash: CHash
): TRet<KEM> {
  ahash(xof);
  ahash(hash);
  return combineKEMS(
    32,
    32,
    expandSeedXof(xof),
    (pk: TArg<Uint8Array[]>, ct: TArg<Uint8Array[]>, ss: TArg<Uint8Array[]>) => {
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

// Internal alias only: this stays exactly `ecdhKem(x25519)`
// and inherits that wrapper's mutation/oracle behavior.
const x25519kem = /* @__PURE__ */ ecdhKem(x25519);
/** KitchenSink preset combining ML-KEM-768 with X25519.
 * Caller randomness splits into 32 ML-KEM coins plus a 32-byte X25519 ephemeral-secret seed.
 */
export const KitchenSink_ml_kem768_x25519: TRet<KEM> = /* @__PURE__ */ (() =>
  createKitchenSink(
    'KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)',
    ml_kem768,
    x25519kem,
    shake256,
    sha256
  ))();

// Always X25519 and ML-KEM - 768, no point to export
/** X25519 + ML-KEM-768 hybrid preset.
 * Uses the hard-coded domain-separation label `\\.//^\\` and hashes only `ct1 || pk1`
 * from the X25519 side in addition to the two component shared secrets.
 */
export const ml_kem768_x25519: TRet<KEM> = /* @__PURE__ */ (() =>
  combineKEMS(
    32,
    32,
    expandSeedXof(shake256),
    // Awesome label, so much escaping hell in a single line.
    (pk: TArg<Uint8Array[]>, ct: TArg<Uint8Array[]>, ss: TArg<Uint8Array[]>) =>
      sha3_256(concatBytes(ss[0], ss[1], ct[1], pk[1], asciiToBytes('\\.//^\\'))),
    ml_kem768,
    x25519kem
  ))();

/**
 * Internal SEC 1-style KEM wrapper for NIST curves.
 * `nseed` is only the rejection-sampling byte budget for deriving one nonzero scalar:
 * current presets use `128` bytes for P-256 and `48` bytes for P-384.
 * `decapsulate()` returns the uncompressed shared point body `x || y` without the `0x04`
 * prefix, not the SEC 1 `x_P`-only primitive output, because current hybrid combiners hash
 * both coordinates.
 */
function nistCurveKem(curve: ECDSA, scalarLen: number, elemLen: number, nseed: number): TRet<KEM> {
  const Fn = curve.Point.Fn;
  if (!Fn) throw new Error('no Point.Fn');
  // Scan scalar-sized windows until one decodes to a nonzero scalar in `[1, n-1]`; if every
  // window is zero or out of range, fail instead of silently reducing modulo `n`.
  function rejectionSampling(seed: TArg<Uint8Array>): TRet<{
    secretKey: Uint8Array;
    publicKey: Uint8Array;
  }> {
    let sk: bigint;
    for (let start = 0, end = scalarLen; ; start = end, end += scalarLen) {
      if (end > seed.length) throw new Error('rejection sampling failed');
      sk = Fn.fromBytes(seed.subarray(start, end), true);
      if (Fn.isValidNot0(sk)) break;
    }
    const secretKey = Fn.toBytes(Fn.create(sk));
    const publicKey = curve.getPublicKey(secretKey, false);
    return { secretKey, publicKey } as TRet<{
      secretKey: Uint8Array;
      publicKey: Uint8Array;
    }>;
  }

  return {
    lengths: {
      secretKey: scalarLen,
      publicKey: elemLen,
      seed: nseed,
      msg: nseed,
      cipherText: elemLen,
    },
    keygen(seed: TArg<Uint8Array> = randomBytes(nseed)) {
      abytes(seed, nseed, 'seed');
      return rejectionSampling(seed);
    },
    getPublicKey(secretKey: TArg<Uint8Array>) {
      return curve.getPublicKey(secretKey, false) as TRet<Uint8Array>;
    },
    encapsulate(publicKey: TArg<Uint8Array>, rand: TArg<Uint8Array> = randomBytes(nseed)) {
      abytes(rand, nseed, 'rand');
      let ek: Uint8Array | undefined = undefined;
      try {
        ek = rejectionSampling(rand).secretKey;
        const sharedSecret = this.decapsulate(publicKey, ek);
        const cipherText = curve.getPublicKey(ek, false) as TRet<Uint8Array>;
        return { sharedSecret, cipherText };
      } finally {
        // Rejection-sampled NIST-curve ephemeral secret keys are temporary encapsulation state and
        // must be wiped even if peer-key validation or shared-secret derivation throws.
        if (ek) cleanBytes(ek);
      }
    },
    decapsulate(cipherText: TArg<Uint8Array>, secretKey: TArg<Uint8Array>) {
      const full = curve.getSharedSecret(secretKey, cipherText);
      return full.subarray(1) as TRet<Uint8Array>;
    },
  };
}

/**
 * Internal ML-KEM + NIST-curve combiner.
 * `nseed` controls only the curve-side rejection-sampling budget; it is expanded from the
 * 32-byte root seed and is not itself part of the exported secret-key length.
 * The domain-separation `label` is used only in the final `sha3_256` combiner, not in
 * `shake256(seed, { dkLen: 64 + nseed })`,
 * and the combiner hashes `ss0 || ss1 || ct1 || pk1 || label`.
 */
function concreteHybridKem(
  label: string,
  mlkem: TArg<KEM>,
  curve: ECDSA,
  nseed: number
): TRet<KEM> {
  const { secretKey: scalarLen, publicKeyUncompressed: elemLen } = curve.lengths;
  if (!scalarLen || !elemLen) throw new Error('wrong curve');
  const curveKem = nistCurveKem(curve, scalarLen, elemLen, nseed);
  const mlkemSeedLen = 64;
  const totalSeedLen = mlkemSeedLen + nseed;

  return combineKEMS(
    32,
    32,
    (seed: TArg<Uint8Array>): TRet<Uint8Array> => {
      abytes(seed, 32);
      const expanded = shake256(seed, { dkLen: totalSeedLen });
      const mlkemSeed = expanded.subarray(0, mlkemSeedLen);
      const curveSeed = expanded.subarray(mlkemSeedLen, totalSeedLen);
      return concatBytes(mlkemSeed, curveSeed) as TRet<Uint8Array>;
    },
    (pk: TArg<Uint8Array[]>, ct: TArg<Uint8Array[]>, ss: TArg<Uint8Array[]>) =>
      sha3_256(concatBytes(ss[0], ss[1], ct[1], pk[1], asciiToBytes(label))),
    mlkem,
    curveKem
  );
}

/** P-256 + ML-KEM-768 hybrid preset. */
export const ml_kem768_p256: TRet<KEM> = /* @__PURE__ */ (() =>
  concreteHybridKem('MLKEM768-P256', ml_kem768, p256, 128))();

/** P-384 + ML-KEM-1024 hybrid preset. */
export const ml_kem1024_p384: TRet<KEM> = /* @__PURE__ */ (() =>
  concreteHybridKem('MLKEM1024-P384', ml_kem1024, p384, 48))();

// Legacy aliases
/** Legacy alias for `ml_kem768_x25519`. */
export const XWing: TRet<KEM> = /* @__PURE__ */ (() => ml_kem768_x25519)();
/** Legacy alias for `ml_kem768_x25519`. */
export const MLKEM768X25519: TRet<KEM> = /* @__PURE__ */ (() => ml_kem768_x25519)();
/** Legacy alias for `ml_kem768_p256`. */
export const MLKEM768P256: TRet<KEM> = /* @__PURE__ */ (() => ml_kem768_p256)();
/** Legacy alias for `ml_kem1024_p384`. */
export const MLKEM1024P384: TRet<KEM> = /* @__PURE__ */ (() => ml_kem1024_p384)();
/** Legacy alias for `QSF_ml_kem768_p256`. */
export const QSFMLKEM768P256: TRet<KEM> = /* @__PURE__ */ (() => QSF_ml_kem768_p256)();
/** Legacy alias for `QSF_ml_kem1024_p384`. */
export const QSFMLKEM1024P384: TRet<KEM> = /* @__PURE__ */ (() => QSF_ml_kem1024_p384)();
/** Legacy alias for `KitchenSink_ml_kem768_x25519`. */
export const KitchenSinkMLKEM768X25519: TRet<KEM> = /* @__PURE__ */ (() =>
  KitchenSink_ml_kem768_x25519)();
