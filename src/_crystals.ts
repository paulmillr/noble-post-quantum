/**
 * Internal methods for lattice-based ML-KEM and ML-DSA.
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { FFTCore, reverseBits } from '@noble/curves/abstract/fft.js';
import { shake128, shake256 } from '@noble/hashes/sha3.js';
import type { TypedArray } from '@noble/hashes/utils.js';
import { type BytesCoderLen, cleanBytes, type Coder, getMask } from './utils.ts';

/** Extendable-output reader used by the CRYSTALS implementations. */
export type XOF = (
  seed: Uint8Array,
  blockLen?: number
) => {
  /**
   * Read diagnostic counters for the current XOF session.
   * @returns Current call and XOF block counters.
   */
  stats: () => { calls: number; xofs: number };
  /**
   * Select one `(x, y)` coordinate pair and get a block reader for it.
   * @param x - First matrix coordinate.
   * @param y - Second matrix coordinate.
   * @returns Lazy block reader for that coordinate pair.
   */
  get: (x: number, y: number) => () => Uint8Array; // return block aligned to blockLen and 3
  /** Wipe any buffered state once the reader is no longer needed. */
  clean: () => void;
};

/** CRYSTALS (ml-kem, ml-dsa) options */
/** Shared polynomial and NTT parameters for CRYSTALS algorithms. */
export type CrystalOpts<T extends TypedArray> = {
  /**
   * Allocate one zeroed polynomial/vector container.
   * @param n - Number of coefficients to allocate.
   * @returns Fresh typed container.
   */
  newPoly: TypedCons<T>;
  /** Polynomial size, typically `256`. */
  N: number;
  /** Prime modulus used for all coefficient arithmetic. */
  Q: number;
  /** Inverse transform normalization factor (`256**-1 mod q` for Dilithium, `128**-1 mod q` for Kyber). */
  F: number;
  /** Principal root of unity for the transform domain. */
  ROOT_OF_UNITY: number;
  /** Number of bits used for bit-reversal ordering. */
  brvBits: number;
  /** `true` for Kyber/ML-KEM mode, `false` for Dilithium/ML-DSA mode. */
  isKyber: boolean;
};

/** Constructor function for typed polynomial containers. */
export type TypedCons<T extends TypedArray> = (n: number) => T;

/**
 * Creates shared modular arithmetic, NTT, and packing helpers for CRYSTALS schemes.
 * @param opts - Polynomial and transform parameters. See {@link CrystalOpts}.
 * @returns CRYSTALS arithmetic and encoding helpers.
 * @example
 * Create shared modular arithmetic and NTT helpers for a CRYSTALS parameter set.
 * ```ts
 * const crystals = genCrystals({
 *   newPoly: (n) => new Uint16Array(n),
 *   N: 256,
 *   Q: 3329,
 *   F: 3303,
 *   ROOT_OF_UNITY: 17,
 *   brvBits: 7,
 *   isKyber: true,
 * });
 * const reduced = crystals.mod(-1);
 * ```
 */
export const genCrystals = <T extends TypedArray>(
  opts: CrystalOpts<T>
): {
  mod: (a: number, modulo?: number) => number;
  smod: (a: number, modulo?: number) => number;
  nttZetas: T;
  NTT: {
    encode: (r: T) => T;
    decode: (r: T) => T;
  };
  bitsCoder: (d: number, c: Coder<number, number>) => BytesCoderLen<T>;
} => {
  // isKyber: true means Kyber, false means Dilithium
  const { newPoly, N, Q, F, ROOT_OF_UNITY, brvBits, isKyber } = opts;
  const mod = (a: number, modulo = Q): number => {
    const result = a % modulo | 0;
    return (result >= 0 ? result | 0 : (modulo + result) | 0) | 0;
  };
  // -(Q-1)/2 < a <= (Q-1)/2
  const smod = (a: number, modulo = Q): number => {
    const r = mod(a, modulo) | 0;
    return (r > modulo >> 1 ? (r - modulo) | 0 : r) | 0;
  };
  // Generate zettas (different from roots of unity, negacyclic uses phi, where acyclic uses omega)
  function getZettas() {
    const out = newPoly(N);
    for (let i = 0; i < N; i++) {
      const b = reverseBits(i, brvBits);
      const p = BigInt(ROOT_OF_UNITY) ** BigInt(b) % BigInt(Q);
      out[i] = Number(p) | 0;
    }
    return out;
  }
  const nttZetas = getZettas();

  // Number-Theoretic Transform
  // Explained: https://electricdusk.com/ntt.html

  // Kyber has slightly different params, since there is no 512th primitive root of unity mod q,
  // only 256th primitive root of unity mod. Which also complicates MultiplyNTT.

  const field = {
    add: (a: number, b: number) => mod((a | 0) + (b | 0)) | 0,
    sub: (a: number, b: number) => mod((a | 0) - (b | 0)) | 0,
    mul: (a: number, b: number) => mod((a | 0) * (b | 0)) | 0,
    inv: (_a: number) => {
      throw new Error('not implemented');
    },
  };
  const nttOpts = {
    N,
    roots: nttZetas as any,
    invertButterflies: true,
    skipStages: isKyber ? 1 : 0,
    brp: false,
  };
  const dif = FFTCore(field, { dit: false, ...nttOpts });
  const dit = FFTCore(field, { dit: true, ...nttOpts });
  const NTT = {
    encode: (r: T): T => {
      return dif(r) as any;
    },
    decode: (r: T): T => {
      dit(r as any);
      // kyber uses 128 here, because brv && stuff
      for (let i = 0; i < r.length; i++) r[i] = mod(F * r[i]);
      return r;
    },
  };
  // Encode polynominal as bits
  const bitsCoder = (d: number, c: Coder<number, number>): BytesCoderLen<T> => {
    const mask = getMask(d);
    const bytesLen = d * (N / 8);
    return {
      bytesLen,
      encode: (poly: T): Uint8Array => {
        const r = new Uint8Array(bytesLen);
        for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < poly.length; i++) {
          buf |= (c.encode(poly[i]) & mask) << bufLen;
          bufLen += d;
          for (; bufLen >= 8; bufLen -= 8, buf >>= 8) r[pos++] = buf & getMask(bufLen);
        }
        return r;
      },
      decode: (bytes: Uint8Array): T => {
        const r = newPoly(N);
        for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < bytes.length; i++) {
          buf |= bytes[i] << bufLen;
          bufLen += 8;
          for (; bufLen >= d; bufLen -= d, buf >>= d) r[pos++] = c.decode(buf & mask);
        }
        return r;
      },
    };
  };

  return { mod, smod, nttZetas, NTT, bitsCoder };
};

const createXofShake =
  (shake: typeof shake128): XOF =>
  (seed: Uint8Array, blockLen?: number) => {
    if (!blockLen) blockLen = shake.blockLen;
    // Optimizations that won't mater:
    // - cached seed update (two .update(), on start and on the end)
    // - another cache which cloned into working copy

    // Faster than multiple updates, since seed less than blockLen
    const _seed = new Uint8Array(seed.length + 2);
    _seed.set(seed);
    const seedLen = seed.length;
    const buf = new Uint8Array(blockLen); // == shake128.blockLen
    let h = shake.create({});
    let calls = 0;
    let xofs = 0;
    return {
      stats: () => ({ calls, xofs }),
      get: (x: number, y: number) => {
        _seed[seedLen + 0] = x;
        _seed[seedLen + 1] = y;
        h.destroy();
        h = shake.create({}).update(_seed);
        calls++;
        return () => {
          xofs++;
          return h.xofInto(buf);
        };
      },
      clean: () => {
        h.destroy();
        cleanBytes(buf, _seed);
      },
    };
  };

/**
 * SHAKE128-based extendable-output reader factory used by ML-KEM.
 * @param seed - Seed bytes for the reader.
 * @param blockLen - Optional output block length.
 * @returns Stateful XOF reader.
 * @example
 * Build the ML-KEM SHAKE128 matrix expander and read one block.
 * ```ts
 * import { randomBytes } from '@noble/post-quantum/utils.js';
 * import { XOF128 } from '@noble/post-quantum/_crystals.js';
 * const reader = XOF128(randomBytes(32));
 * const block = reader.get(0, 0)();
 * ```
 */
export const XOF128: XOF = /* @__PURE__ */ createXofShake(shake128);
/**
 * SHAKE256-based extendable-output reader factory used by ML-DSA.
 * @param seed - Seed bytes for the reader.
 * @param blockLen - Optional output block length.
 * @returns Stateful XOF reader.
 * @example
 * Build the ML-DSA SHAKE256 coefficient expander and read one block.
 * ```ts
 * import { randomBytes } from '@noble/post-quantum/utils.js';
 * import { XOF256 } from '@noble/post-quantum/_crystals.js';
 * const reader = XOF256(randomBytes(32));
 * const block = reader.get(0, 0)();
 * ```
 */
export const XOF256: XOF = /* @__PURE__ */ createXofShake(shake256);
