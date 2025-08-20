/**
 * ML-DSA: Module Lattice-based Digital Signature Algorithm from
 * [FIPS-204](https://csrc.nist.gov/pubs/fips/204/ipd). A.k.a. CRYSTALS-Dilithium.
 *
 * Has similar internals to ML-KEM, but their keys and params are different.
 * Check out [official site](https://www.pq-crystals.org/dilithium/index.shtml),
 * [repo](https://github.com/pq-crystals/dilithium).
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { abool } from '@noble/curves/utils.js';
import { shake256 } from '@noble/hashes/sha3.js';
import type { CHash } from '@noble/hashes/utils.js';
import { genCrystals, type XOF, XOF128, XOF256 } from './_crystals.ts';
import {
  abytes,
  type BytesCoderLen,
  checkHash,
  cleanBytes,
  type CryptoKeys,
  equalBytes,
  getMessage,
  getMessagePrehash,
  randomBytes,
  type Signer,
  type SigOpts,
  splitCoder,
  validateOpts,
  validateSigOpts,
  validateVerOpts,
  vecCoder,
  type VerOpts,
} from './utils.ts';

export type DSAInternalOpts = { externalMu?: boolean };
function validateInternalOpts(opts: DSAInternalOpts) {
  validateOpts(opts);
  if (opts.externalMu !== undefined) abool(opts.externalMu, 'opts.externalMu');
}

/** Signer API, containing internal methods */
export type DSAInternal = CryptoKeys & {
  lengths: Signer['lengths'];
  sign: (msg: Uint8Array, secretKey: Uint8Array, opts?: SigOpts & DSAInternalOpts) => Uint8Array;
  verify: (
    sig: Uint8Array,
    msg: Uint8Array,
    pubKey: Uint8Array,
    opts?: VerOpts & DSAInternalOpts
  ) => boolean;
};
export type DSA = Signer & { internal: DSAInternal };

// Constants
const N = 256;
// 2**23 − 2**13 + 1, 23 bits: multiply will be 46. We have enough precision in JS to avoid bigints
const Q = 8380417;
const ROOT_OF_UNITY = 1753;
// f = 256**−1 mod q, pow(256, -1, q) = 8347681 (python3)
const F = 8347681;
const D = 13;
// Dilithium is kinda parametrized over GAMMA2, but everything will break with any other value.
const GAMMA2_1 = Math.floor((Q - 1) / 88) | 0;
const GAMMA2_2 = Math.floor((Q - 1) / 32) | 0;

type XofGet = ReturnType<ReturnType<XOF>['get']>;

/** Various lattice params. */
export type DSAParam = {
  K: number;
  L: number;
  D: number;
  GAMMA1: number;
  GAMMA2: number;
  TAU: number;
  ETA: number;
  OMEGA: number;
};
/** Internal params for different versions of ML-DSA  */
// prettier-ignore
export const PARAMS: Record<string, DSAParam> = {
  2: { K: 4, L: 4, D, GAMMA1: 2 ** 17, GAMMA2: GAMMA2_1, TAU: 39, ETA: 2, OMEGA: 80 },
  3: { K: 6, L: 5, D, GAMMA1: 2 ** 19, GAMMA2: GAMMA2_2, TAU: 49, ETA: 4, OMEGA: 55 },
  5: { K: 8, L: 7, D, GAMMA1: 2 ** 19, GAMMA2: GAMMA2_2, TAU: 60, ETA: 2, OMEGA: 75 },
} as const;

// NOTE: there is a lot cases where negative numbers used (with smod instead of mod).
type Poly = Int32Array;
const newPoly = (n: number): Int32Array => new Int32Array(n);

const { mod, smod, NTT, bitsCoder } = genCrystals({
  N,
  Q,
  F,
  ROOT_OF_UNITY,
  newPoly,
  isKyber: false,
  brvBits: 8,
});

const id = <T>(n: T): T => n;
type IdNum = (n: number) => number;

const polyCoder = (d: number, compress: IdNum = id, verify: IdNum = id) =>
  bitsCoder(d, {
    encode: (i: number) => compress(verify(i)),
    decode: (i: number) => verify(compress(i)),
  });

const polyAdd = (a: Poly, b: Poly) => {
  for (let i = 0; i < a.length; i++) a[i] = mod(a[i] + b[i]);
  return a;
};
const polySub = (a: Poly, b: Poly): Poly => {
  for (let i = 0; i < a.length; i++) a[i] = mod(a[i] - b[i]);
  return a;
};

const polyShiftl = (p: Poly): Poly => {
  for (let i = 0; i < N; i++) p[i] <<= D;
  return p;
};

const polyChknorm = (p: Poly, B: number): boolean => {
  // Not very sure about this, but FIPS204 doesn't provide any function for that :(
  for (let i = 0; i < N; i++) if (Math.abs(smod(p[i])) >= B) return true;
  return false;
};

const MultiplyNTTs = (a: Poly, b: Poly): Poly => {
  // NOTE: we don't use montgomery reduction in code, since it requires 64 bit ints,
  // which is not available in JS. mod(a[i] * b[i]) is ok, since Q is 23 bit,
  // which means a[i] * b[i] is 46 bit, which is safe to use in JS. (number is 53 bits).
  // Barrett reduction is slower than mod :(
  const c = newPoly(N);
  for (let i = 0; i < a.length; i++) c[i] = mod(a[i] * b[i]);
  return c;
};

// Return poly in NTT representation
function RejNTTPoly(xof: XofGet) {
  // Samples a polynomial ∈ Tq.
  const r = newPoly(N);
  // NOTE: we can represent 3xu24 as 4xu32, but it doesn't improve perf :(
  for (let j = 0; j < N; ) {
    const b = xof();
    if (b.length % 3) throw new Error('RejNTTPoly: unaligned block');
    for (let i = 0; j < N && i <= b.length - 3; i += 3) {
      const t = (b[i + 0] | (b[i + 1] << 8) | (b[i + 2] << 16)) & 0x7fffff; // 3 bytes
      if (t < Q) r[j++] = t;
    }
  }
  return r;
}

type DilithiumOpts = {
  K: number;
  L: number;
  GAMMA1: number;
  GAMMA2: number;
  TAU: number;
  ETA: number;
  OMEGA: number;
  C_TILDE_BYTES: number;
  CRH_BYTES: number;
  TR_BYTES: number;
  XOF128: XOF;
  XOF256: XOF;
  securityLevel: number;
};

function getDilithium(opts: DilithiumOpts) {
  const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA } = opts;
  const { CRH_BYTES, TR_BYTES, C_TILDE_BYTES, XOF128, XOF256, securityLevel } = opts;

  if (![2, 4].includes(ETA)) throw new Error('Wrong ETA');
  if (![1 << 17, 1 << 19].includes(GAMMA1)) throw new Error('Wrong GAMMA1');
  if (![GAMMA2_1, GAMMA2_2].includes(GAMMA2)) throw new Error('Wrong GAMMA2');
  const BETA = TAU * ETA;

  const decompose = (r: number) => {
    // Decomposes r into (r1, r0) such that r ≡ r1(2γ2) + r0 mod q.
    const rPlus = mod(r);
    const r0 = smod(rPlus, 2 * GAMMA2) | 0;
    if (rPlus - r0 === Q - 1) return { r1: 0 | 0, r0: (r0 - 1) | 0 };
    const r1 = Math.floor((rPlus - r0) / (2 * GAMMA2)) | 0;
    return { r1, r0 }; // r1 = HighBits, r0 = LowBits
  };

  const HighBits = (r: number) => decompose(r).r1;
  const LowBits = (r: number) => decompose(r).r0;
  const MakeHint = (z: number, r: number) => {
    // Compute hint bit indicating whether adding z to r alters the high bits of r.

    // From dilithium code
    const res0 = z <= GAMMA2 || z > Q - GAMMA2 || (z === Q - GAMMA2 && r === 0) ? 0 : 1;
    // from FIPS204:
    // // const r1 = HighBits(r);
    // // const v1 = HighBits(r + z);
    // // const res1 = +(r1 !== v1);
    // But they return different results! However, decompose is same.
    // So, either there is a bug in Dilithium ref implementation or in FIPS204.
    // For now, lets use dilithium one, so test vectors can be passed.
    // See
    // https://github.com/GiacomoPope/dilithium-py?tab=readme-ov-file#optimising-decomposition-and-making-hints
    return res0;
  };

  const UseHint = (h: number, r: number) => {
    // Returns the high bits of r adjusted according to hint h
    const m = Math.floor((Q - 1) / (2 * GAMMA2));
    const { r1, r0 } = decompose(r);
    // 3: if h = 1 and r0 > 0 return (r1 + 1) mod m
    // 4: if h = 1 and r0 ≤ 0 return (r1 − 1) mod m
    if (h === 1) return r0 > 0 ? mod(r1 + 1, m) | 0 : mod(r1 - 1, m) | 0;
    return r1 | 0;
  };
  const Power2Round = (r: number) => {
    // Decomposes r into (r1, r0) such that r ≡ r1*(2**d) + r0 mod q.
    const rPlus = mod(r);
    const r0 = smod(rPlus, 2 ** D) | 0;
    return { r1: Math.floor((rPlus - r0) / 2 ** D) | 0, r0 };
  };

  const hintCoder: BytesCoderLen<Poly[] | false> = {
    bytesLen: OMEGA + K,
    encode: (h: Poly[] | false) => {
      if (h === false) throw new Error('hint.encode: hint is false'); // should never happen
      const res = new Uint8Array(OMEGA + K);
      for (let i = 0, k = 0; i < K; i++) {
        for (let j = 0; j < N; j++) if (h[i][j] !== 0) res[k++] = j;
        res[OMEGA + i] = k;
      }
      return res;
    },
    decode: (buf: Uint8Array) => {
      const h = [];
      let k = 0;
      for (let i = 0; i < K; i++) {
        const hi = newPoly(N);
        if (buf[OMEGA + i] < k || buf[OMEGA + i] > OMEGA) return false;
        for (let j = k; j < buf[OMEGA + i]; j++) {
          if (j > k && buf[j] <= buf[j - 1]) return false;
          hi[buf[j]] = 1;
        }
        k = buf[OMEGA + i];
        h.push(hi);
      }
      for (let j = k; j < OMEGA; j++) if (buf[j] !== 0) return false;
      return h;
    },
  };

  const ETACoder = polyCoder(
    ETA === 2 ? 3 : 4,
    (i: number) => ETA - i,
    (i: number) => {
      if (!(-ETA <= i && i <= ETA))
        throw new Error(`malformed key s1/s3 ${i} outside of ETA range [${-ETA}, ${ETA}]`);
      return i;
    }
  );
  const T0Coder = polyCoder(13, (i: number) => (1 << (D - 1)) - i);
  const T1Coder = polyCoder(10);
  // Requires smod. Need to fix!
  const ZCoder = polyCoder(GAMMA1 === 1 << 17 ? 18 : 20, (i: number) => smod(GAMMA1 - i));
  const W1Coder = polyCoder(GAMMA2 === GAMMA2_1 ? 6 : 4);
  const W1Vec = vecCoder(W1Coder, K);
  // Main structures
  const publicCoder = splitCoder('publicKey', 32, vecCoder(T1Coder, K));
  const secretCoder = splitCoder(
    'secretKey',
    32,
    32,
    TR_BYTES,
    vecCoder(ETACoder, L),
    vecCoder(ETACoder, K),
    vecCoder(T0Coder, K)
  );
  const sigCoder = splitCoder('signature', C_TILDE_BYTES, vecCoder(ZCoder, L), hintCoder);
  const CoefFromHalfByte =
    ETA === 2
      ? (n: number) => (n < 15 ? 2 - (n % 5) : false)
      : (n: number) => (n < 9 ? 4 - n : false);

  // Return poly in NTT representation
  function RejBoundedPoly(xof: XofGet) {
    // Samples an element a ∈ Rq with coeffcients in [−η, η] computed via rejection sampling from ρ.
    const r: Poly = newPoly(N);
    for (let j = 0; j < N; ) {
      const b = xof();
      for (let i = 0; j < N && i < b.length; i += 1) {
        // half byte. Should be superfast with vector instructions. But very slow with js :(
        const d1 = CoefFromHalfByte(b[i] & 0x0f);
        const d2 = CoefFromHalfByte((b[i] >> 4) & 0x0f);
        if (d1 !== false) r[j++] = d1;
        if (j < N && d2 !== false) r[j++] = d2;
      }
    }
    return r;
  }

  const SampleInBall = (seed: Uint8Array) => {
    // Samples a polynomial c ∈ Rq with coeffcients from {−1, 0, 1} and Hamming weight τ
    const pre = newPoly(N);
    const s = shake256.create({}).update(seed);
    const buf = new Uint8Array(shake256.blockLen);
    s.xofInto(buf);
    const masks = buf.slice(0, 8);
    for (let i = N - TAU, pos = 8, maskPos = 0, maskBit = 0; i < N; i++) {
      let b = i + 1;
      for (; b > i; ) {
        b = buf[pos++];
        if (pos < shake256.blockLen) continue;
        s.xofInto(buf);
        pos = 0;
      }
      pre[i] = pre[b];
      pre[b] = 1 - (((masks[maskPos] >> maskBit++) & 1) << 1);
      if (maskBit >= 8) {
        maskPos++;
        maskBit = 0;
      }
    }
    return pre;
  };

  const polyPowerRound = (p: Poly) => {
    const res0 = newPoly(N);
    const res1 = newPoly(N);
    for (let i = 0; i < p.length; i++) {
      const { r0, r1 } = Power2Round(p[i]);
      res0[i] = r0;
      res1[i] = r1;
    }
    return { r0: res0, r1: res1 };
  };
  const polyUseHint = (u: Poly, h: Poly): Poly => {
    for (let i = 0; i < N; i++) u[i] = UseHint(h[i], u[i]);
    return u;
  };
  const polyMakeHint = (a: Poly, b: Poly) => {
    const v = newPoly(N);
    let cnt = 0;
    for (let i = 0; i < N; i++) {
      const h = MakeHint(a[i], b[i]);
      v[i] = h;
      cnt += h;
    }
    return { v, cnt };
  };

  const signRandBytes = 32;
  const seedCoder = splitCoder('seed', 32, 64, 32);
  // API & argument positions are exactly as in FIPS204.
  const internal: DSAInternal = {
    info: { type: 'internal-ml-dsa' },
    lengths: {
      secretKey: secretCoder.bytesLen,
      publicKey: publicCoder.bytesLen,
      seed: 32,
      signature: sigCoder.bytesLen,
      signRand: signRandBytes,
    },
    keygen: (seed?: Uint8Array) => {
      // H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128) 2: ▷ expand seed
      const seedDst = new Uint8Array(32 + 2);
      const randSeed = seed === undefined;
      if (randSeed) seed = randomBytes(32);
      abytes(seed!, 32, 'seed');
      seedDst.set(seed!);
      if (randSeed) cleanBytes(seed!);
      seedDst[32] = K;
      seedDst[33] = L;
      const [rho, rhoPrime, K_] = seedCoder.decode(
        shake256(seedDst, { dkLen: seedCoder.bytesLen })
      );
      const xofPrime = XOF256(rhoPrime);
      const s1 = [];
      for (let i = 0; i < L; i++) s1.push(RejBoundedPoly(xofPrime.get(i & 0xff, (i >> 8) & 0xff)));
      const s2 = [];
      for (let i = L; i < L + K; i++)
        s2.push(RejBoundedPoly(xofPrime.get(i & 0xff, (i >> 8) & 0xff)));
      const s1Hat = s1.map((i) => NTT.encode(i.slice()));
      const t0 = [];
      const t1 = [];
      const xof = XOF128(rho);
      const t = newPoly(N);
      for (let i = 0; i < K; i++) {
        // t ← NTT−1(A*NTT(s1)) + s2
        cleanBytes(t); // don't-reallocate
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i)); // super slow!
          polyAdd(t, MultiplyNTTs(aij, s1Hat[j]));
        }
        NTT.decode(t);
        const { r0, r1 } = polyPowerRound(polyAdd(t, s2[i])); // (t1, t0) ← Power2Round(t, d)
        t0.push(r0);
        t1.push(r1);
      }
      const publicKey = publicCoder.encode([rho, t1]); // pk ← pkEncode(ρ, t1)
      const tr = shake256(publicKey, { dkLen: TR_BYTES }); // tr ← H(BytesToBits(pk), 512)
      const secretKey = secretCoder.encode([rho, K_, tr, s1, s2, t0]); // sk ← skEncode(ρ, K,tr, s1, s2, t0)
      xof.clean();
      xofPrime.clean();
      // STATS
      // Kyber512:  { calls: 4, xofs: 12 }, Kyber768: { calls: 9, xofs: 27 }, Kyber1024: { calls: 16, xofs: 48 }
      // DSA44:    { calls: 24, xofs: 24 }, DSA65:    { calls: 41, xofs: 41 }, DSA87:    { calls: 71, xofs: 71 }
      cleanBytes(rho, rhoPrime, K_, s1, s2, s1Hat, t, t0, t1, tr, seedDst);
      return { publicKey, secretKey };
    },
    getPublicKey: (secretKey: Uint8Array) => {
      const [rho, _K, _tr, s1, s2, _t0] = secretCoder.decode(secretKey); // (ρ, K,tr, s1, s2, t0) ← skDecode(sk)
      const xof = XOF128(rho);
      const s1Hat = s1.map((p) => NTT.encode(p.slice()));
      const t1: Poly[] = [];
      const tmp = newPoly(N);
      for (let i = 0; i < K; i++) {
        tmp.fill(0);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i)); // A_ij in NTT
          polyAdd(tmp, MultiplyNTTs(aij, s1Hat[j])); // += A_ij * s1_j
        }
        NTT.decode(tmp); // NTT⁻¹
        polyAdd(tmp, s2[i]); // t_i = A·s1 + s2
        const { r1 } = polyPowerRound(tmp); // r1 = t1, r0 ≈ t0
        t1.push(r1);
      }
      xof.clean();
      cleanBytes(tmp, s1Hat, _t0, s1, s2);
      return publicCoder.encode([rho, t1]);
    },
    // NOTE: random is optional.
    sign: (msg: Uint8Array, secretKey: Uint8Array, opts: SigOpts & DSAInternalOpts = {}) => {
      validateSigOpts(opts);
      validateInternalOpts(opts);
      let { extraEntropy: random, externalMu = false } = opts;
      // This part can be pre-cached per secretKey, but there is only minor performance improvement,
      // since we re-use a lot of variables to computation.
      const [rho, _K, tr, s1, s2, t0] = secretCoder.decode(secretKey); // (ρ, K,tr, s1, s2, t0) ← skDecode(sk)
      // Cache matrix to avoid re-compute later
      const A: Poly[][] = []; // A ← ExpandA(ρ)
      const xof = XOF128(rho);
      for (let i = 0; i < K; i++) {
        const pv = [];
        for (let j = 0; j < L; j++) pv.push(RejNTTPoly(xof.get(j, i)));
        A.push(pv);
      }
      xof.clean();
      for (let i = 0; i < L; i++) NTT.encode(s1[i]); // sˆ1 ← NTT(s1)
      for (let i = 0; i < K; i++) {
        NTT.encode(s2[i]); // sˆ2 ← NTT(s2)
        NTT.encode(t0[i]); // tˆ0 ← NTT(t0)
      }
      // This part is per msg
      const mu = externalMu
        ? msg
        : shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest(); // 6: µ ← H(tr||M, 512) ▷ Compute message representative µ

      // Compute private random seed
      const rnd =
        random === false
          ? new Uint8Array(32)
          : random === undefined
            ? randomBytes(signRandBytes)
            : random;
      abytes(rnd, 32, 'extraEntropy');
      const rhoprime = shake256
        .create({ dkLen: CRH_BYTES })
        .update(_K)
        .update(rnd)
        .update(mu)
        .digest(); // ρ′← H(K||rnd||µ, 512)

      abytes(rhoprime, CRH_BYTES);
      const x256 = XOF256(rhoprime, ZCoder.bytesLen);
      //  Rejection sampling loop
      main_loop: for (let kappa = 0; ; ) {
        const y = [];
        // y ← ExpandMask(ρ , κ)
        for (let i = 0; i < L; i++, kappa++)
          y.push(ZCoder.decode(x256.get(kappa & 0xff, kappa >> 8)()));
        const z = y.map((i) => NTT.encode(i.slice()));
        const w = [];
        for (let i = 0; i < K; i++) {
          // w ← NTT−1(A ◦ NTT(y))
          const wi = newPoly(N);
          for (let j = 0; j < L; j++) polyAdd(wi, MultiplyNTTs(A[i][j], z[j]));
          NTT.decode(wi);
          w.push(wi);
        }
        const w1 = w.map((j) => j.map(HighBits)); // w1 ← HighBits(w)
        // Commitment hash: c˜ ∈{0, 1 2λ } ← H(µ||w1Encode(w1), 2λ)
        const cTilde = shake256
          .create({ dkLen: C_TILDE_BYTES })
          .update(mu)
          .update(W1Vec.encode(w1))
          .digest();
        // Verifer’s challenge
        const cHat = NTT.encode(SampleInBall(cTilde)); // c ← SampleInBall(c˜1); cˆ ← NTT(c)
        // ⟨⟨cs1⟩⟩ ← NTT−1(cˆ◦ sˆ1)
        const cs1 = s1.map((i) => MultiplyNTTs(i, cHat));
        for (let i = 0; i < L; i++) {
          polyAdd(NTT.decode(cs1[i]), y[i]); // z ← y + ⟨⟨cs1⟩⟩
          if (polyChknorm(cs1[i], GAMMA1 - BETA)) continue main_loop; // ||z||∞ ≥ γ1 − β
        }
        // cs1 is now z (▷ Signer’s response)
        let cnt = 0;
        const h = [];
        for (let i = 0; i < K; i++) {
          const cs2 = NTT.decode(MultiplyNTTs(s2[i], cHat)); // ⟨⟨cs2⟩⟩ ← NTT−1(cˆ◦ sˆ2)
          const r0 = polySub(w[i], cs2).map(LowBits); // r0 ← LowBits(w − ⟨⟨cs2⟩⟩)
          if (polyChknorm(r0, GAMMA2 - BETA)) continue main_loop; // ||r0||∞ ≥ γ2 − β
          const ct0 = NTT.decode(MultiplyNTTs(t0[i], cHat)); // ⟨⟨ct0⟩⟩ ← NTT−1(cˆ◦ tˆ0)
          if (polyChknorm(ct0, GAMMA2)) continue main_loop;
          polyAdd(r0, ct0);
          // ▷ Signer’s hint
          const hint = polyMakeHint(r0, w1[i]); // h ← MakeHint(−⟨⟨ct0⟩⟩, w− ⟨⟨cs2⟩⟩ + ⟨⟨ct0⟩⟩)
          h.push(hint.v);
          cnt += hint.cnt;
        }
        if (cnt > OMEGA) continue; // the number of 1’s in h is greater than ω
        x256.clean();
        const res = sigCoder.encode([cTilde, cs1, h]); // σ ← sigEncode(c˜, z mod±q, h)
        // rho, _K, tr is subarray of secretKey, cannot clean.
        cleanBytes(cTilde, cs1, h, cHat, w1, w, z, y, rhoprime, mu, s1, s2, t0, ...A);
        return res;
      }
      // @ts-ignore
      throw new Error('Unreachable code path reached, report this error');
    },
    verify: (
      sig: Uint8Array,
      msg: Uint8Array,
      publicKey: Uint8Array,
      opts: DSAInternalOpts = {}
    ) => {
      validateInternalOpts(opts);
      const { externalMu = false } = opts;
      // ML-DSA.Verify(pk, M, σ): Verifes a signature σ for a message M.
      const [rho, t1] = publicCoder.decode(publicKey); // (ρ, t1) ← pkDecode(pk)
      const tr = shake256(publicKey, { dkLen: TR_BYTES }); // 6: tr ← H(BytesToBits(pk), 512)

      if (sig.length !== sigCoder.bytesLen) return false; // return false instead of exception
      const [cTilde, z, h] = sigCoder.decode(sig); // (c˜, z, h) ← sigDecode(σ), ▷ Signer’s commitment hash c ˜, response z and hint
      if (h === false) return false; // if h = ⊥ then return false
      for (let i = 0; i < L; i++) if (polyChknorm(z[i], GAMMA1 - BETA)) return false;
      const mu = externalMu
        ? msg
        : shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest(); // 7: µ ← H(tr||M, 512)
      // Compute verifer’s challenge from c˜
      const c = NTT.encode(SampleInBall(cTilde)); // c ← SampleInBall(c˜1)
      const zNtt = z.map((i) => i.slice()); // zNtt = NTT(z)
      for (let i = 0; i < L; i++) NTT.encode(zNtt[i]);
      const wTick1 = [];
      const xof = XOF128(rho);
      for (let i = 0; i < K; i++) {
        const ct12d = MultiplyNTTs(NTT.encode(polyShiftl(t1[i])), c); //c * t1 * (2**d)
        const Az = newPoly(N); // // A * z
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i)); // A[i][j] inplace
          polyAdd(Az, MultiplyNTTs(aij, zNtt[j]));
        }
        // wApprox = A*z - c*t1 * (2**d)
        const wApprox = NTT.decode(polySub(Az, ct12d));
        // Reconstruction of signer’s commitment
        wTick1.push(polyUseHint(wApprox, h[i])); // w ′ ← UseHint(h, w'approx )
      }
      xof.clean();
      // c˜′← H (µ||w1Encode(w′1), 2λ),  Hash it; this should match c˜
      const c2 = shake256
        .create({ dkLen: C_TILDE_BYTES })
        .update(mu)
        .update(W1Vec.encode(wTick1))
        .digest();
      // Additional checks in FIPS-204:
      // [[ ||z||∞ < γ1 − β ]] and [[c ˜ = c˜′]] and [[number of 1’s in h is ≤ ω]]
      for (const t of h) {
        const sum = t.reduce((acc, i) => acc + i, 0);
        if (!(sum <= OMEGA)) return false;
      }
      for (const t of z) if (polyChknorm(t, GAMMA1 - BETA)) return false;
      return equalBytes(cTilde, c2);
    },
  };
  return {
    info: { type: 'ml-dsa' },
    internal,
    securityLevel: securityLevel,
    keygen: internal.keygen,
    lengths: internal.lengths,
    getPublicKey: internal.getPublicKey,
    sign: (msg: Uint8Array, secretKey: Uint8Array, opts: SigOpts = {}) => {
      validateSigOpts(opts);
      const M = getMessage(msg, opts.context);
      const res = internal.sign(M, secretKey, opts);
      cleanBytes(M);
      return res;
    },
    verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, opts: VerOpts = {}) => {
      validateVerOpts(opts);
      return internal.verify(sig, getMessage(msg, opts.context), publicKey);
    },
    prehash: (hash: CHash) => {
      checkHash(hash, securityLevel);
      return {
        info: { type: 'hashml-dsa' },
        securityLevel: securityLevel,
        lengths: internal.lengths,
        keygen: internal.keygen,
        getPublicKey: internal.getPublicKey,
        sign: (msg: Uint8Array, secretKey: Uint8Array, opts: SigOpts = {}) => {
          validateSigOpts(opts);
          const M = getMessagePrehash(hash, msg, opts.context);
          const res = internal.sign(M, secretKey, opts);
          cleanBytes(M);
          return res;
        },
        verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, opts: VerOpts = {}) => {
          validateVerOpts(opts);
          return internal.verify(sig, getMessagePrehash(hash, msg, opts.context), publicKey);
        },
      };
    },
  };
}

/** ML-DSA-44 for 128-bit security level. Not recommended after 2030, as per ASD. */
export const ml_dsa44: DSA = /* @__PURE__ */ getDilithium({
  ...PARAMS[2],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 32,
  XOF128,
  XOF256,
  securityLevel: 128,
});

/** ML-DSA-65 for 192-bit security level. Not recommended after 2030, as per ASD. */
export const ml_dsa65: DSA = /* @__PURE__ */ getDilithium({
  ...PARAMS[3],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 48,
  XOF128,
  XOF256,
  securityLevel: 192,
});

/** ML-DSA-87 for 256-bit security level. OK after 2030, as per ASD. */
export const ml_dsa87: DSA = /* @__PURE__ */ getDilithium({
  ...PARAMS[5],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 64,
  XOF128,
  XOF256,
  securityLevel: 256,
});
