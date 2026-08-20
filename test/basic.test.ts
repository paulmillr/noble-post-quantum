import {
  keccak_512,
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  shake128,
  shake128_32,
  shake256,
} from '@noble/hashes/sha3.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, notDeepStrictEqual, throws } from 'node:assert';
import { genCrystals } from '../src/_crystals.ts';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';
import { ml_kem1024, ml_kem512, ml_kem768 } from '../src/ml-kem.ts';
import { slh_dsa_sha2_128f, slh_dsa_shake_128f } from '../src/slh-dsa.ts';
import {
  copyBytes,
  getMask,
  getMessage,
  getMessagePrehash,
  randomBytes,
  SIG_OPT_KEYS,
  validateOpts,
  validateSigOpts,
  validateVerOpts,
  VER_OPT_KEYS,
  vecCoder,
} from '../src/utils.ts';

describe('Basic', () => {
  it('utils validator constructors', () => {
    throws(() => validateOpts(new Uint8Array([1]) as any), TypeError);
    throws(() => validateVerOpts(new Uint8Array([1]) as any), TypeError);
    throws(() => validateSigOpts(new Uint8Array([1]) as any), TypeError);
    throws(() => validateOpts([] as any), TypeError);
    throws(() => validateVerOpts([] as any), TypeError);
    throws(() => validateSigOpts([] as any), TypeError);
    throws(() => copyBytes('ab' as any), TypeError);
    throws(() => copyBytes([257, -1, 2.9] as any), TypeError);
    throws(() => copyBytes(new Uint16Array([0x0102, 0x0304]) as any), TypeError);
    throws(() => copyBytes(new DataView(new ArrayBuffer(4)) as any), TypeError);
    const c = vecCoder(
      {
        bytesLen: 1,
        encode: (n: number) => Uint8Array.of(n),
        decode: (b: Uint8Array) => b[0] || 0,
      },
      2
    );
    throws(() => c.encode([1]), RangeError);
    throws(() => getMessage(new Uint8Array([1]), new Uint8Array(256)), RangeError);
    throws(() => getMessagePrehash(sha3_256, new Uint8Array([1]), new Uint8Array(256)), RangeError);
  });
  it('getMask wide 32-bit edges', () => {
    eql(getMask(31), 0x7fffffff);
    eql(getMask(32), 0xffffffff);
    const crystals = genCrystals({
      newPoly: (n: number) => new Uint32Array(n),
      N: 256,
      Q: 3329,
      F: 3303,
      ROOT_OF_UNITY: 17,
      brvBits: 7,
      isKyber: true,
    });
    throws(
      () =>
        crystals.bitsCoder(27, {
          encode: (value: number) => value,
          decode: (value: number) => value,
        }),
      /expected <= 32/
    );
  });
  describe('Immutability', () => {
    it('ML-KEM', () => {
      // keygen
      const seed = randomBytes(64);
      const seedCopy = Uint8Array.from(seed);
      const keys = ml_kem512.keygen(seed);
      eql(seed, seedCopy);
      const secretCopy = Uint8Array.from(keys.secretKey);
      eql(ml_kem512.getPublicKey(keys.secretKey), keys.publicKey);
      eql(keys.secretKey, secretCopy);

      // encapsulate
      const publicKey = Uint8Array.from(keys.publicKey);
      const msg = randomBytes(32);
      const msgCopy = Uint8Array.from(msg);
      const enc = ml_kem512.encapsulate(publicKey, msg);
      eql(publicKey, keys.publicKey);
      eql(msg, msgCopy);
      // decapsulate
      const cipherText = Uint8Array.from(enc.cipherText);
      const secretKey = Uint8Array.from(keys.secretKey);
      const dec = ml_kem512.decapsulate(cipherText, secretKey);
      eql(cipherText, enc.cipherText);
      eql(secretKey, keys.secretKey);
    });
    it('ML-DSA', () => {
      // keygen
      const seed = randomBytes(32);
      const seedCopy = Uint8Array.from(seed);
      const keys = ml_dsa44.keygen(seed);
      eql(seed, seedCopy);
      const secretCopy = Uint8Array.from(keys.secretKey);
      eql(ml_dsa44.getPublicKey(keys.secretKey), keys.publicKey);
      eql(keys.secretKey, secretCopy);
      // sign
      const secretKey = Uint8Array.from(keys.secretKey);
      const msg = randomBytes(32);
      const msgCopy = Uint8Array.from(msg);
      const random = randomBytes(32);
      const randomCopy = Uint8Array.from(random);
      const sig = ml_dsa44.sign(msg, secretKey, { extraEntropy: random });
      eql(secretKey, keys.secretKey);
      eql(msg, msgCopy);
      eql(random, randomCopy);
      // verify
      const sigCopy = Uint8Array.from(sig);
      const publicKey = Uint8Array.from(keys.publicKey);
      ml_dsa44.verify(sig, msg, publicKey);
      eql(sig, sigCopy);
      eql(publicKey, keys.publicKey);
      eql(msg, msgCopy);
    });
    it('ML-DSA internal externalMu', () => {
      const cases = { ml_dsa44, ml_dsa65, ml_dsa87 };
      for (const mldsa of Object.values(cases)) {
        const keys = mldsa.keygen();
        const secretKey = Uint8Array.from(keys.secretKey);
        const secretCopy = Uint8Array.from(secretKey);
        const publicKey = Uint8Array.from(keys.publicKey);
        const publicCopy = Uint8Array.from(publicKey);
        const mu = Uint8Array.from({ length: 64 }, (_, i) => i + 1);
        const muCopy = Uint8Array.from(mu);
        const random = randomBytes(mldsa.lengths.signRand);
        const randomCopy = Uint8Array.from(random);
        const sig = mldsa.internal.sign(mu, secretKey, {
          externalMu: true,
          extraEntropy: random,
        });
        eql(secretKey, secretCopy);
        eql(mu, muCopy);
        eql(random, randomCopy);
        const sigCopy = Uint8Array.from(sig);
        eql(mldsa.internal.verify(sig, mu, publicKey, { externalMu: true }), true);
        eql(sig, sigCopy);
        eql(mu, muCopy);
        eql(publicKey, publicCopy);
      }
    });
    it('SLH-DSA', () => {
      // keygen
      const seed = randomBytes(48);
      const seedCopy = Uint8Array.from(seed);
      const keys = slh_dsa_sha2_128f.keygen(seed);
      eql(seed, seedCopy);
      const secretCopy = Uint8Array.from(keys.secretKey);
      eql(slh_dsa_sha2_128f.getPublicKey(keys.secretKey), keys.publicKey);
      eql(keys.secretKey, secretCopy);

      // sign
      const secretKey = Uint8Array.from(keys.secretKey);
      const msg = randomBytes(32);
      const msgCopy = Uint8Array.from(msg);
      const random = randomBytes(slh_dsa_sha2_128f.lengths.signRand);
      const randomCopy = Uint8Array.from(random);
      const sig = slh_dsa_sha2_128f.sign(msg, secretKey, { extraEntropy: random });
      eql(secretKey, keys.secretKey);
      eql(msg, msgCopy);
      eql(random, randomCopy);
      // verify
      const sigCopy = Uint8Array.from(sig);
      const publicKey = Uint8Array.from(keys.publicKey);
      slh_dsa_sha2_128f.verify(sig, msg, publicKey);
      eql(publicKey, keys.publicKey);
      eql(sig, sigCopy);
      eql(msg, msgCopy);
    });
  });
  it('ML-KEM rejects public keys with coeffs above q - 1', () => {
    const msg = randomBytes(32);
    const cases = [
      ['ml_kem512', ml_kem512, 64],
      ['ml_kem768', ml_kem768, 64],
      ['ml_kem1024', ml_kem1024, 64],
    ] as const;
    for (const [_name, kem, seedLen] of cases) {
      const seed = Uint8Array.from({ length: seedLen }, (_, i) => i + 1);
      const { publicKey } = kem.keygen(seed);
      const bad = Uint8Array.from(publicKey);
      bad[0] = 0xff;
      bad[1] = (bad[1] & 0xf0) | 0x0f;
      throws(() => kem.encapsulate(bad, msg), /wrong publicKey modulus/);
    }
  });
  it('ML-KEM modulus check boundary: q-1 valid, q invalid', () => {
    const msg = randomBytes(32);
    for (const kem of [ml_kem512, ml_kem768, ml_kem1024]) {
      const { publicKey } = kem.keygen();
      // First 12-bit little-endian coefficient := q (3329 = 0xd01), smallest invalid value
      const bad = Uint8Array.from(publicKey);
      bad[0] = 0x01;
      bad[1] = (bad[1] & 0xf0) | 0x0d;
      throws(() => kem.encapsulate(bad, msg), /wrong publicKey modulus/);
      // First coefficient := q-1 (3328 = 0xd00), largest valid value: must be accepted
      const ok = Uint8Array.from(publicKey);
      ok[0] = 0x00;
      ok[1] = (ok[1] & 0xf0) | 0x0d;
      kem.encapsulate(ok, msg);
    }
  });
  it('ML-KEM decapsulate validates secretKey hash, ignores z corruption', () => {
    for (const kem of [ml_kem512, ml_kem768, ml_kem1024]) {
      const { publicKey, secretKey } = kem.keygen();
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey);
      // Corrupt stored H(ek) at dk[768k+32 .. 768k+64]: input check must fail
      const badH = Uint8Array.from(secretKey);
      badH[secretKey.length - 96 + 32] ^= 1;
      throws(() => kem.decapsulate(cipherText, badH), /hash check failed/);
      // Corrupting z (last 32 bytes) must not affect valid decapsulation:
      // z is only used on the implicit-rejection path
      const badZ = Uint8Array.from(secretKey);
      badZ[secretKey.length - 1] ^= 1;
      eql(kem.decapsulate(cipherText, badZ), sharedSecret);
    }
  });
  it('ML-KEM prepared public key matches one-shot API', () => {
    for (const kem of [ml_kem512, ml_kem768, ml_kem1024]) {
      const { publicKey, secretKey } = kem.keygen();
      const prepared = kem.prepare(publicKey);
      eql(prepared.publicKey, publicKey);
      // encapsulate: same ciphertext + shared secret for the same msg
      const msg = randomBytes(32);
      const a = kem.encapsulate(publicKey, msg);
      const b = prepared.encapsulate(msg);
      eql(b.cipherText, a.cipherText);
      eql(b.sharedSecret, a.sharedSecret);
      // decapsulate: valid and implicit-rejection paths agree with the one-shot API
      eql(prepared.decapsulate(a.cipherText, secretKey), a.sharedSecret);
      const bad = Uint8Array.from(a.cipherText);
      bad[0] ^= 1;
      eql(prepared.decapsulate(bad, secretKey), kem.decapsulate(bad, secretKey));
      // secretKey from a different keypair is rejected
      const other = kem.keygen();
      throws(() => prepared.decapsulate(a.cipherText, other.secretKey), /does not match/);
      // malformed publicKey is rejected at prepare() time
      const badPk = Uint8Array.from(publicKey);
      badPk[0] = 0xff;
      badPk[1] |= 0x0f;
      throws(() => kem.prepare(badPk), /wrong publicKey modulus/);
      // prepared key is detached: mutating the source publicKey has no effect
      const pkCopy = Uint8Array.from(publicKey);
      publicKey.fill(0);
      eql(prepared.encapsulate(msg).cipherText, a.cipherText);
      publicKey.set(pkCopy);
    }
  });
  it('ML-KEM implicit rejection returns J(z || cipherText)', () => {
    for (const kem of [ml_kem512, ml_kem768, ml_kem1024]) {
      const seed = randomBytes(64);
      const { publicKey, secretKey } = kem.keygen(seed);
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey);
      eql(kem.decapsulate(cipherText, secretKey), sharedSecret);
      // Tampered ciphertext: no throw, and K̄ = J(z ‖ c) = SHAKE256(z || c, 32), z = seed[32:64]
      const bad = Uint8Array.from(cipherText);
      bad[0] ^= 1;
      const rejected = kem.decapsulate(bad, secretKey);
      notDeepStrictEqual(rejected, sharedSecret);
      const expected = shake256
        .create({ dkLen: 32 })
        .update(seed.subarray(32))
        .update(bad)
        .digest();
      eql(rejected, expected);
      // Implicit rejection is deterministic
      eql(kem.decapsulate(bad, secretKey), rejected);
    }
  });
  it('ML-DSA externalMu requires 64-byte mu', () => {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    const mu = Uint8Array.from({ length: 64 }, (_, i) => i);
    const sig = ml_dsa65.internal.sign(mu, secretKey, { externalMu: true, extraEntropy: false });
    eql(ml_dsa65.internal.verify(sig, mu, publicKey, { externalMu: true }), true);
    for (const bad of [new Uint8Array(0), new Uint8Array(63), new Uint8Array(65)]) {
      throws(() =>
        ml_dsa65.internal.sign(bad, secretKey, { externalMu: true, extraEntropy: false })
      );
      throws(() => ml_dsa65.internal.verify(sig, bad, publicKey, { externalMu: true }));
    }
  });
  it('ML-DSA prepares and cleans entropy before secret expansion', () => {
    let calls = 0;
    let generated: Uint8Array | undefined;
    const getRandomValues = globalThis.crypto.getRandomValues;
    globalThis.crypto.getRandomValues = ((bytes: Uint8Array) => {
      calls++;
      generated = bytes;
      return bytes.fill(0xa5);
    }) as typeof globalThis.crypto.getRandomValues;
    try {
      throws(() => ml_dsa44.internal.sign(Uint8Array.of(1), new Uint8Array()), /secretKey/);
      // RNG must run before secret decoding, but its output must not survive a decode failure.
      eql({ calls, generated }, { calls: 1, generated: new Uint8Array(32) });
      const badKey = new Uint8Array(ml_dsa44.lengths.secretKey);
      // First packed eta coefficient: 7 decodes outside ML-DSA-44's [-2, 2] range.
      badKey[32 + 32 + 64] = 7;
      throws(() => ml_dsa44.internal.sign(Uint8Array.of(1), badKey), /malformed key/);
      eql({ calls, generated }, { calls: 2, generated: new Uint8Array(32) });
      const callerEntropy = new Uint8Array(32).fill(0x5a);
      throws(
        () =>
          ml_dsa44.internal.sign(Uint8Array.of(1), badKey, {
            extraEntropy: callerEntropy,
          }),
        /malformed key/
      );
      eql({ calls, callerEntropy }, { calls: 2, callerEntropy: new Uint8Array(32).fill(0x5a) });
      globalThis.crypto.getRandomValues = (() => {
        throw new Error('rng failed');
      }) as typeof globalThis.crypto.getRandomValues;
      // An RNG failure must win before malformed secret material is decoded or expanded.
      throws(() => ml_dsa44.internal.sign(Uint8Array.of(1), new Uint8Array()), /rng failed/);
      throws(
        () =>
          ml_dsa44.internal.sign(Uint8Array.of(1), new Uint8Array(), {
            extraEntropy: new Uint8Array(),
          }),
        /extraEntropy/
      );
    } finally {
      globalThis.crypto.getRandomValues = getRandomValues;
    }
  });
  it('ML-DSA verify returns false on malformed hint encoding', () => {
    // [signer, OMEGA, K] per FIPS 204 Table 1; hint block is the trailing OMEGA+K bytes.
    const cases = [
      [ml_dsa44, 80, 4],
      [ml_dsa65, 55, 6],
      [ml_dsa87, 75, 8],
    ] as const;
    const msg = new Uint8Array([1, 2, 3]);
    for (const [dsa, OMEGA, K] of cases) {
      const { publicKey, secretKey } = dsa.keygen();
      const sig = dsa.sign(msg, secretKey, { extraEntropy: false });
      eql(dsa.verify(sig, msg, publicKey), true);
      // Hint counter above OMEGA: sigDecode must return ⊥ → false, not throw
      const badCounter = Uint8Array.from(sig);
      badCounter[badCounter.length - 1] = OMEGA + 1;
      eql(dsa.verify(badCounter, msg, publicKey), false);
      // Non-zero hint padding byte (if padding exists for this signature): non-canonical → false
      const hintStart = sig.length - (OMEGA + K);
      const totalHints = sig[sig.length - 1];
      if (totalHints < OMEGA) {
        const badPad = Uint8Array.from(sig);
        badPad[hintStart + OMEGA - 1] = 1; // padding region [totalHints, OMEGA) must be zero
        eql(dsa.verify(badPad, msg, publicKey), false);
      }
      // Wrong length → false, not throw
      eql(dsa.verify(sig.subarray(0, sig.length - 1), msg, publicKey), false);
    }
  });
  it('SLH-DSA verify returns false on wrong-length signature', () => {
    // FIPS 205 Algorithm 20 step 1 and ml-dsa behavior: malformed signature *length* is a
    // verification failure (false), not a thrown type error.
    for (const slh of [slh_dsa_sha2_128f, slh_dsa_shake_128f]) {
      const { publicKey, secretKey } = slh.keygen();
      const msg = new Uint8Array([1, 2, 3]);
      const sig = slh.sign(msg, secretKey);
      eql(slh.verify(sig, msg, publicKey), true);
      eql(slh.verify(sig.subarray(0, sig.length - 1), msg, publicKey), false);
      const longer = new Uint8Array(sig.length + 1);
      longer.set(sig);
      eql(slh.verify(longer, msg, publicKey), false);
      eql(slh.verify(new Uint8Array(0), msg, publicKey), false);
      eql(slh.internal.verify(new Uint8Array(0), msg, publicKey), false);
      // Wrong-length byte encodings are verification failures; a non-byte API argument is misuse.
      throws(() => slh.verify(new Uint16Array() as any, msg, publicKey), TypeError);
      throws(() => slh.internal.verify(new Uint16Array() as any, msg, publicKey), TypeError);
    }
  });
  it('Hash compatibility', () => {
    const keys44 = ml_dsa44.keygen();
    const keys65 = ml_dsa65.keygen();
    const keys87 = ml_dsa87.keygen();
    const msg = new Uint8Array([1, 2, 3, 4]);
    throws(() => ml_dsa44.prehash(sha3_224).sign(msg, keys44.secretKey));
    ml_dsa44.prehash(sha3_256).sign(msg, keys44.secretKey);
    ml_dsa44.prehash(shake128_32).sign(msg, keys44.secretKey);
    throws(() => ml_dsa44.prehash(shake128).sign(msg, keys44.secretKey)); // small output
    throws(() => ml_dsa44.prehash(keccak_512).sign(msg, keys44.secretKey)); // non nist hash
    throws(() => ml_dsa65.prehash(sha3_256).sign(msg, keys65.secretKey));
    ml_dsa65.prehash(sha3_384).sign(msg, keys65.secretKey);
    throws(() => ml_dsa87.prehash(sha3_384).sign(msg, keys87.secretKey));
    ml_dsa87.prehash(sha3_512).sign(msg, keys87.secretKey);
  });
  describe('sign/ver opts', () => {
    for (const [k, v] of Object.entries({
      ml_dsa65,
      slh_dsa_sha2_128f,
      ml_dsa65_sha3_384: ml_dsa65.prehash(sha3_384),
      slh_dsa_sha2_128f_sha3_384: slh_dsa_sha2_128f.prehash(sha3_384),
    })) {
      it(k, () => {
        const keys = v.keygen();
        const msg = new Uint8Array();
        const context = new Uint8Array([1, 2, 3]);
        // no opts
        const sig = v.sign(msg, keys.secretKey);
        eql(v.verify(sig, msg, keys.publicKey), true);
        // Context
        const sig2 = v.sign(msg, keys.secretKey, { context });
        eql(v.verify(sig2, msg, keys.publicKey, { context }), true);
        // Check that context separation actually works
        eql(v.verify(sig2, msg, keys.publicKey), false);
        eql(v.verify(sig, msg, keys.publicKey, { context }), false);
        // Type check
        throws(() => v.sign(msg, keys.secretKey, new Uint8Array(v.length.signRandBytes)));
        throws(() => v.sign(msg, keys.secretKey, context));
        throws(() => v.sign(msg, keys.secretKey, false));
        throws(() => v.verify(sig, msg, keys.publicKey, false));
        throws(() => v.verify(sig, msg, keys.publicKey, context));
        throws(() => v.sign(msg, keys.secretKey, { extraEntropy: true }));
        // A misspelled option must not be silently dropped. Ignoring it made
        // `{ ctx }` sign with no domain separation, succeed, and verify for anyone
        // who also supplied none: a security parameter lost with no signal.
        throws(() => v.sign(msg, keys.secretKey, { ctx: context }));
        throws(() => v.verify(sig, msg, keys.publicKey, { ctx: context }));
        throws(() => v.sign(msg, keys.secretKey, { context, extraEntopy: false }));
        // `undefined` means unset everywhere else in these validators, and building
        // an options bag by spread is a normal way to reach them, so a present-but
        // -undefined key must stay equivalent to omitting it.
        eql(
          v.verify(v.sign(msg, keys.secretKey, { context: undefined }), msg, keys.publicKey),
          true
        );
      });
    }

    it('pre-hash XOFs must produce the length their OID denotes', () => {
      // getMessagePrehash embeds hash.oid beside hash(msg). RFC 8702 and FIPS 204
      // §5.4.1 fix id-shake128 to 256-bit output and id-shake256 to 512-bit, so a
      // bare noble-hashes default, which is half of each, signs an M' claiming a
      // length it does not have. Only noble would verify it.
      throws(() => ml_dsa44.prehash(shake256));
      throws(() => ml_dsa44.prehash(shake128));
      throws(() => slh_dsa_sha2_128f.prehash(shake256));
      // Correct lengths still work.
      const wide = (h: any, len: number) => {
        const f: any = (m: Uint8Array) => h.create({ dkLen: len }).update(m).digest();
        f.outputLen = len;
        f.blockLen = h.blockLen;
        f.create = () => h.create({ dkLen: len });
        f.oid = h.oid;
        return f;
      };
      const keys = ml_dsa44.keygen();
      const msg = new Uint8Array([1, 2, 3]);
      const signer = ml_dsa44.prehash(wide(shake256, 64));
      eql(signer.verify(signer.sign(msg, keys.secretKey), msg, keys.publicKey), true);
      // The strength bound still applies on its own: SHAKE128 at its OID length is
      // 128-bit collision strength, which is not enough for ML-DSA-87.
      throws(() => ml_dsa87.prehash(wide(shake128, 32)));
    });

    it('externalMu is internal-only, and says so instead of being ignored', () => {
      const keys = ml_dsa65.keygen();
      const mu = new Uint8Array(64).fill(7);
      // The public wrappers cannot honour it: sign wraps the message before the
      // 64-byte check, and verify never forwarded opts at all, so it returned false
      // for a perfectly valid external-mu signature. Rejecting is the honest answer.
      throws(() => ml_dsa65.sign(mu, keys.secretKey, { externalMu: true }));
      throws(() => ml_dsa65.verify(new Uint8Array(3309), mu, keys.publicKey, { externalMu: true }));
      // The internal surface still accepts it.
      const sig = ml_dsa65.internal.sign(mu, keys.secretKey, { externalMu: true });
      eql(ml_dsa65.internal.verify(sig, mu, keys.publicKey, { externalMu: true }), true);
    });

    it('the internal surface rejects keys it does not read', () => {
      // The public wrappers consume `context` when they format M', so it must not travel
      // down with the rest of the bag: accepting a key and then not acting on it is the
      // same silent downgrade a misspelling causes. `extraEntropy` is signing-only.
      const keys = ml_dsa65.keygen();
      const mu = new Uint8Array(64).fill(7);
      const context = new Uint8Array([1, 2, 3]);
      const sig = ml_dsa65.internal.sign(mu, keys.secretKey, { externalMu: true });
      throws(() =>
        ml_dsa65.internal.sign(mu, keys.secretKey, { externalMu: true, context } as any)
      );
      throws(() =>
        ml_dsa65.internal.verify(sig, mu, keys.publicKey, { externalMu: true, context } as any)
      );
      throws(() =>
        ml_dsa65.internal.verify(sig, mu, keys.publicKey, {
          externalMu: true,
          extraEntropy: false,
        } as any)
      );
      // The public wrappers keep working, which is what forwards the stripped bag.
      const msg = new Uint8Array([9, 9]);
      const pubSig = ml_dsa65.sign(msg, keys.secretKey, { context });
      eql(ml_dsa65.verify(pubSig, msg, keys.publicKey, { context }), true);
      eql(ml_dsa65.verify(pubSig, msg, keys.publicKey), false);
    });

    it('the SLH-DSA internal surface rejects keys it does not read', () => {
      // SLH-DSA has no externalMu; its internal surface reads only `extraEntropy`. `context`
      // is consumed by the public wrappers when they format M', so forwarding it down would
      // be the same silent accept-and-ignore downgrade the ML-DSA fix removes.
      const slh = slh_dsa_sha2_128f;
      const keys = slh.keygen();
      const msg = new Uint8Array([9, 9]);
      const context = new Uint8Array([1, 2, 3]);
      const M = getMessage(msg);
      const isig = slh.internal.sign(M, keys.secretKey);
      throws(() => slh.internal.sign(M, keys.secretKey, { context } as any));
      throws(() => slh.internal.sign(M, keys.secretKey, { ctx: context } as any));
      throws(() => slh.internal.verify(isig, M, keys.publicKey, { context } as any));
      // The public wrappers keep working (they strip `context` before forwarding), and
      // context separation is real.
      const sig = slh.sign(msg, keys.secretKey, { context });
      eql(slh.verify(sig, msg, keys.publicKey, { context }), true);
      eql(slh.verify(sig, msg, keys.publicKey), false);
    });

    it('the accepted-key lists cannot be widened at runtime', () => {
      // They are exported, so leaving them mutable would let anything in the process push
      // a key onto the accepted set and re-open the hole this validation closes.
      eql(Object.isFrozen(SIG_OPT_KEYS), true);
      eql(Object.isFrozen(VER_OPT_KEYS), true);
      throws(() => (SIG_OPT_KEYS as unknown as string[]).push('ctx'));
      throws(() => (VER_OPT_KEYS as unknown as string[]).push('ctx'));
    });
  });
});

it.runWhen(import.meta.url);
