import {
  keccak_512,
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  shake128,
  shake128_32,
} from '@noble/hashes/sha3.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';
import { ml_kem512 } from '../src/ml-kem.ts';
import { slh_dsa_sha2_128f } from '../src/slh-dsa.ts';
import { randomBytes } from '../src/utils.ts';

describe('Basic', () => {
  describe('Immutability', () => {
    should('ML-KEM', () => {
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
    should('ML-DSA', () => {
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
    should('SLH-DSA', () => {
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
  should('Hash compatibility', () => {
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
      should(k, () => {
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
      });
    }
  });
});

should.runWhen(import.meta.url);
