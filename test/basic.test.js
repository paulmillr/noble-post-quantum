import { describe, should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import { ml_dsa44 } from '../esm/ml-dsa.js';
import { ml_kem512 } from '../esm/ml-kem.js';
import { slh_dsa_sha2_128f } from '../esm/slh-dsa.js';
import { randomBytes } from '../esm/utils.js';

describe('Basic', () => {
  describe('Immutability', () => {
    should('ML-KEM', () => {
      // keygen
      const seed = randomBytes(64);
      const seedCopy = Uint8Array.from(seed);
      const keys = ml_kem512.keygen(seed);
      deepStrictEqual(seed, seedCopy);
      // encapsulate
      const publicKey = Uint8Array.from(keys.publicKey);
      const msg = randomBytes(32);
      const msgCopy = Uint8Array.from(msg);
      const enc = ml_kem512.encapsulate(publicKey, msg);
      deepStrictEqual(publicKey, keys.publicKey);
      deepStrictEqual(msg, msgCopy);
      // decapsulate
      const cipherText = Uint8Array.from(enc.cipherText);
      const secretKey = Uint8Array.from(keys.secretKey);
      const dec = ml_kem512.decapsulate(cipherText, secretKey);
      deepStrictEqual(cipherText, enc.cipherText);
      deepStrictEqual(secretKey, keys.secretKey);
    });
    should('ML-DSA', () => {
      // keygen
      const seed = randomBytes(32);
      const seedCopy = Uint8Array.from(seed);
      const keys = ml_dsa44.keygen(seed);
      deepStrictEqual(seed, seedCopy);
      // sign
      const secretKey = Uint8Array.from(keys.secretKey);
      const msg = randomBytes(32);
      const msgCopy = Uint8Array.from(msg);
      const random = randomBytes(32);
      const randomCopy = Uint8Array.from(random);
      const sig = ml_dsa44.sign(secretKey, msg, random);
      deepStrictEqual(secretKey, keys.secretKey);
      deepStrictEqual(msg, msgCopy);
      deepStrictEqual(random, randomCopy);
      // verify
      const sigCopy = Uint8Array.from(sig);
      const publicKey = Uint8Array.from(keys.publicKey);
      ml_dsa44.verify(publicKey, msg, sig);
      deepStrictEqual(sig, sigCopy);
      deepStrictEqual(publicKey, keys.publicKey);
      deepStrictEqual(msg, msgCopy);
    });
    should('SLH-DSA', () => {
      // keygen
      const seed = randomBytes(48);
      const seedCopy = Uint8Array.from(seed);
      const keys = slh_dsa_sha2_128f.keygen(seed);
      deepStrictEqual(seed, seedCopy);
      // sign
      const secretKey = Uint8Array.from(keys.secretKey);
      const msg = randomBytes(32);
      const msgCopy = Uint8Array.from(msg);
      const random = randomBytes(32);
      const randomCopy = Uint8Array.from(random);
      const sig = slh_dsa_sha2_128f.sign(secretKey, msg, random);
      deepStrictEqual(secretKey, keys.secretKey);
      deepStrictEqual(msg, msgCopy);
      deepStrictEqual(random, randomCopy);
      // verify
      const sigCopy = Uint8Array.from(sig);
      const publicKey = Uint8Array.from(keys.publicKey);
      slh_dsa_sha2_128f.verify(publicKey, msg, sig);
      deepStrictEqual(publicKey, keys.publicKey);
      deepStrictEqual(sig, sigCopy);
      deepStrictEqual(msg, msgCopy);
    });
  });
});

should.runWhen(import.meta.url);
