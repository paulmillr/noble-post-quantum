import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { ml_dsa44 } from '../src/ml-dsa.ts';
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
      const sig = ml_dsa44.sign(secretKey, msg, random);
      eql(secretKey, keys.secretKey);
      eql(msg, msgCopy);
      eql(random, randomCopy);
      // verify
      const sigCopy = Uint8Array.from(sig);
      const publicKey = Uint8Array.from(keys.publicKey);
      ml_dsa44.verify(publicKey, msg, sig);
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
      const random = randomBytes(32);
      const randomCopy = Uint8Array.from(random);
      const sig = slh_dsa_sha2_128f.sign(secretKey, msg, random);
      eql(secretKey, keys.secretKey);
      eql(msg, msgCopy);
      eql(random, randomCopy);
      // verify
      const sigCopy = Uint8Array.from(sig);
      const publicKey = Uint8Array.from(keys.publicKey);
      slh_dsa_sha2_128f.verify(publicKey, msg, sig);
      eql(publicKey, keys.publicKey);
      eql(sig, sigCopy);
      eql(msg, msgCopy);
    });
  });
});

should.runWhen(import.meta.url);
