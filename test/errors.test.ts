import { should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';
import { ml_kem1024, ml_kem512, ml_kem768 } from '../src/ml-kem.ts';
import {
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
  slh_dsa_shake_128f,
  slh_dsa_shake_128s,
  slh_dsa_shake_192f,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
} from '../src/slh-dsa.ts';
import { sha512, sha224 } from '@noble/hashes/sha2.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { QSFMLKEM768P256, combineSigners, expandSeedXof, ecSigner } from '../src/hybrid.ts';
import { shake256 } from '@noble/hashes/sha3.js';
import { ed25519 } from '@noble/curves/ed25519.js';

const ALGO = {
  ml_dsa44,
  ml_dsa44_prehash: ml_dsa44.prehash(sha512),
  ml_dsa44_int: ml_dsa44.internal,
  ml_kem512,
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128f_prehash: slh_dsa_sha2_128f.prehash(sha512),
  slh_dsa_sha2_128f_internal: slh_dsa_sha2_128f.internal,
  // No point, same code as sha2, but super slow
  // slh_dsa_shake_128s,
  // slh_dsa_shake_128s_prehash: slh_dsa_shake_128s.prehash(sha512),
  // Hybrids
  QSFMLKEM768P256,
  ml_dsa44_ed25519: combineSigners(32, expandSeedXof(shake256), ecSigner(ed25519), ml_dsa44),
};

function getError(fn) {
  try {
    fn();
    throw new Error('NO ERROR!');
  } catch (e) {
    return e;
  }
}
const green = (s) => `\x1b[32m${s}\x1b[0m`;

should('Errors', () => {
  const res = {}; // Record<string, [string, string][]>
  const algoNameLength = Object.keys(ALGO)
    .map((i) => i.length)
    .reduce((acc, i) => Math.max(acc, i));
  for (const name in ALGO) {
    const C = ALGO[name];
    const CE = (s, fn) => {
      if (!res[s]) res[s] = [];
      res[s].push({ algoName: name, name: s, error: getError(fn) });
    };
    const CEG = (s, manglers, value, fn) => {
      for (const m in manglers) CE(s + m, () => fn(manglers[m](value)));
    };
    const BYTES10 = randomBytes(10);
    const U8 = {
      false: () => false,
      bytes10: () => BYTES10,
      empty: () => new Uint8Array(0),
      zero: (b) => new Uint8Array(b.length),
      slice1: (b) => b.slice(1),
      hex: (b) => bytesToHex(b),
      array: (b) => Array.from(b),
    };
    const B = {
      1: () => 1,
      0: () => 0,
      null: () => null,
      string: () => 'true',
    };
    const HASH = {
      false: () => false,
      bytes10: () => BYTES10,
      sha1: () => sha1,
      sha224: () => sha224,
      fn: () => () => {},
    };
    console.log('a', C);
    if (C.keygen) {
      const seed = randomBytes(C.lengths.seed);
      CEG('keygen: wrong seed=', U8, seed, (s) => C.keygen(s));
      const keys = C.keygen();
      if (C.lengths.public) eql(keys.publicKey.length, C.lengths.public);
      if (C.lengths.secret) eql(keys.secretKey.length, C.lengths.secret);
      if (C.getPublicKey) {
        CEG('getPublicKey: wrong secretKey=', U8, keys.secretKey, (s) => C.getPublicKey(s));
      }
      if (C.sign && C.verify) {
        let msg = BYTES10;
        const sig = C.sign(msg, keys.secretKey);
        if (C.lengths.signature) eql(sig.length, C.lengths.signature);
        eql(C.verify(sig, msg, keys.publicKey), true);
        CEG('sign: wrong msg=', U8, msg, (s) => C.sign(s, keys.secretKey));
        CEG('sign: wrong secretKey=', U8, keys.secretKey, (s) => C.sign(msg, s));
        // Verify
        CEG('verify: wrong msg=', U8, msg, (s) => C.verify(sig, s, keys.publicKey));
        CEG('verify: wrong pk=', U8, keys.publicKey, (s) => C.verify(sig, msg, s));
        CEG('verify: wrong sig=', U8, sig, (s) => C.verify(s, msg, keys.publicKey));
        if (C.info && C.info.type && C.info.type.startsWith('hash')) {
          const ctx = BYTES10;
          const sig = C.sign(msg, keys.secretKey, ctx);
          CEG('sign: wrong ctx=', U8, ctx, (s) => C.sign(msg, keys.secretKey, s));
          CEG('verify: wrong ctx=', U8, ctx, (s) => C.verify(sig, msg, keys.publicKey, s));
        }
      }
      if (C.encapsulate && C.decapsulate) {
        const msg = randomBytes(C.lengths.msgRand);
        const { cipherText, sharedSecret } = C.encapsulate(keys.publicKey, msg);
        if (C.lengths.msg) eql(sharedSecret.length, C.lengths.msg);
        CEG('encapsulate: wrong msg=', U8, msg, (s) => C.encapsulate(keys.publicKey, s));
        CEG('encapsulate: wrong publicKey=', U8, msg, (s) => C.encapsulate(keys.s, msg));
        eql(C.decapsulate(cipherText, keys.secretKey), sharedSecret);
        CEG('decapsulate: wrong cipherText=', U8, msg, (s) => C.decapsulate(s, keys.secretKey));
        CEG('decapsulate: wrong secretKey=', U8, msg, (s) => C.encapsulate(cipherText, msg));
      }
      if (C.prehash) {
        CEG('prehash: wrong hash=', HASH, sha512, (s) => C.prehash(s));
      }
    }
  }

  for (const k in res) {
    console.log(green(k));
    for (const { algoName, error } of res[k])
      console.log(`- ${algoName.padEnd(algoNameLength, ' ')}: ${error.message}`);
  }
});

should.runWhen(import.meta.url);
