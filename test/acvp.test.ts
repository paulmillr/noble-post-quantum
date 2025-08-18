import { concatBytes, hexToBytes as hexx } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
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
import { equalBytes } from '../src/utils.ts';

import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js';
import {
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
  shake128_32,
  shake256_64,
} from '@noble/hashes/sha3.js';
import { jsonGZ } from './util.ts';

const ignoreSlowTests = !['1', 'true'].includes(process.env.SLOW_TESTS);

function sum(array) {
  return array.reduce((a, b) => a + b, 0);
}

function checkStrength(hash) {
  return (hash.outputLen * 8) / 2;
}

const HASHES = {
  'SHA2-256': sha256,
  'SHA2-384': sha384,
  'SHA2-512': sha512,
  'SHA2-224': sha224,
  'SHA2-512/224': sha512_224,
  'SHA2-512/256': sha512_256,
  'SHA3-224': sha3_224,
  'SHA3-256': sha3_256,
  'SHA3-384': sha3_384,
  'SHA3-512': sha3_512,
  'SHAKE-128': shake128_32,
  'SHAKE-256': shake256_64,
};

// TODO: use in other libraries? seems useful
// These tests are from 'https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files'
// We can generate even more tests from server, but it is already super slow.
const loadACVP = (name, gzipped = true) => {
  const json = (fname) =>
    jsonGZ(`vectors/acvp-vectors/gen-val/json-files/${name}/${fname}.json${gzipped ? '.gz' : ''}`);
  const prompt = json('prompt');
  const expectedResult = json('expectedResults');
  const internalProjection = json('internalProjection');
  //const registration = json('registration');
  eql(prompt.testGroups.length, expectedResult.testGroups.length);
  eql(prompt.testGroups.length, internalProjection.testGroups.length);
  const groups = [];
  const is205 = name.includes('FIPS205');
  for (let gid = 0; gid < prompt.testGroups.length; gid++) {
    const { tests: pTests, ...pInfo } = prompt.testGroups[gid];
    const { tests: erTests, ...erInfo } = expectedResult.testGroups[gid];
    const { tests: ipTests, ...ipInfo } = internalProjection.testGroups[gid];
    const group = { info: { p: pInfo, er: erInfo, ip: ipInfo }, tests: [] };
    eql(pTests.length, erTests.length);
    eql(pTests.length, ipTests.length);
    for (let tid = 0; tid < pTests.length; tid++) {
      const shouldBeIgnored = is205 && tid > 0;
      if (shouldBeIgnored && ignoreSlowTests) continue;

      group.tests.push({
        p: pTests[tid],
        er: erTests[tid],
        ip: ipTests[tid],
      });
    }
    groups.push(group);
  }
  return groups;
};

describe('AVCP', () => {
  describe('ML-KEM', () => {
    const NAMES = { 'ML-KEM-512': ml_kem512, 'ML-KEM-768': ml_kem768, 'ML-KEM-1024': ml_kem1024 };
    should('keyGen', () => {
      for (const g of loadACVP('ML-KEM-keyGen-FIPS203')) {
        const mlkem = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const { publicKey, secretKey } = mlkem.keygen(concatBytes(hexx(t.p.d), hexx(t.p.z)));
          eql(publicKey, hexx(t.er.ek));
          eql(secretKey, hexx(t.er.dk));
          eql(mlkem.getPublicKey(secretKey), publicKey);
        }
      }
    });
    should('encapDecap', () => {
      for (const g of loadACVP('ML-KEM-encapDecap-FIPS203')) {
        const mlkem = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          if (g.info.p.function === 'encapsulation') {
            const { cipherText, sharedSecret } = mlkem.encapsulate(hexx(t.p.ek), hexx(t.p.m));
            eql(cipherText, hexx(t.er.c));
            eql(sharedSecret, hexx(t.er.k));
          } else if (g.info.p.function === 'decapsulation') {
            const dk = hexx(t.p.dk);
            const c = hexx(t.p.c);
            const sharedSecret = mlkem.decapsulate(c, dk);
            eql(sharedSecret, hexx(t.er.k));
          } else if (g.info.p.function === 'encapsulationKeyCheck') {
            // NOTE: spec doesn't provide any functions for these check and explicitly returns pseudo-random if key is not valid/cipherText broken
            // so we try to emulate key checks using these functions.
            let passed;
            try {
              mlkem.encapsulate(hexx(t.p.ek));
              passed = true;
            } catch {
              passed = false;
            }
            eql(passed, t.ip.testPassed);
          } else if (g.info.p.function === 'decapsulationKeyCheck') {
            const dk = hexx(t.ip.dk);
            const ek = hexx(t.ip.ek);
            eql(mlkem.getPublicKey(dk), ek);
            const c = mlkem.encapsulate(ek);
            let passed;
            try {
              const shared = mlkem.decapsulate(c.cipherText, dk); // mlkem returns pseudo-random garbage if not valid
              passed = equalBytes(shared, c.sharedSecret);
            } catch (e) {
              passed = false;
            }
            eql(passed, t.ip.testPassed);
          }
        }
      }
    });
  });
  describe('ML-DSA', () => {
    const NAMES = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 };
    should('keyGen', () => {
      for (const g of loadACVP('ML-DSA-keyGen-FIPS204')) {
        const mldsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const { publicKey, secretKey } = mldsa.keygen(hexx(t.p.seed));
          eql(publicKey, hexx(t.er.pk));
          eql(secretKey, hexx(t.er.sk));
          eql(mldsa.getPublicKey(secretKey), publicKey);
        }
      }
    });
    should('sigGen', () => {
      for (const g of loadACVP('ML-DSA-sigGen-FIPS204')) {
        const mldsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const rnd = t.p.rnd ? hexx(t.p.rnd) : false;
          const opts = { extraEntropy: rnd, externalMu: g.info.p.externalMu };
          let sig;
          if (g.info.p.signatureInterface === 'internal') {
            if (g.info.p.externalMu) sig = mldsa.internal.sign(hexx(t.p.mu), hexx(t.p.sk), opts);
            else sig = mldsa.internal.sign(hexx(t.p.message), hexx(t.p.sk), opts);
          } else if (g.info.p.signatureInterface === 'external') {
            const ctx = t.p.context ? hexx(t.p.context) : undefined;
            const optsCtx = { ...opts, context: ctx };
            if (g.info.p.preHash === 'preHash') {
              const hash = HASHES[t.p.hashAlg];
              if (checkStrength(hash) < mldsa.securityLevel) continue;
              sig = mldsa.prehash(hash).sign(hexx(t.p.message), hexx(t.p.sk), optsCtx);
            } else {
              sig = mldsa.sign(hexx(t.p.message), hexx(t.p.sk), optsCtx);
            }
          } else throw new Error('unknown signature interface');
          eql(sig, hexx(t.er.signature));
        }
      }
    });
    should('sigVer', () => {
      for (const g of loadACVP('ML-DSA-sigVer-FIPS204')) {
        const mldsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          let valid;
          if (g.info.p.signatureInterface === 'internal') {
            if (g.info.p.externalMu) {
              valid = mldsa.internal.verify(hexx(t.p.signature), hexx(t.p.mu), hexx(t.p.pk), {
                externalMu: true,
              });
            } else {
              valid = mldsa.internal.verify(hexx(t.p.signature), hexx(t.p.message), hexx(t.p.pk));
            }
          } else if (g.info.p.signatureInterface === 'external') {
            const ctx = t.p.context ? hexx(t.p.context) : undefined;
            if (g.info.p.preHash === 'preHash') {
              const hash = HASHES[t.p.hashAlg];
              if (checkStrength(hash) < mldsa.securityLevel) continue;
              valid = mldsa
                .prehash(hash)
                .verify(hexx(t.p.signature), hexx(t.p.message), hexx(t.p.pk), { context: ctx });
            } else {
              valid = mldsa.verify(hexx(t.p.signature), hexx(t.p.message), hexx(t.p.pk), {
                context: ctx,
              });
            }
          } else throw new Error('unknown signature interface');
          eql(valid, t.er.testPassed);
        }
      }
    });
  });
  describe('SLH-DSA', () => {
    const NAMES = {
      'SLH-DSA-SHA2-128s': slh_dsa_sha2_128s,
      'SLH-DSA-SHA2-128f': slh_dsa_sha2_128f,
      'SLH-DSA-SHA2-192s': slh_dsa_sha2_192s,
      'SLH-DSA-SHA2-192f': slh_dsa_sha2_192f,
      'SLH-DSA-SHA2-256s': slh_dsa_sha2_256s,
      'SLH-DSA-SHA2-256f': slh_dsa_sha2_256f,
      'SLH-DSA-SHAKE-128s': slh_dsa_shake_128s,
      'SLH-DSA-SHAKE-128f': slh_dsa_shake_128f,
      'SLH-DSA-SHAKE-192s': slh_dsa_shake_192s,
      'SLH-DSA-SHAKE-192f': slh_dsa_shake_192f,
      'SLH-DSA-SHAKE-256s': slh_dsa_shake_256s,
      'SLH-DSA-SHAKE-256f': slh_dsa_shake_256f,
    };
    should('keyGen', () => {
      for (const g of loadACVP('SLH-DSA-keyGen-FIPS205')) {
        const slhdsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const { publicKey, secretKey } = slhdsa.keygen(
            concatBytes(hexx(t.p.skSeed), hexx(t.p.skPrf), hexx(t.p.pkSeed))
          );
          eql(publicKey, hexx(t.er.pk));
          eql(secretKey, hexx(t.er.sk));
          eql(slhdsa.getPublicKey(secretKey), publicKey);
        }
      }
    });
    should('sigVer', () => {
      for (const g of loadACVP('SLH-DSA-sigVer-FIPS205')) {
        const slhdsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          let valid;
          // We throw error on invalid signature size, so this is reason
          try {
            if (g.info.p.signatureInterface === 'internal') {
              valid = slhdsa.internal.verify(hexx(t.p.signature), hexx(t.p.message), hexx(t.p.pk));
            } else if (g.info.p.signatureInterface === 'external') {
              const ctx = t.p.context ? hexx(t.p.context) : undefined;
              if (g.info.p.preHash === 'preHash') {
                const hash = HASHES[t.p.hashAlg];
                if (checkStrength(hash) < slhdsa.securityLevel) return;
                valid = slhdsa
                  .prehash(hash)
                  .verify(hexx(t.p.signature), hexx(t.p.message), hexx(t.p.pk), { context: ctx });
              } else {
                valid = slhdsa.verify(hexx(t.p.signature), hexx(t.p.message), hexx(t.p.pk), {
                  context: ctx,
                });
              }
            } else throw new Error('unknown signature interface');
          } catch (e) {
            valid = false;
          }
          eql(valid, t.er.testPassed);
        }
      }
    });
    describe('sigGen', () => {
      const all = loadACVP('SLH-DSA-sigGen-FIPS205');
      const total = sum(all.map((g) => g.tests.length));
      let i = 0;
      for (const g of all) {
        const slhdsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          i++;
          should(`vector ${i} of ${total}`, () => {
            const rnd = t.p.additionalRandomness ? hexx(t.p.additionalRandomness) : false;
            let sig;
            if (g.info.p.signatureInterface === 'internal') {
              sig = slhdsa.internal.sign(hexx(t.p.message), hexx(t.p.sk), { extraEntropy: rnd });
            } else if (g.info.p.signatureInterface === 'external') {
              const hash = HASHES[t.p.hashAlg];
              const ctx = t.p.context ? hexx(t.p.context) : undefined;
              const opts = { context: ctx, extraEntropy: rnd };
              if (g.info.p.preHash === 'preHash') {
                if (checkStrength(hash) < slhdsa.securityLevel) return;
                sig = slhdsa.prehash(hash).sign(hexx(t.p.message), hexx(t.p.sk), opts);
              } else {
                sig = slhdsa.sign(hexx(t.p.message), hexx(t.p.sk), opts);
              }
            } else throw new Error('unknown signature interface');
            eql(sig, hexx(t.er.signature));
          });
        }
      }
    });
  });
});

should.runWhen(import.meta.url);
