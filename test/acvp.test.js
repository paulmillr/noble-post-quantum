import { concatBytes, hexToBytes as hexx } from '@noble/hashes/utils';
import { describe, should } from 'micro-should';
import { deepStrictEqual as eql } from 'node:assert';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../esm/ml-dsa.js';
import { ml_kem1024, ml_kem512, ml_kem768 } from '../esm/ml-kem.js';
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
} from '../esm/slh-dsa.js';
import { jsonGZ } from './util.js';

const ignoreSlowTests = !['1', 'true'].includes(process.env.SLOW_TESTS);

function sum(array) {
  return array.reduce((a, b) => a + b, 0);
}

// TODO: use in other libraries? seems useful
// These tests are from 'https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files'
// We can generate even more tests from server, but it is already super slow.
const loadAVCP = (name, gzip) => {
  const json = (fname) => jsonGZ(`post-quantum-vectors/${name}/${fname}.json${gzip ? '.gz' : ''}`);
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
      for (const g of loadAVCP('ML-KEM-keyGen-FIPS203')) {
        const mlkem = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const { publicKey, secretKey } = mlkem.keygen(concatBytes(hexx(t.p.d), hexx(t.p.z)));
          eql(publicKey, hexx(t.er.ek));
          eql(secretKey, hexx(t.er.dk));
        }
      }
    });
    should('encapDecap', () => {
      for (const g of loadAVCP('ML-KEM-encapDecap-FIPS203')) {
        const mlkem = NAMES[g.info.p.parameterSet];
        if (g.info.p.function === 'encapsulation') {
          for (const t of g.tests) {
            const { cipherText, sharedSecret } = mlkem.encapsulate(hexx(t.p.ek), hexx(t.p.m));
            eql(cipherText, hexx(t.er.c));
            eql(sharedSecret, hexx(t.er.k));
          }
        } else {
          const dk = hexx(g.info.p.dk);
          for (const t of g.tests) {
            const sharedSecret = mlkem.decapsulate(hexx(t.p.c), dk);
            eql(sharedSecret, hexx(t.er.k));
          }
        }
      }
    });
  });
  describe('ML-DSA', () => {
    const NAMES = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 };
    should('keyGen', () => {
      for (const g of loadAVCP('ML-DSA-keyGen-FIPS204')) {
        const mldsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const { publicKey, secretKey } = mldsa.keygen(hexx(t.p.seed));
          eql(publicKey, hexx(t.er.pk));
          eql(secretKey, hexx(t.er.sk));
        }
      }
    });
    should('sigGen', () => {
      for (const g of loadAVCP('ML-DSA-sigGen-FIPS204', true)) {
        const mldsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const rnd = t.p.rnd ? hexx(t.p.rnd) : undefined;
          let sig;
          if (g.info.p.signatureInterface === 'internal') {
            if (g.info.p.externalMu) {
              sig = mldsa.internal.sign(hexx(t.p.sk), hexx(t.p.mu), rnd, true);
            } else sig = mldsa.internal.sign(hexx(t.p.sk), hexx(t.p.message), rnd);
          } else if (g.info.p.signatureInterface === 'external') {
            const ctx = t.p.context ? hexx(t.p.context) : undefined;
            if (g.info.p.preHash === 'preHash') {
              sig = mldsa.prehash(t.p.hashAlg).sign(hexx(t.p.sk), hexx(t.p.message), ctx, rnd);
            } else {
              sig = mldsa.sign(hexx(t.p.sk), hexx(t.p.message), ctx, rnd);
            }
          } else throw new Error('unknown signature interface');
          eql(sig, hexx(t.er.signature));
        }
      }
    });
    should('sigVer', () => {
      for (const g of loadAVCP('ML-DSA-sigVer-FIPS204')) {
        const mldsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          let valid;
          if (g.info.p.signatureInterface === 'internal') {
            if (g.info.p.externalMu) {
              valid = mldsa.internal.verify(hexx(t.p.pk), hexx(t.p.mu), hexx(t.p.signature), true);
            } else {
              valid = mldsa.internal.verify(hexx(t.p.pk), hexx(t.p.message), hexx(t.p.signature));
            }
          } else if (g.info.p.signatureInterface === 'external') {
            const ctx = t.p.context ? hexx(t.p.context) : undefined;
            if (g.info.p.preHash === 'preHash') {
              valid = mldsa
                .prehash(t.p.hashAlg)
                .verify(hexx(t.p.pk), hexx(t.p.message), hexx(t.p.signature), ctx);
            } else {
              valid = mldsa.verify(hexx(t.p.pk), hexx(t.p.message), hexx(t.p.signature), ctx);
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
      for (const g of loadAVCP('SLH-DSA-keyGen-FIPS205', true)) {
        const slhdsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const { publicKey, secretKey } = slhdsa.keygen(
            concatBytes(hexx(t.p.skSeed), hexx(t.p.skPrf), hexx(t.p.pkSeed))
          );
          eql(publicKey, hexx(t.er.pk));
          eql(secretKey, hexx(t.er.sk));
        }
      }
    });
    should('sigVer', () => {
      for (const g of loadAVCP('SLH-DSA-sigVer-FIPS205', true)) {
        const slhdsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          let valid;
          // We throw error on invalid signature size, so this is reason
          try {
            if (g.info.p.signatureInterface === 'internal') {
              valid = slhdsa.internal.verify(hexx(t.p.pk), hexx(t.p.message), hexx(t.p.signature));
            } else if (g.info.p.signatureInterface === 'external') {
              const ctx = t.p.context ? hexx(t.p.context) : undefined;
              if (g.info.p.preHash === 'preHash') {
                valid = slhdsa
                  .prehash(t.p.hashAlg)
                  .verify(hexx(t.p.pk), hexx(t.p.message), hexx(t.p.signature), ctx);
              } else {
                valid = slhdsa.verify(hexx(t.p.pk), hexx(t.p.message), hexx(t.p.signature), ctx);
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
      const all = loadAVCP('SLH-DSA-sigGen-FIPS205', true);
      const total = sum(all.map((g) => g.tests.length));
      let i = 0;
      for (const g of all) {
        const slhdsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          i++;
          should(`vector ${i} of ${total}`, () => {
            const rnd = t.p.additionalRandomness ? hexx(t.p.additionalRandomness) : undefined;
            let sig;
            if (g.info.p.signatureInterface === 'internal') {
              sig = slhdsa.internal.sign(hexx(t.p.sk), hexx(t.p.message), rnd);
            } else if (g.info.p.signatureInterface === 'external') {
              const ctx = t.p.context ? hexx(t.p.context) : undefined;
              if (g.info.p.preHash === 'preHash') {
                sig = slhdsa.prehash(t.p.hashAlg).sign(hexx(t.p.sk), hexx(t.p.message), ctx, rnd);
              } else {
                sig = slhdsa.sign(hexx(t.p.sk), hexx(t.p.message), ctx, rnd);
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
