import { deepStrictEqual, throws } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { describe, should } from 'micro-should';
import { concatBytes, hexToBytes } from '@noble/hashes/utils';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../ml-dsa.js';
import { ml_kem512, ml_kem768, ml_kem1024 } from '../ml-kem.js';
import {
  slh_dsa_shake_128f,
  slh_dsa_shake_128s,
  slh_dsa_shake_192f,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
} from '../slh-dsa.js';
import { jsonGZ } from './util.js';

// TODO: use in other libraries? seems useful
// These tests are from 'https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files'
// We can generate even more tests from server, but it is already super slow.
const loadAVCP = (name, gzip) => {
  const json = (fname) => jsonGZ(`AVCP/${name}/${fname}.json${gzip ? '.gz' : ''}`);
  const prompt = json('prompt');
  const expectedResult = json('expectedResults');
  const internalProjection = json('internalProjection');
  //const registration = json('registration');
  deepStrictEqual(prompt.testGroups.length, expectedResult.testGroups.length);
  deepStrictEqual(prompt.testGroups.length, internalProjection.testGroups.length);
  const groups = [];
  for (let gid = 0; gid < prompt.testGroups.length; gid++) {
    const { tests: pTests, ...pInfo } = prompt.testGroups[gid];
    const { tests: erTests, ...erInfo } = expectedResult.testGroups[gid];
    const { tests: ipTests, ...ipInfo } = internalProjection.testGroups[gid];
    const group = { info: { p: pInfo, er: erInfo, ip: ipInfo }, tests: [] };
    deepStrictEqual(pTests.length, erTests.length);
    deepStrictEqual(pTests.length, ipTests.length);
    for (let tid = 0; tid < pTests.length; tid++) {
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
          const { publicKey, secretKey } = mlkem.keygen(
            concatBytes(hexToBytes(t.p.d), hexToBytes(t.p.z))
          );
          deepStrictEqual(publicKey, hexToBytes(t.er.ek));
          deepStrictEqual(secretKey, hexToBytes(t.er.dk));
        }
      }
    });
    should('encapDecap', () => {
      for (const g of loadAVCP('ML-KEM-encapDecap-FIPS203')) {
        const mlkem = NAMES[g.info.p.parameterSet];
        if (g.info.p.function === 'encapsulation') {
          for (const t of g.tests) {
            const { cipherText, sharedSecret } = mlkem.encapsulate(
              hexToBytes(t.p.ek),
              hexToBytes(t.p.m)
            );
            deepStrictEqual(cipherText, hexToBytes(t.er.c));
            deepStrictEqual(sharedSecret, hexToBytes(t.er.k));
          }
        } else {
          const dk = hexToBytes(g.info.p.dk);
          for (const t of g.tests) {
            const sharedSecret = mlkem.decapsulate(hexToBytes(t.p.c), dk);
            deepStrictEqual(sharedSecret, hexToBytes(t.er.k));
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
          const { publicKey, secretKey } = mldsa.keygen(hexToBytes(t.p.seed));
          deepStrictEqual(publicKey, hexToBytes(t.er.pk));
          deepStrictEqual(secretKey, hexToBytes(t.er.sk));
        }
      }
    });
    should('sigGen', () => {
      for (const g of loadAVCP('ML-DSA-sigGen-FIPS204')) {
        const mldsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const rnd = t.p.rnd ? hexToBytes(t.p.rnd) : undefined;
          const sig = mldsa.internal.sign(hexToBytes(t.p.sk), hexToBytes(t.p.message), rnd);
          deepStrictEqual(sig, hexToBytes(t.er.signature));
        }
      }
    });
    should('sigVer', () => {
      for (const g of loadAVCP('ML-DSA-sigVer-FIPS204')) {
        const mldsa = NAMES[g.info.p.parameterSet];
        const pk = hexToBytes(g.info.p.pk);
        for (const t of g.tests) {
          const valid = mldsa.internal.verify(
            pk,
            hexToBytes(t.p.message),
            hexToBytes(t.p.signature)
          );
          deepStrictEqual(valid, t.er.testPassed);
        }
      }
    });
  });
  describe('SLH-DSA', () => {
    const NAMES = {
      'SLH-DSA-SHA2-128s': slh_dsa_sha2_128s,
      'SLH-DSA-SHA2-192s': slh_dsa_sha2_192s,
      'SLH-DSA-SHA2-192f': slh_dsa_sha2_192f,
      'SLH-DSA-SHA2-256f': slh_dsa_sha2_256f,
      'SLH-DSA-SHAKE-128f': slh_dsa_shake_128f,
      'SLH-DSA-SHAKE-192s': slh_dsa_shake_192s,
      'SLH-DSA-SHAKE-256f': slh_dsa_shake_256f,
    };
    should('keyGen', () => {
      for (const g of loadAVCP('SLH-DSA-keyGen-FIPS205')) {
        const slhdsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const { publicKey, secretKey } = slhdsa.keygen(
            concatBytes(hexToBytes(t.p.skSeed), hexToBytes(t.p.skPrf), hexToBytes(t.p.pkSeed))
          );
          deepStrictEqual(publicKey, hexToBytes(t.er.pk));
          deepStrictEqual(secretKey, hexToBytes(t.er.sk));
          0;
        }
      }
    });
    should('sigVer', () => {
      for (const g of loadAVCP('SLH-DSA-sigVer-FIPS205')) {
        const slhdsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          let valid = true;
          // We throw error on invalid signature size, so this is reason
          try {
            valid = slhdsa.verify(
              hexToBytes(t.p.pk),
              hexToBytes(t.p.message),
              hexToBytes(t.p.signature)
            );
          } catch (e) {
            valid = false;
          }
          deepStrictEqual(valid, t.er.testPassed);
        }
      }
    });
    should('sigGen', () => {
      // This is very slow, so it is last
      for (const g of loadAVCP('SLH-DSA-sigGen-FIPS205')) {
        const slhdsa = NAMES[g.info.p.parameterSet];
        for (const t of g.tests) {
          const rnd = t.p.additionalRandomness ? hexToBytes(t.p.additionalRandomness) : undefined;
          const sig = slhdsa.sign(hexToBytes(t.p.sk), hexToBytes(t.p.message), rnd);
          deepStrictEqual(sig, hexToBytes(t.er.signature));
        }
      }
    });
  });
});

// ESM is broken.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  should.run();
}
/*
NOTE: we pass tests from NIST test vectors, however:
- HashML-DSA/HashSLH-DSA not implemented (there is no tests for them)
- 
*/
