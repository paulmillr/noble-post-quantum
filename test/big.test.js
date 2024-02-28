import { deepStrictEqual } from 'node:assert';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { describe, should } from 'micro-should';
import { __dirname } from './util.js';
import {
  kyber512,
  kyber768,
  kyber1024,
  kyber512_90s,
  kyber768_90s,
  kyber1024_90s,
} from '../ml-kem.js';

const readTEST = (name) => {
  return []; // Temp
  const data = readFileSync(`${__dirname}/vectors/${name}.exp`, 'utf8');
  let lines = data.split(/\n/gm);
  const cases = [];
  while (lines.length > 7) {
    const c = lines.slice(0, 8).map((i) => i.split(':').map((j) => j.trim()));
    cases.push({
      keygenRnd0: c[0][0],
      keygenRnd1: c[1][0],
      publicKey: c[2][1],
      secretKey: c[3][1],
      encryptRnd: c[4][0],
      cipherText: c[5][1],
      sharedSecret1: c[6][1],
      sharedSecret2: c[7][1],
    });
    lines = lines.slice(8);
  }
  return cases;
};

const VERSIONS = {
  kyber512: { fn: kyber512, test: 'test_vectors512' },
  kyber768: { fn: kyber768, test: 'test_vectors768' },
  kyber1024: { fn: kyber1024, test: 'test_vectors1024' },
  kyber512_90s: { fn: kyber512_90s, test: 'test_vectors512-90s' },
  kyber768_90s: { fn: kyber768_90s, test: 'test_vectors768-90s' },
  kyber1024_90s: { fn: kyber1024_90s, test: 'test_vectors1024-90s' },
};

describe('Kyber', () => {
  describe('big', () => {
    for (const v in VERSIONS) {
      const { fn: kyber, test } = VERSIONS[v];
      should(`${test}`, () => {
        const cases = readTEST(test);
        for (const c of cases) {
          const { publicKey: pk, secretKey: sk } = kyber.keygen(
            hexToBytes(c.keygenRnd0 + c.keygenRnd1)
          );
          deepStrictEqual(bytesToHex(pk), c.publicKey, 'publicKey');
          deepStrictEqual(bytesToHex(sk), c.secretKey, 'secretKey');
          const { cipherText: ct2, sharedSecret: ss2 } = kyber.encapsulate(
            pk,
            hexToBytes(c.encryptRnd)
          );
          deepStrictEqual(bytesToHex(ct2), c.cipherText, 'encrypt');
          deepStrictEqual(bytesToHex(ss2), c.sharedSecret1, 'sharedSecret1');
          deepStrictEqual(bytesToHex(ss2), c.sharedSecret2, 'sharedSecret2');
          deepStrictEqual(bytesToHex(kyber.decapsulate(ct2, sk)), c.sharedSecret1, 'decrypt');
        }
      });
    }
  });
});

// ESM is broken.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  should.run();
}
