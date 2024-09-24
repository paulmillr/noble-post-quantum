import { deepStrictEqual, throws } from 'node:assert';
import { describe, should } from 'micro-should';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../ml-dsa.js';
import { jsonGZ } from './util.js';

const VECTORS = {
  ml_dsa44: {
    mldsa: ml_dsa44,
    sign: jsonGZ('./wycheproof/mldsa_44_standard_sign_test.json.gz'),
    verify: jsonGZ('./wycheproof/mldsa_44_standard_verify_test.json.gz'),
  },
  ml_dsa65: {
    mldsa: ml_dsa65,
    sign: jsonGZ('./wycheproof/mldsa_65_standard_sign_test.json.gz'),
    verify: jsonGZ('./wycheproof/mldsa_65_standard_verify_test.json.gz'),
  },
  ml_dsa87: {
    mldsa: ml_dsa87,
    sign: jsonGZ('./wycheproof/mldsa_87_standard_sign_test.json.gz'),
    verify: jsonGZ('./wycheproof/mldsa_87_standard_verify_test.json.gz'),
  },
};

describe('ML-DSA Dilithium', () => {
  should('Example', () => {
    const aliceKeys = ml_dsa65.keygen();
    const msg = new Uint8Array(1);
    const sig = ml_dsa65.sign(aliceKeys.secretKey, msg);
    const isValid = ml_dsa65.verify(aliceKeys.publicKey, msg, sig);
    deepStrictEqual(isValid, true);
  });
  for (const k in VECTORS) {
    const v = VECTORS[k];
    should(`Wycheproof (issue 112): ${k}, sign`, () => {
      const mldsa = v.mldsa;
      for (const tg of v.sign.testGroups) {
        const privateKey = hexToBytes(tg.privateKey);
        for (const t of tg.tests) {
          const msg = hexToBytes(t.msg);
          const ctx = t.ctx ? hexToBytes(t.ctx) : undefined;
          if (t.result === 'valid')
            deepStrictEqual(bytesToHex(mldsa.sign(privateKey, msg, ctx)), t.sig);
          else throws(() => mldsa.sign(privateKey, msg, ctx));
        }
      }
    });
    should(`Wycheproof (issue 112): ${k}, verify`, () => {
      const mldsa = v.mldsa;
      for (const tg of v.verify.testGroups) {
        const publicKey = hexToBytes(tg.publicKey);
        for (const t of tg.tests) {
          const sig = hexToBytes(t.sig);
          const ctx = t.ctx ? hexToBytes(t.ctx) : undefined;
          const msg = hexToBytes(t.msg);
          try {
            const res = mldsa.verify(publicKey, msg, sig, ctx);
            deepStrictEqual(res, t.result === 'valid');
          } catch (e) {
            deepStrictEqual(t.result, 'invalid');
          }
        }
      }
    });
  }
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
