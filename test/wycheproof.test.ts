// Wycheproof test vectors from https://github.com/C2SP/wycheproof
import { hexToBytes as hexx } from '@awasm/noble/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';
import { ml_kem1024, ml_kem512, ml_kem768 } from '../src/ml-kem.ts';
import { jsonGZ } from './util.ts';

const loadWP = (name) => jsonGZ(`vectors/wycheproof/${name}.json.gz`);

const KEM_LEVELS = [
  { level: '512', kem: ml_kem512 },
  { level: '768', kem: ml_kem768 },
  { level: '1024', kem: ml_kem1024 },
];

const DSA_LEVELS = [
  { level: '44', dsa: ml_dsa44 },
  { level: '65', dsa: ml_dsa65 },
  { level: '87', dsa: ml_dsa87 },
];

function dsaSign(dsa, secretKey, t) {
  if (t.flags?.includes('Internal')) {
    return dsa.internal.sign(hexx(t.mu), secretKey, {
      externalMu: true,
      extraEntropy: false,
    });
  }
  const opts = {
    extraEntropy: false,
    context: t.ctx !== undefined ? hexx(t.ctx) : undefined,
  };
  return dsa.sign(hexx(t.msg), secretKey, opts);
}

describe('Wycheproof', () => {
  describe('ML-KEM', () => {
    for (const { level, kem } of KEM_LEVELS) {
      describe(`ML-KEM-${level}`, () => {
        should('keygen', () => {
          const data = loadWP(`mlkem_${level}_keygen_seed_test`);
          for (const g of data.testGroups) {
            for (const t of g.tests) {
              const keys = kem.keygen(hexx(t.seed));
              eql(keys.publicKey, hexx(t.ek));
              if (t.dk) eql(keys.secretKey, hexx(t.dk));
            }
          }
        });
        should('decaps', () => {
          const data = loadWP(`mlkem_${level}_test`);
          for (const g of data.testGroups) {
            for (const t of g.tests) {
              if (t.result === 'valid') {
                const keys = kem.keygen(hexx(t.seed));
                eql(keys.publicKey, hexx(t.ek));
                const ss = kem.decapsulate(hexx(t.c), keys.secretKey);
                eql(ss, hexx(t.K));
              } else {
                let threw = false;
                try {
                  const keys = kem.keygen(hexx(t.seed));
                  kem.decapsulate(hexx(t.c), keys.secretKey);
                } catch {
                  threw = true;
                }
                eql(threw, true);
              }
            }
          }
        });
        should('encaps', () => {
          const data = loadWP(`mlkem_${level}_encaps_test`);
          for (const g of data.testGroups) {
            for (const t of g.tests) {
              if (t.result === 'valid') {
                const res = kem.encapsulate(hexx(t.ek), hexx(t.m));
                eql(res.cipherText, hexx(t.c));
                eql(res.sharedSecret, hexx(t.K));
              } else {
                let threw = false;
                try {
                  kem.encapsulate(hexx(t.ek), hexx(t.m));
                } catch {
                  threw = true;
                }
                eql(threw, true);
              }
            }
          }
        });
        // semi_expanded_decaps tests skipped: not applicable
        // (provide semi-expanded dk, not keygen seeds)
      });
    }
  });
  describe('ML-DSA', () => {
    for (const { level, dsa } of DSA_LEVELS) {
      describe(`ML-DSA-${level}`, () => {
        should('verify', () => {
          const data = loadWP(`mldsa_${level}_verify_test`);
          for (const g of data.testGroups) {
            const pk = hexx(g.publicKey);
            for (const t of g.tests) {
              const ctx = t.ctx !== undefined ? hexx(t.ctx) : undefined;
              const opts = ctx !== undefined ? { context: ctx } : {};
              let valid;
              try {
                valid = dsa.verify(hexx(t.sig), hexx(t.msg), pk, opts);
              } catch {
                valid = false;
              }
              if (t.result === 'valid') eql(valid, true);
              else if (t.result === 'invalid') eql(valid, false);
            }
          }
        });
        should('sign (from seed)', () => {
          const data = loadWP(`mldsa_${level}_sign_seed_test`);
          for (const g of data.testGroups) {
            let keys;
            try {
              keys = dsa.keygen(hexx(g.privateSeed));
            } catch {
              // Invalid seed length: all tests in group must be invalid
              for (const t of g.tests) eql(t.result, 'invalid');
              continue;
            }
            eql(keys.publicKey, hexx(g.publicKey));
            for (const t of g.tests) {
              if (t.result === 'valid') {
                const sig = dsaSign(dsa, keys.secretKey, t);
                eql(sig, hexx(t.sig));
              } else {
                let threw = false;
                try {
                  dsaSign(dsa, keys.secretKey, t);
                } catch {
                  threw = true;
                }
                eql(threw, true);
              }
            }
          }
        });
        // sign_noseed tests skipped: not applicable
        // (provide semi-expanded private keys, not seeds)
      });
    }
  });
});

should.runWhen(import.meta.url);
