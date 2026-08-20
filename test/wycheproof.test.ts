// Wycheproof test vectors from https://github.com/C2SP/wycheproof
import { hexToBytes as hexx } from '@noble/hashes/utils.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../src/ml-dsa.ts';
import { ml_kem1024, ml_kem512, ml_kem768 } from '../src/ml-kem.ts';
import { jsonGZGroups } from './util.ts';

/**
 * Yield a vector file's groups, and fail if it turns out to have none.
 *
 * An empty or truncated archive produces zero groups, so every `for await` loop below
 * runs zero iterations and the test passes having asserted nothing. That is the failure
 * mode a vector suite most needs to be immune to: the run is green in exactly the case
 * where it verified nothing at all. Counting on the way past costs nothing and turns a
 * silent pass into a loud failure.
 */
async function* loadWP(name: string) {
  let groups = 0;
  for await (const g of jsonGZGroups(`vectors/wycheproof/${name}.json.gz`)) {
    groups++;
    yield g;
  }
  if (groups === 0) throw new Error(`no test groups in ${name}: vector file empty or corrupt`);
}

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
        it('keygen', async () => {
          for await (const g of loadWP(`mlkem_${level}_keygen_seed_test`)) {
            for (const t of g.tests) {
              const keys = kem.keygen(hexx(t.seed));
              eql(keys.publicKey, hexx(t.ek));
              if (t.dk) eql(keys.secretKey, hexx(t.dk));
            }
          }
        });
        it('decaps', async () => {
          for await (const g of loadWP(`mlkem_${level}_test`)) {
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
        it('encaps', async () => {
          for await (const g of loadWP(`mlkem_${level}_encaps_test`)) {
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
        // The expanded-key import path: `dk` here is the full FIPS 203 decapsulation
        // key, which is exactly what decapsulate() takes, and it is how a key arriving
        // from another implementation reaches this library. These vectors were being
        // skipped as "not applicable"; they are the only negative coverage that path
        // has, including the malleable-ciphertext cases that catch a bad re-encryption
        // comparison.
        it('decaps (expanded key)', async () => {
          for await (const g of loadWP(`mlkem_${level}_semi_expanded_decaps_test`)) {
            for (const t of g.tests) {
              if (t.result === 'valid') {
                eql(kem.decapsulate(hexx(t.c), hexx(t.dk)), hexx(t.K));
              } else {
                let threw = false;
                try {
                  kem.decapsulate(hexx(t.c), hexx(t.dk));
                } catch {
                  threw = true;
                }
                eql(threw, true, `tcId=${t.tcId} ${t.comment}`);
              }
            }
          }
        });
      });
    }
  });
  describe('ML-DSA', () => {
    for (const { level, dsa } of DSA_LEVELS) {
      describe(`ML-DSA-${level}`, () => {
        it('verify', async () => {
          for await (const g of loadWP(`mldsa_${level}_verify_test`)) {
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
        it('sign (from seed)', async () => {
          for await (const g of loadWP(`mldsa_${level}_sign_seed_test`)) {
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
        // Signing from an expanded secret key, which is what sign() accepts and how a
        // key from another implementation arrives. Also the only vector coverage of
        // external-mu against a third party's expected output. Previously skipped as
        // "not applicable".
        it('sign (expanded key)', async () => {
          for await (const g of loadWP(`mldsa_${level}_sign_noseed_test`)) {
            const secretKey = hexx(g.privateKey);
            for (const t of g.tests) {
              // Most vectors here are deterministic (FIPS 204 rnd = 0^32); a few carry
              // their own rnd and must be signed hedged with exactly that value.
              const extraEntropy = t.rnd !== undefined ? hexx(t.rnd) : false;
              const context = t.ctx !== undefined ? hexx(t.ctx) : undefined;
              if (t.result === 'valid') {
                // Some vectors are mu-only: they exercise external-mu against a third
                // party's expected output and carry no message at all.
                if (t.msg !== undefined) {
                  const sig = dsa.sign(hexx(t.msg), secretKey, { extraEntropy, context });
                  eql(sig, hexx(t.sig), `tcId=${t.tcId} ${t.comment}`);
                }
                if (t.mu !== undefined) {
                  const viaMu = dsa.internal.sign(hexx(t.mu), secretKey, {
                    extraEntropy,
                    externalMu: true,
                  });
                  eql(viaMu, hexx(t.sig), `tcId=${t.tcId} externalMu ${t.comment}`);
                }
              } else {
                // Invalid vectors (over-long context, or a malformed expanded secret key:
                // wrong length, s1/s2 coefficients outside the ETA range) must be rejected,
                // not silently skipped. These sk-range checks are the only coverage of a
                // third party's malformed expanded key.
                let threw = false;
                try {
                  if (t.msg !== undefined)
                    dsa.sign(hexx(t.msg), secretKey, { extraEntropy, context });
                  else if (t.mu !== undefined)
                    dsa.internal.sign(hexx(t.mu), secretKey, { extraEntropy, externalMu: true });
                  else dsa.sign(new Uint8Array(), secretKey, { extraEntropy, context });
                } catch {
                  threw = true;
                }
                eql(threw, true, `tcId=${t.tcId} ${t.comment}`);
              }
            }
          }
        });
      });
    }
  });
});

it.runWhen(import.meta.url);
