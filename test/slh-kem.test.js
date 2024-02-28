import { deepStrictEqual } from 'node:assert';
import { describe, should } from 'micro-should';
import { aes256_ctr_drbg } from './_drbg.js';
import { readKAT } from './util.js';
import { concatBytes, hexToBytes } from '@noble/hashes/utils';
import * as sphincs_sha2 from '../slh-dsa.js';
import * as sphincs_shake from '../slh-dsa.js';

import {
  sphincs_shake_128f_simple,
  sphincs_shake_128f_robust,
  sphincs_shake_128s_simple,
  sphincs_shake_128s_robust,
  sphincs_shake_192f_simple,
  sphincs_shake_192f_robust,
  sphincs_shake_192s_simple,
  sphincs_shake_192s_robust,
  sphincs_shake_256f_simple,
  sphincs_shake_256f_robust,
  sphincs_shake_256s_simple,
  sphincs_shake_256s_robust,
  // Only simple mode in SLH-DSA
  slh_dsa_shake_128f,
  slh_dsa_shake_128s,
  slh_dsa_shake_192f,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
} from '../slh-dsa.js';

import {
  sphincs_sha2_128f_simple,
  sphincs_sha2_128f_robust,
  sphincs_sha2_128s_simple,
  sphincs_sha2_128s_robust,
  sphincs_sha2_192f_simple,
  sphincs_sha2_192f_robust,
  sphincs_sha2_192s_simple,
  sphincs_sha2_192s_robust,
  sphincs_sha2_256f_simple,
  sphincs_sha2_256f_robust,
  sphincs_sha2_256s_simple,
  sphincs_sha2_256s_robust,
  // Only simple mode in SLH-DSA
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
} from '../slh-dsa.js';

// SHA2 test suit: 7341s
// SHA2 + SHAKE: 25772s = 7 hours

const SPHINCS_VERSIONS = {
  // SHA2
  sha2_128f_simple: {
    fn: sphincs_sha2.sphincs_sha2_128f_simple,
    KAT: 'sphincs/sphincs-sha2-128f-simple.rsp.gz',
  },
  sha2_128f_robust: {
    fn: sphincs_sha2.sphincs_sha2_128f_robust,
    KAT: 'sphincs/sphincs-sha2-128f-robust.rsp.gz',
  },
  sha2_128s_simple: {
    fn: sphincs_sha2.sphincs_sha2_128s_simple,
    KAT: 'sphincs/sphincs-sha2-128s-simple.rsp.gz',
  },
  sha2_128s_robust: {
    fn: sphincs_sha2.sphincs_sha2_128s_robust,
    KAT: 'sphincs/sphincs-sha2-128s-robust.rsp.gz',
  },
  sha2_192f_simple: {
    fn: sphincs_sha2.sphincs_sha2_192f_simple,
    KAT: 'sphincs/sphincs-sha2-192f-simple.rsp.gz',
  },
  sha2_192f_robust: {
    fn: sphincs_sha2.sphincs_sha2_192f_robust,
    KAT: 'sphincs/sphincs-sha2-192f-robust.rsp.gz',
  },
  sha2_192s_simple: {
    fn: sphincs_sha2.sphincs_sha2_192s_simple,
    KAT: 'sphincs/sphincs-sha2-192s-simple.rsp.gz',
  },
  sha2_192s_robust: {
    fn: sphincs_sha2.sphincs_sha2_192s_robust,
    KAT: 'sphincs/sphincs-sha2-192s-robust.rsp.gz',
  },
  sha2_256f_simple: {
    fn: sphincs_sha2.sphincs_sha2_256f_simple,
    KAT: 'sphincs/sphincs-sha2-256f-simple.rsp.gz',
  },
  sha2_256f_robust: {
    fn: sphincs_sha2.sphincs_sha2_256f_robust,
    KAT: 'sphincs/sphincs-sha2-256f-robust.rsp.gz',
  },
  sha2_256s_simple: {
    fn: sphincs_sha2.sphincs_sha2_256s_simple,
    KAT: 'sphincs/sphincs-sha2-256s-simple.rsp.gz',
  },
  sha2_256s_robust: {
    fn: sphincs_sha2.sphincs_sha2_256s_robust,
    KAT: 'sphincs/sphincs-sha2-256s-robust.rsp.gz',
  },
  // SHAKE
  shake_128f_simple: {
    fn: sphincs_shake.sphincs_shake_128f_simple,
    KAT: 'sphincs/sphincs-shake-128f-simple.rsp.gz',
  },
  shake_128f_robust: {
    fn: sphincs_shake.sphincs_shake_128f_robust,
    KAT: 'sphincs/sphincs-shake-128f-robust.rsp.gz',
  },
  shake_128s_simple: {
    fn: sphincs_shake.sphincs_shake_128s_simple,
    KAT: 'sphincs/sphincs-shake-128s-simple.rsp.gz',
  },
  shake_128s_robust: {
    fn: sphincs_shake.sphincs_shake_128s_robust,
    KAT: 'sphincs/sphincs-shake-128s-robust.rsp.gz',
  },
  shake_192f_simple: {
    fn: sphincs_shake.sphincs_shake_192f_simple,
    KAT: 'sphincs/sphincs-shake-192f-simple.rsp.gz',
  },
  shake_192f_robust: {
    fn: sphincs_shake.sphincs_shake_192f_robust,
    KAT: 'sphincs/sphincs-shake-192f-robust.rsp.gz',
  },
  shake_192s_simple: {
    fn: sphincs_shake.sphincs_shake_192s_simple,
    KAT: 'sphincs/sphincs-shake-192s-simple.rsp.gz',
  },
  shake_192s_robust: {
    fn: sphincs_shake.sphincs_shake_192s_robust,
    KAT: 'sphincs/sphincs-shake-192s-robust.rsp.gz',
  },
  shake_256f_simple: {
    fn: sphincs_shake.sphincs_shake_256f_simple,
    KAT: 'sphincs/sphincs-shake-256f-simple.rsp.gz',
  },
  shake_256f_robust: {
    fn: sphincs_shake.sphincs_shake_256f_robust,
    KAT: 'sphincs/sphincs-shake-256f-robust.rsp.gz',
  },
  shake_256s_simple: {
    fn: sphincs_shake.sphincs_shake_256s_simple,
    KAT: 'sphincs/sphincs-shake-256s-simple.rsp.gz',
  },
  shake_256s_robust: {
    fn: sphincs_shake.sphincs_shake_256s_robust,
    KAT: 'sphincs/sphincs-shake-256s-robust.rsp.gz',
  },
};

describe('SLH-DSA SPHINCS', () => {
  should('Example', () => {
    const sph = slh_dsa_sha2_128f;
    const aliceKeys = sph.keygen();
    const msg = new Uint8Array(1);
    const sig = sph.sign(aliceKeys.secretKey, msg);
    const isValid = sph.verify(aliceKeys.publicKey, msg, sig);
  });
  should('immutable arguments', () => {
    const d = sphincs_sha2.sphincs_sha2_128f_simple;
    const msg = new Uint8Array(0);
    const { publicKey, secretKey } = d.keygen();
    const pk2 = publicKey.slice();
    const sk2 = secretKey.slice();
    const sig = d.sign(sk2, msg);
    deepStrictEqual(sk2, secretKey);
    deepStrictEqual(d.verify(pk2, msg, sig), true);
    deepStrictEqual(pk2, publicKey);
  });

  for (const v in SPHINCS_VERSIONS) {
    const { fn, KAT } = SPHINCS_VERSIONS[v];
    const isFast = true;
    should(`${v}`, () => {
      let i = 0;
      for (const c of readKAT(KAT)) {
        const seed = hexToBytes(c.seed);
        const rng = aes256_ctr_drbg(seed);
        console.log('KAT', c.count, c.mlen);
        const { publicKey, secretKey } = fn.keygen(concatBytes(rng(fn.seedLen)));
        deepStrictEqual(publicKey, hexToBytes(c.pk), 'pk');
        deepStrictEqual(secretKey, hexToBytes(c.sk), 'sk');
        const msg = hexToBytes(c.msg);
        const sig = fn.sign(secretKey, msg, rng(fn.signRandBytes));
        deepStrictEqual(sig, hexToBytes(c.sm).subarray(0, -msg.length), 'sig');
        deepStrictEqual(fn.verify(publicKey, msg, sig), true);
        if (isFast) break;
      }
    });
  }
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
