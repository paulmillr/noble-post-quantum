import { deepStrictEqual } from 'node:assert';
import { describe, should } from 'micro-should';
import { hexToBytes } from '@noble/hashes/utils';
import { aes256_ctr_drbg } from './_drbg.js';
import { readKAT } from './util.js';

import {
  dilithium_v30,
  dilithium_v31,
  ml_dsa44,
  ml_dsa65,
  ml_dsa87,
  dilithium_v30_aes,
  dilithium_v31_aes,
} from '../ml-dsa.js';

const VERSIONS = {
  // ml dsa
  ml_dsa44: { fn: ml_dsa44, KAT: 'PQC-KAT/MLDSA/kat_MLDSA_44.rsp.gz' },
  ml_dsa65: { fn: ml_dsa65, KAT: 'PQC-KAT/MLDSA/kat_MLDSA_65.rsp.gz' },
  ml_dsa87: { fn: ml_dsa87, KAT: 'PQC-KAT/MLDSA/kat_MLDSA_87.rsp.gz' },
  // 3.0
  dilithium_v30_2: {
    fn: dilithium_v30.dilithium2,
    KAT: 'dilithium2/PQCsignKAT_2544.rsp.gz',
    randKAT: 'dilithium2-R/PQCsignKAT_2544.rsp.gz',
  },
  dilithium_v30_3: {
    fn: dilithium_v30.dilithium3,
    KAT: 'dilithium3/PQCsignKat_4016.rsp.gz',
    randKAT: 'dilithium3-R/PQCsignKat_4016.rsp.gz',
  },
  dilithium_v30_5: {
    fn: dilithium_v30.dilithium5,
    KAT: 'dilithium5/PQCsignKAT_4880.rsp.gz',
    randKAT: 'dilithium5-R/PQCsignKAT_4880.rsp.gz',
  },
  // 3.0 AES
  dilithium_v30_2_aes: {
    fn: dilithium_v30_aes.dilithium2,
    KAT: 'dilithium2-AES/PQCsignKAT_2544.rsp.gz',
    randKAT: 'dilithium2-AES-R/PQCsignKAT_2544.rsp.gz',
  },
  dilithium_v30_3_aes: {
    fn: dilithium_v30_aes.dilithium3,
    KAT: 'dilithium3-AES/PQCsignKAT_4016.rsp.gz',
    randKAT: 'dilithium3-AES-R/PQCsignKAT_4016.rsp.gz',
  },
  dilithium_v30_5_aes: {
    fn: dilithium_v30_aes.dilithium5,
    KAT: 'dilithium5-AES/PQCsignKAT_4880.rsp.gz',
    randKAT: 'dilithium5-AES-R/PQCsignKAT_4880.rsp.gz',
  },
  // 3.1 test vectors
  dilithium_v31_2: {
    fn: dilithium_v31.dilithium2,
    KAT: 'dilithium2/PQCsignKAT_Dilithium2.rsp.gz',
    randKAT: 'dilithium2-R/PQCsignKAT_Dilithium2.rsp.gz',
  },
  dilithium_v31_3: {
    fn: dilithium_v31.dilithium3,
    KAT: 'dilithium3/PQCsignKAT_Dilithium3.rsp.gz',
    randKAT: 'dilithium3-R/PQCsignKAT_Dilithium3.rsp.gz',
  },
  dilithium_v31_5: {
    fn: dilithium_v31.dilithium5,
    KAT: 'dilithium5/PQCsignKAT_Dilithium5.rsp.gz',
    randKAT: 'dilithium5-R/PQCsignKAT_Dilithium5.rsp.gz',
  },
  // 3.1 AES
  dilithium_v31_2_aes: {
    fn: dilithium_v31_aes.dilithium2,
    KAT: 'dilithium2-AES/PQCsignKAT_Dilithium2-AES.rsp.gz',
    randKAT: 'dilithium2-AES-R/PQCsignKAT_Dilithium2-AES.rsp.gz',
  },
  dilithium_v31_3_aes: {
    fn: dilithium_v31_aes.dilithium3,
    KAT: 'dilithium3-AES/PQCsignKAT_Dilithium3-AES.rsp.gz',
    randKAT: 'dilithium3-AES-R/PQCsignKAT_Dilithium3-AES.rsp.gz',
  },
  dilithium_v31_5_aes: {
    fn: dilithium_v31_aes.dilithium5,
    KAT: 'dilithium5-AES/PQCsignKAT_Dilithium5-AES.rsp.gz',
    randKAT: 'dilithium5-AES-R/PQCsignKAT_Dilithium5-AES.rsp.gz',
  },
};

describe('ML-DSA Dilithium', () => {
  should('Example', () => {
    const aliceKeys = ml_dsa65.keygen();
    const msg = new Uint8Array(1);
    const sig = ml_dsa65.sign(aliceKeys.secretKey, msg);
    const isValid = ml_dsa65.verify(aliceKeys.publicKey, msg, sig);
  });
  describe('KATs', () => {
    for (const v in VERSIONS) {
      const { fn: dilithium, KAT, randKAT } = VERSIONS[v];
      should(`${KAT}`, () => {
        const cases = readKAT(KAT);
        for (const c of cases) {
          const seed = hexToBytes(c.seed);
          const rng = aes256_ctr_drbg(seed);
          const { publicKey, secretKey } = dilithium.keygen(rng(32));
          deepStrictEqual(publicKey, hexToBytes(c.pk), 'publicKey');
          deepStrictEqual(secretKey, hexToBytes(c.sk), 'secretKey');
          // Signature = sig || msg
          const msg = hexToBytes(c.msg);
          deepStrictEqual(hexToBytes(c.sm).subarray(-msg.length), msg);
          const realSig = hexToBytes(c.sm).subarray(0, -msg.length);
          const signed = dilithium.sign(secretKey, hexToBytes(c.msg));
          deepStrictEqual(signed, realSig, 'sign');
          deepStrictEqual(dilithium.verify(publicKey, hexToBytes(c.msg), realSig), true, 'verify');
        }
      });
      if (randKAT) {
        should(`${KAT} (random)`, () => {
          const cases = readKAT(randKAT);
          for (const c of cases) {
            const seed = hexToBytes(c.seed);
            const rng = aes256_ctr_drbg(seed);
            const { publicKey, secretKey } = dilithium.keygen(rng(32));
            deepStrictEqual(publicKey, hexToBytes(c.pk), 'publicKey');
            deepStrictEqual(secretKey, hexToBytes(c.sk), 'secretKey');
            // Signature = sig || msg
            const msg = hexToBytes(c.msg);
            deepStrictEqual(hexToBytes(c.sm).subarray(-msg.length), msg);
            const realSig = hexToBytes(c.sm).subarray(0, -msg.length);
            const signed = dilithium.sign(
              secretKey,
              hexToBytes(c.msg),
              rng(dilithium.signRandBytes)
            );
            deepStrictEqual(signed, realSig, 'sign');
            deepStrictEqual(
              dilithium.verify(publicKey, hexToBytes(c.msg), realSig),
              true,
              'verify'
            );
          }
        });
      }
    }
  });
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
