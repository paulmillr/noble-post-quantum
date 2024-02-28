import { deepStrictEqual, notDeepStrictEqual, throws } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { describe, should } from 'micro-should';
import { concatBytes, hexToBytes } from '@noble/hashes/utils';
import {
  ml_kem512,
  ml_kem768,
  ml_kem1024,
  kyber512,
  kyber768,
  kyber1024,
  kyber512_90s,
  kyber768_90s,
  kyber1024_90s,
} from '../ml-kem.js';
import { aes256_ctr_drbg } from './_drbg.js';
import { readKAT, __dirname } from './util.js';

const VERSIONS = {
  kyber512: { fn: kyber512, KAT: 'kyber512/PQCkemKAT_1632.rsp.gz' },
  kyber768: { fn: kyber768, KAT: 'kyber768/PQCkemKAT_2400.rsp.gz' },
  kyber1024: { fn: kyber1024, KAT: 'kyber1024/PQCkemKAT_3168.rsp.gz' },
  kyber512_90s: { fn: kyber512_90s, KAT: 'kyber512-90s/PQCkemKAT_1632.rsp.gz' },
  kyber768_90s: { fn: kyber768_90s, KAT: 'kyber768-90s/PQCkemKAT_2400.rsp.gz' },
  kyber1024_90s: { fn: kyber1024_90s, KAT: 'kyber1024-90s/PQCkemKAT_3168.rsp.gz' },
};

const MLKEM_VERSIONS = {
  ml_kem512: { fn: ml_kem512, KAT: 'PQC-KAT/MLKEM/kat_MLKEM_512.rsp.gz' },
  ml_kem768: { fn: ml_kem768, KAT: 'PQC-KAT/MLKEM/kat_MLKEM_768.rsp.gz' },
  ml_kem1024: { fn: ml_kem1024, KAT: 'PQC-KAT/MLKEM/kat_MLKEM_1024.rsp.gz' },
};

describe('ML-KEM Kyber', () => {
  should('Example', () => {
    // Alice generates keys
    const aliceKeys = kyber1024.keygen(); // [Alice] generates key pair (secret and public key)
    const alicePub = aliceKeys.publicKey; // [Alice] sends public key to Bob (somehow)
    // aliceKeys.secretKey never leaves [Alice] system and unknown to other parties

    // Bob creates cipherText for Alice
    // [Bob] generates shared secret for Alice publicKey
    const { cipherText, sharedSecret: bobShared } = kyber1024.encapsulate(alicePub);
    // bobShared never leaves [Bob] system and unknown to other parties

    // Alice gets cipherText from Bob
    // [Alice] decrypts sharedSecret from Bob
    const aliceShared = kyber1024.decapsulate(cipherText, aliceKeys.secretKey);

    // Now, both Alice and Both have same sharedSecret key without exchanging in plainText
    deepStrictEqual(aliceShared, bobShared);

    // Warning: Can be MITM-ed
    const carolKeys = kyber1024.keygen();
    const carolShared = kyber1024.decapsulate(cipherText, carolKeys.secretKey); // No error!
    notDeepStrictEqual(aliceShared, carolShared); // Different key!
  });
  should('DRBG', () => {
    const KATS = Object.values(VERSIONS).map((i) => i.KAT);
    for (const k of KATS) {
      const input = Uint8Array.from({ length: 48 }, (_, j) => j);
      const rng = aes256_ctr_drbg(input);
      for (const c of readKAT(k)) deepStrictEqual(rng(48), hexToBytes(c.seed));
    }
  });
  describe('Basic', () => {
    for (const v in VERSIONS) {
      const { fn: kyber } = VERSIONS[v];
      should(v, () => {
        const { publicKey, secretKey } = kyber.keygen();
        const { cipherText: c, sharedSecret: ss1 } = kyber.encapsulate(publicKey);
        const ss2 = kyber.decapsulate(c, secretKey);
        deepStrictEqual(ss1, ss2, 'random');
      });
    }
  });
  for (const v in MLKEM_VERSIONS) {
    const { fn: kyber, KAT } = MLKEM_VERSIONS[v];
    should(`${v} basic`, () => {
      const { publicKey, secretKey } = kyber.keygen();
      const { cipherText: c, sharedSecret: ss1 } = kyber.encapsulate(publicKey);
      const ss2 = kyber.decapsulate(c, secretKey);
      deepStrictEqual(ss1, ss2, 'random');
    });
    should(`${v} KAT`, () => {
      for (const c of readKAT(KAT, 'count')) {
        const rng = aes256_ctr_drbg(hexToBytes(c.seed));
        deepStrictEqual(rng(32), hexToBytes(c.z));
        deepStrictEqual(rng(32), hexToBytes(c.d));
        deepStrictEqual(rng(32), hexToBytes(c.msg));
        deepStrictEqual(hexToBytes(c.sk).slice(-32), hexToBytes(c.z));
        const { publicKey: pk, secretKey: sk } = kyber.keygen(
          concatBytes(hexToBytes(c.d), hexToBytes(c.z))
        );
        deepStrictEqual(pk, hexToBytes(c.pk), 'publicKey');
        deepStrictEqual(sk, hexToBytes(c.sk), 'secretKey');
        const { cipherText: ct2, sharedSecret: ss2 } = kyber.encapsulate(pk, hexToBytes(c.msg));
        deepStrictEqual(ss2, hexToBytes(c.ss), 'sharedSecret');
        deepStrictEqual(ct2, hexToBytes(c.ct), 'encrypt');
        deepStrictEqual(kyber.decapsulate(ct2, sk), hexToBytes(c.ss), 'decrypt');
      }
    });
  }
  describe('KATs', () => {
    for (const v in VERSIONS) {
      const { fn: kyber, KAT } = VERSIONS[v];
      should(`${KAT}`, () => {
        const cases = readKAT(KAT);
        for (const c of cases) {
          const seed = hexToBytes(c.seed);
          const ciphertext = hexToBytes(c.ct);
          const publicKey = hexToBytes(c.pk);
          const secretKey = hexToBytes(c.sk);
          const sharedSecret = hexToBytes(c.ss);
          const rng = aes256_ctr_drbg(seed);
          const { publicKey: pk, secretKey: sk } = kyber.keygen(concatBytes(rng(32), rng(32)));
          deepStrictEqual(pk, publicKey, 'publicKey');
          deepStrictEqual(sk, secretKey, 'secretKey');
          const { cipherText: ct2, sharedSecret: ss2 } = kyber.encapsulate(pk, rng(32));
          deepStrictEqual(ct2, ciphertext, 'encrypt');
          deepStrictEqual(ss2, sharedSecret, 'sharedSecret');
          deepStrictEqual(sharedSecret, kyber.decapsulate(ciphertext, secretKey), 'decrypt');
        }
      });
    }
  });
});

// ESM is broken.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  should.run();
}
