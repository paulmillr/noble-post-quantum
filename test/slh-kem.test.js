import { deepStrictEqual } from 'node:assert';
import { describe, should } from 'micro-should';
import { aes256_ctr_drbg } from './_drbg.js';
import { readKAT } from './util.js';
import { concatBytes, hexToBytes } from '@noble/hashes/utils';
import * as sphincs_sha2 from '../slh-dsa.js';
import * as sphincs_shake from '../slh-dsa.js';

import {
  slh_dsa_shake_128f,
  slh_dsa_shake_128s,
  slh_dsa_shake_192f,
  slh_dsa_shake_192s,
  slh_dsa_shake_256f,
  slh_dsa_shake_256s,
} from '../slh-dsa.js';

import {
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
} from '../slh-dsa.js';

describe('SLH-DSA SPHINCS', () => {
  should('Example', () => {
    const sph = slh_dsa_sha2_128f;
    const aliceKeys = sph.keygen();
    const msg = new Uint8Array(1);
    const sig = sph.sign(aliceKeys.secretKey, msg);
    const isValid = sph.verify(aliceKeys.publicKey, msg, sig);
  });
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
