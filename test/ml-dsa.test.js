import { deepStrictEqual } from 'node:assert';
import { describe, should } from 'micro-should';
import { hexToBytes } from '@noble/hashes/utils';

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '../ml-dsa.js';

describe('ML-DSA Dilithium', () => {
  should('Example', () => {
    const aliceKeys = ml_dsa65.keygen();
    const msg = new Uint8Array(1);
    const sig = ml_dsa65.sign(aliceKeys.secretKey, msg);
    const isValid = ml_dsa65.verify(aliceKeys.publicKey, msg, sig);
  });
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
